

from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

import anyio

from mcp import MCPError, types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

SERVER_NAME = "customer-support-mcp"
SERVER_VERSION = "1.0.0"

log = logging.getLogger(SERVER_NAME)


def _configure_logging() -> None:
    """Send every log record to stderr. stdout must carry JSON-RPC only."""
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        force=True,
    )


# --------------------------------------------------------------------------- #
# Input schemas (strict validation)
# --------------------------------------------------------------------------- #

# [0-9] rather than \d so Unicode digits (e.g. full-width) are rejected.
CustomerId = Annotated[
    str,
    Field(
        pattern=r"^CUST-[0-9]{5}$",
        description="Customer ID in the form CUST-XXXXX where X is a digit, e.g. CUST-12345.",
    ),
]


class _StrictModel(BaseModel):
    # strict: no coercion ("25" is not a number, True is not a number).
    # extra=forbid: unknown fields are an error, not silently ignored.
    model_config = ConfigDict(strict=True, extra="forbid")


class GetCustomerRecordInput(_StrictModel):
    customer_id: CustomerId


class TriggerRefundInput(_StrictModel):
    customer_id: CustomerId
    amount: Annotated[
        float,
        Field(
            gt=0,
            allow_inf_nan=False,
            description="Refund amount. Must be a finite number greater than 0.",
        ),
    ]
    reason: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=10, max_length=500),
        Field(
            description=(
                "Why the refund is being issued. At least 10 characters after "
                "trimming surrounding whitespace (max 500)."
            )
        ),
    ]


# --------------------------------------------------------------------------- #
# Mock data store
# --------------------------------------------------------------------------- #

CUSTOMERS: dict[str, dict[str, Any]] = {
    "CUST-12345": {
        "customer_id": "CUST-12345",
        "name": "Ava Thompson",
        "email": "ava.thompson@example.com",
        "status": "active",
        "plan": "premium",
        "created_at": "2023-02-14",
    },
    "CUST-00001": {
        "customer_id": "CUST-00001",
        "name": "Ben Carter",
        "email": "ben.carter@example.com",
        "status": "active",
        "plan": "basic",
        "created_at": "2024-06-01",
    },
    "CUST-54321": {
        "customer_id": "CUST-54321",
        "name": "Chloe Nguyen",
        "email": "chloe.nguyen@example.com",
        "status": "suspended",
        "plan": "basic",
        "created_at": "2022-11-30",
    },
}

REFUNDS: list[dict[str, Any]] = []


# --------------------------------------------------------------------------- #
# Tool implementations
# --------------------------------------------------------------------------- #


def _ok(payload: dict[str, Any]) -> types.CallToolResult:
    """Successful result: JSON text (for any client) + structured content."""
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(payload))],
        structured_content=payload,
    )


def _tool_error(message: str) -> types.CallToolResult:
    """Business-level failure the model can read and react to."""
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)],
        is_error=True,
    )


def get_customer_record(args: GetCustomerRecordInput) -> types.CallToolResult:
    record = CUSTOMERS.get(args.customer_id)
    if record is None:
        return _tool_error(f"Customer {args.customer_id} was not found.")
    return _ok(record)


def trigger_refund(args: TriggerRefundInput) -> types.CallToolResult:
    if args.customer_id not in CUSTOMERS:
        return _tool_error(f"Customer {args.customer_id} was not found; no refund issued.")
    refund = {
        "refund_id": f"RFD-{uuid.uuid4().hex[:10].upper()}",
        "customer_id": args.customer_id,
        "amount": round(args.amount, 2),
        "reason": args.reason,
        "status": "queued",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    REFUNDS.append(refund)
    log.info("refund queued id=%s customer=%s amount=%.2f", refund["refund_id"], args.customer_id, args.amount)
    return _ok(refund)


# name -> (input model, implementation, Tool definition)
_TOOLS: dict[str, tuple[type[_StrictModel], Any, types.Tool]] = {
    "get_customer_record": (
        GetCustomerRecordInput,
        get_customer_record,
        types.Tool(
            name="get_customer_record",
            description="Fetch a customer's profile by customer ID (format CUST-XXXXX).",
            input_schema=GetCustomerRecordInput.model_json_schema(),
            annotations=types.ToolAnnotations(
                title="Get customer record",
                read_only_hint=True,
                open_world_hint=False,
            ),
        ),
    ),
    "trigger_refund": (
        TriggerRefundInput,
        trigger_refund,
        types.Tool(
            name="trigger_refund",
            description=(
                "Queue a refund for a customer. Amount must be > 0 and the reason "
                "must be at least 10 characters. This moves money - confirm with the user first."
            ),
            input_schema=TriggerRefundInput.model_json_schema(),
            annotations=types.ToolAnnotations(
                title="Trigger refund",
                read_only_hint=False,
                destructive_hint=False,
                idempotent_hint=False,
                open_world_hint=False,
            ),
        ),
    ),
}


# --------------------------------------------------------------------------- #
# MCP handlers
# --------------------------------------------------------------------------- #


VALIDATION_ERROR_MODES = ("jsonrpc", "tool_result")


def _validation_error_mode() -> str:
    """How argument-validation failures are reported (env ``MCP_VALIDATION_ERRORS``).

    * ``jsonrpc`` (default) - a JSON-RPC ``-32602`` error, as this task's brief asks.
    * ``tool_result``       - a normal result with ``isError: true``. MCP SEP-1303
      (Final) recommends this because protocol errors are handled by the client
      application and never reach the model, so the model cannot self-correct.
    """
    mode = os.environ.get("MCP_VALIDATION_ERRORS", "jsonrpc")
    if mode not in VALIDATION_ERROR_MODES:
        # SystemExit(str) prints to stderr, keeping stdout clean even on failure.
        raise SystemExit(f"MCP_VALIDATION_ERRORS must be one of {VALIDATION_ERROR_MODES}, got {mode!r}")
    return mode


def _describe_validation_error(exc: ValidationError) -> list[dict[str, str]]:
    """Field-level details without echoing raw input values back to the client."""
    return [
        {
            "field": ".".join(str(p) for p in err["loc"]) or "<arguments>",
            "message": err["msg"],
            "type": err["type"],
        }
        for err in exc.errors(include_input=False, include_context=False, include_url=False)
    ]


async def on_list_tools(
    ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
) -> types.ListToolsResult:
    return types.ListToolsResult(tools=[tool for _, _, tool in _TOOLS.values()])


async def on_call_tool(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> types.CallToolResult:
    entry = _TOOLS.get(params.name)
    if entry is None:
        # MCP spec: an unknown tool is a protocol error (-32602), not a tool result.
        raise MCPError(types.INVALID_PARAMS, f"Unknown tool: {params.name!r}")
    model, impl, _ = entry

    try:
        # `arguments` may be omitted by the client; validate {} so the
        # "missing required field" errors are reported uniformly.
        parsed = model.model_validate(params.arguments if params.arguments is not None else {})
    except ValidationError as exc:
        details = _describe_validation_error(exc)
        log.warning("invalid arguments for %s: %s", params.name, details)
        if _validation_error_mode() == "tool_result":
            summary = "; ".join(f"{d['field']}: {d['message']}" for d in details)
            return _tool_error(f"Invalid arguments for tool {params.name!r} - {summary}")
        raise MCPError(
            types.INVALID_PARAMS,
            f"Invalid arguments for tool {params.name!r}",
            data={"errors": details},
        ) from None

    try:
        return impl(parsed)
    except MCPError:
        raise
    except Exception:
        # Full traceback to stderr only; the client gets a generic -32603.
        log.exception("unhandled error in tool %s", params.name)
        raise MCPError(types.INTERNAL_ERROR, "Internal server error") from None


def build_server() -> Server[Any]:
    return Server(
        SERVER_NAME,
        version=SERVER_VERSION,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def _inbound_failure_response(exc: Exception) -> SessionMessage:
    """Build the JSON-RPC error for a line that could not be turned into a message.

    JSON-RPC 2.0 requires ``-32700 Parse error`` for text that is not valid JSON
    and ``-32600 Invalid Request`` for valid JSON that is not a request object.
    The id is ``null`` because the request id cannot be determined. The SDK's
    stdio reader hands these failures to the server as ``Exception`` items, which
    the server loop drops silently - so we answer them here.
    """
    is_syntax_error = isinstance(exc, ValidationError) and any(
        err["type"] == "json_invalid" for err in exc.errors()
    )
    if is_syntax_error:
        error = types.ErrorData(code=types.PARSE_ERROR, message="Parse error")
    else:
        error = types.ErrorData(code=types.INVALID_REQUEST, message="Invalid Request")
    log.warning("rejected inbound line: %s", error.message)  # details stay on stderr
    return SessionMessage(types.JSONRPCError(jsonrpc="2.0", id=None, error=error))


async def run_stdio() -> None:
    server = build_server()
    async with stdio_server() as (raw_read_stream, write_stream):
        to_server, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](0)

        async def forward_inbound() -> None:
            """Pass valid messages through; answer unparseable ones directly."""
            async with to_server:
                async for item in raw_read_stream:
                    if isinstance(item, Exception):
                        await write_stream.send(_inbound_failure_response(item))
                    else:
                        await to_server.send(item)

        log.info("%s %s ready on stdio", SERVER_NAME, SERVER_VERSION)
        async with anyio.create_task_group() as tg:
            tg.start_soon(forward_inbound)
            await server.run(read_stream, write_stream, server.create_initialization_options())
            tg.cancel_scope.cancel()


def main() -> None:
    _configure_logging()
    _validation_error_mode()  # fail fast on a bad setting, before serving anything
    try:
        anyio.run(run_stdio)
    except KeyboardInterrupt:
        log.info("shutting down")


if __name__ == "__main__":
    main()
