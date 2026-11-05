
import sys
from pathlib import Path

import anyio
from mcp import Client, MCPError, StdioServerParameters

SERVER = Path(__file__).resolve().parent / "server.py"
failures = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    failures += 0 if ok else 1
    print(f"  {'OK  ' if ok else 'FAIL'} {label}" + (f"  ->  {detail}" if detail else ""))


async def expect_rpc_error(client: Client, label: str, name: str, args: dict, code: int = -32602) -> None:
    try:
        await client.call_tool(name, args)
        check(label, False, "no error was raised")
    except MCPError as exc:
        fields = [e["field"] for e in (exc.data or {}).get("errors", [])]
        check(label, exc.code == code, f"code {exc.code}, bad field(s): {fields}")


async def main() -> None:
    # Use THIS python to start the server, so the same environment is used for both.
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)])
    async with Client(params) as client:
        print(f"Connected to {client.server_info.name} {client.server_info.version}")

        print("\nTools")
        tools = [t.name for t in (await client.list_tools()).tools]
        check("two tools are listed", sorted(tools) == ["get_customer_record", "trigger_refund"], str(tools))

        print("\nGood input")
        r = await client.call_tool("get_customer_record", {"customer_id": "CUST-12345"})
        check("get_customer_record CUST-12345", not r.is_error and r.structured_content["name"] == "Ava Thompson",
              r.structured_content["name"])
        r = await client.call_tool("trigger_refund", {"customer_id": "CUST-12345", "amount": 19.99,
                                                       "reason": "Item arrived damaged"})
        check("trigger_refund 19.99", not r.is_error and r.structured_content["status"] == "queued",
              r.structured_content["refund_id"])

        print("\nValid format but customer does not exist (tool error, not a protocol error)")
        r = await client.call_tool("get_customer_record", {"customer_id": "CUST-99999"})
        check("unknown customer gives isError=true", r.is_error, r.content[0].text)

        print("\nBad input (should be JSON-RPC error -32602)")
        await expect_rpc_error(client, "customer_id 'oops'", "get_customer_record", {"customer_id": "oops"})
        await expect_rpc_error(client, "customer_id 'CUST-1234' (4 digits)", "get_customer_record", {"customer_id": "CUST-1234"})
        await expect_rpc_error(client, "amount -5", "trigger_refund",
                               {"customer_id": "CUST-12345", "amount": -5, "reason": "Duplicate charge"})
        await expect_rpc_error(client, "amount '25' (a string)", "trigger_refund",
                               {"customer_id": "CUST-12345", "amount": "25", "reason": "Duplicate charge"})
        await expect_rpc_error(client, "reason too short", "trigger_refund",
                               {"customer_id": "CUST-12345", "amount": 5, "reason": "short"})
        await expect_rpc_error(client, "missing arguments", "trigger_refund", {})

    print(f"\n{'ALL CHECKS PASSED' if not failures else str(failures) + ' CHECK(S) FAILED'}")
    sys.exit(1 if failures else 0)


anyio.run(main)
