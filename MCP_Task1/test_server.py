
from __future__ import annotations

import ast
import json
import math
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
SERVER = HERE / "server.py"

LEGACY_PROTOCOL = "2025-11-25"
MODERN_PROTOCOL = "2026-07-28"
MODERN_META = {
    "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL,
    "io.modelcontextprotocol/clientCapabilities": {},
}

INVALID_PARAMS = -32602
METHOD_NOT_FOUND = -32601
INVALID_REQUEST = -32600
PARSE_ERROR = -32700

VALID_ID = "CUST-12345"
VALID_REASON = "Item arrived damaged"


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #


def assert_jsonrpc_lines(lines: list[str]) -> None:
    """Every stdout line must be a single JSON-RPC 2.0 message."""
    for line in lines:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            raise AssertionError(f"stdout contains a non-JSON line (stdout polluted): {line!r}") from None
        assert isinstance(msg, dict), f"stdout line is not a JSON object: {line!r}"
        assert msg.get("jsonrpc") == "2.0", f"stdout line is not JSON-RPC 2.0: {line!r}"
        assert {"result", "error", "method"} & msg.keys(), f"not a request/response/notification: {line!r}"


class StdioSession:
    """A running server process plus helpers for talking JSON-RPC to it."""

    def __init__(self, modern: bool = False, env: dict[str, str] | None = None) -> None:
        self.modern = modern
        self.proc = subprocess.Popen(
            [sys.executable, str(SERVER)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=HERE,
            env={**os.environ, **(env or {})},
        )
        self.stdout_lines: list[str] = []
        self.stderr_lines: list[str] = []
        self._inbox: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._next_id = 0
        self._threads = [
            threading.Thread(target=self._pump_stdout, daemon=True),
            threading.Thread(target=self._pump_stderr, daemon=True),
        ]
        for t in self._threads:
            t.start()

    # -- plumbing ----------------------------------------------------------- #

    def _pump_stdout(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            line = line.rstrip("\n")
            self.stdout_lines.append(line)
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                parsed = None  # purity check reports the bad line later
            self._inbox.put(parsed if isinstance(parsed, dict) else None)

    def _pump_stderr(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self.stderr_lines.append(line.rstrip("\n"))

    def send_raw(self, text: str) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(text + "\n")
        self.proc.stdin.flush()

    def send(self, message: dict[str, Any]) -> None:
        self.send_raw(json.dumps(message))

    def read_message(self, timeout: float = 10.0) -> dict[str, Any]:
        try:
            msg = self._inbox.get(timeout=timeout)
        except queue.Empty:
            tail = "\n".join(self.stderr_lines[-10:])
            raise TimeoutError(f"no message from server within {timeout}s; stderr tail:\n{tail}") from None
        assert msg is not None, "server wrote a non-JSON-object line to stdout"
        return msg

    def _read_response(self, rid: int, timeout: float = 10.0) -> dict[str, Any]:
        while True:
            msg = self.read_message(timeout)
            if msg.get("id") == rid and ("result" in msg or "error" in msg):
                return msg

    # -- protocol helpers --------------------------------------------------- #

    def handshake(self) -> dict[str, Any]:
        """Classic initialize / initialized sequence (legacy era only)."""
        resp = self.request(
            "initialize",
            {
                "protocolVersion": LEGACY_PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "0"},
            },
        )
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return resp

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._next_id += 1
        rid = self._next_id
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None or (self.modern and method != "initialize"):
            body = dict(params or {})
            if self.modern and method != "initialize":
                body["_meta"] = MODERN_META
            msg["params"] = body
        self.send(msg)
        return self._read_response(rid)

    def call(self, name: str, arguments: Any = ...) -> dict[str, Any]:
        """tools/call. Pass ``arguments=...`` (default) to omit the field entirely."""
        params: dict[str, Any] = {"name": name}
        if arguments is not ...:
            params["arguments"] = arguments
        return self.request("tools/call", params)

    def close(self) -> int:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.close()
        except BrokenPipeError:
            pass
        try:
            code = self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            raise
        for t in self._threads:
            t.join(timeout=5)
        return code


def assert_rpc_error(resp: dict[str, Any], code: int) -> dict[str, Any]:
    assert "error" in resp and "result" not in resp, f"expected JSON-RPC error, got: {resp}"
    assert resp["error"]["code"] == code, f"expected {code}, got: {resp['error']}"
    return resp["error"]


def assert_tool_ok(resp: dict[str, Any]) -> dict[str, Any]:
    assert "result" in resp, f"expected a result, got: {resp}"
    assert resp["result"].get("isError") in (False, None)
    return resp["result"]


@pytest.fixture(scope="module", params=["legacy", "modern"])
def session(request):
    """One long-lived server per protocol era, shared by the wire tests."""
    s = StdioSession(modern=request.param == "modern")
    if not s.modern:
        s.handshake()
    yield s
    code = s.close()
    # The headline requirement, checked over the *entire* session transcript:
    assert_jsonrpc_lines(s.stdout_lines)
    assert code == 0, f"server exited with {code}; stderr:\n" + "\n".join(s.stderr_lines[-10:])


@pytest.fixture
def fresh():
    """A brand-new legacy-era server for tests that abuse the connection."""
    s = StdioSession()
    s.handshake()
    yield s
    s.close()
    assert_jsonrpc_lines(s.stdout_lines)


# --------------------------------------------------------------------------- #
# STDIO isolation
# --------------------------------------------------------------------------- #


def test_checker_detects_polluted_stdout():
    """Guard against a vacuous purity check: it must reject stray output."""
    assert_jsonrpc_lines(['{"jsonrpc":"2.0","id":1,"result":{}}'])
    for bad in ["hello", "INFO ready on stdio", "{}", "[1,2]", '{"id":1}', ""]:
        with pytest.raises(AssertionError):
            assert_jsonrpc_lines([bad])


def test_source_never_writes_to_stdout():
    """Static check: no print(), sys.stdout or fd-1 writes anywhere in server.py."""
    tree = ast.parse(SERVER.read_text())
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
            offenders.append(f"line {node.lineno}: print()")
        if isinstance(node, ast.Attribute) and node.attr == "stdout":
            offenders.append(f"line {node.lineno}: .stdout")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "write"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
        ):
            offenders.append(f"line {node.lineno}: os.write()")
    assert not offenders, offenders


def test_logs_go_to_stderr_not_stdout(session):
    session.call("get_customer_record", {"customer_id": "bad"})  # provokes a WARNING log
    assert any("ready on stdio" in line for line in session.stderr_lines), session.stderr_lines
    assert any("invalid arguments" in line for line in session.stderr_lines), session.stderr_lines
    assert not any(line.lstrip().startswith("{") and '"jsonrpc"' in line for line in session.stderr_lines)
    assert_jsonrpc_lines(session.stdout_lines)


# --------------------------------------------------------------------------- #
# Lifecycle / discovery
# --------------------------------------------------------------------------- #


def test_initialize_handshake_reports_server_identity():
    s = StdioSession()
    try:
        resp = s.handshake()
        result = resp["result"]
        assert result["serverInfo"]["name"] == "customer-support-mcp"
        assert "tools" in result["capabilities"]
    finally:
        s.close()


def test_tools_list(session):
    result = session.request("tools/list")["result"]
    tools = {t["name"]: t for t in result["tools"]}
    assert set(tools) == {"get_customer_record", "trigger_refund"}

    get_schema = tools["get_customer_record"]["inputSchema"]
    assert get_schema["required"] == ["customer_id"]
    assert get_schema["properties"]["customer_id"]["pattern"] == "^CUST-[0-9]{5}$"
    assert get_schema["additionalProperties"] is False
    assert tools["get_customer_record"]["annotations"]["readOnlyHint"] is True

    refund_schema = tools["trigger_refund"]["inputSchema"]
    assert set(refund_schema["required"]) == {"customer_id", "amount", "reason"}
    assert refund_schema["properties"]["amount"]["exclusiveMinimum"] == 0
    assert refund_schema["properties"]["reason"]["minLength"] == 10
    assert tools["trigger_refund"]["annotations"]["readOnlyHint"] is False


# --------------------------------------------------------------------------- #
# Happy paths
# --------------------------------------------------------------------------- #


def test_get_customer_record_success(session):
    result = assert_tool_ok(session.call("get_customer_record", {"customer_id": VALID_ID}))
    assert result["structuredContent"]["customer_id"] == VALID_ID
    assert result["structuredContent"]["name"] == "Ava Thompson"
    # text content mirrors structured content for clients that only read text
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]


@pytest.mark.parametrize("amount", [25, 25.5, 0.01, 1e9])
def test_trigger_refund_success(session, amount):
    result = assert_tool_ok(
        session.call("trigger_refund", {"customer_id": VALID_ID, "amount": amount, "reason": VALID_REASON})
    )
    refund = result["structuredContent"]
    assert refund["refund_id"].startswith("RFD-")
    assert refund["amount"] == pytest.approx(amount)
    assert refund["customer_id"] == VALID_ID
    assert refund["status"] == "queued"


# --------------------------------------------------------------------------- #
# Business errors are tool results (isError), not protocol errors
# --------------------------------------------------------------------------- #


def test_unknown_customer_is_a_tool_error_not_a_protocol_error(session):
    resp = session.call("get_customer_record", {"customer_id": "CUST-99999"})
    assert "error" not in resp
    assert resp["result"]["isError"] is True
    assert "not found" in resp["result"]["content"][0]["text"]


def test_refund_for_unknown_customer_is_a_tool_error(session):
    resp = session.call("trigger_refund", {"customer_id": "CUST-99999", "amount": 5, "reason": VALID_REASON})
    assert "error" not in resp
    assert resp["result"]["isError"] is True


# --------------------------------------------------------------------------- #
# Validation: customer_id
# --------------------------------------------------------------------------- #

BAD_CUSTOMER_IDS = [
    "",
    "CUST-1234",  # too short
    "CUST-123456",  # too long
    "cust-12345",  # wrong case
    "CUST12345",  # missing hyphen
    "CUST-ABCDE",  # not digits
    "CUST-12 45",
    " CUST-12345",  # leading whitespace
    "CUST-12345 ",  # trailing whitespace
    "CUST-12345\n",  # `$` would wrongly accept a trailing newline
    "CUST-１２３４５",  # full-width Unicode digits (\d would accept these)
    "CUST-12345; DROP TABLE customers",
    "CUST-12345" * 50,
]
BAD_NON_STRING_IDS = [12345, 12345.0, None, True, ["CUST-12345"], {"id": VALID_ID}]


@pytest.mark.parametrize("bad_id", BAD_CUSTOMER_IDS + BAD_NON_STRING_IDS, ids=repr)
def test_get_customer_record_rejects_bad_customer_id(session, bad_id):
    error = assert_rpc_error(session.call("get_customer_record", {"customer_id": bad_id}), INVALID_PARAMS)
    assert error["data"]["errors"][0]["field"] == "customer_id"


@pytest.mark.parametrize("bad_id", ["CUST-1", "", None, 5, "cust-12345"], ids=repr)
def test_trigger_refund_rejects_bad_customer_id(session, bad_id):
    resp = session.call("trigger_refund", {"customer_id": bad_id, "amount": 5, "reason": VALID_REASON})
    error = assert_rpc_error(resp, INVALID_PARAMS)
    assert [e["field"] for e in error["data"]["errors"]] == ["customer_id"]


# --------------------------------------------------------------------------- #
# Validation: amount
# --------------------------------------------------------------------------- #

BAD_AMOUNTS = [0, 0.0, -0.0, -1, -0.01, "25", "25.0", "", True, False, None, [25], {"v": 25}]


@pytest.mark.parametrize("amount", BAD_AMOUNTS, ids=repr)
def test_trigger_refund_rejects_bad_amount(session, amount):
    resp = session.call("trigger_refund", {"customer_id": VALID_ID, "amount": amount, "reason": VALID_REASON})
    error = assert_rpc_error(resp, INVALID_PARAMS)
    assert [e["field"] for e in error["data"]["errors"]] == ["amount"]


def test_trigger_refund_rejects_overflowing_number_literal(fresh):
    """`1e999` is syntactically valid JSON but overflows to infinity."""
    fresh._next_id += 1
    rid = fresh._next_id
    fresh.send_raw(
        '{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"trigger_refund",'
        '"arguments":{"customer_id":"CUST-12345","amount":1e999,"reason":"Item arrived damaged"}}}' % rid
    )
    resp = fresh._read_response(rid)
    assert "error" in resp and "result" not in resp, resp
    assert resp["error"]["code"] in (INVALID_PARAMS, INVALID_REQUEST), resp


# --------------------------------------------------------------------------- #
# Validation: reason
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "reason",
    [
        "",
        "too short",
        "123456789",  # 9 chars
        "a b c d e ",  # 10 raw chars but only 9 once trimmed
        " " * 10,  # long enough only because of whitespace
        "   short   ",
        "\n\t\n\t\n\t\n\t\n\t",
        1234567890,
        None,
        ["long enough reason"],
        "x" * 501,  # over the 500-char cap
    ],
    ids=lambda r: repr(r)[:30],
)
def test_trigger_refund_rejects_bad_reason(session, reason):
    resp = session.call("trigger_refund", {"customer_id": VALID_ID, "amount": 5, "reason": reason})
    error = assert_rpc_error(resp, INVALID_PARAMS)
    assert [e["field"] for e in error["data"]["errors"]] == ["reason"]


@pytest.mark.parametrize("reason", ["1234567890", " abcdefghij ", "ten chars!", "a b c d ef", "é" * 10, "x" * 500])
def test_trigger_refund_accepts_boundary_reasons(session, reason):
    assert_tool_ok(session.call("trigger_refund", {"customer_id": VALID_ID, "amount": 5, "reason": reason}))


def test_reason_is_stored_trimmed(session):
    result = assert_tool_ok(
        session.call("trigger_refund", {"customer_id": VALID_ID, "amount": 5, "reason": "   Wrong size shipped   "})
    )
    assert result["structuredContent"]["reason"] == "Wrong size shipped"


# --------------------------------------------------------------------------- #
# Validation: argument object shape
# --------------------------------------------------------------------------- #


def test_all_invalid_fields_are_reported_together(session):
    resp = session.call("trigger_refund", {"customer_id": "nope", "amount": -1, "reason": "short"})
    error = assert_rpc_error(resp, INVALID_PARAMS)
    assert {e["field"] for e in error["data"]["errors"]} == {"customer_id", "amount", "reason"}


@pytest.mark.parametrize("arguments", [..., {}, None], ids=["omitted", "empty-object", "null"])
def test_missing_arguments_are_invalid_params(session, arguments):
    error = assert_rpc_error(session.call("trigger_refund", arguments), INVALID_PARAMS)
    assert {e["field"] for e in error["data"]["errors"]} == {"customer_id", "amount", "reason"}
    assert all(e["type"] == "missing" for e in error["data"]["errors"])


def test_unknown_extra_field_is_rejected(session):
    resp = session.call("get_customer_record", {"customer_id": VALID_ID, "include_ssn": True})
    error = assert_rpc_error(resp, INVALID_PARAMS)
    assert error["data"]["errors"][0]["field"] == "include_ssn"


@pytest.mark.parametrize("arguments", ["oops", ["CUST-12345"], 42, True], ids=repr)
def test_non_object_arguments_are_invalid_params(session, arguments):
    assert_rpc_error(session.call("get_customer_record", arguments), INVALID_PARAMS)


def test_error_response_does_not_echo_rejected_input(session):
    secret = "CUST-SUPERSECRET-VALUE"
    resp = session.call("get_customer_record", {"customer_id": secret})
    assert_rpc_error(resp, INVALID_PARAMS)
    assert secret not in json.dumps(resp)


# --------------------------------------------------------------------------- #
# Protocol-level error mapping
# --------------------------------------------------------------------------- #


def test_unknown_tool_is_invalid_params(session):
    error = assert_rpc_error(session.call("does_not_exist", {}), INVALID_PARAMS)
    assert "does_not_exist" in error["message"]


def test_unknown_method_is_method_not_found(session):
    assert_rpc_error(session.request("no/such/method"), METHOD_NOT_FOUND)


def test_response_ids_are_echoed_correctly(session):
    resp = session.call("get_customer_record", {"customer_id": "bad"})
    assert resp["id"] == session._next_id
    assert resp["jsonrpc"] == "2.0"


# --------------------------------------------------------------------------- #
# Resilience
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "garbage, code",
    [
        ("{not json", PARSE_ERROR),
        ('{"jsonrpc": "2.0", "id": 1, "method": ', PARSE_ERROR),  # truncated
        ("", PARSE_ERROR),
        ('{"foo": 1}', INVALID_REQUEST),
        ("[1, 2, 3]", INVALID_REQUEST),
        ('"just a string"', INVALID_REQUEST),
        ("42", INVALID_REQUEST),
        ("null", INVALID_REQUEST),
    ],
    ids=["bad-json", "truncated", "blank", "not-rpc", "array", "string", "number", "null"],
)
def test_malformed_input_gets_spec_error_and_server_survives(fresh, garbage, code):
    fresh.send_raw(garbage)
    msg = fresh.read_message()
    assert msg["id"] is None  # id can't be determined -> null, per JSON-RPC 2.0
    assert_rpc_error(msg, code)

    # ...and the connection is still healthy afterwards.
    assert_tool_ok(fresh.call("get_customer_record", {"customer_id": VALID_ID}))
    assert fresh.proc.poll() is None


def test_errors_do_not_poison_later_calls(session):
    for _ in range(3):
        assert_rpc_error(session.call("get_customer_record", {"customer_id": "bad"}), INVALID_PARAMS)
        assert_tool_ok(session.call("get_customer_record", {"customer_id": VALID_ID}))


def test_pipelined_requests_all_get_matching_responses(fresh):
    ids = list(range(100, 140))
    for rid in ids:
        valid = rid % 2 == 0
        fresh.send(
            {
                "jsonrpc": "2.0",
                "id": rid,
                "method": "tools/call",
                "params": {
                    "name": "get_customer_record",
                    "arguments": {"customer_id": VALID_ID if valid else "bad"},
                },
            }
        )
    seen = {}
    for _ in ids:
        msg = fresh.read_message()
        seen[msg["id"]] = msg
    assert set(seen) == set(ids)
    for rid, msg in seen.items():
        if rid % 2 == 0:
            assert "result" in msg
        else:
            assert_rpc_error(msg, INVALID_PARAMS)


def test_clean_exit_when_client_closes_stdin():
    s = StdioSession()
    s.handshake()
    assert s.close() == 0
    assert_jsonrpc_lines(s.stdout_lines)


# --------------------------------------------------------------------------- #
# Optional mode: validation failures as tool results (MCP SEP-1303)
# --------------------------------------------------------------------------- #


def test_tool_result_mode_returns_validation_errors_to_the_model():
    s = StdioSession(env={"MCP_VALIDATION_ERRORS": "tool_result"})
    try:
        s.handshake()
        resp = s.call("trigger_refund", {"customer_id": "bad", "amount": -1, "reason": "short"})
        assert "error" not in resp, resp
        assert resp["result"]["isError"] is True
        text = resp["result"]["content"][0]["text"]
        assert all(field in text for field in ("customer_id", "amount", "reason")), text
        assert "bad" not in text.replace("Invalid arguments", "")  # rejected input not echoed

        # Protocol-level problems stay JSON-RPC errors in either mode.
        assert_rpc_error(s.call("does_not_exist", {}), INVALID_PARAMS)
        assert_rpc_error(s.request("no/such/method"), METHOD_NOT_FOUND)
        # Valid calls are unaffected.
        assert_tool_ok(s.call("get_customer_record", {"customer_id": VALID_ID}))
    finally:
        s.close()
    assert_jsonrpc_lines(s.stdout_lines)


def test_invalid_validation_mode_fails_fast_with_clean_stdout():
    proc = subprocess.run(
        [sys.executable, str(SERVER)],
        input="",
        capture_output=True,
        text=True,
        timeout=20,
        cwd=HERE,
        env={**os.environ, "MCP_VALIDATION_ERRORS": "bogus"},
    )
    assert proc.returncode != 0
    assert proc.stdout == ""  # even a startup failure must not touch stdout
    assert "MCP_VALIDATION_ERRORS" in proc.stderr


# --------------------------------------------------------------------------- #
# Model-level unit tests (cases that are awkward to express as JSON)
# --------------------------------------------------------------------------- #


def test_models_reject_nan_and_infinity():
    import server
    from pydantic import ValidationError

    for bad in (math.nan, math.inf, -math.inf):
        with pytest.raises(ValidationError):
            server.TriggerRefundInput(customer_id=VALID_ID, amount=bad, reason=VALID_REASON)


def test_models_accept_ints_but_not_bools_for_amount():
    import server
    from pydantic import ValidationError

    assert server.TriggerRefundInput(customer_id=VALID_ID, amount=7, reason=VALID_REASON).amount == 7.0
    with pytest.raises(ValidationError):
        server.TriggerRefundInput(customer_id=VALID_ID, amount=True, reason=VALID_REASON)
