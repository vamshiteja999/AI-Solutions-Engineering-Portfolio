
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import gateway
import mock_server

HERE = Path(__file__).resolve().parent

SECRET = "unit-test-secret-" + "x" * 32
ADMIN, VIEWER = "admin-token", "viewer-token"
ALLOWED_ORIGIN = "https://app.example"

# JSON-RPC / MCP codes used below
PARSE_ERROR, INVALID_REQUEST, INVALID_PARAMS, INTERNAL_ERROR = -32700, -32600, -32602, -32603
UNAUTHENTICATED, UNAUTHORIZED_TOOL, HEADER_MISMATCH = -32000, -32001, -32020


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #


@dataclass
class Resp:
    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def header(self, name: str) -> str | None:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    def all_headers(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name.lower()]

    def json(self) -> Any:
        return json.loads(self.body)

    @property
    def error(self) -> dict[str, Any]:
        data = self.json()
        assert "error" in data and "result" not in data, data
        return data["error"]


def send(
    port: int,
    method: str = "POST",
    path: str = "/mcp",
    body: Any = None,
    token: str | None = None,
    headers: Any = (),
    timeout: float = 10,
    conn: http.client.HTTPConnection | None = None,
) -> Resp:
    owns = conn is None
    conn = conn or http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    if isinstance(body, (dict, list)):
        body = json.dumps(body)
    if isinstance(body, str):
        body = body.encode()
    hdrs = list(headers.items()) if isinstance(headers, dict) else list(headers)
    if token is not None:
        hdrs.append(("Authorization", f"Bearer {token}"))
    if body is not None and not any(k.lower() == "content-type" for k, _ in hdrs):
        hdrs.append(("Content-Type", "application/json"))
    conn.putrequest(method, path, skip_accept_encoding=True)
    for k, v in hdrs:
        conn.putheader(k, v)
    if body is not None:
        conn.putheader("Content-Length", str(len(body)))
    conn.endheaders(body)
    r = conn.getresponse()
    data = r.read()
    resp = Resp(r.status, r.getheaders(), data)
    if owns:
        conn.close()
    return resp


def raw_exchange(port: int, payload: bytes, timeout: float = 3.0) -> bytes:
    """Send raw bytes, return everything the server writes until it closes the socket."""
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(payload)
        chunks: list[bytes] = []
        try:
            while True:
                data = s.recv(65536)
                if not data:
                    break
                chunks.append(data)
        except TimeoutError:
            pass
        return b"".join(chunks)


def rpc(method: str, params: Any = None, id: Any = 1) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def call_tool(port: int, name: Any, token: str | None = VIEWER, id: Any = 1, **kw: Any) -> Resp:
    return send(port, body=rpc("tools/call", {"name": name, "arguments": {}}, id=id), token=token, **kw)


def forge_jwt(claims: dict[str, Any], secret: str = SECRET, header: dict[str, Any] | None = None) -> str:
    """Build a JWT by hand so tests can produce malformed / hostile ones."""
    b64 = lambda d: gateway._b64url_encode(json.dumps(d, separators=(",", ":")).encode())  # noqa: E731
    head = b64(header if header is not None else {"alg": "HS256", "typ": "JWT"})
    signing_input = f"{head}.{b64(claims)}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{gateway._b64url_encode(sig)}"


def serve(server: Any) -> Any:
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def mock():
    server = serve(mock_server.make_mock_server())
    yield server
    server.shutdown()
    server.server_close()


def _config(mock: Any, **overrides: Any) -> gateway.Config:
    values: dict[str, Any] = dict(
        downstream_url=f"http://127.0.0.1:{mock.server_address[1]}/mcp",
        jwt_secret=SECRET,
        static_tokens={ADMIN: "admin", VIEWER: "viewer"},
        allowed_origins=frozenset({ALLOWED_ORIGIN}),
        max_body_bytes=4096,
        downstream_timeout=5.0,
        client_timeout=5.0,
    )
    values.update(overrides)
    return gateway.Config(**values)


@pytest.fixture(scope="module")
def gw(mock) -> int:
    server = serve(gateway.make_server(_config(mock)))
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def gw_short_timeout(mock) -> int:
    server = serve(gateway.make_server(_config(mock, downstream_timeout=0.5)))
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def gw_downstream_dead() -> int:
    dead = f"http://127.0.0.1:{free_port()}/mcp"  # nothing listens here
    cfg = gateway.Config(downstream_url=dead, static_tokens={ADMIN: "admin", VIEWER: "viewer"})
    server = serve(gateway.make_server(cfg))
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def reset_calls(mock):
    mock.reset()
    yield


def reached(mock: Any) -> list[dict[str, Any]]:
    return mock.snapshot()


# --------------------------------------------------------------------------- #
# 1. Authentication
# --------------------------------------------------------------------------- #


def test_missing_token_is_401_with_bearer_challenge(gw, mock):
    resp = send(gw, body=rpc("tools/list"))
    assert resp.status == 401
    assert resp.header("WWW-Authenticate").startswith("Bearer")
    assert resp.error["code"] == UNAUTHENTICATED
    assert reached(mock) == []


@pytest.mark.parametrize(
    "value",
    ["", "Basic dXNlcjpwYXNz", "Bearer", "Bearer ", "Token abc", "Bearertoken", "Bearer a b", "Bearer tok!en", "Bearer \"quoted\""],
    ids=repr,
)
def test_malformed_authorization_header_is_401(gw, mock, value):
    resp = send(gw, body=rpc("tools/list"), headers=[("Authorization", value)])
    assert resp.status == 401
    assert reached(mock) == []


def test_multiple_authorization_headers_are_rejected(gw, mock):
    resp = send(gw, body=rpc("tools/list"), headers=[("Authorization", f"Bearer {VIEWER}"), ("Authorization", f"Bearer {ADMIN}")])
    assert resp.status == 401
    assert reached(mock) == []


def test_unknown_token_is_401_and_not_echoed(gw, mock):
    resp = send(gw, body=rpc("tools/list"), token="not-a-real-token")
    assert resp.status == 401
    assert b"not-a-real-token" not in resp.body
    assert reached(mock) == []


def test_scheme_is_case_insensitive(gw, mock):
    resp = send(gw, body=rpc("tools/list"), headers=[("Authorization", f"bearer {VIEWER}")])
    assert resp.status == 200


def test_authentication_happens_before_body_parsing(gw, mock):
    resp = send(gw, body="{this is not json", token=None)
    assert resp.status == 401  # not -32700: unauthenticated callers learn nothing about parsing
    assert resp.error["code"] == UNAUTHENTICATED
    assert resp.header("Connection") == "close"  # unread body -> connection must not be reused
    assert reached(mock) == []


# -- JWT ---------------------------------------------------------------------- #


def test_jwt_role_claim_is_honoured(gw, mock):
    admin = gateway.issue_jwt(SECRET, "admin", subject="alice")
    viewer = gateway.issue_jwt(SECRET, "viewer", subject="bob")
    assert "result" in call_tool(gw, "admin_reset_key", token=admin).json()
    assert call_tool(gw, "admin_reset_key", token=viewer).error["code"] == UNAUTHORIZED_TOOL
    assert [c["tool"] for c in reached(mock)] == ["admin_reset_key"]


NOW = int(time.time())


@pytest.mark.parametrize(
    "token_factory",
    [
        lambda: gateway.issue_jwt(SECRET, "admin", ttl=-10),  # expired
        lambda: forge_jwt({"role": "admin", "nbf": NOW + 3600}),  # not yet valid
        lambda: forge_jwt({"role": "admin", "exp": "never"}),  # exp has the wrong type
        lambda: forge_jwt({"role": "admin", "exp": True}),  # bool is not a number
        lambda: gateway.issue_jwt("a-completely-different-secret-value!!", "admin"),  # wrong key
        lambda: forge_jwt({"role": "admin"}, header={"alg": "none"}),  # alg=none attack
        lambda: forge_jwt({"role": "admin"}, header={"alg": "HS512", "typ": "JWT"}),  # alg confusion
        lambda: forge_jwt({"role": "admin"}, header={"typ": "JWT"}),  # no alg
        lambda: forge_jwt({"role": "admin"}).rsplit(".", 1)[0] + ".",  # signature stripped
        lambda: "a.b.c",
        lambda: "...",
        lambda: "x" * 10 + "." + "y" * 10 + "." + "z" * 10,
    ],
    ids=["expired", "nbf-future", "exp-string", "exp-bool", "wrong-secret", "alg-none", "alg-hs512", "no-alg", "no-signature",
         "abc", "dots", "junk"],
)
def test_bad_jwts_are_rejected(gw, mock, token_factory):
    resp = call_tool(gw, "get_status", token=token_factory())
    assert resp.status == 401, resp.body
    assert reached(mock) == []


def test_jwt_payload_tampering_invalidates_signature(gw, mock):
    viewer = gateway.issue_jwt(SECRET, "viewer")
    head, _, sig = viewer.split(".")
    evil_payload = gateway._b64url_encode(json.dumps({"role": "admin", "sub": "mallory"}).encode())
    resp = call_tool(gw, "admin_reset_key", token=f"{head}.{evil_payload}.{sig}")
    assert resp.status == 401
    assert reached(mock) == []


@pytest.mark.parametrize("claims", [{}, {"role": None}, {"role": 7}, {"role": "superuser"}, {"role": ["admin"]}, {"role": "ADMIN"}],
                         ids=["no-role", "null", "int", "unknown", "list", "wrong-case"])
def test_authenticated_but_unrecognised_role_is_403(gw, mock, claims):
    resp = call_tool(gw, "get_status", token=forge_jwt(claims))
    assert resp.status == 403
    assert reached(mock) == []


# --------------------------------------------------------------------------- #
# 2. Origin check (DNS-rebinding defence required by the transport spec)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "http://localhost:8080", "https://app.example.evil.com"])
def test_unexpected_origin_is_403_even_with_a_valid_token(gw, mock, origin):
    resp = send(gw, body=rpc("tools/list"), token=ADMIN, headers=[("Origin", origin)])
    assert resp.status == 403
    assert reached(mock) == []


def test_allowed_origin_and_absent_origin_pass(gw):
    assert send(gw, body=rpc("tools/list"), token=VIEWER, headers=[("Origin", ALLOWED_ORIGIN)]).status == 200
    assert send(gw, body=rpc("tools/list"), token=VIEWER).status == 200


def test_origin_is_checked_before_authentication(gw):
    assert send(gw, body=rpc("tools/list"), headers=[("Origin", "https://evil.example")]).status == 403


# --------------------------------------------------------------------------- #
# 3. JSON-RPC parsing
# --------------------------------------------------------------------------- #

BAD_JSON = [
    b"",
    b"{",
    b"not json",
    b'{"jsonrpc":"2.0","id":1,"method":"tools/list",}',
    b"\xff\xfe\x00",  # invalid UTF-8
    b'\xef\xbb\xbf{"jsonrpc":"2.0","id":1,"method":"tools/list"}',  # UTF-8 BOM
    b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":NaN}}',
    b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":Infinity}}',
    b"[" * 3000,  # unterminated nesting (stays under the 4 KiB test body limit so it reaches the parser)
]


@pytest.mark.parametrize("body", BAD_JSON, ids=lambda b: repr(b[:24]))
def test_unparseable_bodies_get_parse_error(gw, mock, body):
    resp = send(gw, body=body, token=VIEWER)
    assert resp.status == 400
    assert resp.json()["id"] is None
    assert resp.error["code"] == PARSE_ERROR
    assert reached(mock) == []


INVALID_REQUESTS = [
    ("scalar", "42"),
    ("string", '"hello"'),
    ("null", "null"),
    ("empty-object", "{}"),
    ("batch", json.dumps([rpc("tools/list")])),
    ("batch-hiding-admin-call", json.dumps([rpc("tools/list", id=1), rpc("tools/call", {"name": "admin_reset_key"}, id=2)])),
    ("empty-batch", "[]"),
    ("no-version", '{"id":1,"method":"tools/list"}'),
    ("wrong-version", '{"jsonrpc":"1.0","id":1,"method":"tools/list"}'),
    ("numeric-version", '{"jsonrpc":2,"id":1,"method":"tools/list"}'),
    ("method-missing", '{"jsonrpc":"2.0","id":1}'),
    ("method-int", '{"jsonrpc":"2.0","id":1,"method":5}'),
    ("method-empty", '{"jsonrpc":"2.0","id":1,"method":""}'),
    ("method-list", '{"jsonrpc":"2.0","id":1,"method":["tools/call"]}'),
    ("params-scalar", '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":5}'),
    ("params-null", '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":null}'),
    ("id-null", '{"jsonrpc":"2.0","id":null,"method":"tools/list"}'),
    ("id-bool", '{"jsonrpc":"2.0","id":true,"method":"tools/list"}'),
    ("id-float", '{"jsonrpc":"2.0","id":1.5,"method":"tools/list"}'),
    ("id-list", '{"jsonrpc":"2.0","id":[1],"method":"tools/list"}'),
    ("response-with-both", '{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}'),
    ("response-without-id", '{"jsonrpc":"2.0","result":{}}'),
]


@pytest.mark.parametrize("label,body", INVALID_REQUESTS, ids=[label for label, _ in INVALID_REQUESTS])
def test_structurally_invalid_jsonrpc_is_rejected_locally(gw, mock, label, body):
    resp = send(gw, body=body, token=VIEWER)
    assert resp.status == 400
    assert resp.error["code"] == INVALID_REQUEST
    assert reached(mock) == []


DUPLICATE_KEY_BODIES = [
    # the classic parser differential: gateway sees tools/list, downstream sees tools/call
    '{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"name":"admin_reset_key"}}',
    '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_status","name":"admin_reset_key"}}',
    '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"admin_reset_key"},"params":{"name":"get_status"}}',
    '{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list"}',
    '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_status","arguments":{"a":1,"a":2}}}',
]


@pytest.mark.parametrize("body", DUPLICATE_KEY_BODIES, ids=range(len(DUPLICATE_KEY_BODIES)))
def test_duplicate_keys_are_rejected_not_guessed(gw, mock, body):
    resp = send(gw, body=body, token=VIEWER)
    assert resp.status == 400
    assert resp.error["code"] == INVALID_REQUEST
    assert "duplicate" in resp.error["message"]
    assert reached(mock) == []


@pytest.mark.parametrize("rpc_id", [1, 0, -7, 2**40, "abc", "", "a-b_c d", "🙂"], ids=repr)
def test_request_id_is_echoed_exactly_on_gateway_errors(gw, rpc_id):
    resp = call_tool(gw, "admin_reset_key", id=rpc_id)
    assert resp.json()["id"] == rpc_id
    assert type(resp.json()["id"]) is type(rpc_id)


def test_oversized_body_is_413_and_closes_the_connection(gw, mock):
    resp = send(gw, body=b" " * 10_000, token=VIEWER)
    assert resp.status == 413
    assert resp.header("Connection") == "close"
    assert reached(mock) == []


def test_chunked_request_bodies_are_refused(gw, mock):
    request = (
        f"POST /mcp HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {VIEWER}\r\nContent-Type: application/json\r\n"
        "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"
    )
    assert b" 411 " in raw_exchange(gw, request.encode()).split(b"\r\n", 1)[0] + b" "
    assert reached(mock) == []


@pytest.mark.parametrize("length_headers", [["Content-Length: 5", "Content-Length: 50"], ["Content-Length: abc"], ["Content-Length: -1"],
                                            ["Content-Length: 5 5"]], ids=["conflicting", "non-numeric", "negative", "garbage"])
def test_bad_content_length_is_400(gw, mock, length_headers):
    request = f"POST /mcp HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {VIEWER}\r\n" + "\r\n".join(length_headers) + "\r\nConnection: close\r\n\r\nhello"
    status_line = raw_exchange(gw, request.encode()).split(b"\r\n", 1)[0]
    assert b" 400 " in status_line + b" "
    assert reached(mock) == []


def test_post_without_content_length_is_411(gw):
    request = f"POST /mcp HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {VIEWER}\r\nConnection: close\r\n\r\n"
    assert b" 411 " in raw_exchange(gw, request.encode()).split(b"\r\n", 1)[0] + b" "


def test_unread_body_cannot_be_smuggled_as_a_second_request(gw, mock):
    """401 before the body is read must not leave the body in the socket as a 'next request'."""
    smuggled = b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n"
    request = (
        b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
        + b"Content-Length: %d\r\n\r\n" % len(smuggled)
        + smuggled
    )
    response = raw_exchange(gw, request)
    assert response.count(b"HTTP/1.1 ") == 1, response  # exactly one response, then the socket closes
    assert response.startswith(b"HTTP/1.1 401")


def test_keep_alive_connection_is_reusable(gw):
    conn = http.client.HTTPConnection("127.0.0.1", gw, timeout=10)
    try:
        for i in range(3):
            resp = send(gw, body=rpc("tools/list", id=i), token=VIEWER, conn=conn)
            assert resp.status == 200 and resp.json()["id"] == i
        denied = send(gw, body=rpc("tools/call", {"name": "admin_x"}, id=9), token=VIEWER, conn=conn)
        assert denied.error["code"] == UNAUTHORIZED_TOOL  # a JSON-RPC-level denial keeps the connection usable
        assert send(gw, body=rpc("tools/list", id=10), token=VIEWER, conn=conn).status == 200
    finally:
        conn.close()


# -- messages that are not requests -------------------------------------------- #


def test_client_notifications_are_forwarded_and_get_202(gw, mock):
    resp = send(gw, body={"jsonrpc": "2.0", "method": "notifications/initialized"}, token=VIEWER)
    assert resp.status == 202 and resp.body == b""
    assert [c["method"] for c in reached(mock)] == ["notifications/initialized"]


def test_denied_notification_gets_http_403_and_idless_error(gw, mock):
    resp = send(gw, body={"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "admin_reset_key"}}, token=VIEWER)
    assert resp.status == 403
    assert resp.json()["id"] is None
    assert resp.error["code"] == UNAUTHORIZED_TOOL
    assert reached(mock) == []


def test_admin_notification_is_allowed_through(gw, mock):
    resp = send(gw, body={"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "admin_reset_key"}}, token=ADMIN)
    assert resp.status == 202
    assert [c["tool"] for c in reached(mock)] == ["admin_reset_key"]


def test_client_response_messages_are_forwarded(gw, mock):
    """Older transports let clients POST replies to server-initiated requests."""
    resp = send(gw, body={"jsonrpc": "2.0", "id": 5, "result": {"roots": []}}, token=VIEWER)
    assert resp.status == 202
    assert len(reached(mock)) == 1


# --------------------------------------------------------------------------- #
# 4. Authorization (the heart of the task)
# --------------------------------------------------------------------------- #


def test_tools_list_is_forwarded_transparently(gw, mock):
    for token in (VIEWER, ADMIN):
        resp = send(gw, body=rpc("tools/list", id="t"), token=token)
        assert resp.status == 200
        data = resp.json()
        assert data["id"] == "t"
        assert data["result"]["tools"] == mock_server.TOOLS  # byte-for-byte what the downstream returned
        assert any(t["name"].startswith("admin_") for t in data["result"]["tools"])  # not filtered
    assert [c["method"] for c in reached(mock)] == ["tools/list", "tools/list"]


def test_viewer_is_denied_admin_tool_without_touching_downstream(gw, mock):
    resp = call_tool(gw, "admin_reset_key", token=VIEWER, id="req-1")
    assert resp.status == 200  # a JSON-RPC error is still a valid JSON-RPC response
    assert resp.json() == {
        "jsonrpc": "2.0",
        "id": "req-1",
        "error": {"code": -32001, "message": "Unauthorized Tool Call", "data": {"tool": "admin_reset_key", "requiredRole": "admin"}},
    }
    assert reached(mock) == []


def test_admin_may_call_admin_tools(gw, mock):
    for name, text in (("admin_reset_key", "API key rotated"), ("admin_delete_user", "user deleted")):
        data = call_tool(gw, name, token=ADMIN).json()
        assert data["result"]["content"][0]["text"] == text
    assert [c["tool"] for c in reached(mock)] == ["admin_reset_key", "admin_delete_user"]


def test_viewer_may_call_ordinary_tools(gw, mock):
    data = call_tool(gw, "get_status", token=VIEWER).json()
    assert data["result"]["content"][0]["text"] == "ok"
    assert [c["tool"] for c in reached(mock)] == ["get_status"]


@pytest.mark.parametrize(
    "name",
    [
        "admin_",
        "admin_x",
        "ADMIN_reset_key",
        "Admin_Reset_Key",
        " admin_reset_key",
        "admin_reset_key ",
        "\tadmin_x",
        "\nadmin_x",
        "ａｄｍｉｎ＿ｒｅｓｅｔ＿ｋｅｙ",  # full-width look-alikes
        "ᴀdmin_x".replace("ᴀ", "a"),
        "​admin_reset_key",  # zero-width space
        "adm­in_reset_key",  # soft hyphen
        "‮admin_x",  # right-to-left override
        "\x00admin_x",
        "admin​_x",
    ],
    ids=repr,
)
def test_admin_prefix_bypass_attempts_are_blocked(gw, mock, name):
    resp = call_tool(gw, name, token=VIEWER)
    assert resp.error["code"] == UNAUTHORIZED_TOOL, name
    assert reached(mock) == []


def test_escaped_unicode_in_json_cannot_hide_the_prefix(gw, mock):
    body = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"admin\\u005freset\\u005fkey"}}'
    assert send(gw, body=body, token=VIEWER).error["code"] == UNAUTHORIZED_TOOL
    body = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"\\u0041dmin_x"}}'
    assert send(gw, body=body, token=VIEWER).error["code"] == UNAUTHORIZED_TOOL
    assert reached(mock) == []


@pytest.mark.parametrize("name", ["get_status", "echo", "administer", "admin", "adminreset", "my_admin_tool", "xadmin_reset_key", "_admin_x"])
def test_names_that_merely_contain_admin_are_not_blocked(gw, mock, name):
    call_tool(gw, name, token=VIEWER)
    assert [c["tool"] for c in reached(mock)] == [name]  # forwarded exactly as sent


@pytest.mark.parametrize(
    "params",
    [{}, {"name": None}, {"name": 5}, {"name": ""}, {"name": ["admin_reset_key"]}, {"name": {"v": "admin_reset_key"}}, {"name": True},
     {"arguments": {"name": "admin_reset_key"}}, ["admin_reset_key"]],
    ids=repr,
)
def test_tools_call_without_a_usable_string_name_is_rejected(gw, mock, params):
    resp = send(gw, body=rpc("tools/call", params), token=VIEWER)
    assert resp.status == 200
    assert resp.error["code"] == INVALID_PARAMS
    assert reached(mock) == []


def test_tools_call_without_params_is_rejected(gw, mock):
    resp = send(gw, body={"jsonrpc": "2.0", "id": 1, "method": "tools/call"}, token=VIEWER)
    assert resp.error["code"] == INVALID_PARAMS
    assert reached(mock) == []


@pytest.mark.parametrize("method", ["ping", "initialize", "prompts/list", "resources/list", "server/discover"])
def test_other_methods_pass_through_for_any_authenticated_role(gw, mock, method):
    send(gw, body=rpc(method, {}), token=VIEWER)
    assert [c["method"] for c in reached(mock)] == [method]


def test_authorization_is_not_confused_by_arguments_mentioning_admin(gw, mock):
    resp = send(gw, body=rpc("tools/call", {"name": "echo", "arguments": {"text": "admin_reset_key", "name": "admin_reset_key"}}), token=VIEWER)
    assert resp.json()["result"]["content"][0]["text"] == "admin_reset_key"
    assert [c["tool"] for c in reached(mock)] == ["echo"]


def test_what_is_inspected_is_what_is_forwarded(gw, mock):
    """The downstream receives the re-serialised parsed value, so it cannot read a body differently."""
    body = '{ "jsonrpc" : "2.0",\n "id": 7, "method":"tools/call", "params":{"name":"echo","arguments":{"text":"h\\u00e9llo"}} }'
    send(gw, body=body, token=VIEWER)
    assert json.loads(reached(mock)[0]["body"]) == json.loads(body)
    assert b"\n" not in reached(mock)[0]["body"]  # normalised, compact form


def test_concurrent_denials_never_leak_a_call_downstream(gw, mock):
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda i: call_tool(gw, "admin_delete_user", token=VIEWER, id=i), range(80)))
    assert all(r.error["code"] == UNAUTHORIZED_TOOL for r in results)
    assert [r.json()["id"] for r in results] == list(range(80))
    assert reached(mock) == []


# --------------------------------------------------------------------------- #
# 5. Mirrored headers (Mcp-Method / Mcp-Name)
# --------------------------------------------------------------------------- #


def _b64_name(value: str) -> str:
    return "=?base64?" + base64.b64encode(value.encode()).decode() + "?="


def test_matching_mirrored_headers_are_accepted_and_forwarded(gw, mock):
    resp = send(gw, body=rpc("tools/call", {"name": "get_status"}), token=VIEWER,
                headers=[("Mcp-Method", "tools/call"), ("Mcp-Name", "get_status"), ("MCP-Protocol-Version", "2026-07-28")])
    assert resp.status == 200 and "result" in resp.json()
    seen = reached(mock)[0]["headers"]
    assert seen["mcp-method"] == "tools/call" and seen["mcp-name"] == "get_status" and seen["mcp-protocol-version"] == "2026-07-28"


def test_base64_sentinel_form_is_decoded_before_comparison(gw, mock):
    ok = send(gw, body=rpc("tools/call", {"name": "get_status"}), token=VIEWER, headers=[("Mcp-Name", _b64_name("get_status"))])
    assert ok.status == 200
    bad = send(gw, body=rpc("tools/call", {"name": "get_status"}), token=VIEWER, headers=[("Mcp-Name", _b64_name("other_tool"))])
    assert bad.status == 400 and bad.error["code"] == HEADER_MISMATCH


@pytest.mark.parametrize(
    "tool,headers",
    [
        ("admin_reset_key", [("Mcp-Name", "get_status")]),  # header claims a harmless tool
        ("get_status", [("Mcp-Name", "admin_reset_key")]),  # header claims an admin tool
        ("get_status", [("Mcp-Method", "tools/list")]),
        ("get_status", [("Mcp-Method", "TOOLS/CALL")]),  # values are case-sensitive
        ("get_status", [("Mcp-Name", "get_status"), ("Mcp-Name", "admin_reset_key")]),  # duplicated header
        ("get_status", [("Mcp-Method", "tools/call"), ("Mcp-Method", "tools/list")]),
        ("get_status", [("Mcp-Name", "=?base64?!!!notbase64!!!?=")]),
        ("get_status", [("Mcp-Name", "=?base64?/w==?=")]),  # decodes to invalid UTF-8
    ],
    ids=["hdr-benign-body-admin", "hdr-admin-body-benign", "method", "method-case", "dup-name", "dup-method", "bad-b64", "bad-utf8"],
)
def test_header_body_mismatch_is_rejected(gw, mock, tool, headers):
    resp = send(gw, body=rpc("tools/call", {"name": tool}, id=3), token=VIEWER, headers=headers)
    assert resp.status == 400
    assert resp.error["code"] == HEADER_MISMATCH
    assert resp.json()["id"] == 3
    assert reached(mock) == []


def test_mirrored_header_names_are_case_insensitive(gw):
    resp = send(gw, body=rpc("tools/call", {"name": "get_status"}), token=VIEWER, headers=[("mcp-name", "admin_reset_key")])
    assert resp.error["code"] == HEADER_MISMATCH


def test_resources_read_uses_uri_as_the_mirrored_name(gw, mock):
    ok = send(gw, body=rpc("resources/read", {"uri": "file:///a"}), token=VIEWER, headers=[("Mcp-Name", "file:///a")])
    assert ok.status == 200
    bad = send(gw, body=rpc("resources/read", {"uri": "file:///a"}), token=VIEWER, headers=[("Mcp-Name", "file:///b")])
    assert bad.error["code"] == HEADER_MISMATCH


# --------------------------------------------------------------------------- #
# 6. Header hygiene
# --------------------------------------------------------------------------- #


def test_client_credential_is_never_forwarded_downstream(gw, mock):
    send(gw, body=rpc("tools/list"), token=ADMIN)
    call = reached(mock)[0]
    assert "authorization" not in call["all_header_names"]
    assert ADMIN not in json.dumps(call["headers"])


def test_gateway_sets_trusted_identity_headers_for_the_downstream(gw, mock):
    send(gw, body=rpc("tools/list"), token=VIEWER)
    send(gw, body=rpc("tools/list"), token=gateway.issue_jwt(SECRET, "admin", subject="alice"))
    first, second = (c["headers"] for c in reached(mock))
    assert first["x-gateway-user-role"] == "viewer"
    assert second["x-gateway-user-role"] == "admin" and second["x-gateway-subject"] == "alice"


def test_spoofed_identity_headers_are_replaced_not_forwarded(gw, mock):
    send(gw, body=rpc("tools/list"), token=VIEWER,
         headers=[("X-Gateway-User-Role", "admin"), ("X-Gateway-Subject", "root"), ("X-Forwarded-For", "6.6.6.6")])
    call = reached(mock)[0]
    assert call["all_header_names"].count("x-gateway-user-role") == 1
    assert call["headers"]["x-gateway-user-role"] == "viewer"
    assert call["headers"]["x-gateway-subject"] == "static-token"
    assert call["headers"]["x-forwarded-for"] == "127.0.0.1"


def test_headers_named_by_connection_are_stripped(gw, mock):
    send(gw, body=rpc("tools/list"), token=VIEWER, headers=[("Connection", "keep-alive, X-Smuggle"), ("X-Smuggle", "1"), ("X-Custom", "kept")])
    call = reached(mock)[0]
    assert "x-smuggle" not in call["all_header_names"]
    assert call["headers"]["x-custom"] == "kept"
    assert call["headers"]["connection"] == "close"  # the gateway's own downstream hop


def test_custom_mcp_param_headers_pass_through(gw, mock):
    send(gw, body=rpc("tools/call", {"name": "get_status"}), token=VIEWER, headers=[("Mcp-Param-Region", "us-west1")])
    assert reached(mock)[0]["headers"]["mcp-param-region"] == "us-west1"


def test_downstream_response_headers_are_relayed(gw):
    resp = send(gw, body=rpc("initialize", {}), token=VIEWER)
    assert resp.header("Mcp-Session-Id") == "mock-session-1"
    assert resp.header("Content-Type") == "application/json"
    assert resp.header("X-Request-Id")
    assert resp.header("Server") == "mcp-gateway/1.0"  # the downstream's Server banner is not leaked
    assert len(resp.all_headers("Date")) == 1


def test_tokens_never_appear_in_logs(gw, caplog):
    caplog.set_level(logging.DEBUG, logger="mcp-gateway")
    jwt = gateway.issue_jwt(SECRET, "viewer", subject="bob")
    for token in (VIEWER, ADMIN, jwt, "bogus-token-value"):
        call_tool(gw, "admin_reset_key", token=token)
    send(gw, body=rpc("tools/list"), headers=[("Authorization", "Bearer " + jwt[:-3] + "xyz")])
    assert "DENY" in caplog.text and "ALLOW" in caplog.text
    for secret in (VIEWER, ADMIN, jwt, "bogus-token-value", SECRET):
        assert secret not in caplog.text


# --------------------------------------------------------------------------- #
# 7. Routing and HTTP methods
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("path", ["/", "/_calls", "/_reset", "/mcp/", "/MCP", "/mcp/extra", "/%6dcp", "/mcp%00", "/healthz/x", "//evil.example/mcp", "/mcp;x"])
def test_only_the_exact_mcp_path_is_proxied(gw, mock, path):
    resp = send(gw, body=rpc("tools/list"), token=ADMIN, path=path)
    assert resp.status == 404
    assert reached(mock) == []


def test_double_slash_is_normalised_by_the_http_layer_and_is_harmless(gw, mock):
    """Python's http.server rewrites '//mcp' to '/mcp' before the gateway sees it (open-redirect fix).
    That is not a bypass: it is the same endpoint, authentication still applies, and the downstream
    path comes from configuration, never from the client."""
    assert send(gw, body=rpc("tools/list"), path="//mcp").status == 401
    assert send(gw, body=rpc("tools/list"), token=VIEWER, path="//mcp").status == 200
    assert send(gw, body=rpc("tools/call", {"name": "admin_x"}), token=VIEWER, path="//mcp").error["code"] == UNAUTHORIZED_TOOL


def test_query_string_is_forwarded_but_does_not_change_routing(gw):
    assert send(gw, body=rpc("tools/list"), token=VIEWER, path="/mcp?x=1&y=2").status == 200
    assert send(gw, body=rpc("tools/list"), path="/mcp?x=1").status == 401


def test_healthz_needs_no_auth_and_never_calls_downstream(gw, mock):
    resp = send(gw, "GET", "/healthz")
    assert resp.status == 200 and resp.json() == {"status": "ok"}
    assert send(gw, "POST", "/healthz", body=b"{}").status == 404
    assert reached(mock) == []


@pytest.mark.parametrize("method", ["PUT", "PATCH", "OPTIONS", "HEAD"])
def test_other_http_methods_are_405(gw, method):
    resp = send(gw, method, "/mcp", token=ADMIN)
    assert resp.status == 405
    assert resp.header("Allow") == "GET, POST, DELETE"
    assert resp.header("X-Request-Id")
    assert (resp.body == b"") == (method == "HEAD")  # HEAD: headers only, never a body


def test_head_response_does_not_corrupt_a_kept_alive_connection(gw):
    conn = http.client.HTTPConnection("127.0.0.1", gw, timeout=10)
    try:
        assert send(gw, "HEAD", "/mcp", token=VIEWER, conn=conn).status == 405
        follow_up = send(gw, body=rpc("tools/list"), token=VIEWER, conn=conn)  # same socket
        assert follow_up.status == 200 and "tools" in follow_up.json()["result"]
    finally:
        conn.close()


def test_put_with_a_body_does_not_leave_it_to_be_parsed_as_a_request(gw):
    smuggled = b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n"
    request = b"PUT /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(smuggled) + smuggled
    response = raw_exchange(gw, request)
    assert response.count(b"HTTP/1.1 ") == 1 and response.startswith(b"HTTP/1.1 405")


def test_extremely_deep_json_is_a_clean_400_never_a_500(gw, mock):
    gw_big = serve(gateway.make_server(_config(mock, max_body_bytes=2 * 1024 * 1024)))
    try:
        port = gw_big.server_address[1]
        for depth in (3000, 50_000):
            nested = '{"a":' * depth + "1" + "}" * depth
            body = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":%s}}' % nested
            resp = send(port, body=body, token=VIEWER)
            assert resp.status in (200, 400), (depth, resp.status)  # accepted, or rejected as too deep - never 5xx
            if resp.status == 400:
                assert resp.error["code"] in (PARSE_ERROR, INVALID_REQUEST)
    finally:
        gw_big.shutdown()
        gw_big.server_close()


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_get_and_delete_require_auth_and_are_relayed(gw, mock, method):
    assert send(gw, method, "/mcp").status == 401
    resp = send(gw, method, "/mcp", token=VIEWER)
    assert resp.status == 405  # the mock's own answer, relayed verbatim
    assert resp.header("Allow") == "POST"


# --------------------------------------------------------------------------- #
# 8. Downstream failures
# --------------------------------------------------------------------------- #


def test_unreachable_downstream_is_a_clean_502(gw_downstream_dead):
    resp = call_tool(gw_downstream_dead, "get_status", token=VIEWER, id="abc")
    assert resp.status == 502
    data = resp.json()
    assert data["id"] == "abc"
    assert data["error"]["code"] == INTERNAL_ERROR
    assert data["error"]["message"] == "Downstream MCP server unavailable"
    assert data["error"]["data"]["requestId"] == resp.header("X-Request-Id")
    body = resp.body.decode().lower()
    for leak in ("refused", "127.0.0.1", "errno", "traceback", "connectionrefused", "oserror"):
        assert leak not in body


def test_slow_downstream_is_a_504(gw_short_timeout):
    resp = send(gw_short_timeout, body=rpc("tools/call", {"name": "slow_tool", "arguments": {"seconds": 3}}, id=4), token=VIEWER)
    assert resp.status == 504
    assert resp.json()["id"] == 4
    assert resp.error["message"] == "Downstream MCP server timed out"


def test_downstream_error_statuses_are_relayed_unchanged(gw, mock):
    resp = send(gw, body=rpc("no/such/method"), token=VIEWER)
    assert resp.status == 200 and resp.error["code"] == -32601  # the downstream's own error object


def test_gateway_survives_a_broken_downstream_and_keeps_serving(gw_downstream_dead):
    for _ in range(3):
        assert call_tool(gw_downstream_dead, "get_status").status == 502
    assert call_tool(gw_downstream_dead, "admin_x").error["code"] == UNAUTHORIZED_TOOL  # policy still enforced locally


# --------------------------------------------------------------------------- #
# 9. Streaming
# --------------------------------------------------------------------------- #


def test_sse_responses_are_streamed_not_buffered(gw):
    conn = http.client.HTTPConnection("127.0.0.1", gw, timeout=10)
    try:
        conn.putrequest("POST", "/mcp", skip_accept_encoding=True)
        body = json.dumps(rpc("tools/call", {"name": "stream_demo"}, id="s1")).encode()
        for k, v in (("Authorization", f"Bearer {VIEWER}"), ("Content-Type", "application/json"),
                     ("Accept", "application/json, text/event-stream"), ("Content-Length", str(len(body)))):
            conn.putheader(k, v)
        conn.endheaders(body)
        started = time.monotonic()
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.getheader("Content-Type") == "text/event-stream"
        assert resp.getheader("X-Accel-Buffering") == "no"
        assert resp.getheader("Transfer-Encoding") == "chunked"
        first = resp.read1(65536)
        first_byte_at = time.monotonic() - started
        rest = resp.read()
        total = time.monotonic() - started
    finally:
        conn.close()

    events = (first + rest).decode()
    assert events.count("event: message") == 3
    assert '"id": "s1"' in events and "stream complete" in events
    assert total >= 2 * mock_server.STREAM_DELAY_SECONDS * 0.9  # the stream really took that long...
    assert first_byte_at < total / 2  # ...yet the first event arrived early: nothing was buffered


def test_connection_is_reusable_after_a_streamed_response(gw):
    conn = http.client.HTTPConnection("127.0.0.1", gw, timeout=10)
    try:
        stream = send(gw, body=rpc("tools/call", {"name": "stream_demo"}), token=VIEWER, conn=conn)
        assert stream.body.count(b"event: message") == 3
        assert send(gw, body=rpc("tools/list"), token=VIEWER, conn=conn).status == 200
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# 10. Unit tests for the pure pieces
# --------------------------------------------------------------------------- #


def test_normalisation_only_over_matches():
    n = gateway._normalise_tool_name
    assert n("  ADMIN_x ") == "admin_x"
    assert n("ａｄｍｉｎ＿ｘ") == "admin_x"
    assert n("ad​min_x") == "admin_x"
    assert n("get_status") == "get_status"
    assert gateway.required_role_for_tool("administer") is None
    assert gateway.required_role_for_tool("Admin_Anything") == "admin"


def test_role_ranking_allows_admin_everywhere_and_viewer_only_unrestricted():
    admin, viewer = gateway.Identity("a", "admin"), gateway.Identity("v", "viewer")
    msg = gateway.Message("request", 1, "tools/call", {"name": "admin_x"})
    assert gateway.authorize(msg, admin) == "admin_x"
    with pytest.raises(gateway.GatewayError) as exc:
        gateway.authorize(msg, viewer)
    assert exc.value.code == UNAUTHORIZED_TOOL


def test_verify_jwt_accepts_valid_and_reports_specific_failures():
    token = gateway.issue_jwt(SECRET, "viewer", subject="s", ttl=60, now=1000)
    assert gateway.verify_jwt(token, SECRET, now=1030)["role"] == "viewer"
    with pytest.raises(ValueError):
        gateway.verify_jwt(token, SECRET, now=1061)  # expired
    with pytest.raises(ValueError):
        gateway.verify_jwt(token, "other-secret", now=1030)


def test_parse_bearer():
    assert gateway.parse_bearer(["Bearer abc.def-ghi_jkl=="]) == "abc.def-ghi_jkl=="
    for bad in (None, [], [""], ["Bearer"], ["Bearer a b"], ["Basic abc"], ["Bearer a", "Bearer b"]):
        with pytest.raises(gateway.GatewayError) as exc:
            gateway.parse_bearer(bad)
        assert exc.value.status == 401


def test_parse_token_table():
    assert gateway.parse_token_table("a=admin, b=viewer") == {"a": "admin", "b": "viewer"}
    assert gateway.parse_token_table("abc==admin") == {"abc=": "admin"}  # tokens may end in '='
    assert gateway.parse_token_table("") == {}
    for bad in ("a", "a=root", "=admin", "a=admin,b"):
        with pytest.raises(ValueError):
            gateway.parse_token_table(bad)


def test_config_validation():
    ok = dict(static_tokens={"t": "admin"})
    gateway.Config(**ok)
    with pytest.raises(ValueError):
        gateway.Config()  # no way to authenticate anyone
    with pytest.raises(ValueError):
        gateway.Config(downstream_url="ftp://x/mcp", **ok)
    with pytest.raises(ValueError):
        gateway.Config(downstream_url="not a url", **ok)
    with pytest.raises(ValueError):
        gateway.Config(mcp_path="mcp", **ok)
    with pytest.raises(ValueError):
        gateway.Config(static_tokens={"t": "root"})


def test_config_from_env_uses_demo_tokens_only_when_nothing_is_configured(monkeypatch, caplog):
    for var in ("GATEWAY_TOKENS", "GATEWAY_JWT_SECRET", "GATEWAY_ALLOWED_ORIGINS"):
        monkeypatch.delenv(var, raising=False)
    with caplog.at_level(logging.WARNING, logger="mcp-gateway"):
        assert dict(gateway.Config.from_env().static_tokens) == dict(gateway.DEMO_TOKENS)
    assert "DEMO" in caplog.text
    monkeypatch.setenv("GATEWAY_TOKENS", "real=admin")
    assert dict(gateway.Config.from_env().static_tokens) == {"real": "admin"}  # demo tokens are NOT mixed in


# --------------------------------------------------------------------------- #
# 11. The real command-line programs, as separate processes
# --------------------------------------------------------------------------- #


def _wait_for(port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"nothing listening on {port}")


def test_cli_end_to_end_as_subprocesses():
    mock_port, gw_port = free_port(), free_port()
    env = {**os.environ, "GATEWAY_TOKENS": "cli-admin=admin,cli-viewer=viewer"}
    env.pop("GATEWAY_JWT_SECRET", None)
    procs = [
        subprocess.Popen([sys.executable, str(HERE / "mock_server.py"), "--port", str(mock_port)],
                         stderr=subprocess.DEVNULL, cwd=HERE),
        subprocess.Popen([sys.executable, str(HERE / "gateway.py"), "--port", str(gw_port), "--downstream",
                          f"http://127.0.0.1:{mock_port}/mcp"], stderr=subprocess.PIPE, text=True, env=env, cwd=HERE),
    ]
    try:
        _wait_for(mock_port)
        _wait_for(gw_port)
        denied = call_tool(gw_port, "admin_reset_key", token="cli-viewer", id=1)
        allowed = call_tool(gw_port, "admin_reset_key", token="cli-admin", id=2)
        listed = send(gw_port, body=rpc("tools/list"), token="cli-viewer")
        assert denied.error["code"] == UNAUTHORIZED_TOOL
        assert allowed.json()["result"]["content"][0]["text"] == "API key rotated"
        assert len(listed.json()["result"]["tools"]) == len(mock_server.TOOLS)

        # the downstream (queried directly) saw the admin call exactly once, and nothing from the viewer's attempt
        seen = json.loads(send(mock_port, "GET", "/_calls").body)
        assert [(c["method"], c["tool"]) for c in seen] == [("tools/call", "admin_reset_key"), ("tools/list", None)]
    finally:
        for p in procs:
            p.terminate()
        stderr = procs[1].communicate(timeout=10)[1]
        procs[0].wait(timeout=10)
    assert "DENY" in stderr and "ALLOW" in stderr
    assert "cli-admin" not in stderr and "cli-viewer" not in stderr
