from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

PROTOCOL_VERSION = "2025-11-25"

TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_status",
        "description": "Return service status.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "echo",
        "description": "Echo text back.",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
    },
    {
        "name": "admin_reset_key",
        "description": "Rotate an API key. Admin only.",
        "inputSchema": {"type": "object", "properties": {"key_id": {"type": "string"}}},
    },
    {
        "name": "admin_delete_user",
        "description": "Delete a user. Admin only.",
        "inputSchema": {"type": "object", "properties": {"user_id": {"type": "string"}}},
    },
    {
        "name": "stream_demo",
        "description": "Responds with an SSE stream (progress notifications, then the result).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "slow_tool",
        "description": "Sleeps for arguments.seconds.",
        "inputSchema": {"type": "object", "properties": {"seconds": {"type": "number"}}},
    },
]

STREAM_DELAY_SECONDS = 0.4  # gap between SSE events (3 events -> ~0.8s total)


def _text_result(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": False}


class MockMCPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int]) -> None:
        super().__init__(address, MockHandler)
        self.calls: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def record(self, entry: dict[str, Any]) -> None:
        with self._lock:
            self.calls.append(entry)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.calls)

    def reset(self) -> None:
        with self._lock:
            self.calls.clear()

    def handle_error(self, request: Any, client_address: Any) -> None:
        # The gateway legitimately hangs up on slow calls (timeout tests); don't dump a traceback for that.
        if isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


class MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mock-mcp/1.0"
    sys_version = ""

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        pass  # keep test output quiet

    # -- helpers ------------------------------------------------------------ #

    def _send_json(self, status: int, payload: Any, extra: dict[str, str] | None = None) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _rpc_error(self, rpc_id: Any, code: int, message: str, status: int = 200) -> None:
        self._send_json(status, {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}})

    def _send_sse(self, rpc_id: Any) -> None:
        events = [
            {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1, "total": 3}},
            {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 2, "total": 3}},
            {"jsonrpc": "2.0", "id": rpc_id, "result": _text_result("stream complete")},
        ]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for i, event in enumerate(events):
            data = f"event: message\ndata: {json.dumps(event)}\n\n".encode()
            self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
            self.wfile.flush()
            if i < len(events) - 1:
                time.sleep(STREAM_DELAY_SECONDS)
        self.wfile.write(b"0\r\n\r\n")

    # -- routes ------------------------------------------------------------- #

    @property
    def route(self) -> str:
        """Request path without the query string."""
        return urlsplit(self.path).path

    def do_GET(self) -> None:
        if self.route == "/_calls":
            # The in-process view keeps raw bytes; the HTTP view must be JSON-safe.
            safe = [{**c, "body": c["body"].decode("utf-8", "replace")} for c in self.server.snapshot()]  # type: ignore[attr-defined]
            self._send_json(200, safe)
        elif self.route == "/mcp":
            # Modern Streamable HTTP has no GET stream endpoint.
            self._send_json(405, {"error": "GET not supported"}, {"Allow": "POST"})
        else:
            self._send_json(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        self._send_json(405, {"error": "sessions not supported"}, {"Allow": "POST"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)

        if self.route == "/_reset":
            self.server.reset()  # type: ignore[attr-defined]
            self._send_json(200, {"ok": True})
            return
        if self.route != "/mcp":
            self._send_json(404, {"error": "not found"})
            return

        try:
            msg = json.loads(raw)
        except ValueError:
            self._rpc_error(None, -32700, "Parse error", status=400)
            return
        if not isinstance(msg, dict):
            self._rpc_error(None, -32600, "Invalid Request", status=400)
            return

        method = msg.get("method")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        rpc_id = msg.get("id")
        tool = params.get("name") if method == "tools/call" else None

        interesting = ("authorization", "x-gateway-user-role", "x-gateway-subject", "x-forwarded-for",
                       "mcp-session-id", "mcp-method", "mcp-name", "mcp-protocol-version", "mcp-param-region",
                       "x-custom", "x-smuggle", "x-spoof", "connection")
        self.server.record(  # type: ignore[attr-defined]
            {
                "method": method,
                "tool": tool,
                "params": params,
                "body": raw,
                "headers": {k.lower(): v for k, v in self.headers.items() if k.lower() in interesting},
                "all_header_names": [k.lower() for k in self.headers.keys()],
            }
        )

        # Notifications (no id) and client replies to server requests (result/error, no method)
        # get 202 Accepted with no body.
        if "id" not in msg or (method is None and ("result" in msg or "error" in msg)):
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if method == "initialize":
            self._send_json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "mock-mcp", "version": "1.0"},
                    },
                },
                {"Mcp-Session-Id": "mock-session-1"},
            )
        elif method == "tools/list":
            self._send_json(200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            self._call_tool(rpc_id, tool, params.get("arguments") or {})
        elif method == "ping":
            self._send_json(200, {"jsonrpc": "2.0", "id": rpc_id, "result": {}})
        else:
            self._rpc_error(rpc_id, -32601, f"Method not found: {method}")

    def _call_tool(self, rpc_id: Any, tool: Any, arguments: Any) -> None:
        args = arguments if isinstance(arguments, dict) else {}
        if tool == "get_status":
            result = _text_result("ok")
        elif tool == "echo":
            result = _text_result(str(args.get("text", "")))
        elif tool == "admin_reset_key":
            result = _text_result("API key rotated")
        elif tool == "admin_delete_user":
            result = _text_result("user deleted")
        elif tool == "stream_demo":
            self._send_sse(rpc_id)
            return
        elif tool == "slow_tool":
            time.sleep(float(args.get("seconds", 1)))
            result = _text_result("done sleeping")
        else:
            self._rpc_error(rpc_id, -32602, f"Unknown tool: {tool!r}")
            return
        self._send_json(200, {"jsonrpc": "2.0", "id": rpc_id, "result": result})


def make_mock_server(host: str = "127.0.0.1", port: int = 0) -> MockMCPServer:
    return MockMCPServer((host, port))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Mock downstream MCP server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9001)
    args = parser.parse_args(argv)
    server = make_mock_server(args.host, args.port)
    print(f"mock MCP server listening on http://{args.host}:{server.server_address[1]}/mcp", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
