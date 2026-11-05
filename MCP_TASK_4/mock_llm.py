"""Mock downstream LLM server for testing primary/backup failovers, timeouts, and 429s."""

import argparse
import http.server
import json
import threading
import time
from typing import Any
from urllib.parse import urlsplit


class MockLLMHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Quiet test output

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        server = self.server  # type: ignore

        if path == "/primary-slow":
            # Simulate timeout (> 3000ms)
            time.sleep(4.0)
            self._send_json(200, {"choices": [{"text": "Delayed response"}]})
        elif path == "/primary-429":
            self._send_json(429, {"error": {"message": "Too many requests"}})
        elif path == "/primary-error":
            self._send_json(500, {"error": {"message": "Internal server error"}})
        elif path == "/primary-success":
            server.primary_calls += 1
            self._send_json(200, {"choices": [{"text": "Primary response generated"}]})
        elif path == "/backup-success":
            server.backup_calls += 1
            self._send_json(200, {"choices": [{"text": "Backup response generated"}]})
        else:
            self._send_json(404, {"error": "Not found"})

    def _send_json(self, status: int, data: dict) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class MockLLMServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

    fn = MockLLMHandler

    def __init__(self, address: tuple[str, int]) -> None:
        super().__init__(address, self.fn)
        self.primary_calls = 0
        self.backup_calls = 0

    def reset(self) -> None:
        self.primary_calls = 0
        self.backup_calls = 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9001)
    args = parser.parse_args()
    server = MockLLMServer(("127.0.0.1", args.port))
    print(f"Mock LLM server listening on port {args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()