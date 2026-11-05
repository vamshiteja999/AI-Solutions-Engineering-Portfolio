#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -x ".venv/bin/python" ]]; then
  echo "Task 1 virtual environment not found. Run ./setup.sh first."
  exit 1
fi

echo "Starting customer-support-mcp over STDIO."
echo "STDOUT is reserved for MCP JSON-RPC. Do not add print() statements to server.py."
exec .venv/bin/python server.py
