#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -x ".venv/bin/python" ]]; then
  echo "Task 1 virtual environment not found. Run ./setup.sh first."
  exit 1
fi

echo "Launching MCP Inspector with this project's exact Python interpreter."
echo "Do not start run_server.sh separately; Inspector launches its own server process."
exec npx -y @modelcontextprotocol/inspector \
  "$PWD/.venv/bin/python" \
  "$PWD/server.py"
