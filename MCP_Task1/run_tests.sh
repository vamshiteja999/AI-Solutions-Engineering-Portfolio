#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -x ".venv/bin/python" ]]; then
  echo "Task 1 virtual environment not found."
  echo "Run: ./setup.sh"
  exit 1
fi

echo "Using: $(.venv/bin/python --version 2>&1)"
echo "Running the Task 1 test suite..."
exec .venv/bin/python -m pytest -v test_server.py
