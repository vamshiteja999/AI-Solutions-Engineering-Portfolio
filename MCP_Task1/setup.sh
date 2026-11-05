#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
PROJECT_DIR="$(pwd)"

echo "=== Task 1 MCP environment setup ==="
echo "Project: $PROJECT_DIR"
echo

# Prefer a stable, supported CPython installation. Python 3.13 is also accepted.
PYTHON=""
for candidate in python3.12 python3.13 python3.11 python3; do
  if command -v "$candidate" >/dev/null 2>&1; then
    version="$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    major="${version%%.*}"
    minor="${version#*.}"
    if [[ "$major" -eq 3 && "$minor" -ge 11 ]]; then
      PYTHON="$(command -v "$candidate")"
      break
    fi
  fi
done

if [[ -z "$PYTHON" ]]; then
  echo "ERROR: Python 3.11, 3.12, or 3.13 was not found."
  echo "Install Python 3.12 (recommended) or Python 3.13, then run this script again."
  exit 1
fi

echo "Using interpreter: $PYTHON"
"$PYTHON" --version

if [[ -d ".venv" ]]; then
  echo
  echo "An existing .venv folder was found."
  read -r -p "Recreate this Task 1 environment from scratch? [y/N] " answer
  if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
    rm -rf ".venv"
  else
    echo "Keeping the existing .venv and reinstalling the pinned requirements."
  fi
fi

if [[ ! -d ".venv" ]]; then
  "$PYTHON" -m venv .venv
fi

VENV_PY="$PROJECT_DIR/.venv/bin/python"

echo
echo "Upgrading pip..."
"$VENV_PY" -m pip install --upgrade pip

echo
echo "Installing pinned project dependencies..."
"$VENV_PY" -m pip install -r requirements.txt

echo
echo "Checking installed versions..."
"$VENV_PY" - <<'PY'
import sys
import mcp
import pydantic
import anyio
import pytest

print("Python:", sys.version.split()[0])
print("MCP package:", getattr(mcp, "__version__", "installed (version metadata checked by pip)"))
print("Pydantic:", pydantic.__version__)
print("AnyIO:", anyio.__version__ if hasattr(anyio, "__version__") else "installed")
print("Pytest:", pytest.__version__)
print("Interpreter:", sys.executable)
PY

echo
echo "Setup complete."
echo "Next run: ./run_tests.sh"
