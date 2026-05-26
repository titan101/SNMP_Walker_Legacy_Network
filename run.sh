#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

# Load .env if present (same variables as run.bat/run.ps1)
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . .env
  set +a
fi

PYTHON_BIN="${SNMP_WALKER_PYTHON:-python3}"
VENV_DIR="${SNMP_WALKER_VENV:-.venv}"

# If .venv is a Windows venv (Scripts/ but no bin/), auto-switch to .venv-wsl
if [ "$VENV_DIR" = ".venv" ] && [ -d ".venv/Scripts" ] && [ ! -d ".venv/bin" ]; then
  VENV_DIR=".venv-wsl"
  echo "Note: .venv is a Windows environment; using .venv-wsl for WSL/Linux." >&2
fi

VENV_PYTHON="$VENV_DIR/bin/python"
INSTALL_STAMP="$VENV_DIR/.snmp-walker-installed"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "$PYTHON_BIN was not found. Ask your server admin for Python 3.10+ with venv support." >&2
  exit 1
fi

if ! "$PYTHON_BIN" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"; then
  "$PYTHON_BIN" --version >&2 || true
  echo "SNMP Walker requires Python 3.10 or newer." >&2
  exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
  if ! "$PYTHON_BIN" -m venv "$VENV_DIR"; then
    echo "Could not create $VENV_DIR. Ask your server admin to enable the Python venv module." >&2
    exit 1
  fi
fi

if [ ! -x "$VENV_PYTHON" ]; then
  echo "$VENV_DIR does not look like a Linux/WSL virtual environment." >&2
  echo "Use SNMP_WALKER_VENV=.venv-wsl ./run.sh, or remove the incompatible venv." >&2
  exit 1
fi

needs_install=0
if [ ! -f "$INSTALL_STAMP" ]; then
  needs_install=1
elif [ "pyproject.toml" -nt "$INSTALL_STAMP" ] || [ "requirements.txt" -nt "$INSTALL_STAMP" ]; then
  needs_install=1
fi

if [ "${SNMP_WALKER_FORCE_INSTALL:-0}" = "1" ]; then
  needs_install=1
fi
if [ "${SNMP_WALKER_SKIP_INSTALL:-0}" = "1" ]; then
  needs_install=0
fi

if [ "$needs_install" = "1" ]; then
  if [ "${SNMP_WALKER_UPGRADE_PIP:-0}" = "1" ]; then
    "$VENV_PYTHON" -m pip install --upgrade pip
  fi
  "$VENV_PYTHON" -m pip install -e .
  touch "$INSTALL_STAMP"
fi

exec "$VENV_PYTHON" -m snmp_walker "$@"
