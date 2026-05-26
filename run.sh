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

# shellcheck disable=SC1091
. ./scripts/bootstrap_env.sh

PYTHON_BIN="${SNMP_WALKER_PYTHON:-python3}"
VENV_DIR="${SNMP_WALKER_VENV:-$(snmp_walker_default_venv_dir)}"

if [ -z "${SNMP_WALKER_VENV:-}" ] && [ "$VENV_DIR" != ".venv" ]; then
  echo "Note: running from a Windows-mounted WSL path; using Linux-side venv $VENV_DIR." >&2
fi

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

snmp_walker_ensure_venv
snmp_walker_install_project

exec "$VENV_PYTHON" -m snmp_walker "$@"
