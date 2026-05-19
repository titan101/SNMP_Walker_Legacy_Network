#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 was not found. Ask your server admin for Python 3.10+ with venv support." >&2
  exit 1
fi

if [ ! -d ".venv" ]; then
  if ! python3 -m venv .venv; then
    echo "Could not create .venv. Ask your server admin to enable the Python venv module." >&2
    exit 1
  fi
fi

.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .

export SNMP_WALKER_HOST="${SNMP_WALKER_HOST:-0.0.0.0}"
export SNMP_WALKER_PORT="${SNMP_WALKER_PORT:-5055}"
export SNMP_WALKER_OPEN_BROWSER="${SNMP_WALKER_OPEN_BROWSER:-0}"
export SNMP_WALKER_PRODUCTION="${SNMP_WALKER_PRODUCTION:-1}"

.venv/bin/python -m snmp_walker --production --no-browser "$@"
