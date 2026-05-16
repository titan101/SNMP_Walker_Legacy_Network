#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .

export SNMP_WALKER_HOST="${SNMP_WALKER_HOST:-0.0.0.0}"
export SNMP_WALKER_PORT="${SNMP_WALKER_PORT:-5055}"
export SNMP_WALKER_OPEN_BROWSER="${SNMP_WALKER_OPEN_BROWSER:-0}"
export SNMP_WALKER_PRODUCTION="${SNMP_WALKER_PRODUCTION:-1}"

.venv/bin/python -m snmp_walker --production --no-browser "$@"
