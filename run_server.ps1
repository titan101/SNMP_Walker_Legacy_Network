$ErrorActionPreference = "Stop"

Set-Location -Path $PSScriptRoot

if (-not (Test-Path -LiteralPath ".\.venv")) {
    python -m venv .venv
}

if (-not $env:SNMP_WALKER_HOST) { $env:SNMP_WALKER_HOST = "0.0.0.0" }
if (-not $env:SNMP_WALKER_PORT) { $env:SNMP_WALKER_PORT = "5055" }
$env:SNMP_WALKER_OPEN_BROWSER = "0"
$env:SNMP_WALKER_PRODUCTION = "1"

.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m snmp_walker --production --no-browser @args
