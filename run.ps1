# run.ps1 -- PowerShell launcher for SNMP Walker Legacy Network
# Usage: .\run.ps1
#        .\run.ps1 --host 0.0.0.0 --production --no-browser
$ErrorActionPreference = "Stop"

$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Venv = Join-Path $Dir ".venv"
$Py = Join-Path $Venv "Scripts\python.exe"
$Pip = Join-Path $Venv "Scripts\pip.exe"

Write-Host "SNMP Walker Legacy Network"

# Load .env if present (sets env vars before python starts)
$EnvFile = Join-Path $Dir ".env"
if (Test-Path $EnvFile) {
    foreach ($line in Get-Content $EnvFile) {
        if ($line -match '^\s*([^#\s][^=]*)=(.*)') {
            [System.Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), "Process")
        }
    }
}

# Create venv if missing
if (-not (Test-Path $Py)) {
    Write-Host "Creating virtual environment..."
    python -m venv $Venv
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create venv. Requires Python 3.10+."
        exit 1
    }
}

# Install package if not yet installed
& $Py -c "import snmp_walker" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing dependencies..."
    & $Pip install -q -e $Dir
    if ($LASTEXITCODE -ne 0) {
        Write-Error "pip install failed."
        exit 1
    }
}

Write-Host "Starting at http://127.0.0.1:5055"
Write-Host "Press Ctrl-C to stop."
Write-Host ""
& $Py -m snmp_walker @args
