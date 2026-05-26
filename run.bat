@echo off
setlocal EnableDelayedExpansion

set "DIR=%~dp0"
set "VENV=%DIR%.venv"
set "PY=%VENV%\Scripts\python.exe"
set "PIP=%VENV%\Scripts\pip.exe"

echo SNMP Walker Legacy Network

rem Load .env if present (sets env vars before python starts)
if exist "%DIR%.env" (
    for /f "usebackq tokens=1,* delims==" %%A in ("%DIR%.env") do (
        if not "%%A"=="" (
            set "first=%%A"
            if not "!first:~0,1!"=="#" set "%%A=%%B"
        )
    )
)

rem Create venv if missing
if not exist "%PY%" (
    echo Creating virtual environment...
    python -m venv "%VENV%"
    if errorlevel 1 (
        echo ERROR: Failed to create venv. Requires Python 3.10+.
        echo Download from https://www.python.org/downloads/
        pause
        exit /b 1
    )
)

rem Install package if not yet installed
"%PY%" -c "import snmp_walker" 2>nul
if errorlevel 1 (
    echo Installing dependencies...
    "%PIP%" install -q -e "%DIR%."
    if errorlevel 1 (
        echo ERROR: pip install failed.
        pause
        exit /b 1
    )
)

echo Starting at http://127.0.0.1:5055
echo Press Ctrl-C to stop.
echo.
"%PY%" -m snmp_walker %*
