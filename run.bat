@echo off
cd /d "%~dp0"
if not exist ".venv" (
    python -m venv .venv
)
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -e .
".venv\Scripts\python.exe" -m snmp_walker
pause
