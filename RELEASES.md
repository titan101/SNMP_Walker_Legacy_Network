# Release Log

Running project log for SNMP Walker Legacy Network. Keep this file updated whenever the app behavior, packaging, deployment method, or supported discovery scope changes.

## 2026-05-26 - No-Admin WSL Bootstrap Fallback

What changed:

- Added a shared Bash bootstrap helper used by `run.sh` and `run_server.sh`.
- If Ubuntu/WSL Python is missing `ensurepip` or `python3-venv`, the launchers now bootstrap a local `uv` binary instead of stopping immediately.
- WSL runs launched from `/mnt/c` keep both the venv and local `uv` tool under `~/.cache/snmp-walker/` instead of the Windows-mounted checkout.
- WSL `/mnt/c` installs now build from a clean Linux-cache source copy to avoid OneDrive/Windows permission failures around `*.egg-info`.
- Dependency installation now uses normal venv pip when available, or `uv pip install --python .venv/bin/python .` when pip is missing.
- Reinstall checks now use a source checksum instead of filesystem mtimes, which avoids repeat installs from Windows-mounted WSL paths.
- Linux installs now copy the app into the venv by default; `SNMP_WALKER_EDITABLE=1` restores editable install behavior for development.
- Replaced the pandas Excel writer with direct `openpyxl` workbook generation to avoid the heavy pandas/numpy dependency chain on WSL/server installs.
- Added `.tools/` to `.gitignore` so the downloaded local bootstrap binary is not committed.
- Documented the no-admin fallback controls: `SNMP_WALKER_UV`, `SNMP_WALKER_UV_AUTO_INSTALL`, and `SNMP_WALKER_TOOLS_DIR`.

Validation:

- Fresh WSL clone reproduced the missing `ensurepip` failure and then completed setup through the local `uv` fallback.
- `python -m pytest -q`
- `python -m compileall snmp_walker`
- `bash -n run.sh`
- `bash -n run_server.sh`

## 2026-05-24 - No-Admin Server Readiness Pass

What changed:

- Hardened target parsing so oversized CIDRs stop at the configured host limit without expanding the full network into memory.
- Made download payload parsing ignore malformed rows and unknown fields instead of raising a server error.
- Updated Bash launchers to check Python 3.10+, create a project-local `.venv`, and skip repeated installs after the first successful setup.
- Added launcher flags for no-admin environments: `SNMP_WALKER_PYTHON`, `SNMP_WALKER_VENV`, `SNMP_WALKER_FORCE_INSTALL`, `SNMP_WALKER_SKIP_INSTALL`, and `SNMP_WALKER_UPGRADE_PIP`.
- Updated README server instructions for WSL, Linux servers, stripped execute bits, firewall notes, and local venv reuse.
- Removed PowerShell/Batch launchers, old compatibility entry shims, the optional WSGI shim, and the roadmap file from the active Linux-focused tree.
- Added structured walk-detail storage for interfaces, ENTITY-MIB inventory rows, and LLDP/CDP neighbor rows.
- Expanded Excel export into a multi-sheet workbook: devices, interfaces, entities, neighbors, and topology edges.
- Added a simple LLDP/CDP topology view to the results page when inventory walks expose neighbor tables.
- Borrowed the NetworkAI adjacency-list pattern: topology now carries source/target interfaces, protocol, inferred link type, bandwidth, and a plain-text `Topology Context` sheet.
- Added visible MIB/OID coverage in the scan UI plus `MIB Walk Plan` and `Walk Status` workbook sheets.
- Added scan-running feedback and no-responder diagnostics for subnet scans that return no SNMP devices.
- Added per-OID scan selection so operators can choose exactly which base, inventory, topology, and traffic OIDs are eligible to run.
- Added an explicit topology empty-state explaining when LLDP/CDP data is needed before a map can be drawn.

Validation:

- `python -m pytest -q`: 22 passed.
- `python -m compileall snmp_walker`
- `bash -n run.sh`
- `bash -n run_server.sh`
- Flask dev `/health` smoke test passed from `.venv`.
- Waitress production `/health` smoke test passed from `.venv`.

## 2026-05-18 - Portable Launcher And Cleanup Pass

What changed:

- Hardened `run.sh` and `run_server.sh` with clear messages for normal users on servers that are missing Python or `venv`.
- Removed the unused duplicate root `templates/index.html`; the packaged template under `snmp_walker/templates/` is the single source of truth.
- Updated README quick-start instructions for clone-and-run Linux server use.

Validation:

- `python -m pytest`
- `python -m compileall snmp_walker app.py snmp_discovery.py wsgi.py`

## 2026-05-16 - Portable Server Package

Commit: `3649810`

What changed:

- Refactored the app into a modular Python package under `snmp_walker/`.
- Split responsibilities into discovery, exports, web routes, config, and CLI startup modules.
- Added `pyproject.toml` so the project can be installed with `pip install -e .`.
- Added `python -m snmp_walker` entry point.
- Added `snmp-walker` console command after package install.
- Added `wsgi.py` for external WSGI server use.
- Added Waitress support for server-friendly production mode.
- Added server launch scripts:
  - `run_server.sh`
  - `run_server.ps1`
- Kept `app.py` and `snmp_discovery.py` as compatibility shims.
- Updated README with laptop, WSL, Linux, and server run instructions.

Validation:

- `pytest`: 10 passed.
- Python compile check passed.
- Editable package install passed.
- `python -m snmp_walker` health and POST scan smoke tests passed.
- `python -m snmp_walker --production` health and POST scan smoke tests passed.
- `snmp-walker` console command health check passed.

Current usage:

```bash
python -m snmp_walker --host 0.0.0.0 --port 5055 --production --no-browser
```

## 2026-05-14 - Hardened Scan Path

Commit: `38e7fdf`

What changed:

- Made default scans fast identity scans.
- Added optional deeper inventory walks.
- Added optional ARP/MAC table walks for heavier endpoint-count use cases.
- Added exception handling so one odd device does not break the whole scan.
- Added Flask app tests for homepage, POST scan path, and CSV download.

Validation:

- `pytest`: 10 passed.
- Python compile check passed.
- Real Flask `/health` and POST route smoke tests passed.

## 2026-05-14 - Community-Only SNMP Inventory

Commit: `b5b8d26`

What changed:

- Expanded collection using read-only SNMP v2c community strings only.
- Added uptime and system contact.
- Added ENTITY-MIB serial and model hints.
- Added interface count, up/down counts, descriptions, and aliases.
- Added LLDP neighbor summary.
- Added Cisco CDP neighbor summary.
- Added ARP and MAC table entry counts where exposed.
- Added docs clarifying no SSH, Telnet, CLI login, config pull, or device changes.

Validation:

- `pytest`: 6 passed.
- Python compile check passed.
- Flask health check passed.

## 2026-05-14 - Initial Public Project

Commit: `b438489`

What changed:

- Built initial local Flask app.
- Added IP, CIDR, and last-octet range input support.
- Added multiple SNMP v2c community probing.
- Added ping status.
- Added hostname, model, device type, location/address, and software version output.
- Added CSV and Excel downloads.
- Added Windows, PowerShell, and WSL/Linux launch scripts.
- Created GitHub repository `titan101/SNMP_Walker_Legacy_Network`.

Validation:

- `pytest`: 4 passed.
- Python compile check passed.
- Flask `/health` smoke test passed.

## Next Candidates

- Add a topology module for basic LLDP/CDP diagram data.
- Add node/edge exports: `local_device`, `local_port`, `remote_device`, `remote_port`.
- Add Mermaid and Graphviz exports for simple diagrams.
- Add multi-sheet Excel export for devices, interfaces, neighbors, serials/modules, and failures.
- Add live progress for long subnet scans.
- Add retry profiles for slower legacy gear.
