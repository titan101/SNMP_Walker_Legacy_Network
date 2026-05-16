# Release Log

Running project log for SNMP Walker Legacy Network. Keep this file updated whenever the app behavior, packaging, deployment method, or supported discovery scope changes.

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
