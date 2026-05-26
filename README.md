# SNMP Walker Legacy Network

Small portable web app for discovering legacy network gear from pasted IPs, CIDRs, and SNMP v1/v2c community strings or SNMPv3 credentials.

## What it collects

- IP address
- Pingable status
- SNMP status
- Hostname
- Device model
- Device type
- Address/location from `sysLocation`
- Software version
- System contact and uptime
- Serial numbers and chassis/module model hints from ENTITY-MIB
- Interface count, up/down counts, interface descriptions, and aliases
- LLDP neighbors where LLDP-MIB is exposed
- CDP neighbors where Cisco CDP MIB is exposed
- ARP and MAC table entry counts where those MIBs are exposed
- A simple LLDP/CDP topology view when neighbor tables are exposed
- Structured adjacency rows with local interface, remote interface, protocol, link type, and bandwidth where IF-MIB exposes it

The app probes each enabled SNMP version against each target and uses the first credential that answers. All collection is read-only SNMP. CSV and Excel downloads do not include the matched community or SNMPv3 username unless you turn on that option in the UI.

The Excel workbook includes multiple sheets:

- `Devices`: one summary row per target
- `MIB Walk Plan`: every GET/WALK object the app can request
- `Walk Status`: per-device walk row counts, empty walks, caps, and errors
- `Interfaces`: interface walk rows when inventory walks are enabled
- `Entities`: chassis/module model and serial rows when ENTITY-MIB is exposed
- `Neighbors`: LLDP/CDP neighbor rows
- `Topology`: edge list for diagramming or handoff
- `Topology Context`: plain adjacency lines for notes, prompts, or change planning

The scan page lets you select individual OIDs from the MIB/OID coverage table. At least one base GET OID must stay selected so the app can test which community string answers.

## Quick Start

Launchers create a local `.venv` folder and install dependencies on first run. Requires Python 3.10+.

### Windows (native)

Double-click `run.bat` or from PowerShell:

```powershell
.\run.ps1
```

Opens `http://127.0.0.1:5055` automatically.

To bind to all interfaces (serve to other machines on the network):

```powershell
.\run.ps1 --host 0.0.0.0 --production --no-browser
```

### Linux / WSL / Server

```bash
chmod +x run.sh run_server.sh
./run.sh          # laptop/WSL - binds 127.0.0.1, opens browser
./run_server.sh   # server - binds 0.0.0.0, Waitress
```

```text
http://SERVER_IP:5055
```

**WSL alongside Windows:** if you ran `run.bat` first, `.venv` is a Windows environment. The bash launchers detect this automatically and create `.venv-wsl` for the Linux side - no manual steps needed. Both venvs share the same source checkout.

**WSL from `/mnt/c` or OneDrive:** the Bash launchers automatically place the Linux venv under `~/.cache/snmp-walker/venvs/` instead of inside the Windows-mounted checkout. This avoids slow or stuck imports from a Windows filesystem. For the cleanest WSL experience, clone the repo under your Linux home directory, for example `~/SNMP_Walker_Legacy_Network`.

When WSL is running from `/mnt/c`, the launcher also builds the package from a clean source copy under `~/.cache/snmp-walker/build-src/`. That avoids OneDrive or Windows permission errors from Python build metadata like `*.egg-info`.

## Portable Layout

The project is packaged so it can run from a laptop, WSL, or a small server:

- `snmp_walker.discovery`: SNMP probe and walk logic
- `snmp_walker.exports`: CSV/XLSX output
- `snmp_walker.web`: Flask routes and UI
- `snmp_walker.cli`: command-line/server startup
- `run.sh`: local Linux/WSL launcher using `.venv`
- `run_server.sh`: Linux server launcher using `.venv`, `0.0.0.0`, and Waitress
- `run.ps1` / `run.bat`: Windows launchers using `.venv`
- `RELEASES.md`: running change notes

## Server Options

Bind to all interfaces with the Waitress server:

```bash
./run_server.sh
```

Then browse to:

```text
http://SERVER_IP:5055
```

Useful overrides:

```bash
SNMP_WALKER_HOST=0.0.0.0 SNMP_WALKER_PORT=8080 ./run_server.sh
```

Useful no-admin/server environment flags:

```bash
SNMP_WALKER_PYTHON=/path/to/python3 ./run_server.sh
SNMP_WALKER_VENV=.venv-wsl ./run_server.sh
SNMP_WALKER_FORCE_INSTALL=1 ./run_server.sh
SNMP_WALKER_SKIP_INSTALL=1 ./run_server.sh
SNMP_WALKER_UPGRADE_PIP=1 ./run_server.sh
SNMP_WALKER_UV_AUTO_INSTALL=0 ./run_server.sh
SNMP_WALKER_EDITABLE=1 ./run_server.sh
```

Use `SNMP_WALKER_SKIP_INSTALL=1` only after the `.venv` has already been built. It is handy on a server where the app is installed but PyPI access is blocked later.

Use `SNMP_WALKER_VENV=.venv-wsl` if you want WSL to keep a separate virtual environment in a shared checkout.

If Python cannot create a complete `.venv` because Ubuntu is missing `ensurepip` or `python3-venv`, the Bash launchers automatically install a local `uv` binary and use it to finish the venv setup without sudo. For normal Linux paths this lives under `.tools/uv/`; for WSL runs from `/mnt/c`, it lives under `~/.cache/snmp-walker/tools/uv/`. That still needs outbound HTTPS access to download `uv` and Python packages.

If the server cannot reach the internet at all, build the `.venv` on a similar Linux machine first, copy it with the checkout, and run with `SNMP_WALKER_SKIP_INSTALL=1`.

If the app starts but you cannot reach it from another machine, the server firewall may need to allow TCP/5055 or whichever port you choose.

Direct package command:

```bash
python -m snmp_walker --host 0.0.0.0 --port 5055 --production --no-browser
```

After `pip install -e .`, this also works:

```bash
snmp-walker --host 0.0.0.0 --port 5055 --production --no-browser
```

## Portable Run Notes

- `run.sh` is for local laptop or WSL use and binds to `127.0.0.1:5055` by default.
- `run_server.sh` is for Linux servers and binds to `0.0.0.0:5055` with Waitress by default.
- Launchers create a project-local `.venv`; no `sudo pip install` or system Python changes are needed.
- If `python3 -m venv` creates a venv without pip, the Bash launchers bootstrap a local `uv` installer and use `uv pip install` instead.
- Linux installs copy the app into the venv by default for reliable server startup. Set `SNMP_WALKER_EDITABLE=1` only when developing the code.
- `SNMP_WALKER_VENV` lets different Linux or WSL runs keep separate local virtual environments in the same checkout.
- Re-run with `SNMP_WALKER_FORCE_INSTALL=1` after dependency trouble or a major Python change.

## Target input examples

```text
10.10.10.1
10.10.20.0/24
192.168.5.10-30
172.16.1.4, 172.16.1.5
```

## Environment Variables / .env File

Copy `.env.example` to `.env` to configure defaults without retyping them in the UI.

| Variable | Default | Purpose |
|----------|---------|---------|
| `SNMP_WALKER_COMMUNITIES` | _(empty)_ | Comma-separated community strings to pre-populate the form |
| `SNMP_WALKER_HOST` | `127.0.0.1` | Bind address (`0.0.0.0` for server use) |
| `SNMP_WALKER_PORT` | `5055` | TCP port |
| `SNMP_WALKER_OPEN_BROWSER` | `true` | Auto-open browser on start |
| `SNMP_WALKER_PRODUCTION` | `false` | Use Waitress instead of Flask dev server |
| `SNMP_WALKER_DEBUG` | `false` | Enable DEBUG logging to `snmp_walker.log` |

`.env` is loaded automatically by `run.bat`, `run.ps1`, `run.sh`, and `run_server.sh`. You can also export variables directly or prefix the command:

```bash
SNMP_WALKER_COMMUNITIES=public,snmpro ./run.sh
```

## Logging

Scan activity, SNMP failures, and walk errors are written to `snmp_walker.log` in the working directory when launched via the CLI or launchers. Set `SNMP_WALKER_DEBUG=true` for verbose per-device output.

## Notes

- This is intentionally read-only SNMP-focused for legacy networks.
- It does not SSH, Telnet, log in, pull running configs, or change devices.
- ICMP ping may be blocked by firewalls even when SNMP works.
- A laptop subnet can scan cleanly and still show zero SNMP responders if endpoints do not run SNMP, UDP/161 is filtered, or the community string is wrong.
- Large subnets can take time; tune workers and timeouts in the form.
- The scan page shows the full MIB/OID coverage table before you run a scan.
- Uncheck OIDs in the MIB/OID coverage table to skip them. The inventory/topology and ARP/MAC mode checkboxes still control whether those groups are eligible to run.
- The default scan is a fast identity pass. Enable "Walk inventory MIBs" for serials, interfaces, LLDP, and CDP.
- The topology view depends on LLDP/CDP and IF-MIB data from the inventory walk; it will be empty if those MIBs are disabled or hidden by the SNMP view.
- Enable "Walk ARP/MAC tables" only when you need endpoint-style counts; those tables can be large and slow on old switches.
- Running project changes are tracked in `RELEASES.md`.
