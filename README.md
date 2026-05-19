# SNMP Walker Legacy Network

Small portable web app for discovering legacy network gear from pasted IPs, CIDRs, and SNMP v2c community strings.

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

The app probes each community string against each target and uses the first one that answers. All collection is read-only SNMP v2c using community strings. CSV and Excel downloads do not include the matched community unless you turn on that option in the UI.

## Beginner Quick Start

You do not need admin rights for the normal launcher. Each launcher creates a local `.venv` folder inside this project and installs the Python requirements there.

### Linux Server

```bash
git clone https://github.com/titan101/SNMP_Walker_Legacy_Network.git
cd SNMP_Walker_Legacy_Network
chmod +x run.sh run_server.sh
./run_server.sh
```

Open:

```text
http://SERVER_IP:5055
```

### Laptop Or WSL

```bash
./run.sh
```

Open `http://127.0.0.1:5055`.

### Windows

PowerShell:

```powershell
.\run.ps1
```

Command Prompt:

```bat
run.bat
```

## Portable Layout

The project is packaged so it can run from a laptop, WSL, or a small server:

- `snmp_walker.discovery`: SNMP probe and walk logic
- `snmp_walker.exports`: CSV/XLSX output
- `snmp_walker.web`: Flask routes and UI
- `snmp_walker.cli`: command-line/server startup
- `wsgi.py`: WSGI entry point for external servers
- `run.sh`: local Linux/WSL launcher using `.venv`
- `run_server.sh`: Linux server launcher using `.venv`, `0.0.0.0`, and Waitress
- `run.ps1` / `run.bat`: Windows launchers using `.venv`
- `RELEASES.md`: running change notes

The old `app.py` and `snmp_discovery.py` files remain as compatibility shims.

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

If Python cannot create `.venv`, ask your server admin for Python venv support. On Ubuntu that package is usually `python3-venv`.

Direct package command:

```bash
python -m snmp_walker --host 0.0.0.0 --port 5055 --production --no-browser
```

After `pip install -e .`, this also works:

```bash
snmp-walker --host 0.0.0.0 --port 5055 --production --no-browser
```

## What Was Updated

- Confirmed the repo already uses the package layout and Waitress server path needed for Linux workspaces.
- Hardened Linux launchers with clearer non-admin error messages when Python or `venv` is missing.
- Removed an unused duplicate root template so the single source of truth is `snmp_walker/templates/index.html`.
- Kept the UI aligned with the shared dark operations-console style used by the companion tools.

## Target input examples

```text
10.10.10.1
10.10.20.0/24
192.168.5.10-30
172.16.1.4, 172.16.1.5
```

## Notes

- This is intentionally SNMP v2c-focused for legacy networks.
- It does not SSH, Telnet, log in, pull running configs, or change devices.
- ICMP ping may be blocked by firewalls even when SNMP works.
- Large subnets can take time; tune workers and timeouts in the form.
- The default scan is a fast identity pass. Enable "Walk inventory MIBs" for serials, interfaces, LLDP, and CDP.
- Enable "Walk ARP/MAC tables" only when you need endpoint-style counts; those tables can be large and slow on old switches.
- Future feature ideas are tracked in `ROADMAP.md`.
- Running project changes are tracked in `RELEASES.md`.
