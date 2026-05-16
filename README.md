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

## Portable Layout

The project is packaged so it can run from a laptop, WSL, or a small server:

- `snmp_walker.discovery`: SNMP probe and walk logic
- `snmp_walker.exports`: CSV/XLSX output
- `snmp_walker.web`: Flask routes and UI
- `snmp_walker.cli`: command-line/server startup
- `wsgi.py`: WSGI entry point for external servers

The old `app.py` and `snmp_discovery.py` files remain as compatibility shims.

## Run Locally

### Windows PowerShell

```powershell
cd SNMP_Walker_Legacy_Network
.\run.ps1
```

### Windows Command Prompt

```bat
cd /d SNMP_Walker_Legacy_Network
run.bat
```

### WSL or Linux

```bash
cd SNMP_Walker_Legacy_Network
chmod +x run.sh
./run.sh
```

Then open http://127.0.0.1:5055.

The launchers create a local `.venv`, install the package in editable mode, and run the app from that environment.

## Run On A Server

Bind to all interfaces with the Waitress server:

```bash
cd /path/to/SNMP_Walker_Legacy_Network
chmod +x run_server.sh
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

Direct package command:

```bash
python -m snmp_walker --host 0.0.0.0 --port 5055 --production --no-browser
```

After `pip install -e .`, this also works:

```bash
snmp-walker --host 0.0.0.0 --port 5055 --production --no-browser
```

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
