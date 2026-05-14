# SNMP Walker Legacy Network

Local web app for discovering legacy network gear from pasted IPs, CIDRs, and SNMP v2c community strings.

## What it collects

- IP address
- Pingable status
- SNMP status
- Hostname
- Device model
- Device type
- Address/location from `sysLocation`
- Software version

The app probes each community string against each target and uses the first one that answers. CSV and Excel downloads do not include the matched community unless you turn on that option in the UI.

## Run

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

The launchers create a local `.venv`, install requirements inside it, and run the app from that environment.

## Target input examples

```text
10.10.10.1
10.10.20.0/24
192.168.5.10-30
172.16.1.4, 172.16.1.5
```

## Notes

- This is intentionally SNMP v2c-focused for legacy networks.
- ICMP ping may be blocked by firewalls even when SNMP works.
- Large subnets can take time; tune workers and timeouts in the form.
- Future feature ideas are tracked in `ROADMAP.md`.
