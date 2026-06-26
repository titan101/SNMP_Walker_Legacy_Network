# CIDR fping + SNMP Audit

Made by Varun and Copilot.

This project contains one combined Ubuntu-ready workflow:

- `CIDR_FPing_SNMP_Audit.sh`

The script accepts CIDR blocks, uses `fping` to find responding IPs, SNMP polls each responding IP, writes a sorted detailed CSV, and creates executive summary CSVs by subnet and device model.

## What It Produces

Every run creates a timestamped folder like:

```text
Audit_Results_20260625_143000/
```

Inside that folder:

```text
alive_ips_by_subnet_YYYYMMDD_HHMMSS.csv
snmp_inventory_detail_YYYYMMDD_HHMMSS.csv
snmp_summary_subnet_totals_YYYYMMDD_HHMMSS.csv
snmp_summary_subnet_model_YYYYMMDD_HHMMSS.csv
scan_errors_YYYYMMDD_HHMMSS.log
run_log_YYYYMMDD_HHMMSS.txt
```

The detailed CSV is sorted by `subnet` and `ip_address`. The source CIDR block is on every row, so Excel can filter by IP block directly instead of trying to infer it from `sysDescr`.

## Ubuntu Setup

Install the network tools:

```bash
sudo apt-get update
sudo apt-get install -y fping snmp
```

Make the script executable:

```bash
chmod +x CIDR_FPing_SNMP_Audit.sh
```

Keep SNMP communities in the project root:

```text
community_strings.txt
```

Use one community string per line. Blank lines and lines starting with `#` are ignored.

The script does not print community strings and does not write the real community string to CSV. It only records which entry matched, such as `community_1` or `community_2`.

If the community file is missing or empty, the script stops before scanning and prompts you:

```text
SNMP community setup is required before the scan can start.
Community strings will not be printed or written to CSV.
  1) Enter path to an existing community file
  2) Create a community file now
  3) Continue with fping only (--no-snmp)
  4) Exit
Choose 1-4:
```

When you create the file from the prompt, each community string is entered with hidden input and the file is saved with owner-only permissions.

## Run It

Option 1: CIDR file:

```bash
cat > cidrs.txt <<'EOF'
10.10.10.0/24
10.10.20.0/24
EOF

./CIDR_FPing_SNMP_Audit.sh -i cidrs.txt
```

Option 2: CIDRs as arguments:

```bash
./CIDR_FPing_SNMP_Audit.sh 10.10.10.0/24 10.10.20.0/24
```

Option 3: paste CIDRs:

```bash
./CIDR_FPing_SNMP_Audit.sh
```

Then paste one CIDR per line and press `Ctrl-D` when done.

## Useful Options

```bash
./CIDR_FPing_SNMP_Audit.sh \
  -i cidrs.txt \
  -c community_strings.txt \
  -o Audit_Results_Test \
  --snmp-jobs 75 \
  --fping-timeout 700 \
  --snmp-timeout 1
```

Use `--no-snmp` when you only want the alive IP list:

```bash
./CIDR_FPing_SNMP_Audit.sh -i cidrs.txt --no-snmp
```

## Detailed CSV Columns

```text
subnet,ip_address,ping_status,snmp_status,community_match,device_family,device_model,sysName,sysObjectID,sysDescr,sysContact,sysLocation
```

Example shape:

```text
subnet,ip_address,ping_status,snmp_status,community_match,device_family,device_model,sysName,sysObjectID,sysDescr,sysContact,sysLocation
10.10.10.0/24,10.10.10.15,alive,OK,community_1,Juniper,EX3400-24T,edge-sw01,.1.3.6.1.4.1.x,"Juniper Networks Inc. ex3400-24t Ethernet Switch kernel JUNOS ...",NA,DFW
10.10.20.0/24,10.10.20.22,alive,OK,community_2,Ciena,3930,metro-nid22,.1.3.6.1.4.1.x,3930 Service Delivery Switch,NA,DFW
```

## Executive Summary CSV

`snmp_summary_subnet_model_YYYYMMDD_HHMMSS.csv` is the main executive summary.

Columns:

```text
subnet,total_usable_ips,used_ips,free_ips,used_percent,free_percent,snmp_success,snmp_failed_or_skipped,device_family,device_model,device_count,percent_of_snmp_success
```

Example shape:

```text
subnet,total_usable_ips,used_ips,free_ips,used_percent,free_percent,snmp_success,snmp_failed_or_skipped,device_family,device_model,device_count,percent_of_snmp_success
10.10.10.0/24,254,28,226,11.0%,89.0%,25,3,Juniper,EX3400-24T,10,40.0%
10.10.10.0/24,254,28,226,11.0%,89.0%,25,3,Juniper,EX4300-32F,4,16.0%
10.10.10.0/24,254,28,226,11.0%,89.0%,25,3,Ciena,3930,11,44.0%
```

This means the `/24` has `254` usable IPs, `28` responded to ping and are treated as used, `226` did not respond and are treated as free, and the `25` successful SNMP results broke down by model.

`snmp_summary_subnet_totals_YYYYMMDD_HHMMSS.csv` is the subnet-only utilization summary:

```text
subnet,total_usable_ips,used_ips,free_ips,used_percent,free_percent,snmp_success,snmp_failed_or_skipped,snmp_success_percent
10.10.10.0/24,254,28,226,11.0%,89.0%,25,3,89.3%
10.10.20.0/24,254,14,240,5.5%,94.5%,13,1,92.9%
```

## Notes

- The old helper scripts were intentionally removed from this folder. The hidden `.gitattributes` file only keeps the Bash script in Linux line endings.
- The script is intentionally chatty: it prints each major step, per-subnet alive counts, SNMP progress, and final output paths.
- `used_ips` means ping-responsive IPs from `fping`. `free_ips` means usable addresses in the CIDR minus ping-responsive IPs.
- Usable IP math treats `/31` as 2 usable addresses and `/32` as 1 usable address.
- Device model normalization currently covers common Juniper, Ciena, Cisco, Smartoptics, Ericsson MINI-LINK, and Linux-style `sysDescr` values. Unknown devices still appear in the detailed CSV as `Unknown`.
- If input CIDR blocks overlap, the same IP can appear once per source CIDR because the subnet column is treated as the inventory context.
