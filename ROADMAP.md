# Feature Ideas

The first build covers the core workflow: paste IPs/subnets, try community strings, identify devices, walk read-only inventory MIBs, and export CSV/XLSX.

Useful next steps:

- Add SNMPv3 support with saved auth/privacy profiles.
- Add a live progress screen so large subnet scans stream results while running.
- Add vendor-specific collectors for Cisco, Juniper, ADVA, MRV, Ciena, Nokia, Arista, Calix, and APC.
- Add detailed interface export as a second worksheet instead of only a per-device summary.
- Add detailed neighbor export as a second worksheet instead of only a per-device summary.
- Add live progress with partial results so a long subnet scan does not look frozen.
- Add a retry queue for failed devices with slower timeout/retry settings.
- Add vendor OID profiles for Cisco, Juniper, ADVA, MRV, Ciena, Nokia, Arista, Calix, Fortinet, Palo Alto, APC, Eaton, and legacy optical shelves.
- Add an OID evidence view showing which OIDs answered for each device.
- Add scan presets: fast identity, inventory, topology, and endpoint-heavy.
- Add Excel worksheets for device summary, interfaces, neighbors, serials/modules, and failed targets.
- Add SNMP view detection hints when a community works but tables are hidden.
- Add import/export for community string profiles with local masking.
- Add a safe local SQLite scan history so overnight scans can be resumed or compared.
- Add subnet grouping and per-site labels for cleaner migration planning exports.
- Add a "retry failed with slower timeout" button for high-latency or overloaded legacy gear.
- Add subnet batching and pause/resume for large overnight scans.
- Add SQLite scan history so old scans can be compared against new scans.
- Add credential masking and an encrypted local secrets file for community/SNMPv3 profiles.
- Add custom OID packs so weird legacy platforms can be identified without changing code.
