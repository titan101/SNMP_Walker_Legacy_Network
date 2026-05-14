from __future__ import annotations

import asyncio
import csv
import ipaddress
import io
import platform
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Iterable

try:
    from pysnmp.hlapi.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        get_cmd,
        walk_cmd,
    )
except ImportError:  # pragma: no cover - exercised in environments missing pysnmp
    CommunityData = None
    ContextData = None
    ObjectIdentity = None
    ObjectType = None
    SnmpEngine = None
    UdpTransportTarget = None
    get_cmd = None
    walk_cmd = None


SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
IF_NUMBER = "1.3.6.1.2.1.2.1.0"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
ENT_PHYSICAL_DESCR = "1.3.6.1.2.1.47.1.1.1.1.2"
ENT_PHYSICAL_SERIAL = "1.3.6.1.2.1.47.1.1.1.1.11"
ENT_PHYSICAL_MODEL = "1.3.6.1.2.1.47.1.1.1.1.13"
LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_PORT_DESC = "1.0.8802.1.1.2.1.4.1.1.8"
CDP_CACHE_DEVICE_ID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDP_CACHE_DEVICE_PORT = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
CDP_CACHE_PLATFORM = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"
IP_NET_TO_MEDIA_PHYS = "1.3.6.1.2.1.4.22.1.2"
DOT1D_TP_FDB_ADDRESS = "1.3.6.1.2.1.17.4.3.1.1"

EXPORT_COLUMNS = [
    "ip",
    "pingable_or_not",
    "hostname",
    "device_model",
    "device_type",
    "address",
    "software_version",
    "serial_numbers",
    "sys_contact",
    "uptime",
    "interface_count",
    "interfaces_up",
    "interfaces_down",
    "interface_summary",
    "lldp_neighbors",
    "cdp_neighbors",
    "arp_entries",
    "mac_entries",
]


@dataclass
class DiscoveryResult:
    ip: str
    pingable_or_not: str = "unknown"
    hostname: str = ""
    device_model: str = ""
    device_type: str = ""
    address: str = ""
    software_version: str = ""
    snmp_status: str = "not_run"
    snmp_error: str = ""
    matched_community: str = ""
    sys_descr: str = ""
    sys_object_id: str = ""
    sys_contact: str = ""
    uptime: str = ""
    serial_numbers: str = ""
    entity_models: str = ""
    interface_count: str = ""
    interfaces_up: str = ""
    interfaces_down: str = ""
    interface_summary: str = ""
    lldp_neighbors: str = ""
    cdp_neighbors: str = ""
    arp_entries: str = ""
    mac_entries: str = ""

    def public_dict(self, include_community: bool = False) -> dict[str, str]:
        data = asdict(self)
        if not include_community:
            data.pop("matched_community", None)
        return data


def parse_targets(raw: str, max_hosts: int = 4096) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    tokens = re.split(r"[\s,;]+", raw.strip())
    for token in tokens:
        if not token:
            continue
        expanded = expand_target(token)
        for ip in expanded:
            if ip not in seen:
                targets.append(ip)
                seen.add(ip)
            if len(targets) > max_hosts:
                raise ValueError(f"Target list exceeded max host limit of {max_hosts}.")
    return targets


def expand_target(token: str) -> list[str]:
    token = token.strip()
    if "/" in token:
        network = ipaddress.ip_network(token, strict=False)
        if network.version != 4:
            raise ValueError(f"Only IPv4 targets are supported: {token}")
        return [str(ip) for ip in network.hosts()]

    range_match = re.fullmatch(r"(\d+\.\d+\.\d+\.)(\d{1,3})-(\d{1,3})", token)
    if range_match:
        prefix, start_text, end_text = range_match.groups()
        start = int(start_text)
        end = int(end_text)
        if start > end or start < 0 or end > 255:
            raise ValueError(f"Invalid IP range: {token}")
        return [str(ipaddress.ip_address(f"{prefix}{last}")) for last in range(start, end + 1)]

    return [str(ipaddress.ip_address(token))]


def parse_communities(raw: str) -> list[str]:
    communities: list[str] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if value not in seen:
            communities.append(value)
            seen.add(value)
    return communities


def ping_host(ip: str, timeout_ms: int = 800) -> str:
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_seconds = max(1, round(timeout_ms / 1000))
        command = ["ping", "-c", "1", "-W", str(timeout_seconds), ip]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(2, timeout_ms / 1000 + 1),
        )
    except (OSError, subprocess.TimeoutExpired):
        return "no"
    return "yes" if completed.returncode == 0 else "no"


async def snmp_get_values_async(
    ip: str,
    community: str,
    timeout_seconds: float,
    retries: int,
) -> tuple[dict[str, str] | None, str]:
    if get_cmd is None:
        return None, "pysnmp is not installed"

    engine = SnmpEngine()
    target = await UdpTransportTarget.create((ip, 161), timeout=timeout_seconds, retries=retries)
    oid_map = {
        SYS_DESCR: "sys_descr",
        SYS_UPTIME: "uptime",
        SYS_CONTACT: "sys_contact",
        SYS_OBJECT_ID: "sys_object_id",
        SYS_NAME: "hostname",
        SYS_LOCATION: "address",
        IF_NUMBER: "interface_count",
    }
    error_indication, error_status, error_index, var_binds = await get_cmd(
        engine,
        CommunityData(community, mpModel=1),
        target,
        ContextData(),
        *(ObjectType(ObjectIdentity(oid)) for oid in oid_map),
    )

    if error_indication:
        return None, str(error_indication)
    if error_status:
        oid_label = "unknown oid"
        if error_index and int(error_index) <= len(var_binds):
            oid_label = str(var_binds[int(error_index) - 1][0])
        return None, f"{error_status.prettyPrint()} at {oid_label}"

    values: dict[str, str] = {}
    for oid, value in var_binds:
        key = oid_map.get(str(oid))
        if key:
            values[key] = value.prettyPrint().strip()
    return values, ""


def snmp_get_values(ip: str, community: str, timeout_seconds: float, retries: int) -> tuple[dict[str, str] | None, str]:
    try:
        return asyncio.run(snmp_get_values_async(ip, community, timeout_seconds, retries))
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


async def snmp_walk_async(
    ip: str,
    community: str,
    oid: str,
    timeout_seconds: float,
    retries: int,
    max_rows: int = 2000,
) -> tuple[dict[str, str], str]:
    if walk_cmd is None:
        return {}, "pysnmp is not installed"

    engine = SnmpEngine()
    target = await UdpTransportTarget.create((ip, 161), timeout=timeout_seconds, retries=retries)
    rows: dict[str, str] = {}
    async for error_indication, error_status, error_index, var_binds in walk_cmd(
        engine,
        CommunityData(community, mpModel=1),
        target,
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False,
    ):
        if error_indication:
            return rows, str(error_indication)
        if error_status:
            oid_label = "unknown oid"
            if error_index and int(error_index) <= len(var_binds):
                oid_label = str(var_binds[int(error_index) - 1][0])
            return rows, f"{error_status.prettyPrint()} at {oid_label}"
        for name, value in var_binds:
            rows[str(name)] = clean_snmp_text(value.prettyPrint())
            if len(rows) >= max_rows:
                return rows, "walk capped"
    return rows, ""


def snmp_walk(
    ip: str,
    community: str,
    oid: str,
    timeout_seconds: float,
    retries: int,
    max_rows: int = 2000,
) -> tuple[dict[str, str], str]:
    try:
        return asyncio.run(snmp_walk_async(ip, community, oid, timeout_seconds, retries, max_rows))
    except Exception as exc:
        return {}, f"{type(exc).__name__}: {exc}"


def discover_one(
    ip: str,
    communities: list[str],
    ping_timeout_ms: int = 800,
    snmp_timeout_seconds: float = 1.2,
    snmp_retries: int = 1,
    do_ping: bool = True,
    walk_details: bool = False,
    walk_traffic_tables: bool = False,
) -> DiscoveryResult:
    result = DiscoveryResult(ip=ip)
    if do_ping:
        result.pingable_or_not = ping_host(ip, ping_timeout_ms)

    last_error = ""
    for community in communities:
        values, error = snmp_get_values(ip, community, snmp_timeout_seconds, snmp_retries)
        if values:
            result.snmp_status = "ok"
            result.matched_community = community
            result.hostname = clean_snmp_text(values.get("hostname", ""))
            result.address = clean_snmp_text(values.get("address", ""))
            result.sys_descr = clean_snmp_text(values.get("sys_descr", ""))
            result.sys_object_id = clean_snmp_text(values.get("sys_object_id", ""))
            result.sys_contact = clean_snmp_text(values.get("sys_contact", ""))
            result.uptime = format_timeticks(values.get("uptime", ""))
            result.interface_count = clean_snmp_text(values.get("interface_count", ""))
            enrich_result(result)
            if walk_details:
                enrich_result_from_walks(result, community, snmp_timeout_seconds, snmp_retries, walk_traffic_tables)
            return result
        last_error = error

    result.snmp_status = "failed" if communities else "no_communities"
    result.snmp_error = last_error or "No community answered"
    return result


def discover_many(
    ips: Iterable[str],
    communities: list[str],
    ping_timeout_ms: int = 800,
    snmp_timeout_seconds: float = 1.2,
    snmp_retries: int = 1,
    workers: int = 24,
    do_ping: bool = True,
    walk_details: bool = False,
    walk_traffic_tables: bool = False,
) -> list[DiscoveryResult]:
    ip_list = list(ips)
    results: list[DiscoveryResult] = []
    max_workers = max(1, min(workers, 128))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                discover_one,
                ip,
                communities,
                ping_timeout_ms,
                snmp_timeout_seconds,
                snmp_retries,
                do_ping,
                walk_details,
                walk_traffic_tables,
            ): ip
            for ip in ip_list
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                ip = futures[future]
                results.append(
                    DiscoveryResult(
                        ip=ip,
                        snmp_status="error",
                        snmp_error=f"{type(exc).__name__}: {exc}",
                    )
                )
    return sorted(results, key=lambda item: ipaddress.ip_address(item.ip))


def clean_snmp_text(value: str) -> str:
    value = value.replace("\x00", "").strip()
    return re.sub(r"\s+", " ", value)


def format_timeticks(value: str) -> str:
    match = re.search(r"(\d+)", value or "")
    if not match:
        return clean_snmp_text(value)
    ticks = int(match.group(1))
    seconds = ticks // 100
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"


def enrich_result(result: DiscoveryResult) -> None:
    descr = result.sys_descr
    oid = result.sys_object_id
    result.device_type = guess_device_type(descr, oid)
    result.device_model = guess_model(descr, oid)
    result.software_version = guess_software_version(descr)


def enrich_result_from_walks(
    result: DiscoveryResult,
    community: str,
    timeout_seconds: float,
    retries: int,
    walk_traffic_tables: bool = False,
) -> None:
    ip = result.ip
    serials, _ = snmp_walk(ip, community, ENT_PHYSICAL_SERIAL, timeout_seconds, retries, max_rows=200)
    models, _ = snmp_walk(ip, community, ENT_PHYSICAL_MODEL, timeout_seconds, retries, max_rows=200)
    descriptions, _ = snmp_walk(ip, community, ENT_PHYSICAL_DESCR, timeout_seconds, retries, max_rows=200)
    result.serial_numbers = summarize_unique(non_empty_values(serials), limit=8)
    result.entity_models = summarize_unique(non_empty_values(models), limit=8)
    if not result.device_model and result.entity_models:
        result.device_model = result.entity_models.split("; ", 1)[0]
    if not result.serial_numbers:
        serial_from_descr = guess_serial_from_text(" ".join(non_empty_values(descriptions)))
        result.serial_numbers = serial_from_descr

    if_descr, _ = snmp_walk(ip, community, IF_DESCR, timeout_seconds, retries, max_rows=1000)
    if_alias, _ = snmp_walk(ip, community, IF_ALIAS, timeout_seconds, retries, max_rows=1000)
    if_admin, _ = snmp_walk(ip, community, IF_ADMIN_STATUS, timeout_seconds, retries, max_rows=1000)
    if_oper, _ = snmp_walk(ip, community, IF_OPER_STATUS, timeout_seconds, retries, max_rows=1000)
    summarize_interfaces(result, if_descr, if_alias, if_admin, if_oper)

    lldp_names, _ = snmp_walk(ip, community, LLDP_REM_SYS_NAME, timeout_seconds, retries, max_rows=500)
    lldp_ports, _ = snmp_walk(ip, community, LLDP_REM_PORT_DESC, timeout_seconds, retries, max_rows=500)
    result.lldp_neighbors = summarize_neighbors(lldp_names, lldp_ports, limit=12)

    cdp_names, _ = snmp_walk(ip, community, CDP_CACHE_DEVICE_ID, timeout_seconds, retries, max_rows=500)
    cdp_ports, _ = snmp_walk(ip, community, CDP_CACHE_DEVICE_PORT, timeout_seconds, retries, max_rows=500)
    cdp_platforms, _ = snmp_walk(ip, community, CDP_CACHE_PLATFORM, timeout_seconds, retries, max_rows=500)
    result.cdp_neighbors = summarize_neighbors(cdp_names, cdp_ports, cdp_platforms, limit=12)

    if walk_traffic_tables:
        arp_entries, _ = snmp_walk(ip, community, IP_NET_TO_MEDIA_PHYS, timeout_seconds, retries, max_rows=3000)
        mac_entries, _ = snmp_walk(ip, community, DOT1D_TP_FDB_ADDRESS, timeout_seconds, retries, max_rows=3000)
        result.arp_entries = str(len(arp_entries)) if arp_entries else ""
        result.mac_entries = str(len(mac_entries)) if mac_entries else ""


def non_empty_values(rows: dict[str, str]) -> list[str]:
    return [value for value in rows.values() if value and value.lower() not in {"0", "unknown", "no such object currently exists at this oid", "no such instance currently exists at this oid"}]


def summarize_unique(values: list[str], limit: int = 8) -> str:
    seen: list[str] = []
    for value in values:
        cleaned = clean_snmp_text(value)
        if cleaned and cleaned not in seen:
            seen.append(cleaned)
        if len(seen) >= limit:
            break
    suffix = "" if len(set(values)) <= limit else f"; +{len(set(values)) - limit} more"
    return "; ".join(seen) + suffix if seen else ""


def summarize_interfaces(
    result: DiscoveryResult,
    if_descr: dict[str, str],
    if_alias: dict[str, str],
    if_admin: dict[str, str],
    if_oper: dict[str, str],
) -> None:
    indexes = sorted({oid_index(oid) for oid in if_descr} | {oid_index(oid) for oid in if_oper}, key=natural_index_key)
    if indexes:
        result.interface_count = str(len(indexes))

    up = 0
    down = 0
    interesting: list[str] = []
    alias_by_index = {oid_index(oid): value for oid, value in if_alias.items()}
    admin_by_index = {oid_index(oid): value for oid, value in if_admin.items()}
    oper_by_index = {oid_index(oid): value for oid, value in if_oper.items()}
    descr_by_index = {oid_index(oid): value for oid, value in if_descr.items()}
    for index in indexes:
        admin = status_name(admin_by_index.get(index, ""))
        oper = status_name(oper_by_index.get(index, ""))
        if oper == "up":
            up += 1
        elif oper:
            down += 1
        alias = alias_by_index.get(index, "")
        descr = descr_by_index.get(index, "")
        if alias or oper == "up":
            label = descr or f"ifIndex {index}"
            detail = f"{label} {oper}".strip()
            if alias:
                detail = f"{detail} ({alias})"
            interesting.append(detail)

    result.interfaces_up = str(up) if indexes else ""
    result.interfaces_down = str(down) if indexes else ""
    result.interface_summary = summarize_unique(interesting, limit=12)


def summarize_neighbors(
    names: dict[str, str],
    ports: dict[str, str],
    platforms: dict[str, str] | None = None,
    limit: int = 12,
) -> str:
    platform_values = platforms or {}
    items: list[str] = []
    for oid, name in names.items():
        suffix = oid_suffix(oid)
        port = lookup_by_suffix(ports, suffix)
        platform_value = lookup_by_suffix(platform_values, suffix)
        detail = clean_snmp_text(name)
        if port:
            detail = f"{detail} via {port}"
        if platform_value:
            detail = f"{detail} [{platform_value}]"
        if detail:
            items.append(detail)
    return summarize_unique(items, limit=limit)


def oid_index(oid: str) -> str:
    return oid.rsplit(".", 1)[-1]


def oid_suffix(oid: str) -> str:
    parts = oid.split(".")
    return ".".join(parts[-3:]) if len(parts) >= 3 else oid


def lookup_by_suffix(rows: dict[str, str], suffix: str) -> str:
    for oid, value in rows.items():
        if oid.endswith(suffix):
            return value
    return ""


def natural_index_key(value: str) -> tuple[int, str]:
    return (int(value), value) if value.isdigit() else (999999, value)


def status_name(value: str) -> str:
    names = {"1": "up", "2": "down", "3": "testing"}
    cleaned = clean_snmp_text(value).lower()
    return names.get(cleaned, cleaned)


def guess_serial_from_text(text: str) -> str:
    match = re.search(r"\b(?:SN|S/N|Serial(?: Number)?)[:\s#-]+([A-Z0-9-]{5,})\b", text, flags=re.IGNORECASE)
    return match.group(1).upper() if match else ""


def guess_device_type(descr: str, oid: str = "") -> str:
    haystack = f"{descr} {oid}".lower()
    checks = [
        ("firewall", ["firewall", "asa", "fortigate", "palo alto", "pan-os", "srx"]),
        ("router", ["router", "asr", "isr", "mx", "edge router", "routing platform"]),
        ("switch", ["switch", "catalyst", "nexus", "ex3400", "ex4300", "qfx", "arista", "procurve"]),
        ("optical transport", ["adva", "fujitsu", "ciena", "mrv", "xg480", "wdm", "optical", "transponder"]),
        ("olt", ["olt", "gpon", "xgs-pon", "calix"]),
        ("wireless", ["wireless", "access point", "aironet", "ap "]),
        ("ups", ["ups", "apc", "eaton"]),
        ("server", ["windows", "linux", "server"]),
    ]
    for device_type, needles in checks:
        if any(needle in haystack for needle in needles):
            return device_type
    return "network device" if descr or oid else ""


def guess_model(descr: str, oid: str = "") -> str:
    text = descr.strip()
    patterns = [
        r"\b(Cisco\s+)?(ASR[- ]?\d+[A-Z0-9-]*)\b",
        r"\b(Cisco\s+)?(ISR[- ]?\d+[A-Z0-9-]*)\b",
        r"\b(Cisco\s+)?(C\d{3,4}[A-Z0-9-]*)\b",
        r"\b(Nexus\s+\d+[A-Z0-9-]*)\b",
        r"\b(EX\d{4}[A-Z0-9-]*)\b",
        r"\b(QFX\d{4}[A-Z0-9-]*)\b",
        r"\b(MX\d{2,4}[A-Z0-9-]*)\b",
        r"\b(DCS-\d{4}[A-Z0-9-]*)\b",
        r"\b(XG\d{3,4}[A-Z0-9-]*)\b",
        r"\b(FSP\s*\d+[A-Z0-9-]*)\b",
        r"\b(6500|7600|9300|9400|9500|9600)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            groups = [group for group in match.groups() if group]
            return groups[-1].upper()

    cisco_match = re.search(r"Cisco\s+([A-Z0-9][A-Z0-9-]{3,})", text, flags=re.IGNORECASE)
    if cisco_match:
        return cisco_match.group(1).upper()

    if oid:
        return f"OID {oid}"
    return ""


def guess_software_version(descr: str) -> str:
    patterns = [
        r"\bVersion\s+([A-Za-z0-9()._\-]+)",
        r"\bSoftware(?:\s+Version)?\s+([A-Za-z0-9()._\-]+)",
        r"\bJUNOS\s+([A-Za-z0-9()._\-]+)",
        r"\bEOS\s+version\s+([A-Za-z0-9()._\-]+)",
        r"\bPAN-OS\s+([A-Za-z0-9()._\-]+)",
        r"\bRelease\s+([A-Za-z0-9()._\-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, descr, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip(".,;")
    return ""


def results_to_csv(results: list[DiscoveryResult], include_community: bool = False) -> bytes:
    buffer = io.StringIO(newline="")
    columns = list(EXPORT_COLUMNS) + ["snmp_status", "snmp_error"]
    if include_community:
        columns.append("matched_community")
    writer = csv.DictWriter(buffer, fieldnames=columns)
    writer.writeheader()
    for result in results:
        data = result.public_dict(include_community=include_community)
        writer.writerow({column: data.get(column, "") for column in columns})
    return buffer.getvalue().encode("utf-8-sig")
