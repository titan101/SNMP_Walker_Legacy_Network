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
    )
except ImportError:  # pragma: no cover - exercised in environments missing pysnmp
    CommunityData = None
    ContextData = None
    ObjectIdentity = None
    ObjectType = None
    SnmpEngine = None
    UdpTransportTarget = None
    get_cmd = None


SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

EXPORT_COLUMNS = [
    "ip",
    "pingable_or_not",
    "hostname",
    "device_model",
    "device_type",
    "address",
    "software_version",
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
        SYS_OBJECT_ID: "sys_object_id",
        SYS_NAME: "hostname",
        SYS_LOCATION: "address",
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
    return asyncio.run(snmp_get_values_async(ip, community, timeout_seconds, retries))


def discover_one(
    ip: str,
    communities: list[str],
    ping_timeout_ms: int = 800,
    snmp_timeout_seconds: float = 1.2,
    snmp_retries: int = 1,
    do_ping: bool = True,
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
            enrich_result(result)
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
            ): ip
            for ip in ip_list
        }
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda item: ipaddress.ip_address(item.ip))


def clean_snmp_text(value: str) -> str:
    value = value.replace("\x00", "").strip()
    return re.sub(r"\s+", " ", value)


def enrich_result(result: DiscoveryResult) -> None:
    descr = result.sys_descr
    oid = result.sys_object_id
    result.device_type = guess_device_type(descr, oid)
    result.device_model = guess_model(descr, oid)
    result.software_version = guess_software_version(descr)


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
