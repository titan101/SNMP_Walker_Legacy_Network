from __future__ import annotations

import asyncio
import ipaddress
import logging
import platform
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

_log = logging.getLogger(__name__)

try:
    from pysnmp.hlapi.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        get_cmd,
        usmAesCfb128Protocol,
        usmDESPrivProtocol,
        usmHMAC192SHA256AuthProtocol,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
        usmNoAuthProtocol,
        usmNoPrivProtocol,
        walk_cmd,
    )
except ImportError:  # pragma: no cover - exercised in environments missing pysnmp
    CommunityData = None
    ContextData = None
    ObjectIdentity = None
    ObjectType = None
    SnmpEngine = None
    UdpTransportTarget = None
    UsmUserData = None
    get_cmd = None
    usmHMACMD5AuthProtocol = None
    usmHMACSHAAuthProtocol = None
    usmHMAC192SHA256AuthProtocol = None
    usmNoAuthProtocol = None
    usmNoPrivProtocol = None
    usmDESPrivProtocol = None
    usmAesCfb128Protocol = None
    walk_cmd = None


SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
IF_NUMBER = "1.3.6.1.2.1.2.1.0"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
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

MIB_WALK_PLAN = [
    {"mode": "base", "operation": "GET", "mib": "SNMPv2-MIB", "name": "sysDescr.0", "oid": SYS_DESCR, "collects": "System description and software evidence"},
    {"mode": "base", "operation": "GET", "mib": "SNMPv2-MIB", "name": "sysObjectID.0", "oid": SYS_OBJECT_ID, "collects": "Vendor/model object identifier"},
    {"mode": "base", "operation": "GET", "mib": "SNMPv2-MIB", "name": "sysUpTime.0", "oid": SYS_UPTIME, "collects": "Device uptime"},
    {"mode": "base", "operation": "GET", "mib": "SNMPv2-MIB", "name": "sysContact.0", "oid": SYS_CONTACT, "collects": "System contact"},
    {"mode": "base", "operation": "GET", "mib": "SNMPv2-MIB", "name": "sysName.0", "oid": SYS_NAME, "collects": "Hostname"},
    {"mode": "base", "operation": "GET", "mib": "SNMPv2-MIB", "name": "sysLocation.0", "oid": SYS_LOCATION, "collects": "Location/address"},
    {"mode": "base", "operation": "GET", "mib": "IF-MIB", "name": "ifNumber.0", "oid": IF_NUMBER, "collects": "Interface count"},
    {"mode": "inventory", "operation": "WALK", "mib": "ENTITY-MIB", "name": "entPhysicalDescr", "oid": ENT_PHYSICAL_DESCR, "collects": "Chassis/module descriptions"},
    {"mode": "inventory", "operation": "WALK", "mib": "ENTITY-MIB", "name": "entPhysicalSerialNum", "oid": ENT_PHYSICAL_SERIAL, "collects": "Serial numbers"},
    {"mode": "inventory", "operation": "WALK", "mib": "ENTITY-MIB", "name": "entPhysicalModelName", "oid": ENT_PHYSICAL_MODEL, "collects": "Chassis/module model hints"},
    {"mode": "inventory", "operation": "WALK", "mib": "IF-MIB", "name": "ifDescr", "oid": IF_DESCR, "collects": "Interface names/descriptions"},
    {"mode": "inventory", "operation": "WALK", "mib": "IF-MIB", "name": "ifSpeed", "oid": IF_SPEED, "collects": "Interface speed in bps"},
    {"mode": "inventory", "operation": "WALK", "mib": "IF-MIB", "name": "ifAdminStatus", "oid": IF_ADMIN_STATUS, "collects": "Configured interface state"},
    {"mode": "inventory", "operation": "WALK", "mib": "IF-MIB", "name": "ifOperStatus", "oid": IF_OPER_STATUS, "collects": "Operational interface state"},
    {"mode": "inventory", "operation": "WALK", "mib": "IF-MIB", "name": "ifHighSpeed", "oid": IF_HIGH_SPEED, "collects": "Interface speed in Mbps"},
    {"mode": "inventory", "operation": "WALK", "mib": "IF-MIB", "name": "ifAlias", "oid": IF_ALIAS, "collects": "Interface aliases/descriptions"},
    {"mode": "topology", "operation": "WALK", "mib": "LLDP-MIB", "name": "lldpRemSysName", "oid": LLDP_REM_SYS_NAME, "collects": "LLDP remote device names"},
    {"mode": "topology", "operation": "WALK", "mib": "LLDP-MIB", "name": "lldpRemPortDesc", "oid": LLDP_REM_PORT_DESC, "collects": "LLDP remote port descriptions"},
    {"mode": "topology", "operation": "WALK", "mib": "CISCO-CDP-MIB", "name": "cdpCacheDeviceId", "oid": CDP_CACHE_DEVICE_ID, "collects": "CDP remote device IDs"},
    {"mode": "topology", "operation": "WALK", "mib": "CISCO-CDP-MIB", "name": "cdpCacheDevicePort", "oid": CDP_CACHE_DEVICE_PORT, "collects": "CDP remote ports"},
    {"mode": "topology", "operation": "WALK", "mib": "CISCO-CDP-MIB", "name": "cdpCachePlatform", "oid": CDP_CACHE_PLATFORM, "collects": "CDP remote platform hints"},
    {"mode": "traffic", "operation": "WALK", "mib": "IP-MIB", "name": "ipNetToMediaPhysAddress", "oid": IP_NET_TO_MEDIA_PHYS, "collects": "ARP table entry count"},
    {"mode": "traffic", "operation": "WALK", "mib": "BRIDGE-MIB", "name": "dot1dTpFdbAddress", "oid": DOT1D_TP_FDB_ADDRESS, "collects": "MAC forwarding table entry count"},
]

BASE_OID_MAP = {
    SYS_DESCR: "sys_descr",
    SYS_UPTIME: "uptime",
    SYS_CONTACT: "sys_contact",
    SYS_OBJECT_ID: "sys_object_id",
    SYS_NAME: "hostname",
    SYS_LOCATION: "address",
    IF_NUMBER: "interface_count",
}

DEFAULT_SELECTED_OIDS = [item["oid"] for item in MIB_WALK_PLAN]

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
    entity_rows: list[dict[str, str]] = field(default_factory=list)
    interface_rows: list[dict[str, str]] = field(default_factory=list)
    neighbor_rows: list[dict[str, str]] = field(default_factory=list)
    walk_errors: list[dict[str, str]] = field(default_factory=list)

    def public_dict(self, include_community: bool = False) -> dict[str, Any]:
        data = asdict(self)
        if not include_community:
            data.pop("matched_community", None)
        return data


@dataclass
class V3Credentials:
    username: str
    auth_protocol: str = "SHA"
    auth_key: str = ""
    priv_protocol: str = "AES"
    priv_key: str = ""


def _build_auth(community: str, snmp_version: str, v3_cred: "V3Credentials | None"):
    """Return CommunityData (v1/v2c) or UsmUserData (v3) for pysnmp auth."""
    if snmp_version == "v3" and v3_cred is not None and UsmUserData is not None:
        auth_map = {
            "MD5": usmHMACMD5AuthProtocol,
            "SHA": usmHMACSHAAuthProtocol,
            "SHA256": usmHMAC192SHA256AuthProtocol,
            "NONE": usmNoAuthProtocol,
        }
        priv_map = {
            "DES": usmDESPrivProtocol,
            "AES": usmAesCfb128Protocol,
            "NONE": usmNoPrivProtocol,
        }
        auth_proto = auth_map.get(v3_cred.auth_protocol.upper(), usmHMACSHAAuthProtocol)
        priv_proto = priv_map.get(v3_cred.priv_protocol.upper(), usmNoPrivProtocol)
        kwargs: dict = {"authProtocol": auth_proto, "privProtocol": priv_proto}
        if v3_cred.auth_key:
            kwargs["authKey"] = v3_cred.auth_key
        if v3_cred.priv_key:
            kwargs["privKey"] = v3_cred.priv_key
        return UsmUserData(v3_cred.username, **kwargs)
    mp_model = 0 if snmp_version == "v1" else 1
    return CommunityData(community, mpModel=mp_model)


def parse_targets(raw: str, max_hosts: int = 4096) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    tokens = re.split(r"[\s,;]+", raw.strip())
    for token in tokens:
        if not token:
            continue
        for ip in iter_target_addresses(token):
            if ip not in seen:
                if len(targets) >= max_hosts:
                    raise ValueError(f"Target list exceeded max host limit of {max_hosts}.")
                targets.append(ip)
                seen.add(ip)
    return targets


def expand_target(token: str) -> list[str]:
    return list(iter_target_addresses(token))


def iter_target_addresses(token: str) -> Iterable[str]:
    token = token.strip()
    if "/" in token:
        network = ipaddress.ip_network(token, strict=False)
        if network.version != 4:
            raise ValueError(f"Only IPv4 targets are supported: {token}")
        for ip in network.hosts():
            yield str(ip)
        return

    range_match = re.fullmatch(r"(\d+\.\d+\.\d+\.)(\d{1,3})-(\d{1,3})", token)
    if range_match:
        prefix, start_text, end_text = range_match.groups()
        start = int(start_text)
        end = int(end_text)
        if start > end or start < 0 or end > 255:
            raise ValueError(f"Invalid IP range: {token}")
        for last in range(start, end + 1):
            yield str(ipaddress.ip_address(f"{prefix}{last}"))
        return

    yield str(ipaddress.ip_address(token))


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
    selected_oids: set[str] | None = None,
    snmp_version: str = "v2c",
    v3_cred: "V3Credentials | None" = None,
) -> tuple[dict[str, str] | None, str]:
    if get_cmd is None:
        return None, "pysnmp is not installed"

    engine = SnmpEngine()
    target = await UdpTransportTarget.create((ip, 161), timeout=timeout_seconds, retries=retries)
    oid_map = selected_base_oid_map(selected_oids)
    if not oid_map:
        return None, "No base GET OIDs selected"
    error_indication, error_status, error_index, var_binds = await get_cmd(
        engine,
        _build_auth(community, snmp_version, v3_cred),
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


def snmp_get_values(
    ip: str,
    community: str,
    timeout_seconds: float,
    retries: int,
    selected_oids: set[str] | None = None,
    snmp_version: str = "v2c",
    v3_cred: "V3Credentials | None" = None,
) -> tuple[dict[str, str] | None, str]:
    try:
        return asyncio.run(snmp_get_values_async(ip, community, timeout_seconds, retries, selected_oids, snmp_version, v3_cred))
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


async def snmp_walk_async(
    ip: str,
    community: str,
    oid: str,
    timeout_seconds: float,
    retries: int,
    max_rows: int = 2000,
    snmp_version: str = "v2c",
    v3_cred: "V3Credentials | None" = None,
) -> tuple[dict[str, str], str]:
    if walk_cmd is None:
        return {}, "pysnmp is not installed"

    engine = SnmpEngine()
    target = await UdpTransportTarget.create((ip, 161), timeout=timeout_seconds, retries=retries)
    rows: dict[str, str] = {}
    async for error_indication, error_status, error_index, var_binds in walk_cmd(
        engine,
        _build_auth(community, snmp_version, v3_cred),
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
    snmp_version: str = "v2c",
    v3_cred: "V3Credentials | None" = None,
) -> tuple[dict[str, str], str]:
    try:
        return asyncio.run(snmp_walk_async(ip, community, oid, timeout_seconds, retries, max_rows, snmp_version, v3_cred))
    except Exception as exc:
        return {}, f"{type(exc).__name__}: {exc}"


def snmp_walk_recorded(
    result: DiscoveryResult,
    community: str,
    oid: str,
    timeout_seconds: float,
    retries: int,
    max_rows: int = 2000,
) -> tuple[dict[str, str], str]:
    rows, error = snmp_walk(result.ip, community, oid, timeout_seconds, retries, max_rows=max_rows)
    plan = mib_plan_for_oid(oid)
    status = "ok"
    if error == "walk capped":
        status = "capped"
    elif error:
        status = "error"
    elif not rows:
        status = "empty"
    result.walk_errors.append(
        {
            "ip": result.ip,
            "hostname": result.hostname,
            "mode": plan.get("mode", ""),
            "mib": plan.get("mib", ""),
            "name": plan.get("name", ""),
            "oid": oid,
            "operation": "WALK",
            "rows": str(len(rows)),
            "status": status,
            "error": "" if error == "walk capped" else error,
        }
    )
    return rows, error


def selected_base_oid_map(selected_oids: set[str] | None = None) -> dict[str, str]:
    if selected_oids is None:
        return dict(BASE_OID_MAP)
    return {oid: key for oid, key in BASE_OID_MAP.items() if oid in selected_oids}


def should_query_oid(oid: str, selected_oids: set[str] | None = None) -> bool:
    return selected_oids is None or oid in selected_oids


def mib_plan_for_oid(oid: str) -> dict[str, str]:
    for item in MIB_WALK_PLAN:
        if item["oid"] == oid:
            return item
    return {"mode": "", "mib": "", "name": "", "oid": oid, "operation": "", "collects": ""}


def discover_one(
    ip: str,
    communities: list[str],
    ping_timeout_ms: int = 800,
    snmp_timeout_seconds: float = 1.2,
    snmp_retries: int = 1,
    do_ping: bool = True,
    walk_details: bool = False,
    walk_traffic_tables: bool = False,
    selected_oids: Iterable[str] | None = None,
    snmp_versions: "list[str] | None" = None,
    v3_credentials: "list[V3Credentials] | None" = None,
) -> DiscoveryResult:
    result = DiscoveryResult(ip=ip)
    selected_oid_set = set(selected_oids) if selected_oids is not None else None
    versions = snmp_versions or ["v2c"]
    if do_ping:
        result.pingable_or_not = ping_host(ip, ping_timeout_ms)

    # Build ordered attempt list: (community, v3_cred, version)
    # v2c/v1 use community strings; v3 uses credentials
    attempts: list[tuple[str, "V3Credentials | None", str]] = []
    for ver in versions:
        if ver == "v3" and v3_credentials:
            attempts.extend(("", cred, "v3") for cred in v3_credentials)
        elif ver in ("v1", "v2c"):
            attempts.extend((community, None, ver) for community in communities)
    has_any = bool(attempts)

    last_error = ""
    for community, v3_cred, ver in attempts:
        values, error = snmp_get_values(ip, community, snmp_timeout_seconds, snmp_retries, selected_oid_set, ver, v3_cred)
        if values:
            result.snmp_status = "ok"
            result.matched_community = f"v3:{v3_cred.username}" if v3_cred else community
            result.hostname = clean_snmp_text(values.get("hostname", ""))
            result.address = clean_snmp_text(values.get("address", ""))
            result.sys_descr = clean_snmp_text(values.get("sys_descr", ""))
            result.sys_object_id = clean_snmp_text(values.get("sys_object_id", ""))
            result.sys_contact = clean_snmp_text(values.get("sys_contact", ""))
            result.uptime = format_timeticks(values.get("uptime", ""))
            result.interface_count = clean_snmp_text(values.get("interface_count", ""))
            enrich_result(result)
            if walk_details:
                enrich_result_from_walks(
                    result,
                    community,
                    snmp_timeout_seconds,
                    snmp_retries,
                    walk_traffic_tables,
                    selected_oid_set,
                    ver,
                    v3_cred,
                )
            return result
        last_error = error

    result.snmp_status = "failed" if has_any else "no_communities"
    result.snmp_error = last_error or "No community answered"
    _log.info("No SNMP from %s: %s", ip, result.snmp_error)
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
    selected_oids: Iterable[str] | None = None,
    snmp_versions: "list[str] | None" = None,
    v3_credentials: "list[V3Credentials] | None" = None,
) -> list[DiscoveryResult]:
    return sorted(
        discover_iter(
            ips,
            communities,
            ping_timeout_ms=ping_timeout_ms,
            snmp_timeout_seconds=snmp_timeout_seconds,
            snmp_retries=snmp_retries,
            workers=workers,
            do_ping=do_ping,
            walk_details=walk_details,
            walk_traffic_tables=walk_traffic_tables,
            selected_oids=selected_oids,
            snmp_versions=snmp_versions,
            v3_credentials=v3_credentials,
        ),
        key=lambda item: ipaddress.ip_address(item.ip),
    )


def discover_iter(
    ips: Iterable[str],
    communities: list[str],
    ping_timeout_ms: int = 800,
    snmp_timeout_seconds: float = 1.2,
    snmp_retries: int = 1,
    workers: int = 24,
    do_ping: bool = True,
    walk_details: bool = False,
    walk_traffic_tables: bool = False,
    selected_oids: Iterable[str] | None = None,
    snmp_versions: "list[str] | None" = None,
    v3_credentials: "list[V3Credentials] | None" = None,
) -> Iterable[DiscoveryResult]:
    ip_list = list(ips)
    max_workers = max(1, min(workers, 128))
    _log.info("Scan start: %d targets %d workers", len(ip_list), max_workers)
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
                selected_oids,
                snmp_versions,
                v3_credentials,
            ): ip
            for ip in ip_list
        }
        for future in as_completed(futures):
            try:
                yield future.result()
            except Exception as exc:
                ip = futures[future]
                _log.exception("Worker crash for %s", ip)
                yield DiscoveryResult(
                    ip=ip,
                    snmp_status="error",
                    snmp_error=f"{type(exc).__name__}: {exc}",
                )


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


async def _gather_walks_async(
    ip: str,
    community: str,
    plan: list[tuple[str, int]],
    timeout_seconds: float,
    retries: int,
    snmp_version: str = "v2c",
    v3_cred: "V3Credentials | None" = None,
) -> list[tuple[dict[str, str], str]]:
    """Run all SNMP walks concurrently. Returns (rows, error) per entry in plan."""
    coros = [
        snmp_walk_async(ip, community, oid, timeout_seconds, retries, max_rows=max_rows, snmp_version=snmp_version, v3_cred=v3_cred)
        for oid, max_rows in plan
    ]
    gathered = await asyncio.gather(*coros, return_exceptions=True)
    return [
        r if not isinstance(r, BaseException) else ({}, f"{type(r).__name__}: {r}")
        for r in gathered
    ]


def _record_walk(result: DiscoveryResult, oid: str, rows: dict[str, str], error: str) -> None:
    plan = mib_plan_for_oid(oid)
    if error == "walk capped":
        status = "capped"
    elif error:
        status = "error"
        _log.warning("%s walk error %s: %s", result.ip, plan.get("name", oid), error)
    elif not rows:
        status = "empty"
    else:
        status = "ok"
    result.walk_errors.append({
        "ip": result.ip,
        "hostname": result.hostname,
        "mode": plan.get("mode", ""),
        "mib": plan.get("mib", ""),
        "name": plan.get("name", ""),
        "oid": oid,
        "operation": "WALK",
        "rows": str(len(rows)),
        "status": status,
        "error": "" if error == "walk capped" else error,
    })


def enrich_result_from_walks(
    result: DiscoveryResult,
    community: str,
    timeout_seconds: float,
    retries: int,
    walk_traffic_tables: bool = False,
    selected_oids: set[str] | None = None,
    snmp_version: str = "v2c",
    v3_cred: "V3Credentials | None" = None,
) -> None:
    walk_plan: list[tuple[str, int]] = [
        (ENT_PHYSICAL_SERIAL, 200),
        (ENT_PHYSICAL_MODEL, 200),
        (ENT_PHYSICAL_DESCR, 200),
        (IF_DESCR, 1000),
        (IF_ALIAS, 1000),
        (IF_ADMIN_STATUS, 1000),
        (IF_OPER_STATUS, 1000),
        (IF_SPEED, 1000),
        (IF_HIGH_SPEED, 1000),
        (LLDP_REM_SYS_NAME, 500),
        (LLDP_REM_PORT_DESC, 500),
        (CDP_CACHE_DEVICE_ID, 500),
        (CDP_CACHE_DEVICE_PORT, 500),
        (CDP_CACHE_PLATFORM, 500),
    ]
    if walk_traffic_tables:
        walk_plan += [(IP_NET_TO_MEDIA_PHYS, 3000), (DOT1D_TP_FDB_ADDRESS, 3000)]

    active_plan = [(oid, mr) for oid, mr in walk_plan if should_query_oid(oid, selected_oids)]
    walk_results = asyncio.run(_gather_walks_async(result.ip, community, active_plan, timeout_seconds, retries, snmp_version, v3_cred))

    data: dict[str, dict[str, str]] = {}
    for (oid, _), (rows, error) in zip(active_plan, walk_results):
        _record_walk(result, oid, rows, error)
        data[oid] = rows

    def get(oid: str) -> dict[str, str]:
        return data.get(oid, {})

    serials = get(ENT_PHYSICAL_SERIAL)
    models = get(ENT_PHYSICAL_MODEL)
    descriptions = get(ENT_PHYSICAL_DESCR)
    result.entity_rows = build_entity_rows(result, descriptions, models, serials)
    result.serial_numbers = summarize_unique(non_empty_values(serials), limit=8)
    result.entity_models = summarize_unique(non_empty_values(models), limit=8)
    if not result.device_model and result.entity_models:
        result.device_model = result.entity_models.split("; ", 1)[0]
    if not result.serial_numbers:
        result.serial_numbers = guess_serial_from_text(" ".join(non_empty_values(descriptions)))

    summarize_interfaces(result, get(IF_DESCR), get(IF_ALIAS), get(IF_ADMIN_STATUS), get(IF_OPER_STATUS), get(IF_SPEED), get(IF_HIGH_SPEED))
    local_ports = interface_lookup(result.interface_rows)

    lldp_names = get(LLDP_REM_SYS_NAME)
    lldp_ports = get(LLDP_REM_PORT_DESC)
    result.lldp_neighbors = summarize_neighbors(lldp_names, lldp_ports, limit=12)
    result.neighbor_rows.extend(
        build_neighbor_rows(result, "LLDP", lldp_names, lldp_ports, suffix_length=3, local_ports=local_ports)
    )

    cdp_names = get(CDP_CACHE_DEVICE_ID)
    cdp_ports = get(CDP_CACHE_DEVICE_PORT)
    cdp_platforms = get(CDP_CACHE_PLATFORM)
    result.cdp_neighbors = summarize_neighbors(cdp_names, cdp_ports, cdp_platforms, limit=12, suffix_length=2)
    result.neighbor_rows.extend(
        build_neighbor_rows(result, "CDP", cdp_names, cdp_ports, cdp_platforms, suffix_length=2, local_ports=local_ports)
    )

    if walk_traffic_tables:
        result.arp_entries = str(len(get(IP_NET_TO_MEDIA_PHYS))) or ""
        result.mac_entries = str(len(get(DOT1D_TP_FDB_ADDRESS))) or ""


def walk_selected(
    result: DiscoveryResult,
    community: str,
    oid: str,
    timeout_seconds: float,
    retries: int,
    selected_oids: set[str] | None,
    max_rows: int,
) -> dict[str, str]:
    if not should_query_oid(oid, selected_oids):
        return {}
    rows, _ = snmp_walk_recorded(result, community, oid, timeout_seconds, retries, max_rows=max_rows)
    return rows


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
    if_speed: dict[str, str] | None = None,
    if_high_speed: dict[str, str] | None = None,
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
    speed_by_index = {oid_index(oid): value for oid, value in (if_speed or {}).items()}
    high_speed_by_index = {oid_index(oid): value for oid, value in (if_high_speed or {}).items()}
    result.interface_rows = []
    for index in indexes:
        admin = status_name(admin_by_index.get(index, ""))
        oper = status_name(oper_by_index.get(index, ""))
        if oper == "up":
            up += 1
        elif oper:
            down += 1
        alias = alias_by_index.get(index, "")
        descr = descr_by_index.get(index, "")
        speed_mbps = interface_speed_mbps(speed_by_index.get(index, ""), high_speed_by_index.get(index, ""))
        result.interface_rows.append(
            {
                "ip": result.ip,
                "hostname": result.hostname,
                "if_index": index,
                "description": descr,
                "alias": alias,
                "admin_status": admin,
                "oper_status": oper,
                "speed_mbps": speed_mbps,
            }
        )
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
    suffix_length: int = 3,
) -> str:
    platform_values = platforms or {}
    items: list[str] = []
    for oid, name in names.items():
        suffix = oid_suffix(oid, suffix_length)
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


def oid_suffix(oid: str, length: int = 3) -> str:
    parts = oid.split(".")
    return ".".join(parts[-length:]) if len(parts) >= length else oid


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


def build_entity_rows(
    result: DiscoveryResult,
    descriptions: dict[str, str],
    models: dict[str, str],
    serials: dict[str, str],
) -> list[dict[str, str]]:
    indexes = sorted(
        {oid_index(oid) for oid in descriptions} | {oid_index(oid) for oid in models} | {oid_index(oid) for oid in serials},
        key=natural_index_key,
    )
    rows: list[dict[str, str]] = []
    descriptions_by_index = {oid_index(oid): value for oid, value in descriptions.items()}
    models_by_index = {oid_index(oid): value for oid, value in models.items()}
    serials_by_index = {oid_index(oid): value for oid, value in serials.items()}
    for index in indexes:
        description = descriptions_by_index.get(index, "")
        model = models_by_index.get(index, "")
        serial = serials_by_index.get(index, "")
        if not any(non_empty_values({"description": description, "model": model, "serial": serial})):
            continue
        rows.append(
            {
                "ip": result.ip,
                "hostname": result.hostname,
                "entity_index": index,
                "description": description,
                "model": model,
                "serial": serial,
            }
        )
    return rows


def build_neighbor_rows(
    result: DiscoveryResult,
    protocol: str,
    names: dict[str, str],
    ports: dict[str, str],
    platforms: dict[str, str] | None = None,
    suffix_length: int = 3,
    local_ports: dict[str, dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    platform_values = platforms or {}
    local_port_values = local_ports or {}
    rows: list[dict[str, str]] = []
    for oid, name in names.items():
        suffix = oid_suffix(oid, suffix_length)
        local_index = neighbor_local_index(suffix, protocol)
        local_port = local_port_name(local_index, local_port_values) or neighbor_local_port_label(suffix, protocol)
        bandwidth_mbps = local_port_values.get(local_index, {}).get("speed_mbps", "")
        remote_device = clean_snmp_text(name)
        remote_port = clean_snmp_text(lookup_by_suffix(ports, suffix))
        remote_platform = clean_snmp_text(lookup_by_suffix(platform_values, suffix))
        if not remote_device and not remote_port and not remote_platform:
            continue
        rows.append(
            {
                "ip": result.ip,
                "hostname": result.hostname,
                "protocol": protocol,
                "local_port": local_port,
                "remote_device": remote_device,
                "remote_port": remote_port,
                "remote_platform": remote_platform,
                "link_type": guess_link_type(local_port, remote_port, remote_platform),
                "bandwidth_mbps": bandwidth_mbps,
                "table_index": suffix,
            }
        )
    return rows


def neighbor_local_port_label(suffix: str, protocol: str) -> str:
    local_index = neighbor_local_index(suffix, protocol)
    if protocol.upper() == "LLDP" and local_index:
        return f"localPort {local_index}"
    if protocol.upper() == "CDP" and local_index:
        return f"ifIndex {local_index}"
    return suffix


def neighbor_local_index(suffix: str, protocol: str) -> str:
    parts = suffix.split(".")
    if protocol.upper() == "LLDP" and len(parts) >= 2:
        return parts[-2]
    if protocol.upper() == "CDP" and parts:
        return parts[0]
    return ""


def interface_lookup(interface_rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    return {row["if_index"]: row for row in interface_rows if row.get("if_index")}


def local_port_name(index: str, local_ports: dict[str, dict[str, str]]) -> str:
    row = local_ports.get(index, {})
    return row.get("description") or row.get("alias") or ""


def interface_speed_mbps(if_speed: str, if_high_speed: str) -> str:
    high_speed = parse_int(if_high_speed)
    if high_speed:
        return str(high_speed)
    speed = parse_int(if_speed)
    if speed:
        return str(max(1, speed // 1_000_000))
    return ""


def parse_int(value: str) -> int:
    match = re.search(r"\d+", value or "")
    return int(match.group(0)) if match else 0


def guess_link_type(local_port: str, remote_port: str, remote_platform: str = "") -> str:
    text = f"{local_port} {remote_port} {remote_platform}".lower()
    if re.search(r"\b(port-channel|portchannel|bundle|ae\d+|po\d+)\b", text):
        return "aggregate"
    if any(word in text for word in ["uplink", "trunk", "core", "agg", "distribution", "dist"]):
        return "uplink"
    if any(word in text for word in ["server", "host", "access point", " ap", "phone", "printer"]):
        return "access"
    if any(word in text for word in ["wan", "provider", "peer", "transit", "edge"]):
        return "interconnect"
    return ""


def topology_edges(results: list[DiscoveryResult]) -> list[dict[str, str]]:
    edges: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for result in results:
        source = result.hostname or result.ip
        for neighbor in result.neighbor_rows:
            target = neighbor.get("remote_device", "")
            if not target:
                continue
            edge = {
                "source": source,
                "source_ip": result.ip,
                "source_port": neighbor.get("local_port", ""),
                "target": target,
                "target_port": neighbor.get("remote_port", ""),
                "protocol": neighbor.get("protocol", ""),
                "remote_platform": neighbor.get("remote_platform", ""),
                "link_type": neighbor.get("link_type", ""),
                "bandwidth_mbps": neighbor.get("bandwidth_mbps", ""),
            }
            key = (
                edge["source"].lower(),
                edge["source_port"].lower(),
                edge["target"].lower(),
                edge["target_port"].lower(),
                edge["protocol"].lower(),
            )
            if key in seen:
                continue
            seen.add(key)
            edges.append(edge)
    return edges


def topology_context_lines(results: list[DiscoveryResult]) -> list[dict[str, str]]:
    lines: list[dict[str, str]] = []
    for edge in topology_edges(results):
        detail = f"{edge['source']} [{edge['source_port'] or '?'}] <-> [{edge['target_port'] or '?'}] {edge['target']}"
        metadata = []
        if edge.get("protocol"):
            metadata.append(edge["protocol"])
        if edge.get("bandwidth_mbps"):
            metadata.append(f"{edge['bandwidth_mbps']}Mbps")
        if edge.get("link_type"):
            metadata.append(edge["link_type"])
        if metadata:
            detail += f" ({', '.join(metadata)})"
        lines.append({"line": detail})
    return lines
