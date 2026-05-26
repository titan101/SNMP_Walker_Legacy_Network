import pytest

from snmp_walker.discovery import (
    DiscoveryResult,
    build_neighbor_rows,
    discover_many,
    enrich_result,
    format_timeticks,
    parse_communities,
    parse_targets,
    snmp_walk_recorded,
    summarize_neighbors,
    summarize_interfaces,
    topology_edges,
)


def test_parse_targets_accepts_ips_cidrs_and_ranges():
    assert parse_targets("192.0.2.1\n192.0.2.4-5\n192.0.2.8/30") == [
        "192.0.2.1",
        "192.0.2.4",
        "192.0.2.5",
        "192.0.2.9",
        "192.0.2.10",
    ]


def test_parse_targets_enforces_limit():
    with pytest.raises(ValueError):
        parse_targets("10.0.0.0/24", max_hosts=10)


def test_parse_targets_stops_large_networks_at_limit():
    with pytest.raises(ValueError):
        parse_targets("10.0.0.0/8", max_hosts=3)


def test_parse_communities_dedupes_and_ignores_comments():
    assert parse_communities("public\n# old\npublic\nprivate\n") == ["public", "private"]


def test_enrich_result_detects_common_cisco_description():
    result = DiscoveryResult(
        ip="192.0.2.1",
        sys_descr="Cisco IOS Software, ASR9000 Software, Version 7.5.2, RELEASE SOFTWARE",
        sys_object_id="1.3.6.1.4.1.9.1.999",
    )
    enrich_result(result)
    assert result.device_type == "router"
    assert result.device_model == "ASR9000"
    assert result.software_version == "7.5.2"


def test_format_timeticks_converts_hundredths_to_duration():
    assert format_timeticks("9006100") == "1d 1h 1m 1s"


def test_summarize_neighbors_matches_table_suffixes():
    names = {"1.0.8802.1.1.2.1.4.1.1.9.1.2.3": "sw01"}
    ports = {"1.0.8802.1.1.2.1.4.1.1.8.1.2.3": "Gi1/0/1"}
    assert summarize_neighbors(names, ports) == "sw01 via Gi1/0/1"


def test_summarize_neighbors_matches_cdp_two_part_suffixes():
    names = {"1.3.6.1.4.1.9.9.23.1.2.1.1.6.101.1": "sw01"}
    ports = {"1.3.6.1.4.1.9.9.23.1.2.1.1.7.101.1": "Gi1/0/1"}
    assert summarize_neighbors(names, ports, suffix_length=2) == "sw01 via Gi1/0/1"


def test_summarize_interfaces_keeps_export_rows():
    result = DiscoveryResult(ip="192.0.2.1", hostname="r1")
    summarize_interfaces(
        result,
        {"1.3.6.1.2.1.2.2.1.2.1": "Gi0/0"},
        {"1.3.6.1.2.1.31.1.1.1.18.1": "uplink"},
        {"1.3.6.1.2.1.2.2.1.7.1": "1"},
        {"1.3.6.1.2.1.2.2.1.8.1": "1"},
        {"1.3.6.1.2.1.2.2.1.5.1": "1000000000"},
        {},
    )
    assert result.interfaces_up == "1"
    assert result.interface_rows == [
        {
            "ip": "192.0.2.1",
            "hostname": "r1",
            "if_index": "1",
            "description": "Gi0/0",
            "alias": "uplink",
            "admin_status": "up",
            "oper_status": "up",
            "speed_mbps": "1000",
        }
    ]


def test_neighbor_rows_feed_topology_edges():
    result = DiscoveryResult(ip="192.0.2.1", hostname="r1")
    result.neighbor_rows = build_neighbor_rows(
        result,
        "CDP",
        {"1.3.6.1.4.1.9.9.23.1.2.1.1.6.101.1": "sw01"},
        {"1.3.6.1.4.1.9.9.23.1.2.1.1.7.101.1": "Gi1/0/1"},
        suffix_length=2,
        local_ports={"101": {"description": "TenGig0/1", "speed_mbps": "10000"}},
    )
    assert topology_edges([result])[0]["target"] == "sw01"
    assert topology_edges([result])[0]["source_port"] == "TenGig0/1"
    assert topology_edges([result])[0]["bandwidth_mbps"] == "10000"


def test_snmp_walk_recorded_keeps_mib_status(monkeypatch):
    def fake_walk(*args, **kwargs):
        return {"1.3.6.1.2.1.2.2.1.2.1": "Gi0/0"}, ""

    monkeypatch.setattr("snmp_walker.discovery.snmp_walk", fake_walk)
    result = DiscoveryResult(ip="192.0.2.1", hostname="r1")
    rows, error = snmp_walk_recorded(result, "public", "1.3.6.1.2.1.2.2.1.2", 1.0, 0)
    assert rows
    assert error == ""
    assert result.walk_errors[0]["mib"] == "IF-MIB"
    assert result.walk_errors[0]["status"] == "ok"
    assert result.walk_errors[0]["rows"] == "1"


def test_discover_many_returns_error_row_when_worker_raises(monkeypatch):
    def broken_discover(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("snmp_walker.discovery.discover_one", broken_discover)
    rows = discover_many(["192.0.2.1"], ["public"], do_ping=False)
    assert rows[0].snmp_status == "error"
    assert "boom" in rows[0].snmp_error
