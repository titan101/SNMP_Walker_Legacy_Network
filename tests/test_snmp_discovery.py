import pytest

from snmp_discovery import (
    DiscoveryResult,
    discover_many,
    enrich_result,
    format_timeticks,
    parse_communities,
    parse_targets,
    summarize_neighbors,
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


def test_discover_many_returns_error_row_when_worker_raises(monkeypatch):
    def broken_discover(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("snmp_discovery.discover_one", broken_discover)
    rows = discover_many(["192.0.2.1"], ["public"], do_ping=False)
    assert rows[0].snmp_status == "error"
    assert "boom" in rows[0].snmp_error
