import pytest

from snmp_discovery import (
    DiscoveryResult,
    enrich_result,
    parse_communities,
    parse_targets,
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
