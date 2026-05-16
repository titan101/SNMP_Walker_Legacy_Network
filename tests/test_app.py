from snmp_discovery import DiscoveryResult
from snmp_walker.web import app


def test_index_get_loads():
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b"SNMP Discovery" in response.data


def test_index_post_runs_fast_identity_scan_by_default(monkeypatch):
    captured = {}

    def fake_discover_many(targets, communities, **kwargs):
        captured["targets"] = targets
        captured["communities"] = communities
        captured["kwargs"] = kwargs
        return [
            DiscoveryResult(
                ip="192.0.2.1",
                pingable_or_not="yes",
                hostname="legacy-rtr",
                device_model="ASR9000",
                device_type="router",
                software_version="7.5.2",
                snmp_status="ok",
            )
        ]

    monkeypatch.setattr("snmp_walker.web.discover_many", fake_discover_many)
    client = app.test_client()
    response = client.post(
        "/",
        data={
            "targets": "192.0.2.1",
            "communities": "public",
            "max_hosts": "10",
            "workers": "1",
            "ping_timeout_ms": "200",
            "snmp_timeout_seconds": "0.3",
            "snmp_retries": "0",
            "do_ping": "on",
        },
    )
    assert response.status_code == 200
    assert b"legacy-rtr" in response.data
    assert captured["targets"] == ["192.0.2.1"]
    assert captured["communities"] == ["public"]
    assert captured["kwargs"]["walk_details"] is False
    assert captured["kwargs"]["walk_traffic_tables"] is False


def test_download_csv_from_result_payload():
    client = app.test_client()
    response = client.post(
        "/download/csv",
        data={
            "results_json": '[{"ip":"192.0.2.1","hostname":"r1","snmp_status":"ok"}]',
        },
    )
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("text/csv")
    assert b"192.0.2.1" in response.data
