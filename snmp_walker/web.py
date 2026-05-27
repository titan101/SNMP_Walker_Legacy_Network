from __future__ import annotations

import io
import ipaddress
import json
import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime

from flask import Flask, render_template, request, send_file

from .config import ServerConfig
from .discovery import (
    BASE_OID_MAP,
    DEFAULT_SELECTED_OIDS,
    MIB_WALK_PLAN,
    DiscoveryResult,
    V3Credentials,
    discover_iter,
    discover_many,
    parse_communities,
    parse_targets,
    topology_context_lines,
    topology_edges,
)
from .exports import results_to_csv, results_to_xlsx


DISCOVERY_RESULT_FIELDS = {field.name for field in fields(DiscoveryResult)}
DISCOVERY_RESULT_LIST_FIELDS = {"entity_rows", "interface_rows", "neighbor_rows", "walk_errors"}

_log = logging.getLogger(__name__)
_SCAN_JOBS: dict[str, "ScanJob"] = {}
_SCAN_JOBS_LOCK = threading.Lock()
_SCAN_JOB_TTL_SECONDS = 60 * 60


@dataclass
class ScanJob:
    job_id: str
    targets_text: str
    communities_text: str
    settings: dict
    total: int
    started: float
    status: str = "running"
    error: str = ""
    elapsed: float | None = None
    results: list[DiscoveryResult] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


def create_app() -> Flask:
    app = Flask(__name__)
    _cfg = ServerConfig.from_env()
    _default_communities = _cfg.default_communities.replace(",", "\n") if _cfg.default_communities else "public\nprivate"

    @app.route("/", methods=["GET", "POST"])
    def index():
        targets_text = "192.168.1.1\n192.168.1.0/30"
        communities_text = _default_communities
        results: list[DiscoveryResult] = []
        error = ""
        elapsed = None
        settings = default_settings()

        if request.method == "POST":
            started = time.perf_counter()
            try:
                scan_request = build_scan_request(request.form)
                targets_text = scan_request["targets_text"]
                communities_text = scan_request["communities_text"]
                settings = scan_request["settings"]
                results = discover_many(
                    scan_request["targets"],
                    scan_request["communities"],
                    ping_timeout_ms=settings["ping_timeout_ms"],
                    snmp_timeout_seconds=settings["snmp_timeout_seconds"],
                    snmp_retries=settings["snmp_retries"],
                    workers=settings["workers"],
                    do_ping=settings["do_ping"],
                    walk_details=settings["walk_details"],
                    walk_traffic_tables=settings["walk_traffic_tables"],
                    selected_oids=settings["selected_oids"],
                    snmp_versions=settings["snmp_versions"],
                    v3_credentials=scan_request["v3_credentials"],
                )
                elapsed = round(time.perf_counter() - started, 2)
                snmp_ok = sum(1 for r in results if r.snmp_status == "ok")
                _log.info("Scan complete: %d targets snmp_ok=%d elapsed=%.1fs", len(scan_request["targets"]), snmp_ok, elapsed)
            except ValueError as exc:
                error = str(exc)

        return render_template(
            "index.html",
            targets=targets_text,
            communities=communities_text,
            results=results,
            results_json=serialize_results(results),
            error=error,
            elapsed=elapsed,
            settings=settings,
            summary=build_summary(results),
            diagnostics=build_diagnostics(results, settings),
            topology=build_topology_view(results),
            mib_walk_plan=MIB_WALK_PLAN,
        )

    @app.route("/api/scans", methods=["POST"])
    def start_scan():
        try:
            scan_request = build_scan_request(request.form)
        except ValueError as exc:
            return {"error": str(exc)}, 400

        cleanup_scan_jobs()
        job = ScanJob(
            job_id=uuid.uuid4().hex,
            targets_text=scan_request["targets_text"],
            communities_text=scan_request["communities_text"],
            settings=scan_request["settings"],
            total=len(scan_request["targets"]),
            started=time.perf_counter(),
        )
        with _SCAN_JOBS_LOCK:
            _SCAN_JOBS[job.job_id] = job

        thread = threading.Thread(
            target=run_scan_job,
            args=(job, scan_request),
            name=f"snmp-scan-{job.job_id[:8]}",
            daemon=True,
        )
        thread.start()
        return job_snapshot(job)

    @app.route("/api/scans/<job_id>")
    def scan_status(job_id: str):
        job = get_scan_job(job_id)
        if job is None:
            return {"error": "Scan job was not found or has expired."}, 404
        return job_snapshot(job)

    @app.route("/scan/<job_id>/results")
    def scan_results(job_id: str):
        job = get_scan_job(job_id)
        if job is None:
            return render_template(
                "index.html",
                targets="",
                communities=_default_communities,
                results=[],
                results_json="[]",
                error="Scan job was not found or has expired.",
                elapsed=None,
                settings=default_settings(),
                summary=build_summary([]),
                diagnostics=[],
                topology=build_topology_view([]),
                mib_walk_plan=MIB_WALK_PLAN,
            ), 404

        snapshot = job_snapshot(job)
        results = deserialize_results(snapshot["results_json"])
        return render_template(
            "index.html",
            targets=job.targets_text,
            communities=job.communities_text,
            results=results,
            results_json=snapshot["results_json"],
            error=job.error,
            elapsed=snapshot["elapsed"],
            settings=job.settings,
            summary=build_summary(results),
            diagnostics=build_diagnostics(results, job.settings),
            topology=build_topology_view(results),
            mib_walk_plan=MIB_WALK_PLAN,
        )

    @app.route("/download/<fmt>", methods=["POST"])
    def download(fmt: str):
        include_community = request.form.get("include_community") == "on"
        results = deserialize_results(request.form.get("results_json", "[]"))
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if fmt == "csv":
            payload = io.BytesIO(results_to_csv(results, include_community=include_community))
            return send_file(
                payload,
                mimetype="text/csv",
                as_attachment=True,
                download_name=f"snmp_discovery_{stamp}.csv",
            )

        if fmt == "xlsx":
            payload = io.BytesIO(results_to_xlsx(results, include_community=include_community))
            return send_file(
                payload,
                mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                as_attachment=True,
                download_name=f"snmp_discovery_{stamp}.xlsx",
            )

        return "Unsupported download format", 400

    @app.route("/health")
    def health():
        return {"status": "ok"}

    return app


def build_scan_request(form) -> dict:
    targets_text = form.get("targets", "")
    communities_text = form.get("communities", "")
    settings = read_settings(form)
    targets = parse_targets(targets_text, max_hosts=settings["max_hosts"])
    communities = parse_communities(communities_text)
    if not targets:
        raise ValueError("Add at least one IP, IP range, or subnet.")
    validate_selected_oids(settings["selected_oids"])

    v3_credentials = build_v3_credentials(settings)
    needs_community = any(version in {"v1", "v2c"} for version in settings["snmp_versions"])
    if needs_community and not communities:
        raise ValueError("Add at least one SNMP community string for v1/v2c scans.")
    if not communities and not v3_credentials:
        raise ValueError("Add a community string or SNMPv3 username.")

    return {
        "targets_text": targets_text,
        "communities_text": communities_text,
        "settings": settings,
        "targets": targets,
        "communities": communities,
        "v3_credentials": v3_credentials,
    }


def build_v3_credentials(settings: dict) -> list[V3Credentials] | None:
    if "v3" not in settings["snmp_versions"] or not settings["v3_username"]:
        return None
    return [
        V3Credentials(
            username=settings["v3_username"],
            auth_protocol=settings["v3_auth_protocol"],
            auth_key=settings["v3_auth_key"],
            priv_protocol=settings["v3_priv_protocol"],
            priv_key=settings["v3_priv_key"],
        )
    ]


def run_scan_job(job: ScanJob, scan_request: dict) -> None:
    settings = scan_request["settings"]
    try:
        for result in discover_iter(
            scan_request["targets"],
            scan_request["communities"],
            ping_timeout_ms=settings["ping_timeout_ms"],
            snmp_timeout_seconds=settings["snmp_timeout_seconds"],
            snmp_retries=settings["snmp_retries"],
            workers=settings["workers"],
            do_ping=settings["do_ping"],
            walk_details=settings["walk_details"],
            walk_traffic_tables=settings["walk_traffic_tables"],
            selected_oids=settings["selected_oids"],
            snmp_versions=settings["snmp_versions"],
            v3_credentials=scan_request["v3_credentials"],
        ):
            with job.lock:
                job.results.append(result)
        with job.lock:
            job.status = "done"
            job.elapsed = round(time.perf_counter() - job.started, 2)
        snmp_ok = sum(1 for result in sorted_results(job.results) if result.snmp_status == "ok")
        _log.info("Scan job %s complete: %d targets snmp_ok=%d elapsed=%.1fs", job.job_id, job.total, snmp_ok, job.elapsed or 0)
    except Exception as exc:  # pragma: no cover - defensive path around background thread
        _log.exception("Scan job %s crashed", job.job_id)
        with job.lock:
            job.status = "error"
            job.error = f"{type(exc).__name__}: {exc}"
            job.elapsed = round(time.perf_counter() - job.started, 2)


def get_scan_job(job_id: str) -> ScanJob | None:
    with _SCAN_JOBS_LOCK:
        return _SCAN_JOBS.get(job_id)


def cleanup_scan_jobs() -> None:
    now = time.perf_counter()
    with _SCAN_JOBS_LOCK:
        expired = [
            job_id
            for job_id, job in _SCAN_JOBS.items()
            if job.status != "running" and (job.elapsed is not None) and now - job.started > _SCAN_JOB_TTL_SECONDS
        ]
        for job_id in expired:
            _SCAN_JOBS.pop(job_id, None)


def job_snapshot(job: ScanJob) -> dict:
    with job.lock:
        results = sorted_results(job.results)
        elapsed = job.elapsed if job.elapsed is not None else round(time.perf_counter() - job.started, 1)
        return {
            "job_id": job.job_id,
            "status": job.status,
            "error": job.error,
            "total": job.total,
            "completed": len(results),
            "elapsed": elapsed,
            "results": [result.public_dict(include_community=False) for result in results],
            "results_json": serialize_results(results),
            "summary": build_summary(results),
            "diagnostics": build_diagnostics(results, job.settings),
        }


def sorted_results(results: list[DiscoveryResult]) -> list[DiscoveryResult]:
    return sorted(results, key=lambda item: ipaddress.ip_address(item.ip))


def default_settings() -> dict:
    return {
        "max_hosts": 4096,
        "workers": 24,
        "ping_timeout_ms": 800,
        "snmp_timeout_seconds": 1.2,
        "snmp_retries": 1,
        "do_ping": True,
        "walk_details": False,
        "walk_traffic_tables": False,
        "include_community": False,
        "selected_oids": list(DEFAULT_SELECTED_OIDS),
        "snmp_versions": ["v2c"],
        "v3_username": "",
        "v3_auth_protocol": "SHA",
        "v3_auth_key": "",
        "v3_priv_protocol": "AES",
        "v3_priv_key": "",
    }


def read_settings(form) -> dict:
    raw_versions = form.getlist("snmp_versions")
    snmp_versions = [v for v in raw_versions if v in ("v1", "v2c", "v3")]
    if not snmp_versions:
        snmp_versions = ["v2c"]
    return {
        "max_hosts": clamp_int(form.get("max_hosts"), 1, 65536, 4096),
        "workers": clamp_int(form.get("workers"), 1, 128, 24),
        "ping_timeout_ms": clamp_int(form.get("ping_timeout_ms"), 100, 10000, 800),
        "snmp_timeout_seconds": clamp_float(form.get("snmp_timeout_seconds"), 0.2, 20.0, 1.2),
        "snmp_retries": clamp_int(form.get("snmp_retries"), 0, 5, 1),
        "do_ping": form.get("do_ping") == "on",
        "walk_details": form.get("walk_details") == "on",
        "walk_traffic_tables": form.get("walk_traffic_tables") == "on",
        "include_community": form.get("include_community") == "on",
        "selected_oids": read_selected_oids(form),
        "snmp_versions": snmp_versions,
        "v3_username": form.get("v3_username", "").strip(),
        "v3_auth_protocol": form.get("v3_auth_protocol", "SHA"),
        "v3_auth_key": form.get("v3_auth_key", "").strip(),
        "v3_priv_protocol": form.get("v3_priv_protocol", "AES"),
        "v3_priv_key": form.get("v3_priv_key", "").strip(),
    }


def read_selected_oids(form) -> list[str]:
    if form.get("oid_selection_present") != "1":
        return list(DEFAULT_SELECTED_OIDS)
    known_oids = set(DEFAULT_SELECTED_OIDS)
    return [oid for oid in form.getlist("selected_oids") if oid in known_oids]


def validate_selected_oids(selected_oids: list[str]) -> None:
    if not any(oid in BASE_OID_MAP for oid in selected_oids):
        raise ValueError("Select at least one base GET OID so SNMP community probing can run.")


def clamp_int(value: str | None, minimum: int, maximum: int, default: int) -> int:
    try:
        number = int(value or default)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


def clamp_float(value: str | None, minimum: float, maximum: float, default: float) -> float:
    try:
        number = float(value or default)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


def build_summary(results: list[DiscoveryResult]) -> dict[str, int]:
    edges = topology_edges(results)
    return {
        "targets": len(results),
        "pingable": sum(1 for result in results if result.pingable_or_not == "yes"),
        "snmp_ok": sum(1 for result in results if result.snmp_status == "ok"),
        "models": sum(1 for result in results if result.device_model),
        "serials": sum(1 for result in results if result.serial_numbers),
        "neighbors": sum(1 for result in results if result.lldp_neighbors or result.cdp_neighbors),
        "topology_edges": len(edges),
    }


def build_diagnostics(results: list[DiscoveryResult], settings: dict) -> list[str]:
    if not results:
        return []

    messages: list[str] = []
    snmp_ok = sum(1 for result in results if result.snmp_status == "ok")
    pingable = sum(1 for result in results if result.pingable_or_not == "yes")
    failed = sum(1 for result in results if result.snmp_status == "failed")

    if snmp_ok == 0 and failed:
        messages.append(
            "No SNMP responders were found. Verify SNMP is enabled on the target devices, UDP/161 is reachable, and the v2c community string is correct."
        )
    if settings.get("do_ping") and pingable == 0:
        messages.append("No targets answered ICMP ping. Firewalls may block ping even when SNMP works.")
    selected_oids = set(settings.get("selected_oids", []))
    topology_oids = {item["oid"] for item in MIB_WALK_PLAN if item["mode"] == "topology"}
    if settings.get("walk_details") and snmp_ok and not selected_oids.intersection(topology_oids):
        messages.append("Topology OIDs are not selected, so no LLDP/CDP map can be drawn.")
    if settings.get("walk_details") and snmp_ok and not any(result.neighbor_rows for result in results):
        messages.append("No LLDP/CDP neighbor rows were found. Those MIBs may be disabled or hidden by the SNMP view.")
    return messages


def serialize_results(results: list[DiscoveryResult]) -> str:
    return json.dumps([asdict(result) for result in results])


def deserialize_results(raw: str) -> list[DiscoveryResult]:
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError:
        rows = []

    results: list[DiscoveryResult] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        clean_row = {}
        for key, value in row.items():
            if key not in DISCOVERY_RESULT_FIELDS:
                continue
            if key in DISCOVERY_RESULT_LIST_FIELDS:
                clean_row[key] = sanitize_detail_rows(value)
                continue
            clean_row[key] = "" if value is None else str(value)
        if not clean_row.get("ip"):
            continue
        results.append(DiscoveryResult(**clean_row))
    return results


def sanitize_detail_rows(value) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    rows: list[dict[str, str]] = []
    for row in value:
        if not isinstance(row, dict):
            continue
        rows.append({str(key): "" if cell is None else str(cell) for key, cell in row.items()})
    return rows


def build_topology_view(results: list[DiscoveryResult]) -> dict:
    edge_rows = topology_edges(results)
    if not edge_rows:
        return {"nodes": [], "edges": [], "width": 820, "height": 0}

    scanned_labels = sorted({result.hostname or result.ip for result in results})
    remote_labels = sorted({edge["target"] for edge in edge_rows if edge["target"] not in scanned_labels})
    node_positions: dict[str, dict] = {}
    row_gap = 72
    top_pad = 56
    left_x = 150
    right_x = 650
    height = max(len(scanned_labels), len(remote_labels), 1) * row_gap + 92

    for index, label in enumerate(scanned_labels):
        node_positions[label] = {
            "label": label,
            "display_label": short_label(label),
            "role": "scanned",
            "x": left_x,
            "y": top_pad + index * row_gap,
        }
    for index, label in enumerate(remote_labels):
        node_positions[label] = {
            "label": label,
            "display_label": short_label(label),
            "role": "neighbor",
            "x": right_x,
            "y": top_pad + index * row_gap,
        }

    positioned_edges = []
    for edge in edge_rows:
        source = node_positions.get(edge["source"])
        target = node_positions.get(edge["target"])
        if not source or not target:
            continue
        positioned_edges.append(
            {
                **edge,
                "x1": source["x"],
                "y1": source["y"],
                "x2": target["x"],
                "y2": target["y"],
                "label_x": (source["x"] + target["x"]) // 2,
                "label_y": (source["y"] + target["y"]) // 2 - 6,
                "display_label": topology_edge_label(edge),
            }
        )

    return {
        "nodes": sorted(node_positions.values(), key=lambda node: (node["x"], node["y"], node["label"])),
        "edges": positioned_edges,
        "context_lines": topology_context_lines(results),
        "width": 820,
        "height": height,
    }


def topology_edge_label(edge: dict) -> str:
    parts = [edge.get("protocol", "")]
    if edge.get("bandwidth_mbps"):
        parts.append(f"{edge['bandwidth_mbps']}M")
    if edge.get("link_type"):
        parts.append(edge["link_type"])
    return " / ".join(part for part in parts if part)


def short_label(value: str, limit: int = 24) -> str:
    return value if len(value) <= limit else f"{value[: limit - 1]}..."


app = create_app()
