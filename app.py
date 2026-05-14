from __future__ import annotations

import io
import json
import threading
import time
import webbrowser
from dataclasses import asdict
from datetime import datetime

import pandas as pd
from flask import Flask, render_template, request, send_file

from snmp_discovery import (
    DiscoveryResult,
    discover_many,
    parse_communities,
    parse_targets,
    results_to_csv,
)


app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    targets_text = "192.168.1.1\n192.168.1.0/30"
    communities_text = "public\nprivate"
    results: list[DiscoveryResult] = []
    error = ""
    elapsed = None
    settings = {
        "max_hosts": 4096,
        "workers": 24,
        "ping_timeout_ms": 800,
        "snmp_timeout_seconds": 1.2,
        "snmp_retries": 1,
        "do_ping": True,
        "walk_details": True,
        "include_community": False,
    }

    if request.method == "POST":
        targets_text = request.form.get("targets", "")
        communities_text = request.form.get("communities", "")
        settings = read_settings(request.form)
        started = time.perf_counter()
        try:
            targets = parse_targets(targets_text, max_hosts=settings["max_hosts"])
            communities = parse_communities(communities_text)
            if not targets:
                raise ValueError("Add at least one IP, IP range, or subnet.")
            if not communities:
                raise ValueError("Add at least one SNMP community string.")
            results = discover_many(
                targets,
                communities,
                ping_timeout_ms=settings["ping_timeout_ms"],
                snmp_timeout_seconds=settings["snmp_timeout_seconds"],
                snmp_retries=settings["snmp_retries"],
                workers=settings["workers"],
                do_ping=settings["do_ping"],
                walk_details=settings["walk_details"],
            )
            elapsed = round(time.perf_counter() - started, 2)
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
        payload = io.BytesIO()
        rows = [result.public_dict(include_community=include_community) for result in results]
        columns = [
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
            "snmp_status",
            "snmp_error",
        ]
        if include_community:
            columns.append("matched_community")
        frame = pd.DataFrame(rows, columns=columns)
        with pd.ExcelWriter(payload, engine="openpyxl") as writer:
            frame.to_excel(writer, sheet_name="SNMP Discovery", index=False)
        payload.seek(0)
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


def read_settings(form) -> dict:
    return {
        "max_hosts": clamp_int(form.get("max_hosts"), 1, 65536, 4096),
        "workers": clamp_int(form.get("workers"), 1, 128, 24),
        "ping_timeout_ms": clamp_int(form.get("ping_timeout_ms"), 100, 10000, 800),
        "snmp_timeout_seconds": clamp_float(form.get("snmp_timeout_seconds"), 0.2, 20.0, 1.2),
        "snmp_retries": clamp_int(form.get("snmp_retries"), 0, 5, 1),
        "do_ping": form.get("do_ping") == "on",
        "walk_details": form.get("walk_details") == "on",
        "include_community": form.get("include_community") == "on",
    }


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
    return {
        "targets": len(results),
        "pingable": sum(1 for result in results if result.pingable_or_not == "yes"),
        "snmp_ok": sum(1 for result in results if result.snmp_status == "ok"),
        "models": sum(1 for result in results if result.device_model),
        "serials": sum(1 for result in results if result.serial_numbers),
        "neighbors": sum(1 for result in results if result.lldp_neighbors or result.cdp_neighbors),
    }


def serialize_results(results: list[DiscoveryResult]) -> str:
    return json.dumps([asdict(result) for result in results])


def deserialize_results(raw: str) -> list[DiscoveryResult]:
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError:
        rows = []
    return [DiscoveryResult(**row) for row in rows if isinstance(row, dict)]


def open_browser():
    time.sleep(1)
    webbrowser.open("http://127.0.0.1:5055")


if __name__ == "__main__":
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host="127.0.0.1", port=5055, debug=False)
