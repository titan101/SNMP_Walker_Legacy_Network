from __future__ import annotations

import csv
import io

import pandas as pd

from .discovery import DiscoveryResult, EXPORT_COLUMNS, MIB_WALK_PLAN, topology_context_lines, topology_edges


MIB_PLAN_COLUMNS = ["mode", "operation", "mib", "name", "oid", "collects"]
WALK_STATUS_COLUMNS = ["ip", "hostname", "mode", "mib", "name", "oid", "operation", "rows", "status", "error"]
INTERFACE_COLUMNS = ["ip", "hostname", "if_index", "description", "alias", "admin_status", "oper_status", "speed_mbps"]
ENTITY_COLUMNS = ["ip", "hostname", "entity_index", "description", "model", "serial"]
NEIGHBOR_COLUMNS = [
    "ip",
    "hostname",
    "protocol",
    "local_port",
    "remote_device",
    "remote_port",
    "remote_platform",
    "link_type",
    "bandwidth_mbps",
    "table_index",
]
TOPOLOGY_COLUMNS = [
    "source",
    "source_ip",
    "source_port",
    "target",
    "target_port",
    "protocol",
    "remote_platform",
    "link_type",
    "bandwidth_mbps",
]
TOPOLOGY_CONTEXT_COLUMNS = ["line"]


def results_to_csv(results: list[DiscoveryResult], include_community: bool = False) -> bytes:
    buffer = io.StringIO(newline="")
    columns = export_columns(include_community)
    writer = csv.DictWriter(buffer, fieldnames=columns)
    writer.writeheader()
    for result in results:
        data = result.public_dict(include_community=include_community)
        writer.writerow({column: data.get(column, "") for column in columns})
    return buffer.getvalue().encode("utf-8-sig")


def results_to_xlsx(results: list[DiscoveryResult], include_community: bool = False) -> bytes:
    payload = io.BytesIO()
    with pd.ExcelWriter(payload, engine="openpyxl") as writer:
        write_sheet(
            writer,
            "Devices",
            [result.public_dict(include_community=include_community) for result in results],
            export_columns(include_community),
        )
        write_sheet(writer, "MIB Walk Plan", MIB_WALK_PLAN, MIB_PLAN_COLUMNS)
        write_sheet(writer, "Walk Status", flatten_detail_rows(results, "walk_errors"), WALK_STATUS_COLUMNS)
        write_sheet(writer, "Interfaces", flatten_detail_rows(results, "interface_rows"), INTERFACE_COLUMNS)
        write_sheet(writer, "Entities", flatten_detail_rows(results, "entity_rows"), ENTITY_COLUMNS)
        write_sheet(writer, "Neighbors", flatten_detail_rows(results, "neighbor_rows"), NEIGHBOR_COLUMNS)
        write_sheet(writer, "Topology", topology_edges(results), TOPOLOGY_COLUMNS)
        write_sheet(writer, "Topology Context", topology_context_lines(results), TOPOLOGY_CONTEXT_COLUMNS)

        for worksheet in writer.sheets.values():
            worksheet.freeze_panes = "A2"
            for column_cells in worksheet.columns:
                values = [str(cell.value or "") for cell in column_cells]
                width = min(max((len(value) for value in values), default=10) + 2, 48)
                worksheet.column_dimensions[column_cells[0].column_letter].width = width
    payload.seek(0)
    return payload.getvalue()


def export_columns(include_community: bool = False) -> list[str]:
    columns = list(EXPORT_COLUMNS) + ["snmp_status", "snmp_error"]
    if include_community:
        columns.append("matched_community")
    return columns


def flatten_detail_rows(results: list[DiscoveryResult], field_name: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for result in results:
        detail_rows = getattr(result, field_name)
        rows.extend(detail_rows)
    return rows


def write_sheet(writer: pd.ExcelWriter, sheet_name: str, rows: list[dict[str, str]], columns: list[str]) -> None:
    frame = pd.DataFrame(rows, columns=columns)
    frame.to_excel(writer, sheet_name=sheet_name, index=False)
