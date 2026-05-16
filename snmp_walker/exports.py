from __future__ import annotations

import csv
import io

import pandas as pd

from .discovery import DiscoveryResult, EXPORT_COLUMNS


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
    rows = [result.public_dict(include_community=include_community) for result in results]
    frame = pd.DataFrame(rows, columns=export_columns(include_community))
    with pd.ExcelWriter(payload, engine="openpyxl") as writer:
        frame.to_excel(writer, sheet_name="SNMP Discovery", index=False)
    payload.seek(0)
    return payload.getvalue()


def export_columns(include_community: bool = False) -> list[str]:
    columns = list(EXPORT_COLUMNS) + ["snmp_status", "snmp_error"]
    if include_community:
        columns.append("matched_community")
    return columns
