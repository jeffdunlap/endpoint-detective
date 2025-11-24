from __future__ import annotations

from typing import Iterable, List

from .models import EndpointReportRow


def render_table(rows: Iterable[EndpointReportRow]) -> str:
    rows_list: List[EndpointReportRow] = list(rows)
    headers = ["IP Address", "Hostname", "Protocols", "Endpoint Type"]
    data = [
        [row.ip_address, row.hostname, row.protocol_list(), row.endpoint_label()] for row in rows_list
    ]
    widths = _column_widths([headers, *data])
    lines = [
        _format_row(headers, widths),
        _format_divider(widths),
    ]
    for row in data:
        lines.append(_format_row(row, widths))
    return "\n".join(lines)


def _column_widths(rows: List[List[str]]) -> List[int]:
    return [max(len(str(row[i])) for row in rows) for i in range(len(rows[0]))]


def _format_row(columns: List[str], widths: List[int]) -> str:
    padded = [str(col).ljust(width) for col, width in zip(columns, widths)]
    return " | ".join(padded)


def _format_divider(widths: List[int]) -> str:
    parts = ["-" * width for width in widths]
    return "-+-".join(parts)
