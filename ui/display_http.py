from __future__ import annotations

from ui.display_common import display_report_rows


def display_http(result: dict, http_table) -> None:
    display_report_rows(result.get("report", {}), http_table)
