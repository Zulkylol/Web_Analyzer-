from __future__ import annotations

from ui.display_common import display_report_rows


def display_ssl_tls(result: dict, ssl_table) -> None:
    display_report_rows(result.get("report", {}), ssl_table)
