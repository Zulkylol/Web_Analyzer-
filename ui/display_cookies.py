from __future__ import annotations

from ui.display_common import display_report_rows


def display_cookies(result: dict, cookies_table) -> None:
    display_report_rows(result.get("report", {}), cookies_table)
