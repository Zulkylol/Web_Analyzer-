from __future__ import annotations

from constants import SPACER


def display_report_rows(report: dict, table) -> None:
    row_idx = 0
    table._row_comments = {}
    for row in report.get("rows", []):
        zebra_tag = "zebra_even" if row_idx % 2 == 0 else "zebra_odd"
        tags = (zebra_tag,) + tuple(row.get("tags", []))
        comment = str(row.get("comment", "") or "")
        comment_value = f"{SPACER}{comment}" if comment else ""
        item_id = table.insert(
            "",
            "end",
            values=(
                row.get("param", ""),
                row.get("value", ""),
                row.get("check", ""),
                row.get("risk", ""),
                comment_value,
            ),
            tags=tags,
        )
        table._row_comments[item_id] = comment
        row_idx += 1
