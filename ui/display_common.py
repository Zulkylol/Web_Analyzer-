# ui/display_common.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations

from constants import SPACER


# ===============================================================
# FUNCTION : display_report_rows
# ===============================================================
def display_report_rows(report: dict, table) -> None:
    """
    Display a normalized report in a Treeview and store raw comments.

    Returns :
        None : no return
    """
    row_idx = 0
    table._row_comments = {}
    for row in report.get("rows", []):
        # Style tags are combined with the zebra striping effect.
        zebra_tag = "zebra_even" if row_idx % 2 == 0 else "zebra_odd"
        row_tags = tuple(row.get("tags", []))
        tags = row_tags if "section_header" in row_tags else (zebra_tag,) + row_tags
        comment = str(row.get("comment", "") or "")
        # Visible text may be padded; the bottom detail panel uses the raw value.
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
        # The detail panel reads from this dictionary instead of the formatted cell content.
        table._row_comments[item_id] = comment
        row_idx += 1
