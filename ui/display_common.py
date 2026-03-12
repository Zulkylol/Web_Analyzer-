from __future__ import annotations

from constants import SPACER


def display_report_rows(report: dict, table) -> None:
    """Affiche un report normalise dans un Treeview et memorise les commentaires bruts."""
    row_idx = 0
    table._row_comments = {}
    for row in report.get("rows", []):
        # Les tags de style se cumulent avec l'effet zebra.
        zebra_tag = "zebra_even" if row_idx % 2 == 0 else "zebra_odd"
        tags = (zebra_tag,) + tuple(row.get("tags", []))
        comment = str(row.get("comment", "") or "")
        # Le texte visible peut etre espace, le detail bas utilisera la valeur brute.
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
        # Le panneau de detail relit ce dictionnaire plutot que le contenu formate de la cellule.
        table._row_comments[item_id] = comment
        row_idx += 1
