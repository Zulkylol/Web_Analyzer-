from __future__ import annotations

from datetime import datetime
from html import escape


# ===============================================================
# FUNCTION : _as_text
# ===============================================================
def _as_text(value) -> str:
    """
    Convert a value into printable text.

    Returns :
        str : printable text
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Oui" if value else "Non"
    return str(value)


# ===============================================================
# FUNCTION : export_pdf_report
# ===============================================================
def export_pdf_report(scan_results: dict, filepath: str) -> None:
    """
    Export the current scan results into a minimal styled PDF.

    Returns :
        None : no return
    """
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    title_style.fontName, title_style.fontSize, title_style.leading = "Helvetica-Bold", 22, 26
    title_style.textColor = colors.HexColor("#0f172a")

    heading_style = styles["Heading2"]
    heading_style.fontName, heading_style.fontSize, heading_style.leading = "Helvetica-Bold", 13, 16
    heading_style.textColor = colors.HexColor("#1d2939")
    heading_style.spaceBefore, heading_style.spaceAfter = 8, 6

    meta_style = ParagraphStyle("PdfMeta", parent=styles["BodyText"], fontName="Helvetica", fontSize=9, leading=12, textColor=colors.HexColor("#475467"))
    cell_style = ParagraphStyle("PdfCell", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.5, leading=10.5, textColor=colors.HexColor("#101828"))
    center_style = ParagraphStyle("PdfCenter", parent=cell_style, alignment=1)
    section_style = ParagraphStyle("PdfSection", parent=cell_style, fontName="Helvetica-Bold", textColor=colors.white)
    recommendation_style = ParagraphStyle("PdfRecommendation", parent=cell_style, fontName="Helvetica-Oblique", textColor=colors.HexColor("#667085"))

    total_rows = total_alerts = high_alerts = medium_alerts = 0
    analyzed_url = "-"
    for result in scan_results.values():
        report = (result or {}).get("report", {})
        summary = report.get("summary", {})
        total_rows += int(summary.get("total_rows", 0) or 0)
        total_alerts += int(summary.get("total_findings", 0) or 0)
        high_alerts += int(summary.get("high_findings", 0) or 0)
        medium_alerts += int(summary.get("medium_findings", 0) or 0)
        if analyzed_url == "-":
            target = (result or {}).get("target", {}) or {}
            analyzed_url = (
                str(target.get("original_url", "") or "")
                or str(target.get("final_url", "") or "")
                or str((result or {}).get("final_url", "") or "")
                or "-"
            )

    overall_risk = "ELEVE" if high_alerts > 0 else "MODERE" if medium_alerts >= 2 else "FAIBLE"

    story = [
        Paragraph("Web Analyzer", title_style),
        Paragraph(
            f"Rapport généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')}<br/>URL analysée : {escape(analyzed_url)}",
            meta_style,
        ),
        Spacer(1, 8),
        Table(
            [["Lignes analysées", "Alertes totales", "Alertes critiques", "Risque global"],
             [str(total_rows), str(total_alerts), str(high_alerts), overall_risk]],
            colWidths=[48 * mm, 48 * mm, 48 * mm, 48 * mm],
            style=TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d7dee8")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]),
        ),
        Spacer(1, 12),
    ]

    risk_colors = {
        "LOW": colors.HexColor("#9a6700"),
        "MEDIUM": colors.HexColor("#b54708"),
        "HIGH": colors.HexColor("#b42318"),
        "CRITICAL": colors.HexColor("#7a271a"),
    }
    status_labels = {"INFO": "OK", "LOW": "Vigil.", "MEDIUM": "Alerte", "HIGH": "KO", "CRITICAL": "KO"}

    for key, title in [("HTTP", "HTTP"), ("SSL/TLS", "TLS"), ("Cookies", "Cookies")]:
        report = ((scan_results.get(key) or {}).get("report") or {})
        rows = report.get("rows", []) or []
        if not rows:
            continue

        story.append(Paragraph(title, heading_style))
        data = [[
            Paragraph("Paramètre", section_style),
            Paragraph("Valeur", section_style),
            Paragraph("État", section_style),
            Paragraph("Risque", section_style),
            Paragraph("Commentaire", section_style),
        ]]
        table_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d7dee8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]

        body_index = 0
        for row in rows:
            tags = set(row.get("tags", []) or [])
            row_index = len(data)

            if "section_header" in tags:
                data.append([Paragraph(escape(_as_text(row.get("param", ""))), section_style), "", "", "", ""])
                table_style.extend([
                    ("SPAN", (0, row_index), (4, row_index)),
                    ("BACKGROUND", (0, row_index), (4, row_index), colors.HexColor("#6c757d")),
                ])
                continue

            risk = str(row.get("risk", "") or "").upper()
            comment_style = recommendation_style if "recommendation" in tags else cell_style
            data.append([
                Paragraph(escape(_as_text(row.get("param", ""))) or "&nbsp;", cell_style),
                Paragraph(escape(_as_text(row.get("value", ""))) or "&nbsp;", cell_style),
                Paragraph(escape(status_labels.get(risk, "")) or "&nbsp;", center_style),
                Paragraph(escape(risk) or "&nbsp;", center_style),
                Paragraph(escape(_as_text(row.get("comment", ""))) or "&nbsp;", comment_style),
            ])
            table_style.append(("BACKGROUND", (0, row_index), (-1, row_index), colors.HexColor("#ffffff" if body_index % 2 == 0 else "#f7f9fc")))
            body_index += 1
            if risk in risk_colors:
                table_style.append(("TEXTCOLOR", (3, row_index), (3, row_index), risk_colors[risk]))
            if "recommendation" in tags:
                table_style.append(("TEXTCOLOR", (4, row_index), (4, row_index), colors.HexColor("#667085")))

        story.append(Table(data, colWidths=[36 * mm, 46 * mm, 18 * mm, 18 * mm, 129 * mm], repeatRows=1, style=TableStyle(table_style)))
        story.append(Spacer(1, 10))

    doc = SimpleDocTemplate(
        filepath,
        pagesize=landscape(A4),
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title="Web Analyzer Report",
        author="Web Analyzer",
    )
    doc.build(story)
