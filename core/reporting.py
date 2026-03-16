# core/reporting.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations

from constants import RISK_ORDER, STATUS_ICON


# ===============================================================
# FUNCTION : normalize_risk
# ===============================================================
def normalize_risk(risk: str, default: str = "INFO") -> str:
    """
    Normalize risk levels to avoid inconsistent variants.

    Returns :
        str : normalized risk level
    """
    risk_text = str(risk or "").strip().upper()
    return risk_text if risk_text in RISK_ORDER else default


# ===============================================================
# FUNCTION : icon_for_risk
# ===============================================================
def icon_for_risk(risk: str, ok_when_info: bool = False) -> str:
    """
    Return the icon associated with a risk level.

    Returns :
        str : icon key
    """
    risk_u = normalize_risk(risk)
    if risk_u == "LOW":
        return STATUS_ICON["low"]
    if risk_u == "MEDIUM":
        return STATUS_ICON["medium"]
    if risk_u in {"HIGH", "CRITICAL"}:
        return STATUS_ICON["high"]
    return STATUS_ICON["ok"] if ok_when_info else STATUS_ICON["info"]


# ===============================================================
# FUNCTION : make_row
# ===============================================================
def make_row(
    param: str,
    value="",
    *,
    risk: str = "INFO",
    comment: str = "",
    ok_when_info: bool = False,
    check: str | None = None,
    tags: tuple[str, ...] = (),
    include_in_findings: bool = False,
) -> dict:
    """
    Build a standard report row shared by HTTP, TLS, and Cookies.

    Returns :
        dict : report row
    """
    normalized_risk = normalize_risk(risk)
    return {
        "param": param,
        "value": value,
        "check": check if check is not None else icon_for_risk(normalized_risk, ok_when_info=ok_when_info),
        "risk": normalized_risk,
        "comment": str(comment or ""),
        "tags": list(tags),
        "include_in_findings": include_in_findings,
    }


# ===============================================================
# FUNCTION : make_section_row
# ===============================================================
def make_section_row(title: str) -> dict:
    """
    Build a visual separator row between report sections.

    Returns :
        dict : section row
    """
    return {
        "param": title,
        "value": "",
        "check": "",
        "risk": "",
        "comment": "",
        "tags": ["section_header"],
        "include_in_findings": False,
        "is_section": True,
    }

# ===============================================================
# FUNCTION : _public_row
# ===============================================================
def _public_row(row: dict) -> dict:
    """
    Convert an internal row into its public report representation.

    Returns :
        dict : public row
    """
    tags = list(row.get("tags", []))
    if row.get("is_section"):
        return {
            "param": row.get("param", ""),
            "value": "",
            "check": "",
            "risk": "",
            "comment": "",
            "tags": tags,
        }
    if "recommendation" in tags:
        return {
            "param": row.get("param", ""),
            "value": row.get("value", ""),
            "check": row.get("check", ""),
            "risk": "",
            "comment": row.get("comment", ""),
            "tags": tags,
        }
    return {
        "param": row.get("param", ""),
        "value": row.get("value", ""),
        "check": row.get("check", ""),
        "risk": normalize_risk(row.get("risk", "INFO")),
        "comment": row.get("comment", ""),
        "tags": tags,
    }


# ===============================================================
# FUNCTION : compute_overall_risk
# ===============================================================
def compute_overall_risk(rows: list[dict]) -> str:
    """
    Return the highest risk level among report rows or findings.

    Returns :
        str : overall risk level
    """
    if not rows:
        return "INFO"
    return max((normalize_risk(row.get("risk", "INFO")) for row in rows), key=lambda risk: RISK_ORDER[risk])


# ===============================================================
# FUNCTION : build_report
# ===============================================================
def build_report(source: str, rows: list[dict], *, error_message: str = "") -> dict:
    """
    Build the final report structure consumed by the UI.

    Returns :
        dict : formatted report
    """
    public_rows = [_public_row(row) for row in rows]
    findings = [_public_row(row) for row in rows if row.get("include_in_findings")]
    # Les compteurs de synthese globale se basent uniquement sur les findings.
    high_findings = sum(1 for finding in findings if normalize_risk(finding.get("risk", "INFO")) in {"HIGH", "CRITICAL"})
    medium_findings = sum(1 for finding in findings if normalize_risk(finding.get("risk", "INFO")) == "MEDIUM")
    # Les lignes purement visuelles ou d'aide ne doivent pas gonfler artificiellement
    # le nombre de lignes "analysees".
    data_rows = [
        row
        for row in public_rows
        if "section_header" not in row.get("tags", []) and "recommendation" not in row.get("tags", [])
    ]

    return {
        "source": source,
        "rows": public_rows,
        "findings": findings,
        "summary": {
            "status": "error" if error_message else "ok",
            "total_rows": len(data_rows),
            "total_findings": len(findings),
            "high_findings": high_findings,
            "medium_findings": medium_findings,
            "risk": compute_overall_risk(findings) if findings else ("HIGH" if error_message else "INFO"),
        },
        "errors": {"message": error_message},
    }
