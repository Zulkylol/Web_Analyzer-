from __future__ import annotations

from constants import STATUS_ICON

RISK_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def normalize_risk(risk: str, default: str = "INFO") -> str:
    """Normalise les niveaux de risque pour eviter les variantes incoherentes."""
    risk_text = str(risk or "").strip().upper()
    return risk_text if risk_text in RISK_ORDER else default


def icon_for_risk(risk: str, ok_when_info: bool = False) -> str:
    """Associe un niveau de risque a l'icone affichee dans les tableaux."""
    risk_u = normalize_risk(risk)
    if risk_u == "LOW":
        return STATUS_ICON["low"]
    if risk_u == "MEDIUM":
        return STATUS_ICON["medium"]
    if risk_u in {"HIGH", "CRITICAL"}:
        return STATUS_ICON["high"]
    return STATUS_ICON["ok"] if ok_when_info else STATUS_ICON["info"]


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
    """Construit une ligne standard du report commun partage par HTTP/TLS/Cookies."""
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


def make_section_row(title: str) -> dict:
    """Construit une ligne de separation visuelle entre sections d'un onglet."""
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


def _public_row(row: dict) -> dict:
    """Nettoie une ligne interne avant exposition dans le report final."""
    if row.get("is_section"):
        return {
            "param": row.get("param", ""),
            "value": "",
            "check": "",
            "risk": "",
            "comment": "",
            "tags": list(row.get("tags", [])),
        }
    return {
        "param": row.get("param", ""),
        "value": row.get("value", ""),
        "check": row.get("check", ""),
        "risk": normalize_risk(row.get("risk", "INFO")),
        "comment": row.get("comment", ""),
        "tags": list(row.get("tags", [])),
    }


def compute_overall_risk(rows: list[dict]) -> str:
    """Retourne le risque le plus eleve parmi une liste de lignes/findings."""
    if not rows:
        return "INFO"
    return max((normalize_risk(row.get("risk", "INFO")) for row in rows), key=lambda risk: RISK_ORDER[risk])


def build_report(source: str, rows: list[dict], *, error_message: str = "") -> dict:
    """Assemble la structure finale lue par l'UI et la synthese globale."""
    public_rows = [_public_row(row) for row in rows]
    findings = [_public_row(row) for row in rows if row.get("include_in_findings")]
    # Les compteurs de synthese globale se basent uniquement sur les findings.
    high_findings = sum(1 for finding in findings if normalize_risk(finding.get("risk", "INFO")) in {"HIGH", "CRITICAL"})
    medium_findings = sum(1 for finding in findings if normalize_risk(finding.get("risk", "INFO")) == "MEDIUM")
    # Les lignes de section ne doivent pas gonfler artificiellement le nombre de lignes "analysees".
    data_rows = [row for row in public_rows if "section_header" not in row.get("tags", [])]

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
