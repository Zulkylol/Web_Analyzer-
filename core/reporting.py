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
    risk_text = str(risk or "").strip().upper()
    return risk_text if risk_text in RISK_ORDER else default


def icon_for_risk(risk: str, ok_when_info: bool = False) -> str:
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


def _public_row(row: dict) -> dict:
    return {
        "param": row.get("param", ""),
        "value": row.get("value", ""),
        "check": row.get("check", ""),
        "risk": normalize_risk(row.get("risk", "INFO")),
        "comment": row.get("comment", ""),
        "tags": list(row.get("tags", [])),
    }


def compute_overall_risk(rows: list[dict]) -> str:
    if not rows:
        return "INFO"
    return max((normalize_risk(row.get("risk", "INFO")) for row in rows), key=lambda risk: RISK_ORDER[risk])


def build_report(source: str, rows: list[dict], *, error_message: str = "") -> dict:
    public_rows = [_public_row(row) for row in rows]
    findings = [_public_row(row) for row in rows if row.get("include_in_findings")]
    high_findings = sum(1 for finding in findings if normalize_risk(finding.get("risk", "INFO")) in {"HIGH", "CRITICAL"})
    medium_findings = sum(1 for finding in findings if normalize_risk(finding.get("risk", "INFO")) == "MEDIUM")

    return {
        "source": source,
        "rows": public_rows,
        "findings": findings,
        "summary": {
            "status": "error" if error_message else "ok",
            "total_rows": len(public_rows),
            "total_findings": len(findings),
            "high_findings": high_findings,
            "medium_findings": medium_findings,
            "risk": compute_overall_risk(findings) if findings else ("HIGH" if error_message else "INFO"),
        },
        "errors": {"message": error_message},
    }
