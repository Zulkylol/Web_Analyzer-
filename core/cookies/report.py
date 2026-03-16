from __future__ import annotations

from constants import STATUS_ICON
from core.reporting import build_report, make_row, make_section_row


# ===============================================================
# FUNCTION : build_cookies_report
# ===============================================================
def build_cookies_report(result: dict) -> dict:
    """Transforme le resultat cookies brut en lignes ordonnees pour l'UI."""
    rows: list[dict] = []
    summary = result.get("summary") or {}
    findings = result.get("findings") or []
    cookies = result.get("cookies") or []
    total_cookies = int(summary.get("total_cookies", 0) or 0)
    sensitive_cookies = int(summary.get("sensitive_cookies", 0) or 0)
    error_message = str(result.get("error", "") or "")

    # ===============================================================
    # FUNCTION : add_row
    # ===============================================================
    def add_row(param, value="", *, risk="INFO", comment="", ok_when_info=False, check=None, tags=(), include=False):
        """
        Append a report row.

        Returns :
            None : no return
        """
        rows.append(
            make_row(
                param,
                value,
                risk=risk,
                comment=comment,
                ok_when_info=ok_when_info,
                check=check,
                tags=tags,
                include_in_findings=include,
            )
        )

    # ===============================================================
    # FUNCTION : add_section
    # ===============================================================
    def add_section(title: str):
        """
        Append a section row.

        Returns :
            None : no return
        """
        rows.append(make_section_row(title))

    if error_message:
        add_row("Erreur cookies", "-", risk="HIGH", comment=error_message, check=STATUS_ICON["high"], include=True)
        return build_report("Cookies", rows, error_message=error_message)

    # Section 1: vue d'ensemble des cookies observes sur la reponse finale.
    add_section("Synthese")
    add_row("URL finale", result.get("final_url", ""), comment=summary.get("comment", ""))
    cookie_count_risk = str(summary.get("cookie_count_risk", "INFO")).upper()
    add_row(
        "Nombre de cookies",
        str(total_cookies),
        risk=cookie_count_risk,
        comment=f"Cookies sensibles detectes: {sensitive_cookies}",
        include=cookie_count_risk != "INFO",
    )
    add_row("Nombre d'alertes", str(summary.get("total_findings", 0)))

    max_severity = str(summary.get("max_severity", "info")).upper()
    add_row(
        "Severite max",
        max_severity,
        risk=max_severity,
        comment="Niveau de risque le plus eleve detecte",
    )

    # Section 2: findings consolides, tries par severite.
    add_section("Alertes")
    if findings:
        for index, finding in enumerate(findings, start=1):
            severity = str(finding.get("severity", "INFO")).upper()
            add_row(
                f"Alerte cookie #{index}",
                finding.get("cookie", "-"),
                risk=severity,
                comment=str(finding.get("issue", "")),
                include=severity != "INFO",
            )
            if finding.get("recommendation"):
                add_row("", "", comment="âž© Recommandation: "+finding["recommendation"], check="", tags=("recommendation",))
    else:
        add_row("Findings cookies", "-", risk="INFO", comment="Aucun probleme de configuration cookie detecte", check=STATUS_ICON["ok"])

    if cookies:
        # Section 3: detail attribut par attribut pour chaque cookie recu.
        add_section("Details des cookies")
        for index, cookie in enumerate(cookies, start=1):
            assessments = cookie.get("assessments") or {}
            samesite = (cookie.get("samesite") or "").strip().lower()
            samesite_text = samesite.capitalize() if samesite else "non defini"
            domain_text = cookie.get("domain") or "hote courant"
            path_text = cookie.get("path") or "/"
            persistence_text = "persistant" if bool(cookie.get("persistent")) else "session"
            size_text = cookie.get("size", 0)
            source = cookie.get("from_url", "-")

            add_row(
                f"Cookie #{index}",
                cookie.get("name", ""),
                risk=assessments.get("name", {}).get("risk", "INFO"),
                tags=("cookie_name",),
            )
            secure_risk = assessments.get("secure", {}).get("risk", "INFO")
            add_row(
                "Secure",
                "oui" if bool(cookie.get("secure")) else "non",
                risk=secure_risk,
                comment=assessments.get("secure", {}).get("comment", ""),
                ok_when_info=bool(cookie.get("secure")),
            )
            httponly_risk = assessments.get("httponly", {}).get("risk", "INFO")
            add_row(
                "HttpOnly",
                "oui" if bool(cookie.get("httponly")) else "non",
                risk=httponly_risk,
                comment=assessments.get("httponly", {}).get("comment", ""),
                ok_when_info=bool(cookie.get("httponly")),
            )
            samesite_risk = assessments.get("samesite", {}).get("risk", "INFO")
            add_row(
                "SameSite",
                samesite_text,
                risk=samesite_risk,
                comment=assessments.get("samesite", {}).get("comment", ""),
                ok_when_info=bool(samesite and samesite in {"lax", "strict", "none"}),
            )
            domain_risk = assessments.get("domain", {}).get("risk", "INFO")
            add_row(
                "Domain",
                domain_text,
                risk=domain_risk,
                comment=assessments.get("domain", {}).get("comment", ""),
            )
            path_risk = assessments.get("path", {}).get("risk", "INFO")
            add_row(
                "Path",
                path_text,
                risk=path_risk,
                comment=assessments.get("path", {}).get("comment", ""),
            )
            type_risk = assessments.get("type", {}).get("risk", "INFO")
            add_row(
                "Type",
                persistence_text,
                risk=type_risk,
                comment=assessments.get("type", {}).get("comment", ""),
            )
            size_risk = assessments.get("size", {}).get("risk", "INFO")
            add_row(
                "Size",
                f"{size_text} octets",
                risk=size_risk,
                comment=assessments.get("size", {}).get("comment", ""),
            )
            add_row(
                "Source",
                source,
                risk=assessments.get("source", {}).get("risk", "INFO"),
                comment=assessments.get("source", {}).get("comment", ""),
                check=STATUS_ICON["info"],
            )

    return build_report("Cookies", rows, error_message=error_message)
