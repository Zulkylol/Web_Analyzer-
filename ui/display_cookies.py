# ui/display_cookies.py

# ===============================================================
# IMPORTS
# ===============================================================
from constants import STATUS_ICON


# ===============================================================
# FUNCTION : display_cookies()
# ===============================================================
def display_cookies(result, cookies_table):
    row_idx = 0
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def add_row(param, value="", check=STATUS_ICON["info"], comment="", risk="", extra_tags=()):
        nonlocal row_idx
        zebra_tag = "zebra_even" if row_idx % 2 == 0 else "zebra_odd"
        tags = (zebra_tag,) + tuple(extra_tags)
        risk_value = str(risk or "").upper()
        cookies_table.insert("", "end", values=(param, value, check, risk_value, comment), tags=tags)
        row_idx += 1

    def yn(flag):
        return "oui" if bool(flag) else "non"

    def normalize_risk(risk):
        risk_l = str(risk or "info").lower()
        return risk_l if risk_l in sev_rank else "info"

    def icon_from_risk(risk, ok_when_info=False):
        risk_l = normalize_risk(risk)
        if risk_l == "low":
            return STATUS_ICON["low"]
        if risk_l == "medium":
            return STATUS_ICON["medium"]
        if risk_l in {"critical", "high"}:
            return STATUS_ICON["high"]
        return STATUS_ICON["ok"] if ok_when_info else STATUS_ICON["info"]

    def cookie_count_risk(total_cookies, sensitive_cookies):
        if total_cookies <= 10:
            return "info"
        if total_cookies <= 20:
            return "low"
        if total_cookies <= 40:
            return "medium" if sensitive_cookies >= 3 else "low"
        return "high" if sensitive_cookies >= 5 else "medium"

    if not result:
        add_row("Cookies", "-", STATUS_ICON["warning"], "Aucun resultat cookie disponible.")
        return

    if result.get("error"):
        add_row("Erreur cookies", "-", STATUS_ICON["high"], result["error"])
        return

    summary = result.get("summary") or {}
    findings = result.get("findings") or []
    cookies = result.get("cookies") or []
    total_cookies = int(summary.get("total_cookies", 0) or 0)
    sensitive_cookies = int(summary.get("sensitive_cookies", 0) or 0)
    cookie_count_risk_value = cookie_count_risk(total_cookies, sensitive_cookies)
    max_severity = normalize_risk(summary.get("max_severity", "info"))

    add_row(
        "URL finale",
        result.get("final_url", ""),
        STATUS_ICON["info"],
        summary.get("comment", ""),
        risk="INFO",
    )
    add_row(
        "Nombre de cookies",
        str(total_cookies),
        icon_from_risk(cookie_count_risk_value),
        f"Cookies sensibles detectes: {sensitive_cookies}.",
        risk=cookie_count_risk_value,
    )
    add_row(
        "Nombre d'alertes",
        str(summary.get("total_findings", 0)),
        STATUS_ICON["info"],
        "",
        risk="INFO",
    )
    add_row(
        "Severite max",
        max_severity.upper(),
        icon_from_risk(max_severity),
        "Niveau de risque le plus eleve detecte.",
        risk=max_severity,
    )

    findings_sorted = sorted(
        findings,
        key=lambda f: sev_rank.get(str(f.get("severity", "info")).lower(), -1),
        reverse=True,
    )

    if findings_sorted:
        for idx, finding in enumerate(findings_sorted, start=1):
            param = "Findings cookies" if idx == 1 else ""
            cookie_name = finding.get("cookie", "-")
            sev = str(finding.get("severity", "info")).upper()
            rule = finding.get("id", "")
            issue = finding.get("issue", "")
            rec = finding.get("recommendation", "")
            icon = icon_from_risk(sev)

            add_row(param, cookie_name, icon, f"{rule} ({sev}) : {issue}", risk=sev)
            if rec:
                add_row("", "↳ Recommandation", STATUS_ICON["info"], rec, risk="INFO")
    else:
        add_row("Findings cookies", "-", STATUS_ICON["ok"], "Aucun probleme de configuration cookie detecte.")

    if cookies:
        add_row("Detail cookie", "", STATUS_ICON["info"], "")
        for i, c in enumerate(cookies, start=1):
            name = c.get("name", "")
            assessments = c.get("assessments") or {}
            samesite = (c.get("samesite") or "").strip().lower()
            samesite_txt = samesite.capitalize() if samesite else "non defini"
            domain_txt = c.get("domain") or "hote courant"
            path_txt = c.get("path") or "/"
            persistence_txt = "persistant" if bool(c.get("persistent")) else "session"
            size_txt = c.get("size", 0)
            source = c.get("from_url", "-")

            add_row(
                "Cookie name",
                name,
                icon_from_risk(assessments.get("name", {}).get("risk", "INFO")),
                "",
                risk=assessments.get("name", {}).get("risk", "INFO"),
                extra_tags=("cookie_name",),
            )
            secure_risk = assessments.get("secure", {}).get("risk", "INFO")
            add_row(
                "Secure",
                yn(c.get("secure")),
                icon_from_risk(secure_risk, ok_when_info=bool(c.get("secure"))),
                assessments.get("secure", {}).get("comment", ""),
                risk=secure_risk,
            )
            httponly_risk = assessments.get("httponly", {}).get("risk", "INFO")
            add_row(
                "HttpOnly",
                yn(c.get("httponly")),
                icon_from_risk(httponly_risk, ok_when_info=bool(c.get("httponly"))),
                assessments.get("httponly", {}).get("comment", ""),
                risk=httponly_risk,
            )

            samesite_risk = assessments.get("samesite", {}).get("risk", "INFO")
            add_row(
                "SameSite",
                samesite_txt,
                icon_from_risk(samesite_risk, ok_when_info=bool(samesite and samesite in {"lax", "strict", "none"})),
                assessments.get("samesite", {}).get("comment", ""),
                risk=samesite_risk,
            )

            domain_risk = assessments.get("domain", {}).get("risk", "INFO")
            add_row(
                "Domain",
                domain_txt,
                icon_from_risk(domain_risk),
                assessments.get("domain", {}).get("comment", ""),
                risk=domain_risk,
            )
            path_risk = assessments.get("path", {}).get("risk", "INFO")
            add_row(
                "Path",
                path_txt,
                icon_from_risk(path_risk),
                assessments.get("path", {}).get("comment", ""),
                risk=path_risk,
            )
            type_risk = assessments.get("type", {}).get("risk", "INFO")
            add_row(
                "Type",
                persistence_txt,
                icon_from_risk(type_risk),
                assessments.get("type", {}).get("comment", ""),
                risk=type_risk,
            )
            size_risk = assessments.get("size", {}).get("risk", "INFO")
            add_row(
                "Size",
                f"{size_txt} octets",
                icon_from_risk(size_risk),
                assessments.get("size", {}).get("comment", ""),
                risk=size_risk,
            )
            add_row(
                "Source",
                source,
                STATUS_ICON["info"],
                assessments.get("source", {}).get("comment", ""),
                risk=assessments.get("source", {}).get("risk", "INFO"),
            )

