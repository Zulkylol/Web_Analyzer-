# ui/display_cookies.py

# ===============================================================
# IMPORTS
# ===============================================================
from constants import SPACER, STATUS_ICON
from utils.url import ck


# ===============================================================
# FUNCTION : display_cookies()
# ===============================================================
def display_cookies(result, cookies_table):
    def add_row(param, value="", check=STATUS_ICON["info"], comment=""):
        cookies_table.insert("", "end", values=(param, value, check, comment))

    def yn(flag):
        return "oui" if bool(flag) else "non"

    def icon_from_tri_state(status):
        return ck(status)

    if not result:
        add_row("Cookies", "-", STATUS_ICON["warning"], "Aucun resultat cookie disponible.")
        return

    if result.get("error"):
        add_row("Erreur cookies", "-", STATUS_ICON["high"], result["error"])
        return

    summary = result.get("summary") or {}
    findings = result.get("findings") or []
    cookies = result.get("cookies") or []

    add_row("URL finale", result.get("final_url", ""), STATUS_ICON["info"], summary.get("comment", ""))
    add_row("Nombre de cookies", str(summary.get("total_cookies", 0)), STATUS_ICON["info"], "")
    add_row("Nombre d'alertes", str(summary.get("total_findings", 0)), STATUS_ICON["info"], "")
    add_row(
        "Severite max",
        str(summary.get("max_severity", "info")).upper(),
        STATUS_ICON["info"],
        "Niveau de risque le plus eleve detecte.",
    )

    sev_counts = summary.get("severity_counts") or {}
    if sev_counts:
        detail = (
            f'critical={sev_counts.get("critical", 0)}, '
            f'high={sev_counts.get("high", 0)}, '
            f'medium={sev_counts.get("medium", 0)}, '
            f'low={sev_counts.get("low", 0)}, '
            f'info={sev_counts.get("info", 0)}'
        )
        add_row("Repartition", "", STATUS_ICON["info"], "Par severite: " + detail)

    status_icon = {
        "missing": STATUS_ICON["missing"],
        "invalid": STATUS_ICON["warning"],
        "warning": STATUS_ICON["warning"],
        "info": STATUS_ICON["info"],
    }
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
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
            icon = status_icon.get(str(finding.get("status", "warning")).lower(), STATUS_ICON["warning"])

            add_row(param, cookie_name, icon, f"{rule} ({sev}) : {issue}")
            if rec:
                add_row("", "↳ Recommandation", STATUS_ICON["info"], SPACER + rec)
    else:
        add_row("Findings cookies", "-", STATUS_ICON["ok"], "Aucun probleme de configuration cookie detecte.")

    if cookies:
        add_row("Detail cookie", "", STATUS_ICON["info"], "")
        for i, c in enumerate(cookies, start=1):
            name = c.get("name", "")
            samesite = (c.get("samesite") or "").strip().lower()
            samesite_txt = samesite.capitalize() if samesite else "non defini"
            domain_txt = c.get("domain") or "hote courant"
            path_txt = c.get("path") or "/"
            persistence_txt = "persistant" if bool(c.get("persistent")) else "session"
            size_txt = c.get("size", 0)
            source = c.get("from_url", "-")

            add_row(f"Cookie #{i}", name, STATUS_ICON["info"], "")
            add_row("", f"Secure: {yn(c.get('secure'))}", ck(bool(c.get("secure"))), "")
            add_row("", f"HttpOnly: {yn(c.get('httponly'))}", ck(bool(c.get("httponly"))), "")

            if not samesite:
                samesite_state = False
            elif samesite in {"lax", "strict", "none"}:
                samesite_state = True
            else:
                samesite_state = False
            add_row("", f"SameSite: {samesite_txt}", icon_from_tri_state(samesite_state), "")

            add_row("", f"Domaine: {domain_txt}", STATUS_ICON["info"], "")
            add_row("", f"Chemin: {path_txt}", STATUS_ICON["info"], "")
            add_row("", f"Type: {persistence_txt}", STATUS_ICON["info"], "")
            add_row("", f"Taille: {size_txt} octets", STATUS_ICON["info"], "")
            add_row("", f"Source: {source}", STATUS_ICON["info"], "")
