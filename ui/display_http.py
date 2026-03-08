# ui/display_http.py

# ===============================================================
# IMPORTS
# ===============================================================
from constants import STATUS_ICON
from utils.url import ck


# ===============================================================
# FUNCTION : display_http()
# ===============================================================
def display_http(result, http_table):
    row_idx = 0

    def add_row(param, value="", check=STATUS_ICON["info"], comment="", risk=""):
        nonlocal row_idx
        zebra_tag = "zebra_even" if row_idx % 2 == 0 else "zebra_odd"
        http_table.insert("", "end", values=(param, value, check, risk, comment), tags=(zebra_tag,))
        row_idx += 1

    redirects = result.get("redirects") or {}
    mixed_urls = result.get("mixed_url") or []

    if result.get("comment"):
        add_row("Erreur HTTP", result.get("status_message", ""), STATUS_ICON["ok"], result.get("comment", ""), risk="-")
        return

    add_row(
        "Code de statut",
        str(result.get("status_code", "")),
        ck(result["status_ok"]),
        result.get("status_message", ""),
        risk=result.get("status_risk", "INFO"),
    )

    http_version = result.get("http_version") or ""
    if http_version:
        add_row(
            "Version HTTP",
            http_version,
            ck(result["http_ok"]),
            result["http_comment"],
            risk=result.get("http_version_risk", "MEDIUM"),
        )
    else:
        add_row(
            "Version HTTP",
            "Inconnue",
            STATUS_ICON["invalid"],
            "Impossible de determiner la version HTTP",
            risk="MEDIUM",
        )

    uses_https = bool(result.get("uses_https"))
    add_row(
        "HTTPS active",
        result.get("https_value", "Oui" if uses_https else "Non"),
        ck(result["uses_https"]),
        result.get("https_comment", ""),
        risk=result.get("https_risk", "MEDIUM"),
    )

    add_row("URL saisie", result.get("original_url", ""), STATUS_ICON["info"], "", risk="INFO")
    add_row(
        "URL finale",
        result.get("final_url", ""),
        ck(result["url_ok"]),
        result["url_comment"],
        risk=result.get("url_risk", "INFO"),
    )

    add_row(
        "Temps de reponse",
        result.get("time", 0.0),
        ck(result["time_ok"]),
        result["time_comment"],
        risk=result.get("time_risk", "INFO"),
    )

    if uses_https:
        mixed = bool(result.get("mixed_content"))
        mixed_level = str(result.get("mixed_content_level", "")).lower()
        mixed_risk = "HIGH" if mixed_level == "active" else "MEDIUM" if mixed else "INFO"
        add_row(
            "Contenu mixte",
            "Oui" if mixed else "Non",
            STATUS_ICON["warning"] if mixed else STATUS_ICON["ok"],
            result.get("mixed_comment", ""),
            risk=mixed_risk,
        )

        for i, item in enumerate(mixed_urls, start=1):
            try:
                url_m, origin = item
            except Exception:
                url_m, origin = str(item), ""
            add_row("URL mixte" if i == 1 else "", url_m, STATUS_ICON["warning"], origin, risk=mixed_risk or "MEDIUM")

    if result.get("header_findings"):
        for i, finding in enumerate(result["header_findings"], start=1):
            param = "Headers de securite" if i == 1 else ""
            header = finding["header"]
            icon = STATUS_ICON.get(finding["status"], STATUS_ICON["info"])
            comment = str(finding.get("issue", ""))
            add_row(param, header, icon, comment, risk=str(finding.get("severity", "")).upper())

            if finding.get("recommendation"):
                add_row("", "↳ Recommandation", STATUS_ICON["info"], finding["recommendation"], risk="INFO")

    num_redir = redirects.get("num_redirects", 0)
    redir_risk = str(redirects.get("risk", "Low")).upper()
    add_row(
        "Nombre de redirections",
        str(num_redir),
        ck(redirects.get("num_ok")),
        redirects.get("num_comment", ""),
        risk=redir_risk,
    )

    r_domains = redirects.get("redirect_domains") or []
    if r_domains:
        add_row("Domaines de redirection", r_domains[0], STATUS_ICON["info"], redirects.get("rd_comment", ""))
        for dom in r_domains[1:]:
            add_row("", dom, STATUS_ICON["info"], "")

    r_ips = redirects.get("redirect_ips") or []
    if r_ips:
        add_row("IPs de redirection", r_ips[0], STATUS_ICON["warning"], redirects.get("ri_comment", ""), risk="MEDIUM")
        for ip in r_ips[1:]:
            add_row("", ip, STATUS_ICON["warning"], "", risk="MEDIUM")

    r_chain = redirects.get("redirect_chain") or []
    if r_chain:
        for i, hop in enumerate(r_chain, start=1):
            hop_url = hop.get("url", "") if isinstance(hop, dict) else str(hop)
            hop_status = hop.get("status", "") if isinstance(hop, dict) else ""
            add_row("Chaine de redirections" if i == 1 else "", str(hop_status), STATUS_ICON["info"], hop_url)

    hop_findings = redirects.get("hop_findings") or []
    if hop_findings:
        for i, finding in enumerate(hop_findings, start=1):
            msg = finding.get("message") or finding.get("comment") or finding.get("issue") or str(finding)
            src = finding.get("from", "")
            dst = finding.get("to", "")
            detail = f"{src} -> {dst}" if src and dst else ""

            add_row("Analyse par hop" if i == 1 else "", "", STATUS_ICON["warning"], msg, risk="MEDIUM")
            if detail:
                add_row("", "", STATUS_ICON["info"], detail)

