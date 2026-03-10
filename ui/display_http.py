# ui/display_http.py

# ===============================================================
# IMPORTS
# ===============================================================
from urllib.parse import urljoin

from constants import STATUS_ICON
from utils.url import icon_for_risk


# ===============================================================
# FUNCTION : display_http()
# ===============================================================
def display_http(result, http_table):
    row_idx = 0

    def add_row(param, value="", check=STATUS_ICON["info"], comment="", risk=""):
        nonlocal row_idx
        zebra_tag = "zebra_even" if row_idx % 2 == 0 else "zebra_odd"
        risk_value = str(risk or "").upper()
        http_table.insert("", "end", values=(param, value, check, risk_value, comment), tags=(zebra_tag,))
        row_idx += 1

    redirects = result.get("redirects") or {}
    mixed_urls = result.get("mixed_url") or []

    if result.get("comment"):
        add_row("Erreur HTTP", result.get("status_message", ""), STATUS_ICON["ok"], result.get("comment", ""), risk="-")
        return

    add_row(
        "Code de statut",
        str(result.get("status_code", "")),
        icon_for_risk(result.get("status_risk", "INFO"), ok_when_info=bool(result.get("status_ok"))),
        result.get("status_message", ""),
        risk=result.get("status_risk", "INFO"),
    )

    http_version = result.get("http_version") or ""
    if http_version:
        add_row(
            "Version HTTP",
            http_version,
            icon_for_risk(result.get("http_version_risk", "MEDIUM"), ok_when_info=bool(result.get("http_ok"))),
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
        icon_for_risk(result.get("https_risk", "MEDIUM"), ok_when_info=bool(result.get("uses_https"))),
        result.get("https_comment", ""),
        risk=result.get("https_risk", "MEDIUM"),
    )

    add_row("URL saisie", result.get("original_url", ""), STATUS_ICON["info"], "", risk="INFO")
    add_row(
        "URL finale",
        result.get("final_url", ""),
        icon_for_risk(result.get("url_risk", "INFO"), ok_when_info=bool(result.get("url_ok"))),
        result["url_comment"],
        risk=result.get("url_risk", "INFO"),
    )

    add_row(
        "Temps de reponse",
        result.get("time", 0.0),
        icon_for_risk(result.get("time_risk", "INFO"), ok_when_info=bool(result.get("time_ok"))),
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
            icon_for_risk(mixed_risk, ok_when_info=not mixed),
            result.get("mixed_comment", ""),
            risk=mixed_risk,
        )

        for i, item in enumerate(mixed_urls, start=1):
            try:
                url_m, origin = item
            except Exception:
                url_m, origin = str(item), ""
            add_row("URL mixte" if i == 1 else "", url_m, icon_for_risk(mixed_risk or "MEDIUM"), origin, risk=mixed_risk or "MEDIUM")

    if result.get("header_findings"):
        for i, finding in enumerate(result["header_findings"], start=1):
            param = "Headers de securite" if i == 1 else ""
            header = finding["header"]
            icon = icon_for_risk(str(finding.get("severity", "")).upper())
            comment = str(finding.get("issue", ""))
            add_row(param, header, icon, comment, risk=str(finding.get("severity", "")).upper())

            if finding.get("recommendation"):
                add_row("", "↳ Recommandation", STATUS_ICON["info"], finding["recommendation"], risk="INFO")

    num_redir = redirects.get("num_redirects", 0)
    redir_risk = str(redirects.get("risk", "Low")).upper()
    add_row(
        "Nombre de redirections",
        str(num_redir),
        icon_for_risk(redir_risk, ok_when_info=bool(redirects.get("num_ok"))),
        redirects.get("num_comment", ""),
        risk=redir_risk,
    )

    r_domains = redirects.get("redirect_domains") or []
    domain_findings = redirects.get("redirect_domain_findings") or []
    if domain_findings:
        for i, finding in enumerate(domain_findings, start=1):
            dom = finding.get("domain", "")
            dom_risk = str(finding.get("risk", "INFO")).upper()
            dom_comment = finding.get("comment", "")
            add_row(
                "Domaines de redirection" if i == 1 else "",
                dom,
                icon_for_risk(dom_risk),
                dom_comment,
                risk=dom_risk,
            )
    elif r_domains:
        add_row("Domaines de redirection", r_domains[0], STATUS_ICON["info"], redirects.get("rd_comment", ""))
        for dom in r_domains[1:]:
            add_row("", dom, STATUS_ICON["info"], "")

    r_ips = redirects.get("redirect_ips") or []
    if r_ips:
        add_row("IPs de redirection", r_ips[0], icon_for_risk("MEDIUM"), redirects.get("ri_comment", ""), risk="MEDIUM")
        for ip in r_ips[1:]:
            add_row("", ip, icon_for_risk("MEDIUM"), "", risk="MEDIUM")

    r_chain = redirects.get("redirect_chain") or []
    if r_chain:
        for i, hop in enumerate(r_chain, start=1):
            if isinstance(hop, dict):
                hop_status = hop.get("status", "")
                hop_url = hop.get("url", "")
                from_url = hop.get("from_url", "")
                location = hop.get("location", "")
                if from_url and location:
                    resolved_from_location = urljoin(from_url, location)
                    if resolved_from_location == hop_url:
                        comment = f"{from_url} -> Redirection: {location}"
                    else:
                        comment = f"{from_url} -> Redirection: {location} -> {hop_url}"
                else:
                    comment = f"Reponse finale: {hop_url}"
            else:
                hop_status = ""
                comment = str(hop)

            add_row("Chaine de redirections" if i == 1 else "", str(hop_status), STATUS_ICON["info"], comment, risk="INFO")

    standard_files = result.get("standard_files") or []
    if standard_files:
        for i, item in enumerate(standard_files, start=1):
            name = item.get("name", "")
            value = item.get("value", "")
            risk = str(item.get("risk", "INFO")).upper()
            comment = item.get("comment", "")
            src_url = item.get("url", "")
            full_comment = f"{comment} ({src_url})" if src_url else comment
            add_row(
                "Fichiers standards" if i == 1 else "",
                f"{name}: {value}",
                icon_for_risk(risk),
                full_comment,
                risk=risk,
            )

    methods = result.get("methods_exposure") or {}
    methods_risk = str(methods.get("risk", "INFO")).upper()
    methods_value = methods.get("value", "Unknown")
    methods_comment = methods.get("comment", "")
    add_row(
        "Methodes HTTP exposees",
        str(methods_value),
        icon_for_risk(methods_risk),
        str(methods_comment),
        risk=methods_risk,
    )


