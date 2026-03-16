from __future__ import annotations

from constants import STATUS_ICON
from core.reporting import build_report, icon_for_risk, make_row, make_section_row


# ===============================================================
# FUNCTION : build_http_report
# ===============================================================
def build_http_report(result: dict) -> dict:
    """
    Transforms the raw HTTP result into ordered rows for the UI.

    Returns :
        dict : report
    """
    rows: list[dict] = []
    target = result.get("target") or {}
    transport = result.get("transport") or {}
    content = result.get("content") or {}
    exposure = result.get("exposure") or {}
    redirects = exposure.get("redirects") or {}
    mixed_urls = content.get("mixed_url") or []
    error_message = str((result.get("errors") or {}).get("message", "") or "")

    def add_row(param, value="", *, risk="INFO", comment="", ok_when_info=False, check=None, tags=(), include=False):
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

    def add_section(title: str):
        rows.append(make_section_row(title))

    if error_message:
        add_row(
            "Erreur HTTP",
            transport.get("status_message", ""),
            risk="HIGH",
            comment=error_message,
            check=STATUS_ICON["high"],
            include=True,
        )
        return build_report("HTTP", rows, error_message=error_message)

    # --------------- CIBLE ET TRANSPORT -------------------
    # Section 1: initial target, final transport, and basic metrics.
    add_section("Cible et transport")
    add_row("URL saisie", target.get("original_url", ""), comment="URL normalisée utilisée pour le scan")

    if target.get("has_url_credentials"):
        add_row(
            "Credentials dans l'URL",
            "Oui",
            risk="HIGH",
            comment="Credentials détectés dans l'URL",
            include=True,
        )

    add_row(
        "URL finale",
        target.get("final_url", ""),
        risk=str(target.get("url_risk", "INFO")).upper(),
        comment=target.get("url_comment", ""),
        ok_when_info=bool(target.get("url_ok")),
        include=str(target.get("url_risk", "INFO")).upper() != "INFO",
    )

    status_risk = transport.get("status_risk", "INFO")
    add_row(
        "Code de statut",
        str(transport.get("status_code", "")),
        risk=status_risk,
        comment=transport.get("status_message", ""),
        ok_when_info=bool(transport.get("status_ok")),
        include=str(status_risk).upper() != "INFO",
    )

    http_version = transport.get("http_version") or ""
    if http_version:
        http_risk = transport.get("http_version_risk", "MEDIUM")
        add_row(
            "Version HTTP",
            http_version,
            risk=http_risk,
            comment=transport.get("http_comment", ""),
            ok_when_info=bool(transport.get("http_ok")),
            include=str(http_risk).upper() != "INFO",
        )
    else:
        add_row(
            "Version HTTP",
            "Inconnue",
            risk="MEDIUM",
            comment="Impossible de déterminer la version HTTP",
            check=STATUS_ICON["invalid"],
            include=True,
        )

    https_risk = transport.get("https_risk", "MEDIUM")
    uses_https = bool(transport.get("uses_https"))
    add_row(
        "HTTP active",
        transport.get("https_value", "Oui" if uses_https else "Non"),
        risk=https_risk,
        comment=transport.get("https_comment", ""),
        ok_when_info=uses_https,
        include=str(https_risk).upper() != "INFO",
    )

    time_risk = transport.get("time_risk", "INFO")
    add_row(
        "Temps de réponse",
        f"{transport.get('time', 0.0)} seconde(s)",
        risk=time_risk,
        comment=transport.get("time_comment", ""),
        ok_when_info=bool(transport.get("time_ok")),
        include=str(time_risk).upper() != "INFO",
    )

    # ------------------ REDIRECTIONS ----------------------
    # Section 2: number of redirections, findings, redirect chain
    add_section("Redirections")
    redirect_error = str(redirects.get("error", "") or "")
    if redirect_error:
        add_row(
            "Redirections",
            "Erreur",
            risk="MEDIUM",
            comment=redirect_error,
            include=True,
        )
    num_risk = str(redirects.get("num_risk", "INFO")).upper()
    add_row(
        "Nombre de redirections",
        str(redirects.get("num_redirects", 0)),
        risk=num_risk,
        comment=redirects.get("num_comment", ""),
        ok_when_info=bool(redirects.get("num_ok")),
        include=num_risk != "INFO",
    )

    domain_findings = redirects.get("redirect_domain_findings") or []
    noteworthy_domain_findings = [
        finding for finding in domain_findings if str(finding.get("risk", "INFO")).upper() != "INFO"
    ]
    if noteworthy_domain_findings:
        for index, finding in enumerate(noteworthy_domain_findings, start=1):
            domain_risk = str(finding.get("risk", "INFO")).upper()
            add_row(
                "Domaines de redirection" if index == 1 else "",
                finding.get("domain", ""),
                risk=domain_risk,
                comment=finding.get("comment", ""),
                ok_when_info=domain_risk == "INFO",
                include=domain_risk != "INFO",
            )

    redirect_ips = redirects.get("redirect_ips") or []
    if redirect_ips:
        add_row(
            "IPs de redirection",
            redirect_ips[0],
            risk="MEDIUM",
            comment=redirects.get("ri_comment", ""),
            include=True,
        )
        for ip in redirect_ips[1:]:
            add_row("", ip, risk="MEDIUM")

    redirect_chain = redirects.get("redirect_chain") or []
    if redirect_chain:
        for index, hop in enumerate(redirect_chain, start=1):
            if isinstance(hop, dict):
                hop_status = hop.get("status", "")
                comment = str(hop.get("display_comment", ""))
            else:
                hop_status = ""
                comment = str(hop)
            add_row("Chaine de redirections" if index == 1 else "", str(hop_status), comment=comment)

    # --------------- SECURITE DE CONTENU ------------------
    # Section 3: security of the received content and protective headers.
    if uses_https or content.get("header_findings"):
        add_section("Sécurité de contenu / headers")

    if uses_https:
        mixed = bool(content.get("mixed_content"))
        mixed_risk = str(content.get("mixed_content_risk", "INFO")).upper()
        add_row(
            "Contenu mixte",
            "Oui" if mixed else "Non",
            risk=mixed_risk,
            comment=content.get("mixed_comment", ""),
            ok_when_info=not mixed,
            include=mixed_risk != "INFO",
        )

        for index, item in enumerate(mixed_urls, start=1):
            try:
                mixed_url, origin = item
            except Exception:
                mixed_url, origin = str(item), ""
            add_row(
                "URL mixte" if index == 1 else "",
                mixed_url,
                risk=mixed_risk or "MEDIUM",
                comment=origin,
                check=icon_for_risk(mixed_risk or "MEDIUM"),
            )

    header_findings = content.get("header_findings") or []
    if header_findings:
        header_idx = 0
        for finding in header_findings:
            if not uses_https and finding.get("header") == "Strict-Transport-Security":
                continue
            header_idx += 1
            severity = str(finding.get("severity", "INFO")).upper()
            header_ok = str(finding.get("status", "")).lower() == "ok"
            add_row(
                f"Header de sécurité #{header_idx}",
                finding.get("header", ""),
                risk=severity,
                comment=str(finding.get("issue", "")),
                ok_when_info=header_ok,
                include=severity != "INFO",
            )
            if finding.get("recommendation"):
                add_row("", "", comment="Recommandation: " + finding["recommendation"], check="", tags=("recommendation",))

    # -------------------- EXPOSITION ----------------------
    # Section 4: additional exposure surface around the HTTP target.
    add_section("Exposition")
    standard_files = exposure.get("standard_files") or []
    if standard_files:
        for index, item in enumerate(standard_files, start=1):
            name = item.get("name", "")
            risk = str(item.get("risk", "INFO")).upper()
            comment = item.get("comment", "")
            source_url = item.get("url", "")
            full_comment = f"{comment} ({source_url})" if source_url else comment
            if name == "robots.txt":
                param = "Fichier Robots"
            elif name == "security.txt":
                param = "Fichier Security"
            else:
                param = "Fichiers standards" if index == 1 else ""
            add_row(
                param,
                f"{name}: {item.get('value', '')}",
                risk=risk,
                comment=full_comment,
                ok_when_info=name == "security.txt" and risk == "INFO",
                include=risk != "INFO",
            )

    methods = exposure.get("methods_exposure") or {}
    methods_risk = str(methods.get("risk", "INFO")).upper()
    add_row(
        "Méthodes HTTP exposées",
        str(methods.get("value", "Unknown")),
        risk=methods_risk,
        comment=str(methods.get("comment", "")),
        ok_when_info=methods_risk == "INFO",
        include=methods_risk != "INFO",
    )

    # Build final report with all rows
    return build_report("HTTP", rows, error_message=error_message)
