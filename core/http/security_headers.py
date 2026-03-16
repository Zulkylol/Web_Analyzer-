# core/http/security_headers.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations
from constants import GOOD_REFERRER, WEAK_REFERRER, CSP_WEAK_TOKENS, SEV_ORDER
import re
from typing import Any, Mapping

# ===============================================================
# FUNCTION : _lower_sev
# ===============================================================
def _lower_sev(sev: str) -> str:
    """
    Compute the next lower severity level.
  
    Returns : 
        str : lower security level
    """
    inv = {v: k for k, v in SEV_ORDER.items()}
    v = SEV_ORDER.get(sev, 0)
    return inv.get(max(0, v - 1), "info")


# ===============================================================
# FUNCTION : _get_header
# ===============================================================
def _get_header(headers: Mapping[str, Any], name: str) -> str | None:
    """
    Return a normalized header value or None if missing/empty.

    Returns:
        str : normalized header value or None 
    """
    v = headers.get(name)
    return str(v).strip() if v is not None and str(v).strip() else None


# ===============================================================
# FUNCTION : _parse_directives
# ===============================================================
def _parse_directives(header_value: str) -> dict[str, str]:
    """
    Parse a semicolon-separated header into directive/value pairs.

    Returns:
        dict[str, str]: Mapping of directives to their values.
    """
    # Used for CSP and Permissions-Policy, where semantics rely on directives.
    directives: dict[str, str] = {}
    for part in header_value.split(";"):
        part = part.strip()
        if not part:
            continue
        if " " in part:
            k, rest = part.split(" ", 1)
            directives[k.strip()] = rest.strip()
        else:
            directives[part] = ""
    return directives

# ===============================================================
# FUNCTION : scan_security_headers
# ===============================================================
def scan_security_headers(
    headers: Mapping[str, Any],
    required_headers: dict[str, str],  # header -> expected severity if missing
    ) -> list[dict[str, str | None]]:
    """ 
    Analyze HTTP security headers and report missing, weak, or invalid configurations.

    Returns:
        list[dict]: Detailed findings (header, status, severity, issue, recommendation, value)
    """
    # Chaque finding est deja pense pour pouvoir etre remonte tel quel dans le report HTTP.
    findings: list[dict[str, Any]] = []

    # ===============================================================
    # FUNCTION : expected
    # ===============================================================
    def expected(header: str) -> str:
        """ 
        Return expected severity for a missing header

        Returns : 
            str : expected headers
        """
        return required_headers.get(header, "info")

    # ===============================================================
    # FUNCTION : add
    # ===============================================================
    def add(header: str, status: str, severity: str, issue: str, rec: str, value: str | None):
        """ 
        Append a structured finding entry 
        """
        findings.append({
            "header": header,
            "status": status,          # ok / missing / weak / invalid / info
            "severity": severity,      # high / medium / low / info
            "issue": issue,
            "recommendation": rec,
            "value": value,
        })

    # ------------------- HSTS ---------------------
    if "Strict-Transport-Security" in required_headers:
        hsts = _get_header(headers, "Strict-Transport-Security")
        if not hsts:
            add(
                "Strict-Transport-Security",
                "missing",
                expected("Strict-Transport-Security"),
                "HSTS absent: risque de downgrade HTTP / SSL stripping",
                "Ajouter: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                None,
            )
        else:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I) 
            max_age = int(m.group(1)) if m else None
            has_include = "includesubdomains" in hsts.lower()

            if max_age is None:
                add(
                    "Strict-Transport-Security",
                    "invalid",
                    _lower_sev(expected("Strict-Transport-Security")),
                    "HSTS présent mais max-age manquant/illisible",
                    "Définir: max-age>=15552000 (180j), idéal 31536000; includeSubDomains recommandé",
                    hsts,
                )
            elif max_age < 15552000:
                add(
                    "Strict-Transport-Security",
                    "weak",
                    _lower_sev(expected("Strict-Transport-Security")),
                    f"HSTS max-age trop faible ({max_age})",
                    "Mettre max-age>=15552000 (180j), idéal 31536000; includeSubDomains recommandé",
                    hsts,
                )
            elif not has_include:
                add(
                    "Strict-Transport-Security",
                    "weak",
                    "low",
                    "HSTS sans includeSubDomains (sous-domaines possiblement non protégés contre le downgrade/MITM)",
                    "Ajouter includeSubDomains si possible (attention aux sous-domaines non-HTTPS)",
                    hsts,
                )
            else:
                add(
                    "Strict-Transport-Security",
                    "ok",
                    "info",
                    "HSTS correctement configuré (checks de base OK)",
                    "",
                    hsts,
                )

    # ------------ CSP (or Report-Only) ------------
    if "Content-Security-Policy" in required_headers:
        csp = _get_header(headers, "Content-Security-Policy")
        csp_ro = _get_header(headers, "Content-Security-Policy-Report-Only")

        if not csp and not csp_ro:
            add(
                "Content-Security-Policy",
                "missing",
                expected("Content-Security-Policy"),
                "CSP absente: surface XSS plus grande",
                "Ajouter une CSP (même minimale) et l’endurcir progressivement",
                None,
            )
        else:
            active_value = csp or csp_ro
            is_report_only = (csp is None) and (csp_ro is not None)

            directives = _parse_directives(active_value or "")
            lc = (active_value or "").lower()

            if any(t in lc for t in CSP_WEAK_TOKENS):
                add(
                    "Content-Security-Policy",
                    "weak",
                    _lower_sev(_lower_sev(expected("Content-Security-Policy"))),
                    "CSP contient unsafe-inline et/ou unsafe-eval (affaiblit la protection contre l'injection de code)",
                    "Durcir la CSP en interdisant les scripts inline et l'évaluation dynamique ('unsafe-inline', 'unsafe-eval')",
                    active_value,
                )
            elif "default-src" not in directives:
                add(
                    "Content-Security-Policy",
                    "weak",
                    "low",
                    "CSP sans default-src (souvent incomplète)",
                    "Ajouter default-src 'self' puis affiner script-src/style-src/img-src…",
                    active_value,
                )
            elif directives.get("object-src", "").strip() not in ("'none'", "none"):
                add(
                    "Content-Security-Policy",
                    "weak",
                    "low",
                    "CSP sans object-src 'none' (plugins)",
                    "Ajouter: object-src 'none'",
                    active_value,
                )
            else:
                if is_report_only:
                    add(
                        "Content-Security-Policy",
                        "info",
                        "info",
                        "CSP en mode Report-Only (ne bloque pas)",
                        "Passer en Content-Security-Policy (enforcement) quand prêt",
                        active_value,
                    )
                else:
                    add(
                        "Content-Security-Policy",
                        "ok",
                        "info",
                        "CSP présente et raisonnable (checks de base OK)",
                        "",
                        active_value,
                    )

    # -------------- X-FRAME-OPTIONS ---------------
    if "X-Frame-Options" in required_headers:
        xfo = _get_header(headers, "X-Frame-Options")
        if not xfo:
            add(
                "X-Frame-Options",
                "missing",
                expected("X-Frame-Options"),
                "Protection clickjacking absente (X-Frame-Options)",
                "Ajouter: X-Frame-Options: DENY (ou SAMEORIGIN)",
                None,
            )
        else:
            v = xfo.strip().upper()
            if v in {"DENY", "SAMEORIGIN"}:
                add("X-Frame-Options", "ok", "info", "X-Frame-Options correctement configuré", "", xfo)
            else:
                add(
                    "X-Frame-Options",
                    "weak",
                    "low",
                    f"Valeur X-Frame-Options non recommandée: {xfo}",
                    "Utiliser DENY ou SAMEORIGIN (ALLOW-FROM est obsolète)",
                    xfo,
                )

    # ----------- X-CONTENT-TYPE-OPTIONS -----------
    if "X-Content-Type-Options" in required_headers:
        xcto = _get_header(headers, "X-Content-Type-Options")
        if not xcto:
            add(
                "X-Content-Type-Options",
                "missing",
                expected("X-Content-Type-Options"),
                "Protection contre MIME sniffing absente",
                "Ajouter: X-Content-Type-Options: Nosniff",
                None,
            )
        else:
            if xcto.lower() == "nosniff":
                add("X-Content-Type-Options", "ok", "info", "X-Content-Type-Options : nosniff correctement configuré", "", xcto)
            else:
                add(
                    "X-Content-Type-Options",
                    "weak",
                    "low",
                    f"Valeur inattendue: {xcto}",
                    "Mettre exactement: nosniff",
                    xcto,
                )

    # -------------- REFERRER-POLICY ---------------
    if "Referrer-Policy" in required_headers:
        rp = _get_header(headers, "Referrer-Policy")
        if not rp:
            add(
                "Referrer-Policy",
                "missing",
                expected("Referrer-Policy"),
                "Referrer-Policy absente (fuites potentielles d’URL)",
                "Ajouter: Referrer-Policy: strict-origin-when-cross-origin (bon défaut)",
                None,
            )
        else:
            v = rp.split(",")[0].strip().lower()
            if v in GOOD_REFERRER:
                add("Referrer-Policy", "ok", "info", "Referrer-Policy correctement configuré", "", rp)
            elif v in WEAK_REFERRER:
                add(
                    "Referrer-Policy",
                    "weak",
                    "low",
                    f"Referrer-Policy faible: {v}",
                    "Utiliser strict-origin-when-cross-origin ou no-referrer selon besoin",
                    rp,
                )
            else:
                add(
                    "Referrer-Policy",
                    "info",
                    "info",
                    f"Referrer-Policy non classée: {v}",
                    "Vérifier qu’elle correspond à ta politique de confidentialité",
                    rp,
                )

    # ------------- PERMISSIONS-POLICY -------------
    if "Permissions-Policy" in required_headers:
        pp = _get_header(headers, "Permissions-Policy")
        if not pp:
            add(
                "Permissions-Policy",
                "missing",
                expected("Permissions-Policy"),
                "Permissions-Policy absente (durcissement optionnel)",
                "Optionnel: restreindre camera, microphone, geolocation, etc",
                None,
            )
        else:
            lc = pp.lower()
            if "*" in lc:
                add(
                    "Permissions-Policy",
                    "weak",
                    "low",
                    "Permissions-Policy semble trop permissive ('*' détecté)",
                    "Éviter '*'; préférer des allowlists minimales ou '()' pour désactiver",
                    pp,
                )
            else:
                sensitive = ["geolocation", "camera", "microphone"]
                missing_sens = [f for f in sensitive if f not in lc]
                if missing_sens:
                    add(
                        "Permissions-Policy",
                        "info",
                        "info",
                        f"Permissions-Policy présente, mais features sensibles non explicitement mentionnées: {', '.join(missing_sens)}",
                        "Optionnel: ajouter geolocation=(), camera=(), microphone=() si non nécessaires",
                        pp,
                    )
                else:
                    add("Permissions-Policy", "ok", "info", "Permissions-Policy présente, sans features sensibles autorisées", "", pp)

    return findings
