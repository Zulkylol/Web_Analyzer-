from __future__ import annotations

from core.cookies.policy import SEV_RANK, cookie_sensitivity_flags


# ===============================================================
# FUNCTION : add_finding
# ===============================================================
def add_finding(
    findings: list[dict],
    category: str,
    severity: str,
    cookie_name: str,
    issue: str,
    recommendation: str,
    status: str = "warning",
) -> None:
    """Ajoute un finding normalise a la liste des alertes cookies."""
    findings.append(
        {
            "category": category,
            "severity": severity,
            "cookie": cookie_name,
            "status": status,
            "issue": issue,
            "recommendation": recommendation,
        }
    )


# ===============================================================
# FUNCTION : select_finding
# ===============================================================
def select_finding(findings: list[dict], categories: tuple[str, ...]) -> dict | None:
    """Retourne le finding le plus severe parmi plusieurs categories equivalentes."""
    matches = [finding for finding in findings if str(finding.get("category", "")) in categories]
    if not matches:
        return None
    return max(matches, key=lambda finding: SEV_RANK.get(str(finding.get("severity", "info")).lower(), -1))


# ===============================================================
# FUNCTION : max_severity
# ===============================================================
def max_severity(findings: list[dict]) -> str:
    """Retourne la severite maximale d'une liste de findings cookies."""
    if not findings:
        return "info"
    return max(
        (str(finding.get("severity", "info")).lower() for finding in findings),
        key=lambda severity: SEV_RANK.get(severity, -1),
    )


# ===============================================================
# FUNCTION : find_scope_collision_names
# ===============================================================
def find_scope_collision_names(cookies: list[dict]) -> set[str]:
    """Detecte les noms de cookie reutilises sur plusieurs couples domaine/path."""
    scopes_by_name: dict[str, set[tuple[str, str]]] = {}
    for cookie in cookies:
        name = str(cookie.get("name", ""))
        scope = (
            (cookie.get("domain") or "").lower(),
            (cookie.get("path") or "/"),
        )
        scopes_by_name.setdefault(name, set()).add(scope)

    return {name for name, scopes in scopes_by_name.items() if len(scopes) > 1}


# ===============================================================
# FUNCTION : build_scope_collision_findings
# ===============================================================
def build_scope_collision_findings(duplicate_names: set[str]) -> list[dict]:
    """Construit les findings globaux de collision de scope."""
    findings: list[dict] = []
    for name in sorted(duplicate_names):
        add_finding(
            findings,
            "scope",
            "low",
            name,
            "Meme nom de cookie utilise sur plusieurs scopes domain/path",
            "Uniformiser les scopes ou renommer les cookies pour eviter les collisions",
        )
    return findings


# ===============================================================
# FUNCTION : build_cookie_findings
# ===============================================================
def build_cookie_findings(cookie: dict) -> list[dict]:
    """Genere les findings metier pour un cookie donne."""
    findings: list[dict] = []
    name = str(cookie.get("name", ""))
    highly_sensitive, _maybe_sensitive, sensitive = cookie_sensitivity_flags(name)
    secure = bool(cookie.get("secure"))
    httponly = bool(cookie.get("httponly"))
    samesite = (cookie.get("samesite") or "").lower().strip()
    domain = (cookie.get("domain") or "").strip()
    path = (cookie.get("path") or "/").strip() or "/"
    max_age = cookie.get("max_age")
    persistent = bool(cookie.get("persistent"))
    size = int(cookie.get("size", 0) or 0)
    source_scheme = (cookie.get("source_scheme") or "").lower()
    source_host = (cookie.get("source_host") or "").lower()
    is_https_cookie = source_scheme == "https"

    # Les checks ci-dessous transforment chaque attribut en risque metier lisible.
    if not secure and is_https_cookie:
        add_finding(
            findings,
            "secure",
            "high" if highly_sensitive else "low",
            name,
            "Le cookie est servi en HTTPS sans attribut Secure",
            "Ajouter Secure pour forcer l'envoi du cookie uniquement en HTTPS",
            status="missing",
        )

    if not httponly and sensitive:
        add_finding(
            findings,
            "httponly",
            "high" if highly_sensitive else "medium",
            name,
            "Cookie de session/authentification sans HttpOnly",
            "Ajouter HttpOnly pour limiter l'acces via JavaScript (XSS)",
            status="missing",
        )

    if not samesite:
        add_finding(
            findings,
            "samesite",
            "medium" if sensitive else "low",
            name,
            "Attribut SameSite absent",
            "Definir SameSite=Lax (ou Strict selon le besoin fonctionnel)",
            status="missing",
        )

    if samesite == "none" and not secure:
        add_finding(
            findings,
            "samesite_secure",
            "high",
            name,
            "SameSite=None sans Secure",
            "Avec SameSite=None, Secure est requis par les navigateurs modernes",
            status="invalid",
        )

    if samesite and samesite not in {"lax", "strict", "none"}:
        add_finding(
            findings,
            "samesite",
            "low",
            name,
            f"Valeur SameSite non reconnue: {samesite}",
            "Utiliser Strict, Lax ou None",
            status="invalid",
        )

    if highly_sensitive and persistent:
        add_finding(
            findings,
            "type",
            "low",
            name,
            "Cookie sensible persistant (non-session)",
            "Preferer un cookie de session si possible pour les identifiants sensibles",
        )

    if highly_sensitive and isinstance(max_age, int) and max_age > 60 * 60 * 24 * 30:
        add_finding(
            findings,
            "type",
            "medium",
            name,
            f"Duree de vie longue pour un cookie sensible ({max_age}s)",
            "Reduire Max-Age au strict necessaire",
        )

    if domain and source_host and domain.startswith(".") and not source_host.endswith(domain.lstrip(".").lower()):
        add_finding(
            findings,
            "domain",
            "low",
            name,
            f"Portee domaine large ({domain})",
            "Si possible, restreindre Domain a l'hote le plus specifique",
        )

    if highly_sensitive and path == "/":
        add_finding(
            findings,
            "path",
            "low",
            name,
            "Sensitive cookie path is root (/)",
            "Restrict Path where possible",
        )

    if size > 4096:
        add_finding(
            findings,
            "size",
            "medium",
            name,
            f"Taille de cookie elevee ({size} octets, > 4096)",
            "Reduire la taille pour eviter troncature/rejet par navigateur ou proxy",
        )

    if name.startswith("__Host-") and (not secure or domain or path != "/"):
        add_finding(
            findings,
            "secure",
            "high",
            name,
            "Le prefixe __Host- est invalide (regles non respectees)",
            "__Host- exige Secure, Path=/ et aucun attribut Domain",
            status="invalid",
        )

    if name.startswith("__Secure-") and not secure:
        add_finding(
            findings,
            "secure",
            "high",
            name,
            "Le prefixe __Secure- est utilise sans Secure",
            "Ajouter Secure pour respecter les exigences du prefixe __Secure-",
            status="invalid",
        )

    return findings


# ===============================================================
# FUNCTION : build_cookie_assessments
# ===============================================================
def build_cookie_assessments(cookie: dict, findings: list[dict], *, has_scope_collision: bool = False) -> dict:
    """Projette les findings d'un cookie en assessments par attribut pour le report detaille."""
    samesite = (cookie.get("samesite") or "").strip().lower()
    domain = (cookie.get("domain") or "").strip()
    path = (cookie.get("path") or "/").strip() or "/"
    size = int(cookie.get("size", 0) or 0)
    persistent = bool(cookie.get("persistent"))
    _highly_sensitive, _maybe_sensitive, sensitive = cookie_sensitivity_flags(cookie.get("name", ""))

    secure_finding = select_finding(findings, ("secure", "samesite_secure"))
    httponly_finding = select_finding(findings, ("httponly",))
    samesite_finding = select_finding(findings, ("samesite", "samesite_secure"))
    domain_finding = select_finding(findings, ("domain",))
    path_finding = select_finding(findings, ("path",))
    type_finding = select_finding(findings, ("type",))
    size_finding = select_finding(findings, ("size",))

    name_risk = max_severity(findings)
    if has_scope_collision and SEV_RANK.get(name_risk, -1) < SEV_RANK["low"]:
        name_risk = "low"

    return {
        "name": {
            "risk": str(name_risk).upper(),
        },
        "secure": {
            "risk": str(secure_finding.get("severity", "info")).upper() if secure_finding else "INFO",
            "comment": secure_finding.get("issue", "") if secure_finding else "Attribut Secure present" if cookie.get("secure") else "Attribut Secure absent",
        },
        "httponly": {
            "risk": (
                str(httponly_finding.get("severity", "info")).upper()
                if httponly_finding
                else "INFO"
                if cookie.get("httponly") or not sensitive
                else "LOW"
            ),
            "comment": (
                httponly_finding.get("issue", "")
                if httponly_finding
                else "Attribut HttpOnly present"
                if cookie.get("httponly")
                else "Attribut HttpOnly absent (non sensible)"
                if not sensitive
                else "Attribut HttpOnly absent"
            ),
        },
        "samesite": {
            "risk": str(samesite_finding.get("severity", "info")).upper() if samesite_finding else "INFO",
            "comment": samesite_finding.get("issue", "") if samesite_finding else f"SameSite defini sur {samesite}" if samesite else "SameSite non defini",
        },
        "domain": {
            "risk": str(domain_finding.get("severity", "info")).upper() if domain_finding else "INFO",
            "comment": domain_finding.get("issue", "") if domain_finding else "Cookie limite a l'hote courant" if not domain else "Attribut Domain explicite",
        },
        "path": {
            "risk": str(path_finding.get("severity", "info")).upper() if path_finding else "INFO",
            "comment": path_finding.get("issue", "") if path_finding else f"Path configure sur {path}",
        },
        "type": {
            "risk": str(type_finding.get("severity", "info")).upper() if type_finding else "INFO",
            "comment": type_finding.get("issue", "") if type_finding else "Cookie persistant" if persistent else "Cookie de session",
        },
        "size": {
            "risk": str(size_finding.get("severity", "info")).upper() if size_finding else "INFO",
            "comment": size_finding.get("issue", "") if size_finding else f"Taille observee: {size} octets",
        },
        "source": {
            "risk": "INFO",
            "comment": "URL source de l'en-tete Set-Cookie",
        },
    }
