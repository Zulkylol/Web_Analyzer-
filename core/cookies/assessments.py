# core/cookies/assessments.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations

from constants import SEV_RANK
from core.cookies.policy import cookie_sensitivity_flags, max_severity


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
    """
    Add a normalized finding to the cookie alerts list.

    Returns :
        None : no return value
    """
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
    """
    Return the most severe finding across equivalent categories.

    Returns :
        dict | None : selected finding
    """
    matches = [finding for finding in findings if str(finding.get("category", "")) in categories]
    if not matches:
        return None
    return max(matches, key=lambda finding: SEV_RANK.get(str(finding.get("severity", "info")).lower(), -1))


# ===============================================================
# FUNCTION : find_scope_collision_names
# ===============================================================
def find_scope_collision_names(cookies: list[dict]) -> set[str]:
    """
    Detect cookie names reused across multiple domain and path pairs.

    Returns :
        set[str] : duplicated cookie names
    """
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
    """
    Build global findings for cookie scope collisions.

    Returns :
        list[dict] : scope collision findings
    """
    findings: list[dict] = []
    for name in sorted(duplicate_names):
        add_finding(
            findings,
            "scope",
            "low",
            name,
            "Même nom de cookie utilisé sur plusieurs scopes domain/path",
            "Uniformiser les scopes ou renommer les cookies pour éviter les collisions",
        )
    return findings


# ===============================================================
# FUNCTION : build_cookie_findings
# ===============================================================
def build_cookie_findings(cookie: dict) -> list[dict]:
    """
    Build rule-based findings for a single cookie.

    Returns :
        list[dict] : cookie findings
    """
    findings: list[dict] = []
    name = str(cookie.get("name", ""))
    name_lower = name.lower()
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
    is_csrf_cookie = "csrf" in name_lower or "xsrf" in name_lower

    # Les checks ci-dessous transforment chaque attribut en risque metier lisible.
    if not secure and is_https_cookie:
        add_finding(
            findings,
            "secure",
            "high" if highly_sensitive else "low",
            name,
            "Le cookie est servi en HTTPS sans attribut Secure (peut être envoyé sur une requête non chiffrée)",
            "Ajouter Secure pour forcer l'envoi du cookie uniquement en HTTPS",
            status="missing",
        )

    if not httponly and sensitive:
        severity = "high" if highly_sensitive else "info" if is_csrf_cookie else "low"
        issue = (
            "Cookie de session/authentification sans HttpOnly (lecture possible via JavaScript en cas de XSS)"
            if highly_sensitive
            else "Cookie CSRF/XSRF sans HttpOnly (souvent lisible côté client)"
            if is_csrf_cookie
            else "Cookie potentiellement sensible sans HttpOnly (lecture possible via JavaScript)"
        )
        add_finding(
            findings,
            "httponly",
            severity,
            name,
            issue,
            "Ajouter HttpOnly pour limiter l'accès via JavaScript (XSS)",
            status="missing",
        )

    if not samesite:
        add_finding(
            findings,
            "samesite",
            "medium" if highly_sensitive else "low",
            name,
            "Attribut SameSite absent (plus exposé aux requêtes cross-site)",
            "Définir SameSite=Lax (ou Strict selon le besoin fonctionnel)",
            status="missing",
        )

    if samesite == "none" and not secure:
        add_finding(
            findings,
            "samesite_secure",
            "high",
            name,
            "SameSite=None sans Secure (configuration refusée ou dégradée par les navigateurs modernes)",
            "Avec SameSite=None, Secure est requis par les navigateurs modernes",
            status="invalid",
        )

    if samesite and samesite not in {"lax", "strict", "none"}:
        add_finding(
            findings,
            "samesite",
            "low",
            name,
            f"Valeur SameSite non reconnue: {samesite} (interprétation navigateur potentiellement incohérente)",
            "Utiliser Strict, Lax ou None",
            status="invalid",
        )

    if highly_sensitive and persistent:
        add_finding(
            findings,
            "type",
            "low",
            name,
            "Cookie sensible persistant (non-session) (reste stocké au-delà de la session)",
            "Préférer un cookie de session si possible pour les identifiants sensibles",
        )

    if highly_sensitive and isinstance(max_age, int) and max_age > 60 * 60 * 24 * 30:
        add_finding(
            findings,
            "type",
            "medium",
            name,
            f"Durée de vie longue pour un cookie sensible ({max_age}s) (fenêtre d'exposition plus large)",
            "Réduire Max-Age au strict nécessaire",
        )

    if domain and source_host and domain.startswith(".") and not source_host.endswith(domain.lstrip(".").lower()):
        add_finding(
            findings,
            "domain",
            "low",
            name,
            f"Portée domaine large ({domain}) (surface d'envoi étendue aux sous-domaines)",
            "Si possible, restreindre Domain à l'hôte le plus spécifique",
        )

    if highly_sensitive and path == "/":
        add_finding(
            findings,
            "path",
            "low",
            name,
            "Cookie sensible avec Path=/ (portée applicative très large)",
            "Restreindre Path si possible",
        )

    if size > 4096:
        add_finding(
            findings,
            "size",
            "medium",
            name,
            f"Taille de cookie élevée ({size} octets, > 4096) (risque de rejet ou de troncature)",
            "Réduire la taille pour éviter troncature/rejet par navigateur ou proxy",
        )

    if name.startswith("__Host-") and (not secure or domain or path != "/"):
        add_finding(
            findings,
            "secure",
            "high",
            name,
            "Le préfixe __Host- est invalide (règles non respectées, garanties de portée perdues)",
            "__Host- exige Secure, Path=/ et aucun attribut Domain",
            status="invalid",
        )

    if name.startswith("__Secure-") and not secure:
        add_finding(
            findings,
            "secure",
            "high",
            name,
            "Le préfixe __Secure- est utilisé sans Secure (préfixe trompeur et protection non assurée)",
            "Ajouter Secure pour respecter les exigences du préfixe __Secure-",
            status="invalid",
        )

    return findings


# ===============================================================
# FUNCTION : build_cookie_assessments
# ===============================================================
def build_cookie_assessments(cookie: dict, findings: list[dict], *, has_scope_collision: bool = False) -> dict:
    """
    Project cookie findings into per-attribute assessments for the detailed report.

    Returns :
        dict : cookie assessments
    """
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
            "comment": secure_finding.get("issue", "") if secure_finding else "Attribut Secure présent (envoi limité aux requêtes HTTPS)" if cookie.get("secure") else "Attribut Secure absent",
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
                else "Attribut HttpOnly présent (non lisible via JavaScript)"
                if cookie.get("httponly")
                else "Attribut HttpOnly absent (cookie non sensible)"
                if not sensitive
                else "Attribut HttpOnly absent"
            ),
        },
        "samesite": {
            "risk": str(samesite_finding.get("severity", "info")).upper() if samesite_finding else "INFO",
            "comment": samesite_finding.get("issue", "") if samesite_finding else f"SameSite défini sur {samesite} (contrôle des envois cross-site)" if samesite else "SameSite non défini",
        },
        "domain": {
            "risk": str(domain_finding.get("severity", "info")).upper() if domain_finding else "INFO",
            "comment": domain_finding.get("issue", "") if domain_finding else "Cookie limité à l'hôte courant (portée plus restreinte)" if not domain else "Attribut Domain explicite",
        },
        "path": {
            "risk": str(path_finding.get("severity", "info")).upper() if path_finding else "INFO",
            "comment": path_finding.get("issue", "") if path_finding else f"Path configuré sur {path} (périmètre d'envoi du cookie)",
        },
        "type": {
            "risk": str(type_finding.get("severity", "info")).upper() if type_finding else "INFO",
            "comment": type_finding.get("issue", "") if type_finding else "Cookie persistant (reste stocké après fermeture du navigateur)" if persistent else "Cookie de session (supprimé à la fermeture du navigateur)",
        },
        "size": {
            "risk": str(size_finding.get("severity", "info")).upper() if size_finding else "INFO",
            "comment": size_finding.get("issue", "") if size_finding else f"Taille observée: {size} octets (impact potentiel sur compatibilité/performance)",
        },
        "source": {
            "risk": "INFO",
            "comment": "URL source de l'en-tête Set-Cookie",
        },
    }
