from __future__ import annotations

from core.cookies.policy import cookie_sensitivity_flags


def add_finding(
    findings: list[dict],
    rule_id: str,
    severity: str,
    cookie_name: str,
    issue: str,
    recommendation: str,
    status: str = "warning",
) -> None:
    findings.append(
        {
            "id": rule_id,
            "severity": severity,
            "cookie": cookie_name,
            "status": status,
            "issue": issue,
            "recommendation": recommendation,
        }
    )


def analyze_cookie_rules(cookie: dict, findings: list[dict]) -> None:
    name = cookie["name"]
    highly_sensitive, _maybe_sensitive, sensitive = cookie_sensitivity_flags(name)
    secure = bool(cookie["secure"])
    httponly = bool(cookie["httponly"])
    samesite = (cookie.get("samesite") or "").lower().strip()
    domain = (cookie.get("domain") or "").strip()
    path = (cookie.get("path") or "/").strip() or "/"
    max_age = cookie.get("max_age")
    persistent = bool(cookie.get("persistent"))
    size = int(cookie.get("size", 0))
    source_scheme = (cookie.get("source_scheme") or "").lower()
    source_host = (cookie.get("source_host") or "").lower()
    is_https_cookie = source_scheme == "https"

    if not secure and is_https_cookie:
        add_finding(
            findings,
            "CK-001",
            "high" if highly_sensitive else "low",
            name,
            "Le cookie est servi en HTTPS sans attribut Secure.",
            "Ajouter Secure pour forcer l'envoi du cookie uniquement en HTTPS.",
            status="missing",
        )

    if not httponly and sensitive:
        add_finding(
            findings,
            "CK-002",
            "high" if highly_sensitive else "medium",
            name,
            "Cookie de session/authentification sans HttpOnly.",
            "Ajouter HttpOnly pour limiter l'acces via JavaScript (XSS).",
            status="missing",
        )

    if not samesite:
        add_finding(
            findings,
            "CK-003",
            "medium" if sensitive else "low",
            name,
            "Attribut SameSite absent.",
            "Definir SameSite=Lax (ou Strict selon le besoin fonctionnel).",
            status="missing",
        )

    if samesite == "none" and not secure:
        add_finding(
            findings,
            "CK-004",
            "high",
            name,
            "SameSite=None sans Secure.",
            "Avec SameSite=None, Secure est requis par les navigateurs modernes.",
            status="invalid",
        )

    if samesite and samesite not in {"lax", "strict", "none"}:
        add_finding(
            findings,
            "CK-005",
            "low",
            name,
            f"Valeur SameSite non reconnue: {samesite}.",
            "Utiliser Strict, Lax ou None.",
            status="invalid",
        )

    if highly_sensitive and persistent:
        add_finding(
            findings,
            "CK-006",
            "low",
            name,
            "Cookie sensible persistant (non-session).",
            "Preferer un cookie de session si possible pour les identifiants sensibles.",
        )

    if highly_sensitive and isinstance(max_age, int) and max_age > 60 * 60 * 24 * 30:
        add_finding(
            findings,
            "CK-007",
            "medium",
            name,
            f"Duree de vie longue pour un cookie sensible ({max_age}s).",
            "Reduire Max-Age au strict necessaire.",
        )

    if domain and source_host and domain.startswith(".") and not source_host.endswith(domain.lstrip(".").lower()):
        add_finding(
            findings,
            "CK-008",
            "low",
            name,
            f"Portee domaine large ({domain}).",
            "Si possible, restreindre Domain a l'hote le plus specifique.",
        )

    if highly_sensitive and path == "/":
        add_finding(
            findings,
            "CK-009",
            "low",
            name,
            "Sensitive cookie path is root (/).",
            "Restrict Path where possible.",
        )

    if size > 4096:
        add_finding(
            findings,
            "CK-010",
            "medium",
            name,
            f"Taille de cookie elevee ({size} octets, > 4096).",
            "Reduire la taille pour eviter troncature/rejet par navigateur ou proxy.",
        )

    if name.startswith("__Host-") and (not secure or domain or path != "/"):
        add_finding(
            findings,
            "CK-011",
            "high",
            name,
            "Le prefixe __Host- est invalide (regles non respectees).",
            "__Host- exige Secure, Path=/ et aucun attribut Domain.",
            status="invalid",
        )

    if name.startswith("__Secure-") and not secure:
        add_finding(
            findings,
            "CK-012",
            "high",
            name,
            "Le prefixe __Secure- est utilise sans Secure.",
            "Ajouter Secure pour respecter les exigences du prefixe __Secure-.",
            status="invalid",
        )


def add_scope_collision_findings(cookies: list[dict], findings: list[dict]) -> None:
    scopes_by_name: dict[str, set[tuple[str, str]]] = {}
    for cookie in cookies:
        name = cookie["name"]
        scope = ((cookie.get("domain") or "").lower(), cookie.get("path") or "/")
        scopes_by_name.setdefault(name, set()).add(scope)

    for name, scopes in scopes_by_name.items():
        if len(scopes) > 1:
            add_finding(
                findings,
                "CK-013",
                "low",
                name,
                "Meme nom de cookie utilise sur plusieurs scopes domain/path.",
                "Uniformiser les scopes ou renommer les cookies pour eviter les collisions.",
            )
