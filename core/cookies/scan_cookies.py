# core/cookies/scan_cookies.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations

from http.cookies import SimpleCookie
from urllib.parse import urlparse
import re

import requests

from constants import HEADER
from utils.url import normalize_url


HIGHLY_SENSITIVE_COOKIE_NAMES = {
    "sessionid",
    "phpsessid",
    "jsessionid",
    "connect.sid",
    "sid",
    "auth",
    "authorization",
    "access_token",
    "refresh_token",
    "jwt",
    "csrf_token",
    "xsrf-token",
    "__host-session",
    "__secure-session",
}

MAYBE_SENSITIVE_COOKIE_RE = re.compile(
    r"(^|[_\-.])(session|sess|auth|token|jwt|csrf|xsrf|sid)($|[_\-.])",
    re.IGNORECASE,
)

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ===============================================================
# HELPERS
# ===============================================================
def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except Exception:
        return None


def _extract_set_cookie_headers(response: requests.Response) -> list[str]:
    values = []
    raw_headers = getattr(response, "raw", None)
    raw_headers = getattr(raw_headers, "headers", None)

    # urllib3 HTTPHeaderDict usually provides getlist.
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        values.extend(raw_headers.getlist("Set-Cookie"))

    # Fallback for environments where only merged headers are available.
    if not values:
        merged = response.headers.get("Set-Cookie")
        if merged:
            values.append(merged)
    return [v for v in values if v]


def _parse_cookie_line(set_cookie_line: str) -> dict | None:
    parts = [p.strip() for p in set_cookie_line.split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        return None

    name, value = parts[0].split("=", 1)
    attrs: dict[str, str | bool] = {}

    for token in parts[1:]:
        if "=" in token:
            k, v = token.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[token.strip().lower()] = True

    secure = bool(attrs.get("secure", False))
    httponly = bool(attrs.get("httponly", False))
    samesite = str(attrs.get("samesite", "")).strip().lower() if "samesite" in attrs else ""
    domain = str(attrs.get("domain", "")).strip()
    path = str(attrs.get("path", "")).strip() or "/"
    max_age = _to_int(attrs.get("max-age")) if "max-age" in attrs else None
    expires = str(attrs.get("expires", "")).strip() if "expires" in attrs else ""
    persistent = bool(expires) or (max_age is not None)
    size = len(set_cookie_line.encode("utf-8"))

    return {
        "name": name.strip(),
        "value_len": len(value),
        "secure": secure,
        "httponly": httponly,
        "samesite": samesite,
        "domain": domain,
        "path": path,
        "max_age": max_age,
        "expires": expires,
        "persistent": persistent,
        "size": size,
        "priority": str(attrs.get("priority", "")).strip(),
        "partitioned": bool(attrs.get("partitioned", False)),
        "raw": set_cookie_line,
    }


def _add_finding(
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


def _severity_counts(findings: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _max_severity(findings: list[dict]) -> str:
    if not findings:
        return "info"
    return max(
        (str(f.get("severity", "info")).lower() for f in findings),
        key=lambda s: SEV_RANK.get(s, -1),
    )


def _analyze_cookie_rules(
    cookie: dict,
    findings: list[dict],
) -> None:
    name = cookie["name"]
    name_l = name.lower().strip()
    highly_sensitive = name_l in HIGHLY_SENSITIVE_COOKIE_NAMES
    maybe_sensitive = bool(MAYBE_SENSITIVE_COOKIE_RE.search(name_l))
    sensitive = highly_sensitive or maybe_sensitive
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
        _add_finding(
            findings,
            "CK-001",
            "high" if highly_sensitive else "low",
            name,
            "Le cookie est servi en HTTPS sans attribut Secure.",
            "Ajouter Secure pour forcer l'envoi du cookie uniquement en HTTPS.",
            status="missing",
        )

    if not httponly and highly_sensitive:
        _add_finding(
            findings,
            "CK-002",
            "high",
            name,
            "Cookie de session/authentification sans HttpOnly.",
            "Ajouter HttpOnly pour limiter l'acces via JavaScript (XSS).",
            status="missing",
        )

    if not samesite:
        _add_finding(
            findings,
            "CK-003",
            "medium" if sensitive else "low",
            name,
            "Attribut SameSite absent.",
            "Definir SameSite=Lax (ou Strict selon le besoin fonctionnel).",
            status="missing",
        )

    if samesite == "none" and not secure:
        _add_finding(
            findings,
            "CK-004",
            "high",
            name,
            "SameSite=None sans Secure.",
            "Avec SameSite=None, Secure est requis par les navigateurs modernes.",
            status="invalid",
        )

    if samesite and samesite not in {"lax", "strict", "none"}:
        _add_finding(
            findings,
            "CK-005",
            "low",
            name,
            f"Valeur SameSite non reconnue: {samesite}.",
            "Utiliser Strict, Lax ou None.",
            status="invalid",
        )

    if highly_sensitive and persistent:
        _add_finding(
            findings,
            "CK-006",
            "low",
            name,
            "Cookie sensible persistant (non-session).",
            "Preferer un cookie de session si possible pour les identifiants sensibles.",
        )

    if highly_sensitive and isinstance(max_age, int) and max_age > 60 * 60 * 24 * 30:
        _add_finding(
            findings,
            "CK-007",
            "medium",
            name,
            f"Duree de vie longue pour un cookie sensible ({max_age}s).",
            "Reduire Max-Age au strict necessaire.",
        )

    if (
        domain
        and source_host
        and domain.startswith(".")
        and not source_host.endswith(domain.lstrip(".").lower())
    ):
        _add_finding(
            findings,
            "CK-008",
            "low",
            name,
            f"Portee domaine large ({domain}).",
            "Si possible, restreindre Domain a l'hote le plus specifique.",
        )

    if highly_sensitive and path == "/":
        _add_finding(
            findings,
            "CK-009",
            "low",
            name,
            "Sensitive cookie path is root (/).",
            "Restrict Path where possible.",
        )

    if size > 4096:
        _add_finding(
            findings,
            "CK-010",
            "medium",
            name,
            f"Taille de cookie elevee ({size} octets, > 4096).",
            "Reduire la taille pour eviter troncature/rejet par navigateur ou proxy.",
        )

    if name.startswith("__Host-"):
        if not secure or domain or path != "/":
            _add_finding(
                findings,
                "CK-011",
                "high",
                name,
                "Le prefixe __Host- est invalide (regles non respectees).",
                "__Host- exige Secure, Path=/ et aucun attribut Domain.",
                status="invalid",
            )
    if name.startswith("__Secure-") and not secure:
        _add_finding(
            findings,
            "CK-012",
            "high",
            name,
            "Le prefixe __Secure- est utilise sans Secure.",
            "Ajouter Secure pour respecter les exigences du prefixe __Secure-.",
            status="invalid",
        )


# ===============================================================
# FUNCTION : scan_cookies_config()
# ===============================================================
def scan_cookies_config(url: str) -> dict:
    result = {
        "target_url": url,
        "final_url": "",
        "cookies": [],
        "findings": [],
        "summary": {
            "total_cookies": 0,
            "total_findings": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "max_severity": "info",
            "comment": "",
        },
        "error": "",
    }

    normalized = normalize_url(url)
    result["target_url"] = normalized

    try:
        response = requests.get(
            normalized,
            headers=HEADER,
            timeout=8,
            allow_redirects=True,
        )
    except requests.exceptions.RequestException as exc:
        result["error"] = f"Cookie scan request failed: {exc}"
        return result

    result["final_url"] = response.url
    all_responses = list(response.history) + [response]

    parsed_cookies = []
    for resp in all_responses:
        parsed_resp = urlparse(resp.url)
        resp_scheme = (parsed_resp.scheme or "").lower()
        resp_host = (parsed_resp.hostname or "").lower()
        for line in _extract_set_cookie_headers(resp):
            cookie = _parse_cookie_line(line)
            if cookie is None:
                continue
            cookie["from_url"] = resp.url
            cookie["source_scheme"] = resp_scheme
            cookie["source_host"] = resp_host
            parsed_cookies.append(cookie)

    # Fallback: if response parser missed malformed lines, try SimpleCookie on merged header.
    if not parsed_cookies:
        merged = response.headers.get("Set-Cookie", "")
        if merged:
            tmp = SimpleCookie()
            try:
                tmp.load(merged)
                for k, morsel in tmp.items():
                    parsed_cookies.append(
                        {
                            "name": k,
                            "value_len": len(morsel.value),
                            "secure": bool(morsel["secure"]),
                            "httponly": bool(morsel["httponly"]),
                            "samesite": (morsel["samesite"] or "").lower(),
                            "domain": morsel["domain"] or "",
                            "path": morsel["path"] or "/",
                            "max_age": _to_int(morsel["max-age"]),
                            "expires": morsel["expires"] or "",
                            "persistent": bool(morsel["expires"] or morsel["max-age"]),
                            "size": len(str(morsel).encode("utf-8")),
                            "priority": "",
                            "partitioned": False,
                            "raw": str(morsel),
                            "from_url": response.url,
                            "source_scheme": (urlparse(response.url).scheme or "").lower(),
                            "source_host": (urlparse(response.url).hostname or "").lower(),
                        }
                    )
            except Exception:
                pass

    findings: list[dict] = []
    for cookie in parsed_cookies:
        _analyze_cookie_rules(cookie, findings)

    # duplicate cookie names with different domain/path scope
    scopes_by_name: dict[str, set[tuple[str, str]]] = {}
    for cookie in parsed_cookies:
        name = cookie["name"]
        scope = ((cookie.get("domain") or "").lower(), cookie.get("path") or "/")
        scopes_by_name.setdefault(name, set()).add(scope)

    for name, scopes in scopes_by_name.items():
        if len(scopes) > 1:
            _add_finding(
                findings,
                "CK-013",
                "low",
                name,
                "Meme nom de cookie utilise sur plusieurs scopes domain/path.",
                "Uniformiser les scopes ou renommer les cookies pour eviter les collisions.",
            )

    result["cookies"] = parsed_cookies
    result["findings"] = findings
    result["summary"]["total_cookies"] = len(parsed_cookies)
    result["summary"]["total_findings"] = len(findings)
    result["summary"]["severity_counts"] = _severity_counts(findings)
    result["summary"]["max_severity"] = _max_severity(findings)
    result["summary"]["comment"] = (
        "Aucun en-tete Set-Cookie detecte."
        if not parsed_cookies
        else "Analyse cookies terminee."
    )

    return result

