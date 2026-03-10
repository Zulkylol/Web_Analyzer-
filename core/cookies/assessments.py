from __future__ import annotations

from core.cookies.policy import SEV_RANK, cookie_sensitivity_flags


def select_finding(findings: list[dict], rule_ids: tuple[str, ...]) -> dict | None:
    matches = [finding for finding in findings if str(finding.get("id", "")) in rule_ids]
    if not matches:
        return None
    return max(matches, key=lambda finding: SEV_RANK.get(str(finding.get("severity", "info")).lower(), -1))


def max_severity(findings: list[dict]) -> str:
    if not findings:
        return "info"
    return max(
        (str(finding.get("severity", "info")).lower() for finding in findings),
        key=lambda severity: SEV_RANK.get(severity, -1),
    )


def build_cookie_assessments(cookie: dict, findings: list[dict]) -> dict:
    samesite = (cookie.get("samesite") or "").strip().lower()
    domain = (cookie.get("domain") or "").strip()
    path = (cookie.get("path") or "/").strip() or "/"
    size = int(cookie.get("size", 0) or 0)
    persistent = bool(cookie.get("persistent"))
    _highly_sensitive, _maybe_sensitive, sensitive = cookie_sensitivity_flags(cookie.get("name", ""))

    secure_finding = select_finding(findings, ("CK-001", "CK-004", "CK-011", "CK-012"))
    httponly_finding = select_finding(findings, ("CK-002",))
    samesite_finding = select_finding(findings, ("CK-003", "CK-004", "CK-005"))
    domain_finding = select_finding(findings, ("CK-008",))
    path_finding = select_finding(findings, ("CK-009",))
    type_finding = select_finding(findings, ("CK-006", "CK-007"))
    size_finding = select_finding(findings, ("CK-010",))

    return {
        "name": {
            "risk": max_severity(findings),
            "comment": "Nom de cookie observe dans Set-Cookie" if findings else "Nom de cookie observe",
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
