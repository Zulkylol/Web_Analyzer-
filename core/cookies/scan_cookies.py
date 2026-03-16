from __future__ import annotations

import requests

from constants import HEADER
from core.cookies.assessments import (
    build_cookie_assessments,
    build_cookie_findings,
    build_scope_collision_findings,
    find_scope_collision_names,
)
from core.cookies.parser import collect_response_cookies
from core.cookies.report import build_cookies_report
from core.cookies.result import init_cookies_result
from core.cookies.summary import (
    cookie_count_risk,
    count_sensitive_cookies,
    max_severity,
    sort_findings_by_severity,
)
from utils.url import normalize_url


# ===============================================================
# FUNCTION : scan_cookies_config
# ===============================================================
def scan_cookies_config(url: str) -> dict:
    """Pipeline cookies: requete, parsing Set-Cookie, evaluations, resume, puis report."""
    result = init_cookies_result()
    normalized = normalize_url(url)

    try:
        response = requests.get(
            normalized,
            headers=HEADER,
            timeout=8,
            allow_redirects=True,
        )
        result["final_url"] = response.url
        cookies = collect_response_cookies(response)
        # Une collision de scope signifie ici: meme nom de cookie, mais pas meme domaine/path.
        duplicate_names = find_scope_collision_names(cookies)

        findings: list[dict] = []
        for cookie in cookies:
            # Chaque cookie produit a la fois des findings "bruts" et des assessments par attribut.
            cookie_findings = build_cookie_findings(cookie)
            cookie["assessments"] = build_cookie_assessments(
                cookie,
                cookie_findings,
                has_scope_collision=cookie.get("name") in duplicate_names,
            )
            findings.extend(cookie_findings)

        findings.extend(build_scope_collision_findings(duplicate_names))

        # Le resume sert au report cookies et a la synthese globale.
        sensitive_count = count_sensitive_cookies(cookies)
        sorted_findings = sort_findings_by_severity(findings)

        result["cookies"] = cookies
        result["findings"] = sorted_findings
        result["summary"]["total_cookies"] = len(cookies)
        result["summary"]["sensitive_cookies"] = sensitive_count
        result["summary"]["cookie_count_risk"] = cookie_count_risk(len(cookies), sensitive_count)
        result["summary"]["total_findings"] = len(sorted_findings)
        result["summary"]["max_severity"] = max_severity(sorted_findings)
        result["summary"]["comment"] = (
            "Aucun en-tete Set-Cookie detecte"
            if not cookies
            else "Analyse cookies terminee"
        )
    except requests.exceptions.RequestException as exc:
        result["error"] = f"Cookie scan request failed: {exc}"
        result["errors"]["message"] = result["error"]
    except Exception as exc:
        result["error"] = f"Cookie scan failed: {exc}"
        result["errors"]["message"] = result["error"]

    # Comme pour HTTP/TLS, l'UI consomme uniquement le report final harmonise.
    result["report"] = build_cookies_report(result)
    return result
