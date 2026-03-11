from __future__ import annotations

import requests

from constants import HEADER
from core.cookies.assessments import build_cookie_assessments
from core.cookies.parser import collect_response_cookies
from core.cookies.report import build_cookies_report
from core.cookies.result import init_cookies_result
from core.cookies.rules import add_scope_collision_findings, analyze_cookie_rules
from core.cookies.summary import (
    cookie_count_risk,
    count_sensitive_cookies,
    max_severity,
    severity_counts,
    sort_findings_by_severity,
)
from utils.url import normalize_url


def scan_cookies_config(url: str) -> dict:
    result = init_cookies_result(url)
    normalized = normalize_url(url)
    result["target_url"] = normalized

    try:
        response = requests.get(
            normalized,
            headers=HEADER,
            timeout=8,
            allow_redirects=True,
        )
        result["final_url"] = response.url
        cookies = collect_response_cookies(response)

        findings: list[dict] = []
        for cookie in cookies:
            analyze_cookie_rules(cookie, findings)

        add_scope_collision_findings(cookies, findings)

        for cookie in cookies:
            cookie_findings = [finding for finding in findings if finding.get("cookie") == cookie.get("name")]
            cookie["assessments"] = build_cookie_assessments(cookie, cookie_findings)

        sensitive_count, highly_sensitive_count = count_sensitive_cookies(cookies)
        sorted_findings = sort_findings_by_severity(findings)

        result["cookies"] = cookies
        result["findings"] = sorted_findings
        result["summary"]["total_cookies"] = len(cookies)
        result["summary"]["sensitive_cookies"] = sensitive_count
        result["summary"]["highly_sensitive_cookies"] = highly_sensitive_count
        result["summary"]["cookie_count_risk"] = cookie_count_risk(len(cookies), sensitive_count)
        result["summary"]["total_findings"] = len(sorted_findings)
        result["summary"]["severity_counts"] = severity_counts(sorted_findings)
        result["summary"]["max_severity"] = max_severity(sorted_findings)
        result["summary"]["comment"] = (
            "Aucun en-tete Set-Cookie detecte."
            if not cookies
            else "Analyse cookies terminee."
        )
    except requests.exceptions.RequestException as exc:
        result["error"] = f"Cookie scan request failed: {exc}"
        result["errors"]["message"] = result["error"]
    except Exception as exc:
        result["error"] = f"Cookie scan failed: {exc}"
        result["errors"]["message"] = result["error"]

    result["report"] = build_cookies_report(result)
    return result
