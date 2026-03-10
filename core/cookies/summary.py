from __future__ import annotations

from core.cookies.policy import SEV_RANK, cookie_sensitivity_flags


def severity_counts(findings: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def max_severity(findings: list[dict]) -> str:
    if not findings:
        return "info"
    return max(
        (str(finding.get("severity", "info")).lower() for finding in findings),
        key=lambda severity: SEV_RANK.get(severity, -1),
    )


def sort_findings_by_severity(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda finding: SEV_RANK.get(str(finding.get("severity", "info")).lower(), -1),
        reverse=True,
    )


def cookie_count_risk(total_cookies: int, sensitive_cookies: int) -> str:
    if total_cookies <= 10:
        return "info"
    if total_cookies <= 20:
        return "low"
    if total_cookies <= 40:
        return "medium" if sensitive_cookies >= 3 else "low"
    return "high" if sensitive_cookies >= 5 else "medium"


def count_sensitive_cookies(cookies: list[dict]) -> tuple[int, int]:
    sensitive_count = 0
    highly_sensitive_count = 0

    for cookie in cookies:
        highly_sensitive, _maybe_sensitive, sensitive = cookie_sensitivity_flags(cookie.get("name", ""))
        if sensitive:
            sensitive_count += 1
        if highly_sensitive:
            highly_sensitive_count += 1

    return sensitive_count, highly_sensitive_count
