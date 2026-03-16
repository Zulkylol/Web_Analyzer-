from __future__ import annotations

from constants import SEV_RANK
from core.cookies.policy import cookie_sensitivity_flags, max_severity


# ===============================================================
# FUNCTION : sort_findings_by_severity
# ===============================================================
def sort_findings_by_severity(findings: list[dict]) -> list[dict]:
    """
    Sort findings by severity.

    Returns :
        list[dict] : sorted findings
    """
    return sorted(
        findings,
        key=lambda finding: SEV_RANK.get(str(finding.get("severity", "info")).lower(), -1),
        reverse=True,
    )


# ===============================================================
# FUNCTION : cookie_count_risk
# ===============================================================
def cookie_count_risk(total_cookies: int, sensitive_cookies: int) -> str:
    """
    Rate cookie volume risk.

    Returns :
        str : risk level
    """
    if total_cookies <= 10:
        return "info"
    if total_cookies <= 20:
        return "low"
    if total_cookies <= 40:
        return "medium" if sensitive_cookies >= 3 else "low"
    return "high" if sensitive_cookies >= 5 else "medium"


# ===============================================================
# FUNCTION : count_sensitive_cookies
# ===============================================================
def count_sensitive_cookies(cookies: list[dict]) -> int:
    """
    Count sensitive cookies.

    Returns :
        int : sensitive count
    """
    sensitive_count = 0

    for cookie in cookies:
        _highly_sensitive, _maybe_sensitive, sensitive = cookie_sensitivity_flags(cookie.get("name", ""))
        if sensitive:
            sensitive_count += 1
    return sensitive_count
