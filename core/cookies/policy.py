from __future__ import annotations

from constants import HIGHLY_SENSITIVE_COOKIE_NAMES, MAYBE_SENSITIVE_COOKIE_RE, SEV_RANK


# ===============================================================
# FUNCTION : cookie_sensitivity_flags
# ===============================================================
def cookie_sensitivity_flags(name: str) -> tuple[bool, bool, bool]:
    """
    Classify cookie name sensitivity.

    Returns :
        tuple[bool, bool, bool] : sensitivity flags
    """
    name_l = name.lower().strip()
    highly_sensitive = name_l in HIGHLY_SENSITIVE_COOKIE_NAMES
    maybe_sensitive = bool(MAYBE_SENSITIVE_COOKIE_RE.search(name_l))
    sensitive = highly_sensitive or maybe_sensitive
    return highly_sensitive, maybe_sensitive, sensitive


# ===============================================================
# FUNCTION : max_severity
# ===============================================================
def max_severity(findings: list[dict]) -> str:
    """
    Return the highest severity found in a cookie findings list.

    Returns :
        str : max severity
    """
    if not findings:
        return "info"
    return max(
        (str(finding.get("severity", "info")).lower() for finding in findings),
        key=lambda severity: SEV_RANK.get(severity, -1),
    )
