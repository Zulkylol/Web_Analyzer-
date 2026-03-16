from __future__ import annotations

import re


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
