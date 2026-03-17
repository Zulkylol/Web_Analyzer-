# constants.py


import re
import ssl


# ===============================================================
# SHARED REPORTING / UI
# ===============================================================
SPACER: str = "               "

STATUS_ICON = {
    "ok": "✅",
    "info": "ℹ️",
    "low": "⚠️",
    "medium": "❗",
    "weak": "⚠️",
    "invalid": "❗",
    "warning": "❗",
    "missing": "❌",
    "ko": "❌",
    "high": "❌",
}

RISK_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


# ===============================================================
# HTTP SCAN
# ===============================================================
HEADER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/121.0.0.0 Safari/537.36"
}


# ===============================================================
# HTTP SECURITY HEADERS
# ===============================================================
SECURITY_HEADERS = {
    "Strict-Transport-Security": "medium",
    "Content-Security-Policy": "high",
    "X-Frame-Options": "medium",
    "X-Content-Type-Options": "low",
    "Referrer-Policy": "low",
    "Permissions-Policy": "low",
}

CSP_WEAK_TOKENS = (
    "'unsafe-inline'",
    "'unsafe-eval'",
)

GOOD_REFERRER = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}

WEAK_REFERRER = {
    "unsafe-url",
    "no-referrer-when-downgrade",
}

SEV_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
}


# ===============================================================
# TLS ANALYSIS
# ===============================================================
SUPPORTED_TLS_VERSIONS = (
    ("TLS1.0", ssl.TLSVersion.TLSv1),
    ("TLS1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS1.3", ssl.TLSVersion.TLSv1_3),
)

WEAK_TLS_ALGORITHMS = ("RC4", "3DES", "DES", "MD5")

WEAK_CIPHER_TESTS = {
    "3DES": "DES-CBC3-SHA",
    "AES-CBC": "AES128-SHA:AES256-SHA",
    "RC4": "RC4-SHA",
    "MD5": "RSA-MD5",
}


# ===============================================================
# COOKIE ANALYSIS
# ===============================================================
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
    "__host-session",
    "__secure-session",
}

MAYBE_SENSITIVE_COOKIE_RE = re.compile(
    r"(^|[_\-.])(session|sess|auth|token|jwt|csrf|xsrf|sid)($|[_\-.])",
    re.IGNORECASE,
)

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
