SECURITY_HEADERS = {
    "Strict-Transport-Security": "medium",
    "Content-Security-Policy": "high",
    "X-Frame-Options": "medium",
    "X-Content-Type-Options": "low",
    "Referrer-Policy": "low",
    "Permissions-Policy": "info",
}

HEADER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/121.0.0.0 Safari/537.36"
    }   

SPACER: str = "               "

CSP_WEAK_TOKENS = (
    "'unsafe-inline'",
    "'unsafe-eval'"
    )

GOOD_REFERRER = {
    "no-referrer", 
    "strict-origin", 
    "strict-origin-when-cross-origin"
    }

WEAK_REFERRER = {
    "unsafe-url", 
    "no-referrer-when-downgrade"
    }

SEV_ORDER = {
    "info": 0, 
    "low": 1, 
    "medium": 2, 
    "high": 3
    }

STATUS_ICON = {
    "ok": "✅",
    "info": "ℹ️",
    "weak": "⚠️",
    "invalid": "⚠️",
    "warning" : "⚠️",
    "missing": "❌",
    "ko" : "❌",
    "high" : "❌",
}