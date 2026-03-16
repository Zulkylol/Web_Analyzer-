# ===============================================================
# FUNCTION : init_cookies_result
# ===============================================================
def init_cookies_result() -> dict:
    """Initialise la structure commune utilisee par le scan cookies."""
    return {
        "final_url": "",
        "cookies": [],
        "findings": [],
        "summary": {
            "total_cookies": 0,
            "sensitive_cookies": 0,
            "cookie_count_risk": "info",
            "total_findings": 0,
            "max_severity": "info",
            "comment": "",
        },
        "errors": {"message": ""},
        "report": {},
    }
