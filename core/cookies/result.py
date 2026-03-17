# ===============================================================
# FUNCTION : init_cookies_result
# ===============================================================
def init_cookies_result() -> dict:
    """
    Initialize the shared result structure used by the cookie scan.

    Returns :
        dict : default cookie result structure
    """
    return {
        "final_url": "",
        "tls_bypassed": False,
        "tls_bypass_comment": "",
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
