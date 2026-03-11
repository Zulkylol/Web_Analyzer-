def init_cookies_result(url: str) -> dict:
    return {
        "target_url": url,
        "final_url": "",
        "cookies": [],
        "findings": [],
        "summary": {
            "total_cookies": 0,
            "sensitive_cookies": 0,
            "highly_sensitive_cookies": 0,
            "cookie_count_risk": "info",
            "total_findings": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "max_severity": "info",
            "comment": "",
        },
        "error": "",
        "errors": {"message": ""},
        "report": {},
    }
