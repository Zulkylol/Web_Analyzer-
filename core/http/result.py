# core/http/result.py

# ===============================================================
# FUNCTION : init_http_result
# ===============================================================
def init_http_result(normalized_url: str) -> dict:
    """
    Initialize the default result dictionary used for HTTP analysis.

    Returns :
        dict : default HTTP result structure
    """

    # La structure HTTP reste plus simple que TLS, mais elle est organisee par grands blocs.
    result = {
        "target": {
            "original_url": normalized_url,
            "final_url": None,
            "has_url_credentials": False,
            "url_ok": True,
            "url_comment": "Identique à l'adresse saisie",
            "url_risk": "INFO",
        },
        "transport": {
            "status_code": 0,
            "status_ok": False,
            "status_message": "",
            "status_risk": "INFO",
            "tls_bypassed": False,
            "tls_bypass_comment": "",
            "http_version": "",
            "http_ok": False,
            "http_comment": "",
            "http_version_risk": "MEDIUM",
            "uses_https": False,
            "https_value": "Non",
            "https_comment": "",
            "https_risk": "MEDIUM",
            "time": 0.0,
            "time_comment": "",
            "time_ok": False,
            "time_risk": "INFO",
        },
        "content": {
            "mixed_content": False,
            "mixed_content_level": "",
            "mixed_content_risk": "INFO",
            "mixed_url": [],
            "mixed_comment": "Aucun contenu mixte détecté",
            "header_findings": [],
        },
        "exposure": {
            "standard_files": [],
            "methods_exposure": {
                "value": "Unknown",
                "risk": "INFO",
                "comment": "",
            },
            "redirects": {},
        },
        "errors": {"message": ""},
        "report": {},
    }
    return result
