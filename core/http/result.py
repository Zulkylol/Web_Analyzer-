# core/http/result.py

# ===============================================================
# FUNCTION : init_http_result(normalized_url)
# ===============================================================
def init_http_result(normalized_url: str) -> dict:
    """
    Initialize and return the default result dictionary used for HTTP security analysis.

    Returns:
        dict: A pre-structured dictionary containing all fields required
            for the HTTP analysis workflow, initialized with default values.
    """

    # Ce dictionnaire sert de contrat interne entre le scan HTTP, le report et l'UI.
    result = {
        "status_code": 0,
        "status_ok" : False,
        "status_message": "",
        "status_risk": "INFO",
        "http_version": "",
        "http_ok" : False,
        "http_comment" : "",
        "http_version_risk": "MEDIUM",
        "uses_https": False,
        "https_value": "Non",
        "https_comment": "",
        "https_risk": "MEDIUM",
        "mixed_content": False,
        "mixed_content_level": "",
        "mixed_content_risk": "INFO",
        "mixed_url": [],
        "mixed_comment": "Aucun contenu mixte détecté",
        "original_url": normalized_url,
        "final_url": None,
        "url_risk": "INFO",
        "time": 0.0,
        "time_comment": "",
        "time_ok" : False,
        "time_risk": "INFO",
        "standard_files": [],
        "methods_exposure": {
            "value": "Unknown",
            "risk": "INFO",
            "comment": "",
        },
        "redirects": {},
        "errors": {"message": ""},
        "report": {},
    }
    return result
