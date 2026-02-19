# ===============================================================
# FUNCTION : init_http_result(input_url, normalized_url)
# ===============================================================
def init_http_result(input_url: str, normalized_url: str) -> dict:
    """
    Initialize and return the default result dictionary used for HTTP security analysis.

    Returns:
        dict: A pre-structured dictionary containing all fields required
            for the HTTP analysis workflow, initialized with default values.
    """

    result = {
        "status_code": 0,
        "status_ok" : False,
        "status_message": "",
        "http_version": "",
        "http_ok" : False,
        "http_comment" : "",
        "uses_https": False,
        "https_comment": "",
        "mixed_content": False,
        "mixed_url": [],
        "mixed_comment": "Aucun contenu mixte détecté",
        "original_url": normalized_url,
        "input_url" : input_url,
        "final_url": None,
        "time": 0.0,
        "time_comment": "",
        "time_ok" : False,
        "missing_headers": [],
        "headers_comment": [],
        "redirects": {},
        "comment": "",
    }
    return result