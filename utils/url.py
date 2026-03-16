# ===============================================================
# FUNCTION : normalize_url
# ===============================================================
def normalize_url(url: str) -> str:
    """
    Add http:// if no scheme is provided.

    Le projet part toujours d'une URL complete pour simplifier les scans HTTP/TLS/Cookies.
    """
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url
