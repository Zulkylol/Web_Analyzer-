# utils/urls.py

# ===============================================================
# FUNCTION : normalize_url
# ===============================================================
def normalize_url(url: str) -> str:
    """
    Add http:// if no scheme is provided.

    The project always starts from a complete URL to simplify HTTP/TLS/Cookies scans.
    """
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url
