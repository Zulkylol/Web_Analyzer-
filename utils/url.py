def normalize_url(url: str) -> str:
    """
    Add http:// if no scheme is provided.
    """
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url
