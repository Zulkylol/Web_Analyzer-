def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url

def ck(status):
    if status is True:
        return "✅"
    elif status is False:
        return "❌"
    else:
        return "⚠️"
