from constants import STATUS_ICON

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url

def ck(status):
    if status is True:
        return STATUS_ICON["ok"]
    elif status is False:
        return STATUS_ICON["ko"]
    else:
        return STATUS_ICON["warning"]
