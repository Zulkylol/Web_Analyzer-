# utils/url.py

# ===============================================================
# IMPORTS
# ===============================================================
from constants import STATUS_ICON


# ===============================================================
# FUNCTION : normalize_url()
# ===============================================================  
def normalize_url(url: str) -> str:
    """
    Add http:// if no scheme is provided
    """

    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url

# ===============================================================
# FUNCTION : ck()
# ===============================================================  
def ck(status):
    """
    Map status value to its display icon
    """

    if status is True:
        return STATUS_ICON["ok"]
    elif status is False:
        return STATUS_ICON["ko"]
    else:
        return STATUS_ICON["warning"]
