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


def icon_for_risk(risk: str, ok_when_info: bool = False):
    risk_u = str(risk or "").strip().upper()
    if risk_u == "LOW":
        return STATUS_ICON["low"]
    if risk_u == "MEDIUM":
        return STATUS_ICON["medium"]
    if risk_u in {"HIGH", "CRITICAL"}:
        return STATUS_ICON["high"]
    return STATUS_ICON["ok"] if ok_when_info else STATUS_ICON["info"]
