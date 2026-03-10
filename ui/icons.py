from constants import STATUS_ICON


def icon_for_risk(risk: str, ok_when_info: bool = False):
    risk_u = str(risk or "").strip().upper()
    if risk_u == "LOW":
        return STATUS_ICON["low"]
    if risk_u == "MEDIUM":
        return STATUS_ICON["medium"]
    if risk_u in {"HIGH", "CRITICAL"}:
        return STATUS_ICON["high"]
    return STATUS_ICON["ok"] if ok_when_info else STATUS_ICON["info"]
