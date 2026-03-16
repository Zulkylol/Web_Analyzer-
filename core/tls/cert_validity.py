from __future__ import annotations

from datetime import datetime, timezone

from cryptography import x509


# ===============================================================
# FUNCTION : analyze_validity
# ===============================================================
def analyze_validity(x509_cert: x509.Certificate) -> dict:
    """
    Analyze certificate validity dates.

    Returns :
        dict : validity rows
    """
    valid_from = {"value": x509_cert.not_valid_before_utc.isoformat(), "ok": False, "comment": "", "risk": "HIGH"}
    valid_to = {"value": x509_cert.not_valid_after_utc.isoformat(), "ok": False, "comment": "", "risk": "HIGH"}

    now = datetime.now(timezone.utc)

    try:
        not_before = x509_cert.not_valid_before_utc
        not_after = x509_cert.not_valid_after_utc
        is_valid_now = not_before <= now <= not_after
        days_left = (not_after - now).days

        valid_from["ok"] = is_valid_now
        valid_from["comment"] = (
            "Le certificat est actuellement dans sa période de validité"
            if is_valid_now
            else "Le certificat est hors de sa période de validité"
        )
        valid_from["risk"] = "INFO" if is_valid_now else "HIGH"

        if days_left < 0:
            valid_to["ok"] = False
            valid_to["comment"] = "Le certificat est déjà expiré"
            valid_to["risk"] = "HIGH"
        elif days_left < 30:
            valid_to["ok"] = None
            valid_to["comment"] = f"Le certificat expire bientôt ({days_left} jours restants)"
            valid_to["risk"] = "MEDIUM"
        else:
            valid_to["ok"] = True
            valid_to["comment"] = f"La durée de validité restante est confortable ({days_left} jours restants)"
            valid_to["risk"] = "INFO"
    except Exception:
        valid_from["ok"] = False
        valid_from["comment"] = "Impossible d'évaluer si le certificat est actuellement valide"
        valid_from["risk"] = "HIGH"
        valid_to["ok"] = None
        valid_to["comment"] = "Impossible d'évaluer la date d'expiration du certificat"
        valid_to["risk"] = "MEDIUM"

    return {
        "valid_from": valid_from,
        "valid_to": valid_to,
    }
