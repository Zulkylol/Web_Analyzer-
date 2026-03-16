# core/tls/cert_validity.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations

from datetime import datetime, timezone

from cryptography import x509


# ===============================================================
# FUNCTION : analyze_validity
# ===============================================================
def analyze_validity(x509_cert: x509.Certificate) -> dict:
    """
    Check certificate validity dates and expiration status.

    Returns:
        dict: Validity analysis block.
    """
    validity = {
        "not_before": x509_cert.not_valid_before_utc.isoformat(),
        "not_after": x509_cert.not_valid_after_utc.isoformat(),
        "is_valid_now": False,
        "expires_ok": False,
        "expires_soon_comment": "",
    }
    now = datetime.now(timezone.utc)

    try:
        not_before = x509_cert.not_valid_before_utc
        not_after = x509_cert.not_valid_after_utc
        validity["is_valid_now"] = not_before <= now <= not_after
        days_left = (not_after - now).days

        if days_left < 0:
            validity["expires_ok"] = False
            validity["expires_soon_comment"] = "Certificat expire."
        elif days_left < 30:
            validity["expires_ok"] = None
            validity["expires_soon_comment"] = f"Certificat expire bientot ({days_left} jours restants)."
        else:
            validity["expires_ok"] = True
            validity["expires_soon_comment"] = f"Validite confortable ({days_left} jours restants)."
    except Exception:
        validity["is_valid_now"] = False
        validity["expires_ok"] = None
        validity["expires_soon_comment"] = "Impossible d'evaluer la validite."

    return validity
