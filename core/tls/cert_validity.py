# core/tls/cert_validity.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations
from datetime import datetime, timezone
from cryptography import x509

# ===============================================================
# FUNCTION : analyze_validity()
# ===============================================================
def analyze_validity(result: dict, x509_cert: x509.Certificate) -> None:
    """
    Check certificate validity dates and expiration status.

    Updates result["certificate"]["validity"] in place with current
    validity state and remaining lifetime evaluation.

    Args:
        result (dict): Analysis dictionary to update.
        x509_cert (x509.Certificate): Parsed certificate.
    """
    cert_validity = result["certificate"]["validity"]

    cert_validity["not_before"] = x509_cert.not_valid_before_utc.isoformat()
    cert_validity["not_after"] = x509_cert.not_valid_after_utc.isoformat()
    now = datetime.now(timezone.utc)

    try:
        not_before = x509_cert.not_valid_before_utc
        not_after = x509_cert.not_valid_after_utc

        cert_validity["is_valid_now"] = not_before <= now <= not_after
        days_left = (not_after - now).days

        if days_left < 0:
            cert_validity["expires_ok"] = False
            cert_validity["expires_soon_comment"] = "Certificat expiré."
        elif days_left < 30:
            cert_validity["expires_ok"] = None
            cert_validity["expires_soon_comment"] = f"⚠️ Certificat expire bientôt ({days_left} jours restants)."
        else:
            cert_validity["expires_ok"] = True
            cert_validity["expires_soon_comment"] = f"Validité confortable ({days_left} jours restants)."
    except Exception:
        cert_validity["is_valid_now"] = False
        cert_validity["expires_ok"] = None
        cert_validity["expires_soon_comment"] = "Impossible d'évaluer la validité."
