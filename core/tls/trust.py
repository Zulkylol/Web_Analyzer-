# core/tls/trust.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations
from cryptography import x509
from utils.tls import is_chain_trusted_by_mozilla

# ===============================================================
# FUNCTION : analyze_trust()
# ===============================================================
def analyze_trust(result: dict, x509_cert: x509.Certificate, url: str) -> None:
    """
    Check certificate trust and self-signed status.

    Updates result with self-signed detection and Mozilla trust validation.
    May set negotiated TLS version or an error if missing.

    Args:
        result (dict): Analysis dictionary to update.
        x509_cert (x509.Certificate): Parsed certificate.
        url (str): Target URL for trust validation.
    """
    tls = result["tls"]
    trust = result["trust"]

    trust["is_self_signed"] = x509_cert.issuer == x509_cert.subject

    trusted, tls_info = is_chain_trusted_by_mozilla(url)
    trust["is_trusted"] = trusted

    # comportement identique à ton code
    if tls.get("negotiated_version", "") == "":
        if trusted:
            tls["negotiated_version"] = tls_info
        else:
            result["errors"]["message"] = tls_info
