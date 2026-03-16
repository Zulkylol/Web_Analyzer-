# core/tls/cert_trust.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations

from cryptography import x509

from utils.tls import is_chain_trusted_by_mozilla


# ===============================================================
# FUNCTION : analyze_trust
# ===============================================================
def analyze_trust(
    x509_cert: x509.Certificate,
    url: str,
    negotiated_version: str = "",
) -> tuple[dict, str, str]:
    """
    Analyze certificate trust and self-signed status.

    Returns :
        tuple[dict, str, str] : trust block, version value, error message
    """
    authority_name = ""
    for attribute in x509_cert.issuer:
        if attribute.oid._name == "commonName":
            authority_name = attribute.value
            break

    is_self_signed = x509_cert.issuer == x509_cert.subject
    trusted, tls_info = is_chain_trusted_by_mozilla(url)

    trust = {
        "authority_name": authority_name,
        "authority_ok": trusted,
        "authority_comment": (
            "Autorité de certification reconnue par la chaîne de confiance"
            if trusted
            else "Autorité de certification non reconnue par la chaîne de confiance"
        ),
        "authority_risk": "INFO" if trusted else "HIGH",
        "is_self_signed": is_self_signed,
        "self_signed_ok": not is_self_signed,
        "self_signed_comment": (
            "Le certificat est autosigné"
            if is_self_signed
            else "Le certificat n'est pas autosigné"
        ),
        "self_signed_risk": "HIGH" if is_self_signed else "INFO",
    }

    error_message = ""
    if not negotiated_version:
        if trusted:
            negotiated_version = tls_info
        else:
            error_message = tls_info

    return trust, negotiated_version, error_message
