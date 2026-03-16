# core/tls/trust.py

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
    Check certificate trust and self-signed status.

    Returns:
        tuple[dict, str, str]:
            - trust block
            - negotiated TLS version (possibly completed)
            - error message
    """
    trust = {
        "is_trusted": False,
        "is_self_signed": x509_cert.issuer == x509_cert.subject,
    }

    trusted, tls_info = is_chain_trusted_by_mozilla(url)
    trust["is_trusted"] = trusted

    if negotiated_version == "":
        if trusted:
            negotiated_version = tls_info
            error_message = ""
        else:
            error_message = tls_info
    else:
        error_message = ""

    return trust, negotiated_version, error_message
