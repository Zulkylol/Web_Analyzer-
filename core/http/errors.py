# core/http/errors.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations

import requests

# ===============================================================
# FUNCTION : map_http_scan_error
# ===============================================================
def map_http_scan_error(exc: Exception) -> str:
    """
    Convert request exceptions into a readable HTTP scan error message.

    Returns : 
        str : readable error
    """
    if isinstance(exc, requests.exceptions.SSLError):
        txt = repr(exc)
        if "CERTIFICATE_VERIFY_FAILED" in txt and "unable to get local issuer certificate" in txt:
            return (
                "Erreur TLS/SSL : verification du certificat impossible "
                "(CA intermediaire manquante / chaine incomplete) "
                "Le navigateur peut reussir via cache, mais Python/OpenSSL echoue"
            )
        if "CERTIFICATE_VERIFY_FAILED" in txt:
            return "Erreur TLS/SSL : verification du certificat impossible (CERTIFICATE_VERIFY_FAILED)"
        return f"Erreur TLS/SSL : {exc}"
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "Timeout de connexion (ConnectTimeout)"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "Timeout de lecture (ReadTimeout)"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return f"Connexion impossible : {exc}"
    if isinstance(exc, requests.exceptions.RequestException):
        return f"Erreur reseau : {exc}"
    return f"Erreur : {exc}"
