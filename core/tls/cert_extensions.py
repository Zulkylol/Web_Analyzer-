# core/tls/cert_extensions.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


# ===============================================================
# FUNCTION : analyze_extensions
# ===============================================================
def analyze_extensions(x509_cert: x509.Certificate) -> dict:
    """
    Analyze common certificate extensions.

    Returns :
        dict : extension rows
    """
    extensions = {
        "basic_constraints": {"value": "", "ok": None, "comment": "", "risk": "MEDIUM"},
        "key_usage": {"value": "", "ok": None, "comment": "", "risk": "MEDIUM"},
        "extended_key_usage": {"value": "", "ok": None, "comment": "", "risk": "MEDIUM"},
        "crl_distribution_points": {"value": "", "ok": None, "comment": "", "risk": "LOW"},
    }

    for extension_class, key in [
        (x509.BasicConstraints, "basic_constraints"),
        (x509.KeyUsage, "key_usage"),
        (x509.ExtendedKeyUsage, "extended_key_usage"),
        (x509.CRLDistributionPoints, "crl_distribution_points"),
    ]:
        try:
            extension = x509_cert.extensions.get_extension_for_class(extension_class)
            extensions[key]["value"] = str(extension.value)
        except Exception:
            pass

    # ------------------- BASIC CONSTRAINTS ---------------------
    basic_constraints = extensions["basic_constraints"]["value"]
    try:
        basic_constraints_ca = x509_cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value.ca
    except Exception:
        basic_constraints_ca = None

    if basic_constraints:
        if basic_constraints_ca is True:
            extensions["basic_constraints"]["ok"] = False
            extensions["basic_constraints"]["comment"] = "Le certificat est marqué comme CA, ce qui est anormal pour un certificat serveur"
            extensions["basic_constraints"]["risk"] = "HIGH"
        else:
            extensions["basic_constraints"]["ok"] = True
            extensions["basic_constraints"]["comment"] = "Le certificat n'est pas déclaré comme autorité de certification"
            extensions["basic_constraints"]["risk"] = "INFO"
    else:
        extensions["basic_constraints"]["ok"] = None
        extensions["basic_constraints"]["comment"] = "L'extension Basic Constraints est absente du certificat"
        extensions["basic_constraints"]["risk"] = "MEDIUM"

    # ---------------------- EXTENDED KU ------------------------
    extended_key_usage = extensions["extended_key_usage"]["value"]
    try:
        extended_key_usage_has_server_auth = (
            ExtendedKeyUsageOID.SERVER_AUTH
            in x509_cert.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
        )
    except Exception:
        extended_key_usage_has_server_auth = None

    if extended_key_usage:
        if extended_key_usage_has_server_auth is True:
            extensions["extended_key_usage"]["ok"] = True
            extensions["extended_key_usage"]["comment"] = "L'EKU autorise explicitement l'authentification serveur TLS"
            extensions["extended_key_usage"]["risk"] = "INFO"
        else:
            extensions["extended_key_usage"]["ok"] = False
            extensions["extended_key_usage"]["comment"] = "L'EKU est présent mais ne contient pas l'usage serverAuth"
            extensions["extended_key_usage"]["risk"] = "MEDIUM"
    else:
        extensions["extended_key_usage"]["ok"] = None
        extensions["extended_key_usage"]["comment"] = "L'extension Extended Key Usage est absente du certificat"
        extensions["extended_key_usage"]["risk"] = "MEDIUM"

    # ----------------------- KEY USAGE -------------------------
    key_usage = extensions["key_usage"]["value"]
    try:
        key_usage_has_digital_signature = x509_cert.extensions.get_extension_for_class(
            x509.KeyUsage
        ).value.digital_signature
    except Exception:
        key_usage_has_digital_signature = None

    if key_usage:
        if key_usage_has_digital_signature is True:
            extensions["key_usage"]["ok"] = True
            extensions["key_usage"]["comment"] = "L'usage digitalSignature est bien présent dans le certificat"
            extensions["key_usage"]["risk"] = "INFO"
        else:
            extensions["key_usage"]["ok"] = False
            extensions["key_usage"]["comment"] = "L'usage digitalSignature est absent, ce qui est atypique pour TLS"
            extensions["key_usage"]["risk"] = "MEDIUM"
    else:
        extensions["key_usage"]["ok"] = None
        extensions["key_usage"]["comment"] = "L'extension Key Usage est absente du certificat"
        extensions["key_usage"]["risk"] = "MEDIUM"

    # ------------------- CRL DISITRIBUTION ---------------------
    crl_distribution_points = extensions["crl_distribution_points"]["value"]
    if crl_distribution_points:
        extensions["crl_distribution_points"]["ok"] = True
        extensions["crl_distribution_points"]["comment"] = "Le certificat indique un ou plusieurs points de révocation CRL"
        extensions["crl_distribution_points"]["risk"] = "INFO"
    else:
        extensions["crl_distribution_points"]["ok"] = None
        extensions["crl_distribution_points"]["comment"] = "Aucun point de distribution CRL n'est indiqué dans le certificat"
        extensions["crl_distribution_points"]["risk"] = "LOW"

    return extensions
