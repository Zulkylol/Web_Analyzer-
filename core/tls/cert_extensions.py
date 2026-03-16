# core/tls/cert_extensions.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations

from cryptography import x509


# ===============================================================
# FUNCTION : analyze_extensions
# ===============================================================
def analyze_extensions(x509_cert: x509.Certificate) -> dict:
    """
    Extract and validate common X.509 extensions for a TLS server certificate.

    Returns:
        dict: Extensions analysis block.
    """
    extensions = {
        "key_usage": "",
        "extended_key_usage": "",
        "basic_constraints": "",
        "crl_distribution_points": "",
        "basic_constraints_ok": None,
        "basic_constraints_comment": "",
        "eku_ok": None,
        "eku_comment": "",
        "ku_ok": None,
        "ku_comment": "",
        "crl_ok": None,
        "crl_comment": "",
    }

    for extension_class, key in [
        (x509.BasicConstraints, "basic_constraints"),
        (x509.KeyUsage, "key_usage"),
        (x509.ExtendedKeyUsage, "extended_key_usage"),
        (x509.CRLDistributionPoints, "crl_distribution_points"),
    ]:
        try:
            extension = x509_cert.extensions.get_extension_for_class(extension_class)
            extensions[key] = str(extension.value)
        except Exception:
            pass

    basic_constraints = extensions["basic_constraints"]
    if basic_constraints:
        if "CA=True" in basic_constraints:
            extensions["basic_constraints_ok"] = False
            extensions["basic_constraints_comment"] = "Certificat marque comme CA (anormal pour serveur)."
        else:
            extensions["basic_constraints_ok"] = True
            extensions["basic_constraints_comment"] = "Certificat non CA."
    else:
        extensions["basic_constraints_ok"] = None
        extensions["basic_constraints_comment"] = "BasicConstraints absent."

    extended_key_usage = extensions["extended_key_usage"]
    if extended_key_usage:
        if "serverAuth" in extended_key_usage or "TLS Web Server Authentication" in extended_key_usage:
            extensions["eku_ok"] = True
            extensions["eku_comment"] = "EKU autorise l'authentification serveur."
        else:
            extensions["eku_ok"] = False
            extensions["eku_comment"] = "EKU ne contient pas serverAuth."
    else:
        extensions["eku_ok"] = None
        extensions["eku_comment"] = "EKU absent."

    key_usage = extensions["key_usage"]
    if key_usage:
        if "digital_signature" in key_usage:
            extensions["ku_ok"] = True
            extensions["ku_comment"] = "digitalSignature present."
        else:
            extensions["ku_ok"] = False
            extensions["ku_comment"] = "digitalSignature absent."
    else:
        extensions["ku_ok"] = None
        extensions["ku_comment"] = "KeyUsage absent."

    crl_distribution_points = extensions["crl_distribution_points"]
    if crl_distribution_points:
        extensions["crl_ok"] = True
        extensions["crl_comment"] = "Point(s) de revocation indique(s)."
    else:
        extensions["crl_ok"] = None
        extensions["crl_comment"] = "Aucun point CRL indique."

    return extensions
