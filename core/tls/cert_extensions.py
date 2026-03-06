# core/tls/cert_extensions.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations
from cryptography import x509

# ===============================================================
# FUNCTION : analyze_extensions(result, x509_cert)
# ===============================================================
def analyze_extensions(result: dict, x509_cert: x509.Certificate) -> None:
    """
    Extract and validate common X.509 extensions for a TLS server certificate.

    Updates result["certificate"]["extensions"] in place with string
    values and basic validation flags/comments.

    Args:
        result (dict): Analysis dictionary to update.
        x509_cert (x509.Certificate): Parsed certificate object.
    """
    cert_ext = result["certificate"]["extensions"]

    # dump extensions as string
    for ext_class, key in [
        (x509.BasicConstraints, "basic_constraints"),
        (x509.KeyUsage, "key_usage"),
        (x509.ExtendedKeyUsage, "extended_key_usage"),
        (x509.CRLDistributionPoints, "crl_distribution_points"),
    ]:
        try:
            ext = x509_cert.extensions.get_extension_for_class(ext_class)
            cert_ext[key] = str(ext.value)
        except Exception:
            pass

    # BasicConstraints
    bc = cert_ext["basic_constraints"]
    if bc:
        if "CA=True" in bc:
            cert_ext["basic_constraints_ok"] = False
            cert_ext["basic_constraints_comment"] = "Certificat marqué comme CA (anormal pour serveur)."
        else:
            cert_ext["basic_constraints_ok"] = True
            cert_ext["basic_constraints_comment"] = "Certificat non CA."
    else:
        cert_ext["basic_constraints_ok"] = None
        cert_ext["basic_constraints_comment"] = "BasicConstraints absent."

    # EKU
    eku = cert_ext["extended_key_usage"]
    if eku:
        if "serverAuth" in eku or "TLS Web Server Authentication" in eku:
            cert_ext["eku_ok"] = True
            cert_ext["eku_comment"] = "EKU autorise l'authentification serveur."
        else:
            cert_ext["eku_ok"] = False
            cert_ext["eku_comment"] = "EKU ne contient pas serverAuth."
    else:
        cert_ext["eku_ok"] = None
        cert_ext["eku_comment"] = "EKU absent."

    # KU
    ku = cert_ext["key_usage"]
    if ku:
        if "digital_signature" in ku:
            cert_ext["ku_ok"] = True
            cert_ext["ku_comment"] = "digitalSignature présent."
        else:
            cert_ext["ku_ok"] = False
            cert_ext["ku_comment"] = "digitalSignature absent."
    else:
        cert_ext["ku_ok"] = None
        cert_ext["ku_comment"] = "KeyUsage absent."

    # CRL
    crl = cert_ext["crl_distribution_points"]
    if crl:
        cert_ext["crl_ok"] = True
        cert_ext["crl_comment"] = "Point(s) de révocation indiqué(s)."
    else:
        cert_ext["crl_ok"] = None
        cert_ext["crl_comment"] = "Aucun point CRL indiqué."
