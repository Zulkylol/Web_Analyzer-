# core/tls/cert_identity.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations
from cryptography import x509
from cryptography.x509.oid import NameOID

# ===============================================================
# FUNCTION : analyze_identity()
# ===============================================================
def analyze_identity(result: dict, x509_cert: x509.Certificate, hostname_for_match: str) -> None:
    """
    Extract certificate identity (CN/SAN) and check if it matches the given hostname.

    Updates result["certificate"]["subject"], result["certificate"]["issuer"], and
    result["hostname_check"] in place (match/comment + multi-domain warning).

    Args:
        result (dict): Analysis dictionary to update.
        x509_cert (x509.Certificate): Parsed certificate object.
        hostname_for_match (str): Hostname to validate against CN/SAN (supports wildcards).
    """
    cert = result["certificate"]
    cert_subject = cert["subject"]
    cert_issuer = cert["issuer"]
    hostname_check = result["hostname_check"]

    # Subject CN
    try:
        cert_subject["common_name"] = (
            x509_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        )
    except IndexError:
        cert_subject["common_name"] = ""

    # Issuer CN
    for attr in x509_cert.issuer:
        if attr.oid._name == "commonName":
            cert_issuer["common_name"] = attr.value

    cn = cert_subject["common_name"]

    # SAN DNS
    try:
        san_ext = x509_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns = san_ext.value.get_values_for_type(x509.DNSName)
        cert_subject["san_dns"] = [d for d in san_dns if d != cn]
    except Exception:
        cert_subject["san_dns"] = []

    # Host match (CN + SAN)
    san_list = [cn] + cert_subject["san_dns"]
    match = False
    for entry in san_list:
        if entry.startswith("*."):
            if hostname_for_match.endswith(entry[1:]):
                match = True
                break
        elif entry == hostname_for_match:
            match = True
            break

    hostname_check["match"] = match
    hostname_check["comment"] = (
        "Le certificat correspond au domaine" if match else "Le certificat ne correspond PAS au domaine"
    )

    # Multi-domain warning
    san_count = len(cert_subject["san_dns"])
    if san_count > 200:
        hostname_check["warnings"]["multi_domain"] = "Certificat multi-domaines massif"
        hostname_check["ok"] = None
    elif san_count > 50:
        hostname_check["warnings"]["multi_domain"] = "Certificat multi-domaines important"
        hostname_check["ok"] = None
    else:
        hostname_check["warnings"]["multi_domain"] = "Certificat avec peu de domaine"
        hostname_check["ok"] = True
