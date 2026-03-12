# core/tls/cert_identity.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations
from cryptography import x509
from cryptography.x509.oid import NameOID


def _normalize_dns_name(value: str) -> str:
    """Normalize DNS names for safe comparison."""
    return str(value or "").strip().rstrip(".").lower()


def _dns_name_matches(pattern: str, hostname: str) -> bool:
    """
    Match hostname against cert identity with strict wildcard handling.

    Accepted wildcard form: "*.example.com" (left-most label only),
    matching exactly one subdomain label.
    """
    p = _normalize_dns_name(pattern)
    h = _normalize_dns_name(hostname)
    if not p or not h:
        return False

    if p.startswith("*."):
        # On n'accepte que le wildcard standard du label le plus a gauche.
        suffix = p[2:]
        if not suffix or "." not in suffix:
            return False
        if not h.endswith("." + suffix):
            return False
        return h.count(".") == suffix.count(".") + 1

    return p == h


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

    # Le matching se fait sur CN + SAN pour supporter les certificats courants.
    san_list = [cn] + cert_subject["san_dns"]
    match = False
    for entry in san_list:
        if _dns_name_matches(entry, hostname_for_match):
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
    elif san_count > 50:
        hostname_check["warnings"]["multi_domain"] = "Certificat multi-domaines important"
    else:
        hostname_check["warnings"]["multi_domain"] = "Certificat avec peu de domaine"
