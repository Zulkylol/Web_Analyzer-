# core/tls/cert_identity.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations

from cryptography import x509
from cryptography.x509.oid import NameOID


# ===============================================================
# FUNCTION : _normalize_dns_name
# ===============================================================
def _normalize_dns_name(value: str) -> str:
    """Normalize DNS names for safe comparison."""
    return str(value or "").strip().rstrip(".").lower()


# ===============================================================
# FUNCTION : _dns_name_matches
# ===============================================================
def _dns_name_matches(pattern: str, hostname: str) -> bool:
    """
    Match hostname against cert identity with strict wildcard handling.

    Accepted wildcard form: "*.example.com" (left-most label only),
    matching exactly one subdomain label.
    """
    pattern_text = _normalize_dns_name(pattern)
    hostname_text = _normalize_dns_name(hostname)
    if not pattern_text or not hostname_text:
        return False

    if pattern_text.startswith("*."):
        # Only accept the standard left-most-label wildcard form.
        suffix = pattern_text[2:]
        if not suffix or "." not in suffix:
            return False
        if not hostname_text.endswith("." + suffix):
            return False
        return hostname_text.count(".") == suffix.count(".") + 1

    return pattern_text == hostname_text


# ===============================================================
# FUNCTION : analyze_identity
# ===============================================================
def analyze_identity(x509_cert: x509.Certificate, hostname_for_match: str) -> tuple[dict, dict, dict]:
    """
    Extract certificate identity information and evaluate hostname matching.

    Returns:
        tuple[dict, dict, dict]:
            - subject
            - issuer
            - hostname_check
    """
    subject = {"common_name": "", "san_dns": []}
    issuer = {"common_name": ""}
    hostname_check = {
        "match": False,
        "comment": "",
        "warnings": {"multi_domain": ""},
    }

    try:
        subject["common_name"] = x509_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        subject["common_name"] = ""

    for attribute in x509_cert.issuer:
        if attribute.oid._name == "commonName":
            issuer["common_name"] = attribute.value
            break

    common_name = subject["common_name"]

    try:
        san_extension = x509_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns = san_extension.value.get_values_for_type(x509.DNSName)
        subject["san_dns"] = [dns_name for dns_name in san_dns if dns_name != common_name]
    except Exception:
        subject["san_dns"] = []

    identity_candidates = [common_name] + subject["san_dns"]
    match = any(_dns_name_matches(candidate, hostname_for_match) for candidate in identity_candidates)
    hostname_check["match"] = match
    hostname_check["comment"] = (
        "Le certificat correspond au domaine"
        if match
        else "Le certificat ne correspond PAS au domaine"
    )

    san_count = len(subject["san_dns"])
    if san_count > 200:
        hostname_check["warnings"]["multi_domain"] = "Certificat multi-domaines massif"
    elif san_count > 50:
        hostname_check["warnings"]["multi_domain"] = "Certificat multi-domaines important"
    else:
        hostname_check["warnings"]["multi_domain"] = "Certificat avec peu de domaine"

    return subject, issuer, hostname_check
