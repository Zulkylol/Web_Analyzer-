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
    """
    Normalize a DNS name for comparison.

    Returns :
        str : normalized name
    """
    return str(value or "").strip().rstrip(".").lower()


# ===============================================================
# FUNCTION : _dns_name_matches
# ===============================================================
def _dns_name_matches(pattern: str, hostname: str) -> bool:
    """
    Match a hostname against a certificate pattern.

    Returns :
        bool : match result
    """
    pattern_text = _normalize_dns_name(pattern)
    hostname_text = _normalize_dns_name(hostname)
    if not pattern_text or not hostname_text:
        return False

    if pattern_text.startswith("*."):
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
def analyze_identity(x509_cert: x509.Certificate, hostname_for_match: str) -> dict:
    """
    Analyze certificate identity and SAN matching.

    Returns :
        dict : identity analysis
    """
    identity = {
        "common_name": "",
        "common_name_comment": "Nom commun (CN) présenté par le certificat du serveur",
        "common_name_risk": "INFO",
        "san_dns": [],
        "san_ok": False,
        "san_comment": "",
        "san_risk": "HIGH",
        "san_warning": "",
    }

    try:
        identity["common_name"] = x509_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        identity["common_name"] = ""

    common_name = identity["common_name"]

    try:
        san_extension = x509_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns = san_extension.value.get_values_for_type(x509.DNSName)
        identity["san_dns"] = [dns_name for dns_name in san_dns if dns_name != common_name]
    except Exception:
        identity["san_dns"] = []

    identity_candidates = [common_name] + identity["san_dns"]
    match = any(_dns_name_matches(candidate, hostname_for_match) for candidate in identity_candidates)
    identity["san_ok"] = match
    identity["san_comment"] = (
        "Le certificat présenté correspond bien au domaine analysé"
        if match
        else "Le certificat présenté ne correspond pas au domaine analysé"
    )
    identity["san_risk"] = "INFO" if match else "HIGH"

    san_count = len(identity["san_dns"])
    if san_count > 200:
        identity["san_warning"] = "Certificat multi-domaines massif avec un très grand nombre de SAN"
    elif san_count > 50:
        identity["san_warning"] = "Certificat multi-domaines important avec de nombreux SAN"
    else:
        identity["san_warning"] = "Certificat avec un nombre limité de SAN déclarés"

    return identity
