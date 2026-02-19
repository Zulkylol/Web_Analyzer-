# core/tls/cert_metadata.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations
from cryptography import x509
from cryptography.hazmat.primitives import hashes

# ===============================================================
# FUNCTION : analyze_metadata()
# ===============================================================
def analyze_metadata(result: dict, x509_cert: x509.Certificate) -> None:
    """
    Analyze certificate metadata (version, serial number, and signature).

    Updates result["certificate"] in place with validation flags and comments
    regarding:
        - X.509 version (expects v3)
        - Serial number validity and bit length
        - Signature hash algorithm strength
        - SHA-256 fingerprint

    Args:
        result (dict): Analysis dictionary to update.
        x509_cert (x509.Certificate): Parsed certificate object.
    """
    cert = result["certificate"]
    cert_version = cert["version"]
    cert_serial = cert["serial"]
    cert_signature = cert["signature"]

    # Version
    cert_version["id"] = x509_cert.version.name
    if x509_cert.version.name != "v3":
        cert_version["ok"] = False
        cert_version["comment"] = "Certificat non v3 (obsolète)."
    else:
        cert_version["ok"] = True
        cert_version["comment"] = "Certificat X.509 v3."

    # Serial
    sn = x509_cert.serial_number
    bitlen = sn.bit_length()
    cert_serial["hex"] = hex(sn)

    if sn <= 0:
        cert_serial["ok"] = False
        cert_serial["comment"] = "Serial non valide (doit être positif)."
    elif bitlen < 32:
        cert_serial["ok"] = True
        cert_serial["comment"] = f"⚠️ Serial très court ({bitlen} bits) : possible PKI interne/ancienne."
    else:
        cert_serial["ok"] = True
        cert_serial["comment"] = f"Serial OK ({bitlen} bits)."

    # Signature
    try:
        sig = x509_cert.signature_hash_algorithm.name.lower()
        algo = x509_cert.signature_algorithm_oid._name.lower()
        cert_signature["hash_algorithm"] = sig

        if "md5" in sig:
            ok, comment = False, "Signature MD5 (critique)."
        elif "sha1" in sig:
            ok, comment = False, "Signature SHA-1 (obsolète)."
        elif "dsa" in algo:
            ok, comment = None, "Signature DSA (déconseillée)."
        else:
            ok, comment = True, "Signature moderne (SHA-2+)."

        cert_signature["ok"] = ok
        cert_signature["comment"] = comment
    except Exception:
        cert_signature["hash_algorithm"] = ""

    try:
        cert_signature["fingerprint_sha256"] = x509_cert.fingerprint(hashes.SHA256()).hex()
    except Exception:
        cert_signature["fingerprint_sha256"] = ""
