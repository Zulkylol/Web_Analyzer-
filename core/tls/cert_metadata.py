# core/tls/cert_metadata.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes


# ===============================================================
# FUNCTION : analyze_metadata
# ===============================================================
def analyze_metadata(x509_cert: x509.Certificate) -> tuple[dict, dict, dict]:
    """
    Analyze certificate metadata (version, serial number, and signature).

    Returns:
        tuple[dict, dict, dict]:
            - version
            - serial
            - signature
    """
    version = {"id": "", "ok": False, "comment": ""}
    serial = {"hex": "", "ok": True, "comment": ""}
    signature = {
        "hash_algorithm": "",
        "fingerprint_sha256": "",
        "ok": True,
        "comment": "",
    }

    version["id"] = x509_cert.version.name
    if x509_cert.version.name != "v3":
        version["ok"] = False
        version["comment"] = "Certificat non v3 (obsolete)."
    else:
        version["ok"] = True
        version["comment"] = "Certificat X.509 v3."

    serial_number = x509_cert.serial_number
    serial_bit_length = serial_number.bit_length()
    serial["hex"] = hex(serial_number)

    if serial_number <= 0:
        serial["ok"] = False
        serial["comment"] = "Serial non valide (doit etre positif)."
    elif serial_bit_length < 32:
        serial["ok"] = True
        serial["comment"] = f"Serial tres court ({serial_bit_length} bits) : possible PKI interne/ancienne."
    else:
        serial["ok"] = True
        serial["comment"] = f"Serial OK ({serial_bit_length} bits)."

    try:
        signature_hash = x509_cert.signature_hash_algorithm.name.lower()
        signature_algorithm = x509_cert.signature_algorithm_oid._name.lower()
        signature["hash_algorithm"] = signature_hash

        if "md5" in signature_hash:
            signature["ok"] = False
            signature["comment"] = "Signature MD5 (critique)."
        elif "sha1" in signature_hash:
            signature["ok"] = False
            signature["comment"] = "Signature SHA-1 (obsolete)."
        elif "dsa" in signature_algorithm:
            signature["ok"] = None
            signature["comment"] = "Signature DSA (deconseillee)."
        else:
            signature["ok"] = True
            signature["comment"] = "Signature moderne (SHA-2+)."
    except Exception:
        signature["hash_algorithm"] = ""

    try:
        signature["fingerprint_sha256"] = x509_cert.fingerprint(hashes.SHA256()).hex()
    except Exception:
        signature["fingerprint_sha256"] = ""

    return version, serial, signature
