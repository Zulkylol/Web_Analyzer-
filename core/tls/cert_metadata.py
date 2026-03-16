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
def analyze_metadata(x509_cert: x509.Certificate) -> dict:
    """
    Analyze certificate metadata fields.

    Returns :
        dict : metadata rows
    """
    version = {"value": "", "ok": False, "comment": "", "risk": "MEDIUM"}
    serial = {"value": "", "ok": True, "comment": "", "risk": "INFO"}
    signature = {"value": "", "ok": True, "comment": "", "risk": "INFO"}
    fingerprint = {"value": "", "comment": "Empreinte SHA-256 du certificat présenté par le serveur", "risk": "INFO"}

    # ----------------------- VERSION ---------------------------
    version["value"] = x509_cert.version.name
    if x509_cert.version.name != "v3":
        version["ok"] = False
        version["comment"] = "Le certificat utilise une version antérieure à X.509 v3"
        version["risk"] = "MEDIUM"
    else:
        version["ok"] = True
        version["comment"] = "Le certificat utilise le format X.509 v3"
        version["risk"] = "INFO"

    # ------------------------ SERIAL ---------------------------
    serial_number = x509_cert.serial_number
    serial_bit_length = serial_number.bit_length()
    serial["value"] = hex(serial_number)

    if serial_number <= 0:
        serial["ok"] = False
        serial["comment"] = "Le numéro de série n'est pas valide ; il doit être strictement positif"
        serial["risk"] = "INFO"
    elif serial_bit_length < 32:
        serial["ok"] = True
        serial["comment"] = (
            f"Le numéro de série est très court ({serial_bit_length} bits), ce qui évoque souvent une PKI interne ou ancienne"
        )
        serial["risk"] = "INFO"
    else:
        serial["ok"] = True
        serial["comment"] = f"Le numéro de série a une longueur correcte ({serial_bit_length} bits)"
        serial["risk"] = "INFO"

    # ----------------------- SIGNATURE -------------------------
    try:
        signature_hash = x509_cert.signature_hash_algorithm.name.lower()
        signature_algorithm = x509_cert.signature_algorithm_oid._name.lower()
        signature["value"] = signature_hash

        if "md5" in signature_hash:
            signature["ok"] = False
            signature["comment"] = "Une signature MD5 a été détectée ; cet algorithme est critique"
            signature["risk"] = "HIGH"
        elif "sha1" in signature_hash:
            signature["ok"] = False
            signature["comment"] = "Une signature SHA-1 a été détectée ; cet algorithme est aujourd'hui obsolète"
            signature["risk"] = "HIGH"
        elif "dsa" in signature_algorithm:
            signature["ok"] = None
            signature["comment"] = "Une signature DSA a été détectée ; cet algorithme est déconseillé pour TLS"
            signature["risk"] = "MEDIUM"
        else:
            signature["ok"] = True
            signature["comment"] = "L'algorithme de signature appartient à une famille moderne (SHA-2 ou supérieure)"
            signature["risk"] = "INFO"
    except Exception:
        signature["value"] = ""
        signature["ok"] = None
        signature["comment"] = "Impossible d'analyser l'algorithme de signature du certificat"
        signature["risk"] = "MEDIUM"
    
    # ---------------------- FINGERPRINT ------------------------
    try:
        fingerprint["value"] = x509_cert.fingerprint(hashes.SHA256()).hex()
    except Exception:
        fingerprint["value"] = ""

    return {
        "version": version,
        "serial": serial,
        "signature": signature,
        "fingerprint": fingerprint,
    }
