# core/tls/cert_public_key.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# ===============================================================
# FUNCTION : analyze_public_key()
# ===============================================================
def analyze_public_key(result: dict, x509_cert: x509.Certificate) -> None:
    """
    Analyze the certificate public key and assess its strength for TLS usage.

    Extracts key type, size, curve (if EC), PEM encoding, and generates validation flags/comments 
    based on common security recommendations (e.g., RSA key length, accepted EC curves, DSA deprecation).

    Updates result["certificate"]["public_key"] in place with:
        - type, size, curve, pem
        - ok (bool | None)
        - comment (str)
        - summary (str)

    Args:
        result (dict): Analysis dictionary to update.
        x509_cert (x509.Certificate): Parsed certificate object.
    """
    cert_public_key = result["certificate"]["public_key"]

    try:
        public_key = x509_cert.public_key()
        pk_type = public_key.__class__.__name__
        pk_size = getattr(public_key, "key_size", None)

        cert_public_key["type"] = pk_type
        cert_public_key["size"] = pk_size

        try:
            cert_public_key["pem"] = public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        except Exception:
            cert_public_key["pem"] = ""

        curve_name = ""
        if hasattr(public_key, "curve") and public_key.curve is not None:
            curve_name = getattr(public_key.curve, "name", "") or ""
        cert_public_key["curve"] = curve_name

        ok = True
        comment = ""

        if pk_type == "RSAPublicKey":
            if not pk_size:
                ok, comment = None, "Taille RSA inconnue."
            elif pk_size < 2048:
                ok, comment = False, f"RSA {pk_size} bits (trop faible)."
            elif pk_size == 2048:
                ok, comment = True, "RSA 2048 bits (minimum moderne)."
            elif pk_size == 3072:
                ok, comment = True, "RSA 3072 bits (très bien)."
            else:
                ok, comment = None, f"RSA {pk_size} bits (OK, mais plus lent / pas forcément utile)."

        elif pk_type in ("EllipticCurvePublicKey", "ECPublicKey"):
            good = {"secp256r1", "prime256v1", "secp384r1", "secp521r1"}
            bad = {"secp192r1", "secp224r1"}
            c = (curve_name or "").lower()

            if not c:
                ok, comment = None, "Clé EC détectée mais courbe inconnue."
            elif c in bad:
                ok, comment = False, f"Courbe EC faible/legacy ({curve_name})."
            elif c in good:
                ok, comment = True, f"Courbe EC moderne ({curve_name})."
            else:
                ok, comment = None, f"Courbe EC non standard à vérifier ({curve_name})."

        elif pk_type == "DSAPublicKey":
            ok, comment = False, "DSA (déconseillé/obsolète pour TLS serveur)."
        else:
            ok, comment = None, f"Type de clé non standard ({pk_type}) à vérifier."

        cert_public_key["ok"] = ok
        cert_public_key["comment"] = comment

        if pk_type == "RSAPublicKey":
            cert_public_key["summary"] = f"RSA {pk_size} bits" if pk_size else "RSA (taille inconnue)"
        elif pk_type in ("EllipticCurvePublicKey", "ECPublicKey"):
            cert_public_key["summary"] = f"EC {curve_name}" if curve_name else "EC (courbe inconnue)"
        elif pk_type == "DSAPublicKey":
            cert_public_key["summary"] = f"DSA {pk_size} bits" if pk_size else "DSA"
        else:
            cert_public_key["summary"] = pk_type

    except Exception as e:
        cert_public_key["ok"] = None
        cert_public_key["comment"] = f"⚠️ Impossible d'analyser la clé publique: {e}"
