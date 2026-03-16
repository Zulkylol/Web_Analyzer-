from __future__ import annotations

from cryptography import x509


# ===============================================================
# FUNCTION : analyze_public_key
# ===============================================================
def analyze_public_key(x509_cert: x509.Certificate) -> dict:
    """
    Analyze the certificate public key and assess its strength for TLS usage.

    Returns:
        dict: Public key analysis block.
    """
    public_key_result = {
        "type": "",
        "size": None,
        "curve": "",
        "ok": True,
        "comment": "",
        "summary": "",
    }

    try:
        public_key = x509_cert.public_key()
        public_key_type = public_key.__class__.__name__
        public_key_size = getattr(public_key, "key_size", None)

        public_key_result["type"] = public_key_type
        public_key_result["size"] = public_key_size

        curve_name = ""
        if hasattr(public_key, "curve") and public_key.curve is not None:
            curve_name = getattr(public_key.curve, "name", "") or ""
        public_key_result["curve"] = curve_name

        if public_key_type == "RSAPublicKey":
            if not public_key_size:
                public_key_result["ok"] = None
                public_key_result["comment"] = "Taille RSA inconnue."
            elif public_key_size < 2048:
                public_key_result["ok"] = False
                public_key_result["comment"] = f"RSA {public_key_size} bits (trop faible)."
            elif public_key_size == 2048:
                public_key_result["ok"] = True
                public_key_result["comment"] = "RSA 2048 bits (minimum moderne)."
            elif public_key_size == 3072:
                public_key_result["ok"] = True
                public_key_result["comment"] = "RSA 3072 bits (tres bien)."
            else:
                public_key_result["ok"] = True
                public_key_result["comment"] = (
                    f"RSA {public_key_size} bits (robuste, mais plus lent / pas forcement utile)."
                )

        elif public_key_type in ("EllipticCurvePublicKey", "ECPublicKey"):
            good_curves = {"secp256r1", "prime256v1", "secp384r1", "secp521r1"}
            weak_curves = {"secp192r1", "secp224r1"}
            curve_name_lower = (curve_name or "").lower()

            if not curve_name_lower:
                public_key_result["ok"] = None
                public_key_result["comment"] = "Cle EC detectee mais courbe inconnue."
            elif curve_name_lower in weak_curves:
                public_key_result["ok"] = False
                public_key_result["comment"] = f"Courbe EC faible/legacy ({curve_name})."
            elif curve_name_lower in good_curves:
                public_key_result["ok"] = True
                public_key_result["comment"] = f"Courbe EC moderne ({curve_name})."
            else:
                public_key_result["ok"] = None
                public_key_result["comment"] = f"Courbe EC non standard a verifier ({curve_name})."

        elif public_key_type == "DSAPublicKey":
            public_key_result["ok"] = False
            public_key_result["comment"] = "DSA (deconseille/obsolete pour TLS serveur)."
        else:
            public_key_result["ok"] = None
            public_key_result["comment"] = f"Type de cle non standard ({public_key_type}) a verifier."

        if public_key_type == "RSAPublicKey":
            public_key_result["summary"] = (
                f"RSA {public_key_size} bits" if public_key_size else "RSA (taille inconnue)"
            )
        elif public_key_type in ("EllipticCurvePublicKey", "ECPublicKey"):
            public_key_result["summary"] = f"EC {curve_name}" if curve_name else "EC (courbe inconnue)"
        elif public_key_type == "DSAPublicKey":
            public_key_result["summary"] = f"DSA {public_key_size} bits" if public_key_size else "DSA"
        else:
            public_key_result["summary"] = public_key_type

    except Exception as exc:
        public_key_result["ok"] = None
        public_key_result["comment"] = f"Impossible d'analyser la cle publique: {exc}"

    return public_key_result
