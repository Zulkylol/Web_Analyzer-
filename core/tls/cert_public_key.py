from __future__ import annotations

from cryptography import x509


# ===============================================================
# FUNCTION : analyze_public_key
# ===============================================================
def analyze_public_key(x509_cert: x509.Certificate) -> dict:
    """
    Analyze the certificate public key.

    Returns :
        dict : public key row
    """
    public_key_row = {
        "value": "",
        "type": "",
        "size": None,
        "curve": "",
        "ok": True,
        "comment": "",
        "risk": "INFO",
    }

    try:
        public_key = x509_cert.public_key()
        public_key_type = public_key.__class__.__name__
        public_key_size = getattr(public_key, "key_size", None)

        public_key_row["type"] = public_key_type
        public_key_row["size"] = public_key_size

        curve_name = ""
        if hasattr(public_key, "curve") and public_key.curve is not None:
            curve_name = getattr(public_key.curve, "name", "") or ""
        public_key_row["curve"] = curve_name

        if public_key_type == "RSAPublicKey":
            if not public_key_size:
                public_key_row["ok"] = None
                public_key_row["comment"] = "La taille de la clé RSA n'a pas pu être déterminée"
                public_key_row["risk"] = "MEDIUM"
            elif public_key_size < 2048:
                public_key_row["ok"] = False
                public_key_row["comment"] = f"La clé RSA est de {public_key_size} bits, ce qui est trop faible aujourd'hui"
                public_key_row["risk"] = "HIGH"
            elif public_key_size == 2048:
                public_key_row["ok"] = True
                public_key_row["comment"] = "La clé RSA est de 2048 bits, soit le minimum moderne acceptable"
                public_key_row["risk"] = "INFO"
            elif public_key_size == 3072:
                public_key_row["ok"] = True
                public_key_row["comment"] = "La clé RSA est de 3072 bits, avec un niveau de robustesse très correct"
                public_key_row["risk"] = "INFO"
            else:
                public_key_row["ok"] = True
                public_key_row["comment"] = (
                    f"La clé RSA est de {public_key_size} bits ; elle est robuste, mais plus coûteuse sans bénéfice toujours utile"
                )
                public_key_row["risk"] = "INFO"

        elif public_key_type in ("EllipticCurvePublicKey", "ECPublicKey"):
            good_curves = {"secp256r1", "prime256v1", "secp384r1", "secp521r1"}
            weak_curves = {"secp192r1", "secp224r1"}
            curve_name_lower = (curve_name or "").lower()

            if not curve_name_lower:
                public_key_row["ok"] = None
                public_key_row["comment"] = "Une clé EC a été détectée, mais la courbe n'a pas pu être identifiée"
                public_key_row["risk"] = "MEDIUM"
            elif curve_name_lower in weak_curves:
                public_key_row["ok"] = False
                public_key_row["comment"] = f"La courbe EC utilisée ({curve_name}) est faible ou legacy"
                public_key_row["risk"] = "HIGH"
            elif curve_name_lower in good_curves:
                public_key_row["ok"] = True
                public_key_row["comment"] = f"La courbe EC utilisée ({curve_name}) est moderne et adaptée"
                public_key_row["risk"] = "INFO"
            else:
                public_key_row["ok"] = None
                public_key_row["comment"] = f"La courbe EC utilisée ({curve_name}) n'est pas standard et mérite vérification"
                public_key_row["risk"] = "MEDIUM"

        elif public_key_type == "DSAPublicKey":
            public_key_row["ok"] = False
            public_key_row["comment"] = "Une clé DSA a été détectée ; cet usage est déconseillé et obsolète pour TLS serveur"
            public_key_row["risk"] = "HIGH"
        else:
            public_key_row["ok"] = None
            public_key_row["comment"] = f"Le type de clé détecté ({public_key_type}) n'est pas standard et mérite vérification"
            public_key_row["risk"] = "MEDIUM"

        if public_key_type == "RSAPublicKey":
            public_key_row["value"] = f"RSA {public_key_size} bits" if public_key_size else "RSA (taille inconnue)"
        elif public_key_type in ("EllipticCurvePublicKey", "ECPublicKey"):
            public_key_row["value"] = f"EC {curve_name}" if curve_name else "EC (courbe inconnue)"
        elif public_key_type == "DSAPublicKey":
            public_key_row["value"] = f"DSA {public_key_size} bits" if public_key_size else "DSA"
        else:
            public_key_row["value"] = public_key_type

    except Exception as exc:
        public_key_row["ok"] = None
        public_key_row["comment"] = f"Impossible d'analyser la clé publique : {exc}"
        public_key_row["risk"] = "MEDIUM"

    return public_key_row
