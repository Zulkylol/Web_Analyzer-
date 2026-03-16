# core/tls/protocol.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations

import ssl

from utils.tls import server_accepts_cipher, server_supports_tls_version


# ===============================================================
# FUNCTION : analyze_tls_versions_and_policy
# ===============================================================
def analyze_tls_versions_and_policy(version_value: str, url: str) -> tuple[dict, dict, dict]:
    """
    Analyze TLS version support and policy.

    Returns :
        tuple[dict, dict, dict] : version row, supported versions, policy row
    """
    
    # ----------------------- ACTUAL VERSION ---------------------------
    version = {"value": version_value, "ok": None, "comment": "", "risk": "MEDIUM"}

    if version_value == "TLSv1":
        version["ok"] = False
        version["comment"] = "TLS 1.0 est obsolète et présente des faiblesses connues"
        version["risk"] = "HIGH"
    elif version_value == "TLSv1.1":
        version["ok"] = False
        version["comment"] = "TLS 1.1 est obsolète et devrait être désactivé"
        version["risk"] = "HIGH"
    elif version_value == "TLSv1.2":
        version["ok"] = True
        version["comment"] = "TLS 1.2 reste sécurisé, même s'il est progressivement remplacé par TLS 1.3"
        version["risk"] = "LOW"
    elif version_value == "TLSv1.3":
        version["ok"] = True
        version["comment"] = "TLS 1.3 est la version la plus moderne et actuellement recommandée"
        version["risk"] = "INFO"
    else:
        version["ok"] = None
        version["comment"] = "La version TLS négociée est inconnue ou n'a pas pu être analysée"
        version["risk"] = "MEDIUM"

    
    # --------------------- SUPPORTED VERSIONS -------------------------
    supported_versions = {}
    for tls_name, tls_version in [
        ("TLS1.0", ssl.TLSVersion.TLSv1),
        ("TLS1.1", ssl.TLSVersion.TLSv1_1),
        ("TLS1.2", ssl.TLSVersion.TLSv1_2),
        ("TLS1.3", ssl.TLSVersion.TLSv1_3),
    ]:
        supported = server_supports_tls_version(url, tls_version)
        if tls_name in {"TLS1.0", "TLS1.1"}:
            comment = (
                "Cette version legacy est encore acceptée par le serveur et devrait être désactivée"
                if supported
                else "Cette version legacy n'est pas supportée par le serveur"
            )
            risk = "HIGH" if supported else "INFO"
            ok = not supported
        else:
            comment = (
                "Cette version est supportée par le serveur"
                if supported
                else "Cette version n'est pas supportée par le serveur"
            )
            risk = "INFO"
            ok = supported

        supported_versions[tls_name] = {
            "supported": supported,
            "ok": ok,
            "comment": comment,
            "risk": risk,
        }

    # ----------------------- VERSION POLICY ---------------------------
    if supported_versions["TLS1.0"]["supported"] or supported_versions["TLS1.1"]["supported"]:
        disabled_legacy_versions = []
        if supported_versions["TLS1.0"]["supported"]:
            disabled_legacy_versions.append("TLS 1.0")
        if supported_versions["TLS1.1"]["supported"]:
            disabled_legacy_versions.append("TLS 1.1")
        policy = {
            "value": "KO",
            "ok": False,
            "comment": f"Le serveur accepte encore {', '.join(disabled_legacy_versions)} ; ces versions TLS sont obsolètes",
            "risk": "HIGH",
        }
    elif supported_versions["TLS1.3"]["supported"]:
        policy = {
            "value": "OK",
            "ok": True,
            "comment": "TLS 1.0 et TLS 1.1 sont désactivés, et TLS 1.3 est bien supporté",
            "risk": "INFO",
        }
    elif supported_versions["TLS1.2"]["supported"]:
        policy = {
            "value": "OK",
            "ok": True,
            "comment": "TLS 1.0 et TLS 1.1 sont désactivés, et TLS 1.2 reste supporté",
            "risk": "INFO",
        }
    else:
        policy = {
            "value": "KO",
            "ok": False,
            "comment": "Le serveur ne supporte pas TLS 1.2 ou supérieur, ce qui pose un réel problème",
            "risk": "HIGH",
        }

    return version, supported_versions, policy


# ===============================================================
# FUNCTION : analyze_cipher_and_weak_ciphers
# ===============================================================
def analyze_cipher_and_weak_ciphers(
    cipher_name: str,
    cipher_bits: int,
    supported_versions: dict,
    hostname: str,
    port: int,
) -> tuple[dict, dict]:
    """
    Analyze the negotiated cipher and weak cipher support.

    Returns :
        tuple[dict, dict] : cipher row, weak ciphers row
    """
    cipher = {
        "value": cipher_name,
        "name": cipher_name,
        "bits": cipher_bits,
        "ok": True,
        "comment": "",
        "risk": "INFO",
        "bits_risk": "HIGH" if (cipher_bits or 0) < 128 else "INFO",
    }

    weak_algorithms = ["RC4", "3DES", "DES", "MD5"]
    if any(algorithm in cipher_name for algorithm in weak_algorithms):
        cipher["ok"] = False
        cipher["comment"] = "Une suite cryptographique faible a été détectée (RC4/3DES/DES/MD5)"
        cipher["risk"] = "HIGH"
    elif cipher_bits and cipher_bits < 128:
        cipher["ok"] = False
        cipher["comment"] = "La taille de clé négociée est inférieure à 128 bits"
        cipher["risk"] = "HIGH"
    elif "GCM" in cipher_name or "CHACHA20" in cipher_name:
        cipher["ok"] = True
        cipher["comment"] = "La suite cryptographique négociée est moderne et de type AEAD"
        cipher["risk"] = "INFO"
    else:
        cipher["ok"] = True
        cipher["comment"] = "La suite cryptographique négociée reste acceptable dans ce contexte"
        cipher["risk"] = "INFO"

    supports_legacy_tls = any(
        bool((supported_versions.get(version_name) or {}).get("supported"))
        for version_name in ("TLS1.0", "TLS1.1", "TLS1.2")
    )
    if not supports_legacy_tls:
        return (
            cipher,
            {
                "value": "OK",
                "support": {},
                "ok": True,
                "comment": "Le serveur fonctionne uniquement en TLS 1.3 ; aucun cipher legacy n'est testable",
                "risk": "INFO",
            },
        )

    weak_cipher_tests = {
        "3DES": "DES-CBC3-SHA",
        "AES-CBC": "AES128-SHA:AES256-SHA",
        "RC4": "RC4-SHA",
        "MD5": "RSA-MD5",
    }

    weak_cipher_support = {}
    for weak_name, cipher_string in weak_cipher_tests.items():
        weak_cipher_support[weak_name] = server_accepts_cipher(
            hostname,
            port,
            ssl.TLSVersion.TLSv1_2,
            cipher_string,
        )

    if any(weak_cipher_support.values()):
        accepted_weak_ciphers = [name for name, accepted in weak_cipher_support.items() if accepted]
        if any(weak_cipher_support.get(name) for name in ("3DES", "RC4", "MD5")):
            weak_risk = "HIGH"
        elif weak_cipher_support.get("AES-CBC"):
            weak_risk = "LOW"
        else:
            weak_risk = "LOW"

        weak_ciphers = {
            "value": "Faible",
            "support": weak_cipher_support,
            "ok": False,
            "comment": f"Le serveur accepte encore les suites faibles suivantes : {', '.join(accepted_weak_ciphers)}",
            "risk": weak_risk,
        }
    else:
        weak_ciphers = {
            "value": "OK",
            "support": weak_cipher_support,
            "ok": True,
            "comment": "Aucune suite cryptographique faible n'a été acceptée par le serveur",
            "risk": "INFO",
        }

    return cipher, weak_ciphers
