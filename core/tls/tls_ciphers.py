# core/tls/tls_ciphers.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations

import ssl

from utils.tls import server_accepts_cipher


# ===============================================================
# FUNCTION : analyze_cipher_and_weak_ciphers
# ===============================================================
def analyze_cipher_and_weak_ciphers(
    cipher_name: str,
    cipher_bits: int,
    supported_versions: dict,
    hostname: str,
    port: int,
) -> tuple[bool | None, str, dict, bool | None, str]:
    """
    Evaluate the negotiated cipher and test support for weak ciphers.

    Returns:
        tuple[bool | None, str, dict, bool | None, str]:
            - cipher_ok
            - cipher_comment
            - weak_cipher_support
            - weak_cipher_ok
            - weak_cipher_comment
    """
    weak_algorithms = ["RC4", "3DES", "DES", "MD5"]
    if any(algorithm in cipher_name for algorithm in weak_algorithms):
        cipher_ok = False
        cipher_comment = "Cipher faible detectee (RC4/3DES/DES/MD5)"
    elif cipher_bits and cipher_bits < 128:
        cipher_ok = False
        cipher_comment = "Taille de cle inferieure a 128 bits"
    elif "GCM" in cipher_name or "CHACHA20" in cipher_name:
        cipher_ok = True
        cipher_comment = "Cipher moderne securisee (AEAD)"
    else:
        cipher_ok = True
        cipher_comment = "Cipher acceptable."

    if not (
        supported_versions.get("TLS1.0")
        or supported_versions.get("TLS1.1")
        or supported_versions.get("TLS1.2")
    ):
        return (
            cipher_ok,
            cipher_comment,
            {},
            True,
            "Serveur uniquement TLS 1.3 -> pas de ciphers legacy testables",
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
        weak_cipher_ok = False
        weak_cipher_comment = f"Le serveur accepte encore : {', '.join(accepted_weak_ciphers)}"
    else:
        weak_cipher_ok = True
        weak_cipher_comment = "Aucun cipher faible accepte"

    return cipher_ok, cipher_comment, weak_cipher_support, weak_cipher_ok, weak_cipher_comment
