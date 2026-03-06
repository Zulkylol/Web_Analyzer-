# core/tls/tls_ciphers.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations
import ssl
from utils.tls import server_accepts_cipher

# ===============================================================
# FUNCTION : analyze_cipher_and_weak_ciphers()
# ===============================================================
def analyze_cipher_and_weak_ciphers(result: dict, hostname: str, port: int) -> None:
    """
    Evaluate the negotiated cipher and test support for weak ciphers.

    Assesses cipher strength (algorithm and key size) and checks whether
    the server still accepts legacy/weak ciphers under TLS ≤ 1.2.

    Updates result["tls"] in place with:
        - cipher validation (ok/comment)
        - weak_cipher_support results
        - weak_cipher_ok (bool)
        - weak_cipher_comment (str)

    Args:
        result (dict): Analysis dictionary to update.
        hostname (str): Target host.
        port (int): Target port.
    """
    tls = result["tls"]
    tls_cipher = tls["cipher"]
    support = tls.get("supported_versions", {})

    name = tls_cipher.get("name", "")
    bits = tls_cipher.get("bits", 0)

    weak_algorithms = ["RC4", "3DES", "DES", "MD5"]
    if any(w in name for w in weak_algorithms):
        tls_cipher["ok"] = False
        tls_cipher["comment"] = "Cipher faible détectée (RC4/3DES/DES/MD5)"
    elif bits and bits < 128:
        tls_cipher["ok"] = False
        tls_cipher["comment"] = "Taille de clé inférieure à 128 bits"
    elif "GCM" in name or "CHACHA20" in name:
        tls_cipher["ok"] = True
        tls_cipher["comment"] = "Cipher moderne sécurisée (AEAD)"
    else:
        tls_cipher["ok"] = True
        tls_cipher["comment"] = "Cipher acceptable."

    # Weak cipher tests
    if not (support.get("TLS1.0") or support.get("TLS1.1") or support.get("TLS1.2")):
        tls["weak_cipher_support"] = {}
        tls["weak_cipher_comment"] = "Serveur uniquement TLS 1.3 → pas de ciphers legacy testables"
        return

    weak_cipher_tests = {
        "3DES": "DES-CBC3-SHA",
        "AES-CBC": "AES128-SHA:AES256-SHA",
        "RC4": "RC4-SHA",
        "MD5": "RSA-MD5",
    }

    weak_results = {}
    for n, cipher in weak_cipher_tests.items():
        accepted = server_accepts_cipher(hostname, port, ssl.TLSVersion.TLSv1_2, cipher)
        weak_results[n] = accepted

    tls["weak_cipher_support"] = weak_results

    if any(weak_results.values()):
        tls["weak_cipher_ok"] = False
        bad = [k for k, v in weak_results.items() if v]
        tls["weak_cipher_comment"] = f"Le serveur accepte encore : {', '.join(bad)}"
    else:
        tls["weak_cipher_ok"] = True
        tls["weak_cipher_comment"] = "Aucun cipher faible accepté"
