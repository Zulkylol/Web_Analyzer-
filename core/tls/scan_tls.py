# core/scan_tls.py
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from utils.url import normalize_url
from utils.tls import (
    is_chain_trusted_by_mozilla,
    server_supports_tls_version,
    server_accepts_cipher,
)


# ===============================================================
# FUNCTION : check_ssl_tls_config()
# ===============================================================
def scan_tls_config(url: str) -> dict:
    """
    Analyse la config SSL/TLS d'un serveur (certificat, validité, clés, extensions, versions TLS, cipher).

    Note:
        Les erreurs réseau/TLS (connexion, handshake, etc.) sont capturées et renvoyées dans result["errors"]["message"].
        Les erreurs de logique interne (bugs) ne sont pas volontairement masquées par un try/except global.
    """
    # =========================================================
    # 1)------------------ INITIALIZATION----------------------
    # =========================================================
    result = {
        "target": {"hostname": "", "port": 443, "url": ""},
        "certificate": {
            "subject": {"common_name": "", "san_dns": []},
            "issuer": {"common_name": ""},
            "version": {"id": "", "ok": False, "comment": ""},
            "validity": {
                "not_before": "",
                "not_after": "",
                "is_valid_now": False,
                "expires_ok": False,
                "expires_soon_comment": "",
            },
            "serial": {"hex": "", "ok": True, "comment": ""},
            "signature": {
                "hash_algorithm": "",
                "fingerprint_sha256": "",
                "ok": True,
                "comment": "",
            },
            "public_key": {
                "pem": "",
                "type": "",
                "size": None,
                "curve": "",
                "ok": True,
                "comment": "",
                "summary": "",
            },
            "extensions": {
                "key_usage": "",
                "extended_key_usage": "",
                "basic_constraints": "",
                "crl_distribution_points": "",
                "basic_constraints_ok": None,
                "basic_constraints_comment": "",
                "eku_ok": None,
                "eku_comment": "",
                "ku_ok": None,
                "ku_comment": "",
                "crl_ok": None,
                "crl_comment": "",
            },
        },
        "trust": {"is_trusted": False, "is_self_signed": False},
        "hostname_check": {
            "match": False,
            "comment": "",
            "ok": False,
            "warnings": {"wildcard": "", "multi_domain": ""},
        },
        "tls": {
            "negotiated_version": "",
            "nv_ok": False,
            "nv_comment": "",
            "supported_versions": {},
            "weak_cipher_support": {},
            "weak_cipher_ok": True,
            "weak_cipher_comment": "",
            "policy": {"ok": True, "comment": ""},
            "cipher": {"name": "", "protocol": "", "bits": 0, "ok": True, "comment": ""},
        },
        "errors": {"message": ""},
    }

    # =========================================================
    # -------------------- LOCALS ALIAS -----------------------
    # =========================================================
    cert = result["certificate"]
    tls = result["tls"]
    trust = result["trust"]

    cert_subject = cert["subject"]
    cert_issuer = cert["issuer"]
    cert_validity = cert["validity"]
    cert_version = cert["version"]
    cert_serial = cert["serial"]
    cert_signature = cert["signature"]
    cert_public_key = cert["public_key"]
    cert_ext = cert["extensions"]
    hostname_check = result["hostname_check"]
    tls_cipher = tls["cipher"]
    tls_policy = tls["policy"]

    # =========================================================
    # 0)----------------- URL NORMALIZATION -------------------
    # =========================================================
    url = normalize_url(url)
    parsed_url = urlparse(url)
    hostname = (parsed_url.hostname or "").lower().strip() or url
    port = parsed_url.port or 443

    result["target"]["hostname"] = hostname
    result["target"]["port"] = port
    result["target"]["url"] = url

    hostname_for_match = parsed_url.hostname or hostname  # fallback robuste

    # =========================================================
    # 1)-------------- NETWORK/TLS (TRY MINIMAL) --------------
    # =========================================================
    der_cert = None
    negotiated_version = ""
    cipher_tuple = None
    tls_info = None  

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # permet d’attraper les certs expirés

        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                negotiated_version = ssock.version() or ""
                cipher_tuple = ssock.cipher()
                der_cert = ssock.getpeercert(binary_form=True)

    except (socket.timeout, TimeoutError) as e:
        result["errors"]["message"] = f"Timeout connexion/handshake: {e}"
        return result
    except ssl.SSLError as e:
        result["errors"]["message"] = f"Erreur TLS/SSL: {e}"
        return result
    except OSError as e:
        # regroupe: DNS, refus connexion, pas de route, etc.
        result["errors"]["message"] = f"Erreur réseau (OS): {e}"
        return result

    # Si on n'a pas récupéré de cert, on arrête proprement
    if not der_cert:
        result["errors"]["message"] = "Impossible de récupérer le certificat serveur."
        return result

    # On garde ces infos hors try global
    tls["negotiated_version"] = negotiated_version

    if cipher_tuple:
        tls_cipher["name"] = cipher_tuple[0]
        tls_cipher["protocol"] = cipher_tuple[1]
        tls_cipher["bits"] = cipher_tuple[2]




    # =========================================================
    # 2)-------- IDENTITY (CN / SAN / HOSTNAME) ---------------
    # =========================================================

    # Parsing certificate
    x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())

    # Subject (CN)
    try:
        cert_subject["common_name"] = (
            x509_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        )
    except IndexError:
        cert_subject["common_name"] = ""

    # Issuer (CN)
    for attr in x509_cert.issuer:
        if attr.oid._name == "commonName":
            cert_issuer["common_name"] = attr.value

    cn = cert_subject["common_name"]

    # SAN
    try:
        san_ext = x509_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns = san_ext.value.get_values_for_type(x509.DNSName)
        cert_subject["san_dns"] = [d for d in san_dns if d != cn]
    except Exception:
        cert_subject["san_dns"] = []

    # Match hostname
    san_list = [cn] + cert_subject["san_dns"]  # inclut CN pour compatibilité
    match = False
    for entry in san_list:
        if entry.startswith("*."):
            if hostname_for_match.endswith(entry[1:]):
                match = True
                break
        elif entry == hostname_for_match:
            match = True
            break

    hostname_check["match"] = match
    hostname_check["comment"] = (
        "Le certificat correspond au domaine" if match else "Le certificat ne correspond PAS au domaine"
    )

    # Multi-domain warning
    san_count = len(cert_subject["san_dns"])
    if san_count > 200:
        hostname_check["warnings"]["multi_domain"] = "Certificat multi-domaines massif"
        hostname_check["ok"] = None
    elif san_count > 50:
        hostname_check["warnings"]["multi_domain"] = "Certificat multi-domaines important"
        hostname_check["ok"] = None
    else:
        hostname_check["warnings"]["multi_domain"] = "Certificat avec peu de domaine"
        hostname_check["ok"] = True

    # =========================================================
    # 3) -------------- CERT TIME VALIDITY -------------------
    # =========================================================

    cert_validity["not_before"] = x509_cert.not_valid_before_utc.isoformat()
    cert_validity["not_after"] = x509_cert.not_valid_after_utc.isoformat()
    now = datetime.now(timezone.utc)

    try:
        not_before = x509_cert.not_valid_before_utc
        not_after = x509_cert.not_valid_after_utc

        is_valid = not_before <= now <= not_after
        cert_validity["is_valid_now"] = is_valid

        days_left = (not_after - now).days

        if days_left < 0:
            cert_validity["expires_ok"] = False
            cert_validity["expires_soon_comment"] = "Certificat expiré."
        elif days_left < 30:
            cert_validity["expires_ok"] = None
            cert_validity["expires_soon_comment"] = (
                f"⚠️ Certificat expire bientôt ({days_left} jours restants)."
            )
        else:
            cert_validity["expires_ok"] = True
            cert_validity["expires_soon_comment"] = (
                f"Validité confortable ({days_left} jours restants)."
            )
    except Exception:
        cert_validity["is_valid_now"] = False
        cert_validity["expires_ok"] = None
        cert_validity["expires_soon_comment"] = "Impossible d'évaluer la validité."

    # =========================================================
    # 4) CERTIFICAT (version / serial / signature / fingerprint)
    # =========================================================
    cert_version["id"] = x509_cert.version.name
    if x509_cert.version.name != "v3":
        cert_version["ok"] = False
        cert_version["comment"] = "Certificat non v3 (obsolète)."
    else:
        cert_version["ok"] = True
        cert_version["comment"] = "Certificat X.509 v3."

    sn = x509_cert.serial_number
    bitlen = sn.bit_length()
    cert_serial["hex"] = hex(sn)

    if sn <= 0:
        cert_serial["ok"] = False
        cert_serial["comment"] = "Serial non valide (doit être positif)."
    elif bitlen < 32:
        cert_serial["ok"] = True
        cert_serial["comment"] = (
            f"⚠️ Serial très court ({bitlen} bits) : possible PKI interne/ancienne."
        )
    else:
        cert_serial["ok"] = True
        cert_serial["comment"] = f"Serial OK ({bitlen} bits)."

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


    # =========================================================
    # 4) ----------------- CERT TRUST -------------------------
    # =========================================================
    trust["is_self_signed"] = x509_cert.issuer == x509_cert.subject

    trusted, tls_info = is_chain_trusted_by_mozilla(url)
    trust["is_trusted"] = trusted
    if tls["negotiated_version"] == "":
        if trusted:
            tls["negotiated_version"] = tls_info
        else:
            result["errors"]["message"] = tls_info


    # =========================================================
    # 5)----------------- PUBLIC KEY -------------------------
    # =========================================================
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
            if curve_name:
                cert_public_key["summary"] = f"EC {curve_name} ({pk_size} bits)" if pk_size else f"EC {curve_name}"
            else:
                cert_public_key["summary"] = "EC (courbe inconnue)"
        elif pk_type == "DSAPublicKey":
            cert_public_key["summary"] = f"DSA {pk_size} bits" if pk_size else "DSA"
        else:
            cert_public_key["summary"] = pk_type

    except Exception as e:
        cert_public_key["ok"] = None
        cert_public_key["comment"] = f"⚠️ Impossible d'analyser la clé publique: {e}"

    # =========================================================
    # 6)----------------- EXTENSIONS --------------------------
    # =========================================================
    for ext_class, key in [
        (x509.BasicConstraints, "basic_constraints"),
        (x509.KeyUsage, "key_usage"),
        (x509.ExtendedKeyUsage, "extended_key_usage"),
        (x509.CRLDistributionPoints, "crl_distribution_points"),
    ]:
        try:
            ext = x509_cert.extensions.get_extension_for_class(ext_class)
            cert_ext[key] = str(ext.value)
        except Exception:
            pass

    bc = cert_ext["basic_constraints"]
    if bc:
        if "CA=True" in bc:
            cert_ext["basic_constraints_ok"] = False
            cert_ext["basic_constraints_comment"] = "Certificat marqué comme CA (anormal pour serveur)."
        else:
            cert_ext["basic_constraints_ok"] = True
            cert_ext["basic_constraints_comment"] = "Certificat non CA."
    else:
        cert_ext["basic_constraints_ok"] = None
        cert_ext["basic_constraints_comment"] = "BasicConstraints absent."

    eku = cert_ext["extended_key_usage"]
    if eku:
        if "serverAuth" in eku or "TLS Web Server Authentication" in eku:
            cert_ext["eku_ok"] = True
            cert_ext["eku_comment"] = "EKU autorise l'authentification serveur."
        else:
            cert_ext["eku_ok"] = False
            cert_ext["eku_comment"] = "EKU ne contient pas serverAuth."
    else:
        cert_ext["eku_ok"] = None
        cert_ext["eku_comment"] = "EKU absent."

    ku = cert_ext["key_usage"]
    if ku:
        if "digital_signature" in ku:
            cert_ext["ku_ok"] = True
            cert_ext["ku_comment"] = "digitalSignature présent."
        else:
            cert_ext["ku_ok"] = False
            cert_ext["ku_comment"] = "digitalSignature absent."
    else:
        cert_ext["ku_ok"] = None
        cert_ext["ku_comment"] = "KeyUsage absent."

    crl = cert_ext["crl_distribution_points"]
    if crl:
        cert_ext["crl_ok"] = True
        cert_ext["crl_comment"] = "Point(s) de révocation indiqué(s)."
    else:
        cert_ext["crl_ok"] = None
        cert_ext["crl_comment"] = "Aucun point CRL indiqué."

    # =========================================================
    # 7)-------- TLS (nv + support + policy + cipher) ---------
    # =========================================================
    nv = tls["negotiated_version"]

    if nv == "TLSv1":
        tls["nv_ok"] = False
        tls["nv_comment"] = "TLS 1.0 est obsolète et vulnérable."
    elif nv == "TLSv1.1":
        tls["nv_ok"] = False
        tls["nv_comment"] = "TLS 1.1 est obsolète (à désactiver)."
    elif nv == "TLSv1.2":
        tls["nv_ok"] = True
        tls["nv_comment"] = "TLS 1.2 est encore sécurisé mais progressivement remplacé par TLS 1.3."
    elif nv == "TLSv1.3":
        tls["nv_ok"] = True
        tls["nv_comment"] = "TLS 1.3 est la version la plus moderne et recommandée."
    else:
        tls["nv_ok"] = None
        tls["nv_comment"] = "Version TLS inconnue ou non analysée."

    support = {
        "TLS1.0": server_supports_tls_version(url, ssl.TLSVersion.TLSv1),
        "TLS1.1": server_supports_tls_version(url, ssl.TLSVersion.TLSv1_1),
        "TLS1.2": server_supports_tls_version(url, ssl.TLSVersion.TLSv1_2),
        "TLS1.3": server_supports_tls_version(url, ssl.TLSVersion.TLSv1_3),
    }
    tls["supported_versions"] = support

    if support["TLS1.0"] or support["TLS1.1"]:
        tls_policy["ok"] = False
        bad = []
        if support["TLS1.0"]:
            bad.append("TLS 1.0")
        if support["TLS1.1"]:
            bad.append("TLS 1.1")
        tls_policy["comment"] = f"Le serveur accepte encore {', '.join(bad)} (obsolète)."
    else:
        tls_policy["ok"] = True
        if support["TLS1.3"]:
            tls_policy["comment"] = "TLS 1.0/1.1 désactivés. TLS 1.3 supporté."
        elif support["TLS1.2"]:
            tls_policy["comment"] = "TLS 1.0/1.1 désactivés. TLS 1.2 supporté."
        else:
            tls_policy["comment"] = "TLS 1.2+ non supporté (problème)."

    name = tls_cipher["name"]
    bits = tls_cipher["bits"]

    weak_algorithms = ["RC4", "3DES", "DES", "MD5"]
    if any(w in name for w in weak_algorithms):
        tls_cipher["ok"] = False
        tls_cipher["comment"] = "Cipher faible détectée (RC4/3DES/DES/MD5)."
    elif bits < 128:
        tls_cipher["ok"] = False
        tls_cipher["comment"] = "Taille de clé inférieure à 128 bits."
    elif "GCM" in name or "CHACHA20" in name:
        tls_cipher["ok"] = True
        tls_cipher["comment"] = "Cipher moderne sécurisée (AEAD)."
    else:
        tls_cipher["ok"] = True
        tls_cipher["comment"] = "Cipher acceptable."

    # Weak cipher tests (si TLS<1.3 testable)
    if not (support.get("TLS1.0") or support.get("TLS1.1") or support.get("TLS1.2")):
        tls["weak_cipher_support"] = {}
        tls["weak_cipher_comment"] = "Serveur uniquement TLS 1.3 → pas de ciphers legacy testables."
    else:
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
            tls["weak_cipher_comment"] = "Aucun cipher faible accepté."

    return result