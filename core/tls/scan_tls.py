from __future__ import annotations

from core.tls.cert_extensions import analyze_extensions
from core.tls.cert_identity import analyze_identity
from core.tls.cert_metadata import analyze_metadata
from core.tls.cert_public_key import analyze_public_key
from core.tls.report import build_tls_report
from core.tls.cert_validity import analyze_validity
from core.tls.result import init_tls_result
from core.tls.risk import compute_tls_risks
from core.tls.tls_ciphers import analyze_cipher_and_weak_ciphers
from core.tls.tls_policy import analyze_tls_versions_and_policy
from core.tls.trust import analyze_trust
from utils.tls import fetch_tls_artifacts, load_x509_certificate, prepare_tls_target


# ===============================================================
# FUNCTION : scan_tls_config
# ===============================================================
def scan_tls_config(url: str) -> dict:
    """Pipeline TLS complet: handshake, parsing X509, analyses, calcul des risques, report."""
    normalized_url, hostname, port, hostname_for_match = prepare_tls_target(url)
    result = init_tls_result()
    try:
        artifacts = fetch_tls_artifacts(hostname, port)
        if artifacts.error:
            result["errors"]["message"] = artifacts.error
        else:
            # On recupere d'abord les artefacts bruts de session TLS.
            result["tls"]["negotiated_version"] = artifacts.negotiated_version
            if artifacts.cipher_tuple:
                name, _, bits = artifacts.cipher_tuple
                result["tls"]["cipher"].update({"name": name, "bits": bits})

            x509_cert = load_x509_certificate(artifacts.der_cert)

            (
                result["certificate"]["subject"],
                result["certificate"]["issuer"],
                result["hostname_check"],
            ) = analyze_identity(x509_cert, hostname_for_match)

            result["certificate"]["validity"] = analyze_validity(x509_cert)

            (
                result["certificate"]["version"],
                result["certificate"]["serial"],
                result["certificate"]["signature"],
            ) = analyze_metadata(x509_cert)

            result["certificate"]["public_key"] = analyze_public_key(x509_cert)
            result["certificate"]["extensions"] = analyze_extensions(x509_cert)

            (
                result["trust"],
                result["tls"]["negotiated_version"],
                trust_error,
            ) = analyze_trust(
                x509_cert,
                normalized_url,
                result["tls"]["negotiated_version"],
            )
            if trust_error and not result["errors"]["message"]:
                result["errors"]["message"] = trust_error

            (
                result["tls"]["nv_ok"],
                result["tls"]["nv_comment"],
                result["tls"]["supported_versions"],
                result["tls"]["policy"],
            ) = analyze_tls_versions_and_policy(
                result["tls"]["negotiated_version"],
                normalized_url,
            )

            (
                result["tls"]["cipher"]["ok"],
                result["tls"]["cipher"]["comment"],
                result["tls"]["weak_cipher_support"],
                result["tls"]["weak_cipher_ok"],
                result["tls"]["weak_cipher_comment"],
            ) = analyze_cipher_and_weak_ciphers(
                result["tls"]["cipher"].get("name", ""),
                result["tls"]["cipher"].get("bits", 0),
                result["tls"]["supported_versions"],
                hostname,
                port,
            )

            result["risks"] = compute_tls_risks(result)
    except Exception as exc:
        result["errors"]["message"] = f"Erreur TLS : {exc}"

    # Le report harmonise la sortie avec HTTP et Cookies.
    result["report"] = build_tls_report(result)
    return result
