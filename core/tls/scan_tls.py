from __future__ import annotations

from core.tls.cert_extensions import analyze_extensions
from core.tls.cert_identity import analyze_identity
from core.tls.cert_metadata import analyze_metadata
from core.tls.cert_public_key import analyze_public_key
from core.tls.cert_validity import analyze_validity
from core.tls.result import init_tls_result
from core.tls.risk import compute_tls_risks
from core.tls.tls_ciphers import analyze_cipher_and_weak_ciphers
from core.tls.tls_policy import analyze_tls_versions_and_policy
from core.tls.trust import analyze_trust
from utils.tls import fetch_tls_artifacts, load_x509_certificate, prepare_tls_target


def scan_tls_config(url: str) -> dict:
    normalized_url, hostname, port, hostname_for_match = prepare_tls_target(url)
    result = init_tls_result()
    result["target"].update({"hostname": hostname, "port": port, "url": normalized_url})

    artifacts = fetch_tls_artifacts(hostname, port)
    if artifacts.error:
        result["errors"]["message"] = artifacts.error
        return result

    result["tls"]["negotiated_version"] = artifacts.negotiated_version
    if artifacts.cipher_tuple:
        name, proto, bits = artifacts.cipher_tuple
        result["tls"]["cipher"].update({"name": name, "protocol": proto, "bits": bits})

    x509_cert = load_x509_certificate(artifacts.der_cert)

    analyze_identity(result, x509_cert, hostname_for_match)
    analyze_validity(result, x509_cert)
    analyze_metadata(result, x509_cert)
    analyze_public_key(result, x509_cert)
    analyze_extensions(result, x509_cert)
    analyze_trust(result, x509_cert, normalized_url)
    analyze_tls_versions_and_policy(result, normalized_url)
    analyze_cipher_and_weak_ciphers(result, hostname, port)
    result["risks"] = compute_tls_risks(result)
    return result
