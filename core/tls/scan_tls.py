# core/tls/scan_tls.py
from __future__ import annotations

from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from utils.url import normalize_url

from core.tls.network import fetch_tls_artifacts
from core.tls.trust import analyze_trust
from core.tls.cert_identity import analyze_identity
from core.tls.cert_validity import analyze_validity
from core.tls.cert_metadata import analyze_metadata
from core.tls.cert_public_key import analyze_public_key
from core.tls.cert_extensions import analyze_extensions
from core.tls.tls_policy import analyze_tls_versions_and_policy
from core.tls.tls_ciphers import analyze_cipher_and_weak_ciphers
from core.tls.result import init_tls_result
from utils.url import normalize_url

def scan_tls_config(url: str) -> dict:


    # 0) URL normalization
    url = normalize_url(url)
    result = init_tls_result()

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().strip() or url
    port = parsed.port or 443

    result["target"].update({"hostname": hostname, "port": port, "url": url})
    hostname_for_match = parsed.hostname or hostname

    # 1) Network/TLS fetch (cert + negotiated + cipher)
    net = fetch_tls_artifacts(hostname, port)
    if net.error:
        result["errors"]["message"] = net.error
        return result

    result["tls"]["negotiated_version"] = net.negotiated_version
    if net.cipher_tuple:
        name, proto, bits = net.cipher_tuple
        result["tls"]["cipher"].update({"name": name, "protocol": proto, "bits": bits})

    # 2) Parse x509 cert
    x509_cert = x509.load_der_x509_certificate(net.der_cert, default_backend())

    # 3) Cert analyses
    analyze_identity(result, x509_cert, hostname_for_match)
    analyze_validity(result, x509_cert)
    analyze_metadata(result, x509_cert)
    analyze_public_key(result, x509_cert)
    analyze_extensions(result, x509_cert)

    # 4) Trust (may provide info if negotiated version missing)
    analyze_trust(result, x509_cert, url)

    # 5) TLS versions/policy + cipher checks
    analyze_tls_versions_and_policy(result, url)
    analyze_cipher_and_weak_ciphers(result, hostname, port)

    return result
