from __future__ import annotations

from core.tls.cert_extensions import analyze_extensions
from core.tls.cert_identity import analyze_identity
from core.tls.cert_metadata import analyze_metadata
from core.tls.cert_public_key import analyze_public_key
from core.tls.cert_trust import analyze_trust
from core.tls.cert_validity import analyze_validity
from core.tls.protocol import analyze_cipher_and_weak_ciphers, analyze_tls_versions_and_policy
from core.tls.report import build_tls_report
from core.tls.result import init_tls_result
from utils.tls import fetch_tls_artifacts, load_x509_certificate, prepare_tls_target


# ===============================================================
# FUNCTION : scan_tls_config
# ===============================================================
def scan_tls_config(url: str) -> dict:
    """Pipeline TLS complet: handshake, parsing X509, analyses directes, puis report."""
    normalized_url, hostname, port, hostname_for_match = prepare_tls_target(url)
    result = init_tls_result()
    identity = result["identity"]
    trust = result["trust"]
    certificate = result["certificate"]
    protocol = result["protocol"]

    try:
        artifacts = fetch_tls_artifacts(hostname, port)
        if artifacts.error:
            result["errors"]["message"] = artifacts.error
        else:
            # Bloc 1: informations immediates de session TLS.
            protocol["version"]["value"] = artifacts.negotiated_version
            if artifacts.cipher_tuple:
                name, _, bits = artifacts.cipher_tuple
                protocol["cipher"]["value"] = name
                protocol["cipher"]["name"] = name
                protocol["cipher"]["bits"] = bits

            x509_cert = load_x509_certificate(artifacts.der_cert)

            # Bloc 2: identite, confiance et metadonnees du certificat.
            identity.update(analyze_identity(x509_cert, hostname_for_match))

            (
                trust_block,
                protocol["version"]["value"],
                trust_error,
            ) = analyze_trust(
                x509_cert,
                normalized_url,
                protocol["version"]["value"],
            )
            trust.update(trust_block)
            if trust_error and not result["errors"]["message"]:
                result["errors"]["message"] = trust_error

            certificate.update(analyze_validity(x509_cert))
            certificate.update(analyze_metadata(x509_cert))
            certificate["public_key"] = analyze_public_key(x509_cert)
            certificate["extensions"] = analyze_extensions(x509_cert)

            # Bloc 3: protocole, politique TLS et ciphers.
            (
                protocol["version"],
                protocol["supported_versions"],
                protocol["policy"],
            ) = analyze_tls_versions_and_policy(
                protocol["version"]["value"],
                normalized_url,
            )

            (
                protocol["cipher"],
                protocol["weak_ciphers"],
            ) = analyze_cipher_and_weak_ciphers(
                protocol["cipher"].get("name", ""),
                protocol["cipher"].get("bits", 0),
                protocol["supported_versions"],
                hostname,
                port,
            )
    except Exception as exc:
        result["errors"]["message"] = f"Erreur TLS : {exc}"

    # Le report est toujours construit pour garder un contrat stable cote UI.
    result["report"] = build_tls_report(result)
    return result
