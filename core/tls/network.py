# core/tls/network.py
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class TLSArtifacts:
    der_cert: Optional[bytes]
    negotiated_version: str
    cipher_tuple: Optional[Tuple[str, str, int]]
    error: str = ""


def fetch_tls_artifacts(hostname: str, port: int, timeout: int = 5) -> TLSArtifacts:
    der_cert = None
    negotiated_version = ""
    cipher_tuple = None

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                negotiated_version = ssock.version() or ""
                cipher_tuple = ssock.cipher()
                der_cert = ssock.getpeercert(binary_form=True)

    except (socket.timeout, TimeoutError) as e:
        return TLSArtifacts(None, "", None, f"Timeout connexion/handshake: {e}")
    except ssl.SSLError as e:
        return TLSArtifacts(None, "", None, f"Erreur TLS/SSL: {e}")
    except OSError as e:
        return TLSArtifacts(None, "", None, f"Erreur réseau (OS): {e}")

    if not der_cert:
        return TLSArtifacts(None, negotiated_version, cipher_tuple, "Impossible de récupérer le certificat serveur.")

    return TLSArtifacts(der_cert, negotiated_version, cipher_tuple)
