# utils/tls.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations
import socket
import ssl
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlparse
import certifi


# ===============================================================
# FUNCTION : strip_pem_headers()
# ===============================================================

def strip_pem_headers(pem_key: str) -> str:
    """
    Remove PEM header, footer, and line breaks from a public key string.
    """
    return pem_key.replace("-----BEGIN PUBLIC KEY-----", "") \
                  .replace("-----END PUBLIC KEY-----", "") \
                  .replace("\n", "")


# ===============================================================
# FUNCTION : public_key_to_clear_text()
# ===============================================================
def public_key_to_clear_text(pem_or_base64: str) -> str: 
    """
    Return Base64 public key without PEM headers or extra whitespace.
    """

    # If the key contains PEM markers, remove them
    if "BEGIN PUBLIC KEY" in pem_or_base64:
        lines = pem_or_base64.splitlines()
        # Keep only the lines between the markers
        lines = [line for line in lines if "-----" not in line]
        return "".join(lines)
    else:
        # Otherwise, assume it is already raw Base64
        return pem_or_base64.strip()
    

# ===============================================================
# FUNCTION : is_chain_trusted_by_mozilla()
# ===============================================================    
def is_chain_trusted_by_mozilla(url: str, timeout=5) -> tuple[bool, str]:
    """
    Verify if a server's TLS certificate chain is trusted (Mozilla CA bundle).

    Returns:
        (is_trusted, tls_version_or_error)
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or url
    port = parsed.port or 443

    ctx = ssl.create_default_context(cafile=certifi.where())
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                # If we reach this point, the certificate chain is trusted by Mozilla
                return True, ssock.version()
    except ssl.SSLCertVerificationError as e:
        return False, f"Cert verification failed: {e}"
    except Exception as e:
        return False, f"TLS error: {e}"
    

# ===============================================================
# FUNCTION : server_supports_tls_version()
# ===============================================================   
def server_supports_tls_version(url: str, tls_version: ssl.TLSVersion, timeout=5) -> bool:
    """
    Test whether a server supports a specific TLS version by attempting a handshake.

    Returns:
        bool: True if the TLS handshake succeeds with the specified version, otherwise False.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or url
    port = parsed.port or 443

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # test handshake
    ctx.minimum_version = tls_version
    ctx.maximum_version = tls_version

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return True
    except Exception:
        return False
    

# ===============================================================
# FUNCTION : server_accepts_cipher()
# ===============================================================  
def server_accepts_cipher(hostname, port, tls_version, cipher_string):
    """
    Check whether a server accepts a specific cipher suite for a given TLS version.

    Returns:
        bool: True if the handshake succeeds with the specified cipher, otherwise False.
    """
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = tls_version
        context.maximum_version = tls_version
        context.set_ciphers(cipher_string)

        with socket.create_connection((hostname, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True  # handshake succeed 

    except ssl.SSLError:
        return False 
    except Exception:
        return False

@dataclass
class TLSArtifacts:
    der_cert: Optional[bytes]
    negotiated_version: str
    cipher_tuple: Optional[Tuple[str, str, int]]
    error: str = ""

# ===============================================================
# FUNCTION : fetch_tls_artifacts()
# ===============================================================
def fetch_tls_artifacts(hostname: str, port: int, timeout: int = 5) -> TLSArtifacts:
    """
    Connect to a server over TLS and retrieve its certificate and session details.

    Returns DER certificate, negotiated TLS version, and cipher suite,
    or an error inside a TLSArtifacts object.

    Args:
        hostname (str): Target host.
        port (int): Target port.
        timeout (int): Connection timeout (seconds).

    Returns:
        TLSArtifacts
    """
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
