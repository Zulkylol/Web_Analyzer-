import ssl, socket
import certifi
from urllib.parse import urlparse


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
