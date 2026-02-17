import ssl, socket
import certifi
from urllib.parse import urlparse


def strip_pem_headers(pem_key: str) -> str:
    """
    Enlève les balises -----BEGIN/END PUBLIC KEY----- et les retours à la ligne
    d'une clé publique ou privée PEM.
    """
    return pem_key.replace("-----BEGIN PUBLIC KEY-----", "") \
                  .replace("-----END PUBLIC KEY-----", "") \
                  .replace("\n", "")

def public_key_to_clear_text(pem_or_base64: str) -> str:
    """
    Transforme une clé publique PEM ou Base64 en chaîne Base64 "pure",
    sans balises ni retours à la ligne.
    """
    # Si la clé contient déjà des balises, on les enlève
    if "BEGIN PUBLIC KEY" in pem_or_base64:
        lines = pem_or_base64.splitlines()
        # Garde uniquement les lignes entre les balises
        lines = [line for line in lines if "-----" not in line]
        return "".join(lines)
    else:
        # Sinon, on suppose que c'est déjà du Base64 pur
        return pem_or_base64.strip()
    
    
def is_chain_trusted_by_mozilla(url: str, timeout=5) -> tuple[bool, str]:
    parsed = urlparse(url)
    hostname = parsed.hostname or url
    port = parsed.port or 443

    ctx = ssl.create_default_context(cafile=certifi.where())
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Si on arrive ici, la chaîne est considérée comme "trusted" par Mozilla
                return True, ssock.version()
    except ssl.SSLCertVerificationError as e:
        return False, f"Cert verification failed: {e}"
    except Exception as e:
        return False, f"TLS error: {e}"
    

def server_supports_tls_version(url: str, tls_version: ssl.TLSVersion, timeout=5) -> bool:
    parsed = urlparse(url)
    hostname = parsed.hostname or url
    port = parsed.port or 443

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # on veut juste tester le handshake
    ctx.minimum_version = tls_version
    ctx.maximum_version = tls_version

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return True
    except Exception:
        return False
    
def server_accepts_cipher(hostname, port, tls_version, cipher_string):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = tls_version
        context.maximum_version = tls_version
        context.set_ciphers(cipher_string)

        with socket.create_connection((hostname, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True  # handshake réussi → accepté

    except ssl.SSLError:
        return False  # refusé
    except Exception:
        return False
