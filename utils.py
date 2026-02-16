import ttkbootstrap as ttk
from typing import Tuple
import ssl, socket
import certifi
from urllib.parse import urlparse
import ssl, socket, tempfile
import requests, certifi
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def map_http_version(version_number: int) -> Tuple[str, str]:
    versions = {
        9 : ("HTTP/0.9", "Obsolete"), 
        10: ("HTTP/1.0", "Obsolete"),
        11: ("HTTP/1.1", "Standard"),
        20: ("HTTP/2", "Modern & performant"),
    }
    return versions.get(version_number, (f"Unknown ({version_number})", "❓ Inconnu"))

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url

def clear_tables(http_table,ssl_table,cookies_table):
    for item in http_table.get_children():
        http_table.delete(item)
    for item in ssl_table.get_children():
        ssl_table.delete(item)
    for item in cookies_table.get_children():
        cookies_table.delete(item)

def create_result_table(parent, title):
    """Crée un tableau avec 3 colonnes et un titre."""
    frame = ttk.LabelFrame(parent, text=title)
    frame.pack(side="left", padx=5, pady=5, fill="both", expand=True)

    # Columns
    columns = ("param", "value", "check", "comment")
    tree = ttk.Treeview(frame, columns=columns, show="headings", height=10)
    
    # Columns name
    tree.heading("param", text="Paramètre")
    tree.heading("value", text="Valeur")
    tree.heading("check", text="Check")
    tree.heading("comment", text="Commentaire")
    
    # width and alignment
    tree.column("param", width=180, anchor="w", stretch=False)
    tree.column("value", width=150, anchor="center", stretch=False)
    tree.column("check", width=30, anchor="center", stretch=False)
    tree.column("comment", width=200, anchor="w", stretch=True)

    # Vertical scrollbar 
    scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscroll=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    tree.pack(fill="both", expand=True)
    return tree

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
    
def ck(status):
    if status is True:
        return "✅"
    elif status is False:
        return "❌"
    else:
        return "⚠️"

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

