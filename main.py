# =========================
# Standard library
# =========================
import re
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
import ipaddress

# =========================
# Third-party
# =========================
import requests
import ttkbootstrap as ttk
from ttkbootstrap.constants import SUCCESS, INFO, WARNING
from tkinter import messagebox
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

# =========================
# Optional dependency
# =========================
try:
    import httpx
except ImportError:
    httpx = None

# =========================
# Local modules
# =========================
from http_status_codes import HTTP_STATUS_CODES
from utils import *      # ⚠️ à éviter si possible
from constants import *  # ⚠️ à éviter si possible


# ===============================================================
# FUNCTION : check_http_security()
# ===============================================================
def check_http_config(url: str) -> dict:
    """
    Check the web server’s security configuration at the HTTP level.

    Args:
        url (str): URL provided by the user

    Returns:
        dict : dictionary that stores the analysis results

    Raises:
        None: All network-related exceptions are caught and handled internally.
    """
    
    # =========================================================
    # 1)------------------- INITIALIZATION --------------------
    # =========================================================
    raw_url = url
    url = normalize_url(url)

    result = {
        "status_code": 0,
        "status_ok" : False,
        "status_message": "",
        "http_version": "",
        "http_ok" : False,
        "http_comment" : "",
        "uses_https": False,
        "https_comment": "",
        "mixed_content": False,
        "mixed_url": [],
        "mixed_comment": "Aucun contenu mixte détecté",
        "original_url": url,
        "input_url" : raw_url,
        "final_url": None,
        "time": 0.0,
        "time_comment": "",
        "time_ok" : False,
        "missing_headers": [],
        "headers_comment": [],
        "redirects": {},
        "comment": "",
    }


    # =========================================================
    # 2)---------------------- REQUEST ------------------------
    # =========================================================
    try:
        response = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=5,
            allow_redirects=True,
        )


    # =========================================================
    # 3)----------- CHECK HTTP CODE AND MAPPING) --------------
    # =========================================================
        # Check HTTP response code and map it
        result["status_code"] = response.status_code
        result["status_message"] = HTTP_STATUS_CODES.get(response.status_code, "Code inconnu")
        
        if 200 <= response.status_code < 400:
            result["status_ok"] = True
        elif 400 <= response.status_code < 500:
            result["status_ok"] = None  # client error (warning)
        else:
            result["status_ok"] = False  # 5xx serveur KO
        
        
    # =========================================================
    # 4)---------------- VARIOUS URL CHECKS ------------------- 
    # =========================================================
        result["final_url"] = response.url
        original_parsed = urlparse(result["original_url"])
        final_parsed = urlparse(result["final_url"])

        # findings = liste of findings (severity, ok_value, message)
        # ok_value: False = KO, None = Warning, True = OK/info
        findings = []

        def add_finding(ok_value, message, severity_weight):
            """
            severity_weight: 3 = critique, 2 = warning, 1 = info/positif
            ok_value: False / None / True
            """
            findings.append({
                "ok": ok_value,
                "weight": severity_weight,
                "message": message
            })

        # a) Credentials dans l'URL (critique)
        if (original_parsed.username or original_parsed.password or
            final_parsed.username or final_parsed.password):
            add_finding(False, "Credentials détectés dans l’URL", 3)

        # b) Downgrade HTTPS -> HTTP (critique)
        if original_parsed.scheme == "https" and final_parsed.scheme == "http":
            add_finding(False, "Downgrade HTTPS → HTTP", 3)

        # c) Upgrade HTTP -> HTTPS (positif / info)
        if original_parsed.scheme == "http" and final_parsed.scheme == "https":
            add_finding(True, "Redirection HTTP → HTTPS (sécurisé)", 1)

        # d) Changement d’hôte (warning)
        if (original_parsed.hostname and final_parsed.hostname and
            original_parsed.hostname.lower() != final_parsed.hostname.lower()):
            add_finding(None, f"Changement d’hôte ({original_parsed.hostname} → {final_parsed.hostname})", 2)

        # Default values
        result["url_ok"] = True
        result["url_comment"] = "OK"
        result["url_findings"] = []

        if findings:
            # Trier par gravité (poids décroissant), puis par "ok" (False > None > True)
            order_ok = {False: 0, None: 1, True: 2}
            findings_sorted = sorted(
                findings,
                key=lambda f: (-f["weight"], order_ok.get(f["ok"], 99))
            )

            # Le constat le plus grave devient le verdict global
            top = findings_sorted[0]
            result["url_ok"] = top["ok"]
            result["url_comment"] = top["message"]

            # Garder tous les constats pour affichage détaillé si tu veux
            result["url_findings"] = [f["message"] for f in findings_sorted]


    # =========================================================
    # 5)--------------- HTTP VERSION CHECKS -------------------
    # =========================================================
        if httpx:
            try:
                with httpx.Client(http2=True, timeout=5) as c:
                    r2 = c.get(url)
                    hv = getattr(r2, "http_version", "") or ""
                    result["http_version"] = hv.upper()
            except Exception:
                pass

        if not result["http_version"]:
            v = getattr(response.raw, "version", None)
            version_label, version_comment = map_http_version(v)
            result["http_version"] = version_label
            result["http_comment"] = version_comment

            # Déterminer http_ok en fonction de la version
            if v in (11, 20):           # HTTP/1.1 ou HTTP/2
                result["http_ok"] = True
            elif v in (9, 10):          # Obsolètes
                result["http_ok"] = False
            else:
                result["http_ok"] = None

        # HTTPS
        result["uses_https"] = result["final_url"].startswith("https://")
        result["https_comment"] = "Site sécurisé (HTTPS)" if result["uses_https"] else "Site non sécurisé (HTTP)"


    # =========================================================
    # 6)-------------- RESPONSE TIME CHECKS -------------------
    # =========================================================
        result["time"] = response.elapsed.total_seconds()
        t = result["time"]
        if t < 0.8:
            result["time_ok"] = True
            result["time_comment"] = "Temps de réponse rapide"
        elif t < 2:
            result["time_ok"] = True
            result["time_comment"] = "Temps correct"
        elif t < 5:
            result["time_ok"] = None
            result["time_comment"] = "Temps de réponse lent"
        else:
            result["time_ok"] = False
            result["time_comment"] = "Très lent ou proche timeout"


    # =========================================================
    # 7)------------ SECURITY HEADERS CHECKS -----------------
    # =========================================================
        for h in SECURITY_HEADERS:
            if h == "Content-Security-Policy":
                csp_value = (
                    response.headers.get("Content-Security-Policy")
                    or response.headers.get("Content-Security-Policy-Report-Only")
                )
                if csp_value:
                    result["headers_comment"].append("present")
                else:
                    result["missing_headers"].append(h)
                    result["headers_comment"].append("absent")
                continue

            if response.headers.get(h):
                result["headers_comment"].append("present")
            else:
                result["missing_headers"].append(h)
                result["headers_comment"].append("absent")


    # =========================================================
    # 8)------------- MIXED CONTENT DETECTION -----------------
    # =========================================================
        if result["uses_https"]:
            soup = BeautifulSoup(response.text, "html.parser")

            tags_attrs = {
                "img": ["src", "srcset"],
                "script": ["src"],
                "link": ["href"],
                "iframe": ["src"],
                "audio": ["src"],
                "video": ["src", "poster"],
                "source": ["src"],
                "form": ["action"],
            }

            mixed = []
            for tag, attrs in tags_attrs.items():
                for elem in soup.find_all(tag):
                    for attr in attrs:
                        val = elem.get(attr)
                        if not val:
                            continue
                        if attr == "srcset":
                            for part in val.split(","):
                                u = part.strip().split(" ")[0]
                                if u.startswith("http://"):
                                    mixed.append((u, f"{tag}[srcset]"))
                        elif isinstance(val, str) and val.startswith("http://"):
                            mixed.append((val, f"{tag}[{attr}]"))

            # style inline
            for elem in soup.find_all(style=True):
                css = elem.get("style") or ""
                for u in re.findall(r'url\(\s*["\']?(http://[^"\')\s]+)', css):
                    mixed.append((u, "inline-style"))
            
            # CSS externes
            for link in soup.find_all("link", href=True):
                rel = link.get("rel") or []
                if any(r.lower() == "stylesheet" for r in rel):
                    css_url = urljoin(result["final_url"], link["href"])

                    try:
                        css_resp = requests.get(
                            css_url,
                            headers={"User-Agent": "Mozilla/5.0"},
                            timeout=3,
                        )

                        for u in re.findall(r'url\(\s*["\']?(http://[^"\')\s]+)', css_resp.text):
                            mixed.append((u, "external-css"))

                    except Exception:
                        # on ignore silencieusement si CSS inaccessible
                        pass

            if mixed:
                result["mixed_content"] = True
                result["mixed_comment"] = f"{len(mixed)} ressources HTTP détectées"
                result["mixed_url"] = list(set(mixed))


    # =========================================================
    # 9)----------- CALL check_http_redirections() ------------
    # =========================================================
        result["redirects"] = check_http_redirections(response, url)

    # =========================================================
    # 10)----------- EXCEPTIONS MANAGMENT ---------------------
    # =========================================================
    except requests.exceptions.SSLError as e:
        txt = repr(e)

        if "CERTIFICATE_VERIFY_FAILED" in txt and "unable to get local issuer certificate" in txt:
            result["comment"] = (
                "Erreur TLS/SSL : vérification du certificat impossible "
                "(CA intermédiaire manquante / chaîne incomplète). "
                "Le navigateur peut réussir via cache, mais Python/OpenSSL échoue."
            )
        elif "CERTIFICATE_VERIFY_FAILED" in txt:
            result["comment"] = (
                "Erreur TLS/SSL : vérification du certificat impossible "
                "(CERTIFICATE_VERIFY_FAILED)."
            )
        else:
            result["comment"] = f"Erreur TLS/SSL : {e}"
    except requests.exceptions.ConnectTimeout:
        result["comment"] = "Timeout de connexion (ConnectTimeout)"
    except requests.exceptions.ReadTimeout:
        result["comment"] = "Timeout de lecture (ReadTimeout)"
    except requests.exceptions.ConnectionError as e:
        result["comment"] = f"Connexion impossible : {e}"
    except requests.exceptions.RequestException as e:
        result["comment"] = f"Erreur réseau : {e}"
    return result
    

# ===============================================================
# FUNCTION : check_http_redirections()
# ===============================================================
def check_http_redirections(response, original_url: str) -> dict:
    """
    Checks the redirects performed by the web server

    Args:
        response (Response) : response of the request sent in check_http_config()
        original_url (str): URL provided by the user

    Returns:
        dict : dictionary that stores the analysis results of redirections

    Raises:
        
    """
    # =========================================================
    # 1)------------------ INITIALIZATION ---------------------
    # =========================================================

    history = response.history or []
    result = {
        "num_redirects": len(history),
        "num_ok" : False,
        "num_comment": "",
        "redirect_domains": [],
        "rd_comment": "",     
        "redirect_ips": [],
        "ri_comment": "",      
        "risk": "Low",
    }

    # =========================================================
    # 2)----------- STORE REDIRECT DOMAINS/IPS ----------------
    # =========================================================
    if not history:
        result["num_comment"] = "Aucune redirection"
        return result

    initial_domain = urlparse(original_url).hostname

    for resp in history:
        loc = resp.headers.get("Location")
        target = urljoin(resp.url, loc) if loc else resp.url
        domain = urlparse(target).hostname

        if domain:
            result["redirect_domains"].append(domain)
            try:
                ipaddress.ip_address(domain)
                result["redirect_ips"].append(domain)
            except ValueError:
                pass


    # =========================================================
    # 3)--------------- REDIRECTIONS VOLUME -------------------
    # =========================================================
    if len(history) > 6:
        result["risk"] = "High"
        result["num_comment"] = "Nombre excessif de redirections !"
        result["num_ok"] = False
    elif len(history) > 2:
        result["risk"] = "Medium"
        result["num_comment"] = "Plusieurs redirections détectées."
        result["num_ok"] = None
    else:
        result["num_comment"] = "Nombre de redirection(s) normal"
        result["num_ok"] = True
    

    # =========================================================
    # 4)--------------- SWITCHING DOMAIN/IP -------------------
    # =========================================================
    if initial_domain:
        for dom in result["redirect_domains"]:
            if dom != initial_domain and dom not in result["redirect_ips"]:
                result["rd_comment"] = f"Redirection vers un autre domaine ({dom})."
                if result["risk"] == "Low":
                    result["risk"] = "Medium"
                break

    if result["redirect_ips"]:
        result["ri_comment"] = f"Redirection vers IP brute ({', '.join(result['redirect_ips'])})."
        if result["risk"] == "Low":
            result["risk"] = "Medium"

    return result


# ===============================================================
# FUNCTION : display_http()
# ===============================================================
def display_http(result):

    # Helper function to reduce text
    def add_row(param, value="", check="ⓘ", comment=""):
        http_table.insert("", "end", values=(param, value, check, comment))

    # =========================================================
    # 1)------------------- DATA CLEANING ---------------------
    # =========================================================
    redirects = result.get("redirects") or {}
    missing_headers = result.get("missing_headers") or []
    headers_comment = result.get("headers_comment") or []
    mixed_urls = result.get("mixed_url") or []


    # =========================================================
    # 2)-------------- HTTP VERSION + HTTPS -------------------
    # =========================================================
    # Si erreur HTTP → afficher uniquement l'erreur et stop
    if result.get("comment"):
        add_row("Erreur HTTP", result.get("status_message", ""), "❌", result.get("comment", ""))
        return

    # Status / HTTP version / HTTPS
    add_row("Code de statut", str(result.get("status_code", "")), ck(result["status_ok"]),
            result.get("status_message", ""))

    http_version = result.get("http_version") or ""
    if http_version:
        # si tu stockes "HTTP/2" directement
        add_row("Version HTTP", http_version, ck(result["http_ok"]), result["http_comment"])
    else:
        add_row("Version HTTP", "Inconnue", "⚠️", "Impossible de déterminer la version HTTP")

    uses_https = bool(result.get("uses_https"))
    add_row("HTTPS activé", "Oui" if uses_https else "Non",
            ck(result["uses_https"]),
            result.get("https_comment", ""))

    # =========================================================
    # 3)---------------------- URLS ---------------------------
    # =========================================================
    add_row("URL saisie", result.get("original_url", ""), "ⓘ", "")
    add_row("URL finale", result.get("final_url", ""), ck(result["url_ok"]),result["url_comment"])

    extra = result.get("url_findings") or []
    for msg in extra[1:]:
        add_row("", "", "ⓘ", msg)   


    # =========================================================
    # 4)---------------------- TIME ---------------------------
    # =========================================================
    t = result.get("time", 0.0)
    add_row("Temps de réponse",result["time"] ,ck(result["time_ok"]), result["time_comment"])


    # =========================================================
    # 5)----------------- MIXED CONTENT -----------------------
    # =========================================================
    if uses_https:
        mixed = bool(result.get("mixed_content"))
        add_row("Contenu mixte", "Oui" if mixed else "Non",
                "⚠️" if mixed else "✅",
                result.get("mixed_comment", ""))

        if mixed_urls:
            # 1ère ligne avec label, puis lignes vides
            for i, item in enumerate(mixed_urls, start=1):
                # item peut être (url, origin)
                try:
                    url_m, origin = item
                except Exception:
                    url_m, origin = str(item), ""

                param = "URL mixte" if i == 1 else ""
                add_row(param, url_m, "⚠️", origin)


    # =========================================================
    # 6)---------------- SECURITY HEADERS----------------------
    # =========================================================
    # Dans ton result actuel: missing_headers liste des noms, headers_comment = ["present"/"absent"] pour CHAQUE header checké
    # => Si tu veux un affichage propre, mieux vaut reconstruire: tous les headers absents avec commentaire "absent".
    if missing_headers:
        for i, header in enumerate(missing_headers, start=1):
            param = "Headers sécu manquants" if i == 1 else ""
            add_row(param, header, "❌", "absent")
            

    # =========================================================
    # 6)------------------ REDIRECTIONS ----------------------
    # =========================================================
    num_redir = redirects.get("num_redirects", 0)
    risk = redirects.get("risk", "Low")

    risk_icon = {"Low": "✅", "Medium": "⚠️", "High": "❌"}.get(risk, "ⓘ")
    add_row("Nombre de redirections", str(num_redir), ck(redirects["num_ok"]), redirects.get("num_comment", ""))

    # Domaines
    r_domains = redirects.get("redirect_domains") or []
    if r_domains:
        add_row("Domaines de redirection", r_domains[0], "ⓘ", redirects.get("rd_comment", ""))
        for dom in r_domains[1:]:
            add_row("", dom, "ⓘ", "")

    # IPs
    r_ips = redirects.get("redirect_ips") or []
    if r_ips:
        add_row("IPs de redirection", r_ips[0], "⚠️", redirects.get("ri_comment", ""))
        for ip in r_ips[1:]:
            add_row("", ip, "⚠️", "")

# ===============================================================
# FUNCTION : check_ssl_tls_config()
# ===============================================================
def check_ssl_tls_config(url: str) -> dict:
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


# ===============================================================
# FUNCTION : display_ssl_tls()
# ===============================================================
def display_ssl_tls(result):

    def add(p, v, c="", com=""):
        ssl_table.insert("", "end", values=(p, v, c, com))

    cert = result["certificate"]
    tls = result["tls"]
    trust = result["trust"]

    # --- Common name ----
    add("Nom", cert["subject"]["common_name"])

    # --- SAN(s) ----
    san = cert["subject"]["san_dns"]

    if san:
        add("Subject Alternative Name", san[0], ck(result["hostname_check"]["match"]),
            SPACER + result["hostname_check"]["comment"])
        for s in san[1:]:
            add("", s)
    else:
        add("Subject Alternative Name", "Aucun SAN", "⚠️",
            SPACER + "Extension SAN absente (certificat legacy / config atypique)")

    # --- SAN number ---
    add("Nombre de SAN", len(san), ck(result["hostname_check"]["ok"]),
        SPACER + result["hostname_check"]["warnings"]["multi_domain"])

    # --- Certificat validity ---
    add("Début de validité", cert["validity"]["not_before"],
        ck(cert["validity"]["is_valid_now"]),
        SPACER + ("Certificat valide" if cert["validity"]["is_valid_now"] else "Certificat expiré"))
    
    add("Fin de validité", cert["validity"]["not_after"],
        ck(cert["validity"]["expires_ok"]),
        SPACER + cert["validity"]["expires_soon_comment"])

    # --- Certificat version ---
    add("Version du certificat", cert["version"]["id"],
        ck(cert["version"]["ok"]),
        SPACER + cert["version"]["comment"])

    # --- Certificat serial num ---
    add("Serial number", cert["serial"]["hex"],
        ck(cert["serial"]["ok"]),
        SPACER + cert["serial"]["comment"])

    # --- Certificat hash algorithm ---
    add("Algorithme", cert["signature"]["hash_algorithm"],
        ck(cert["signature"]["ok"]),
        SPACER + cert["signature"]["comment"])

    # --- Fingerprint ---
    add("Empreinte", cert["signature"]["fingerprint_sha256"], "ⓘ")

    # --- Authority ---
    add("Autorité certifiante", cert["issuer"]["common_name"],
        ck(trust["is_trusted"]),
        SPACER + ("Autorité reconnue" if trust["is_trusted"] else "Autorité non reconnue"))

    # --- Auto-signed ---
    add("Auto-signé", trust["is_self_signed"],
        "✖" if trust["is_self_signed"] else "✔",
        SPACER + ("Certificat autosigné" if trust["is_self_signed"] else "Certificat non autosigné"))

    # --- Public Key ---
    add("Clé publique", cert["public_key"].get("summary", ""),
        ck(cert["public_key"]["ok"]),
        SPACER + cert["public_key"]["comment"])

    # --- Extensions (basic constraint) ---
    add("Basic constraints", cert["extensions"]["basic_constraints"],
        ck(cert["extensions"]["basic_constraints_ok"]),
        SPACER + cert["extensions"]["basic_constraints_comment"])
    
    # --- Extensions (EKU) ---
    add("KU étendu", cert["extensions"]["extended_key_usage"],
        ck(cert["extensions"]["eku_ok"]),
        SPACER + cert["extensions"]["eku_comment"])

    # --- Extensions (KU) ---
    add("Key usage (KU)", cert["extensions"]["key_usage"],
        ck(cert["extensions"]["ku_ok"]),
        SPACER + cert["extensions"]["ku_comment"])

    # --- Extensions (CRL) ---
    add("Liste de révocation", cert["extensions"]["crl_distribution_points"],
        ck(cert["extensions"]["crl_ok"]),
        SPACER + cert["extensions"]["crl_comment"])

    # --- TLS actual version ---
    add("Version TLS", tls["negotiated_version"], ck(tls["nv_ok"]),
        SPACER + tls["nv_comment"])

    # --- TLS supported version ---
    if tls["supported_versions"]:
        s = tls["supported_versions"]
        for v in ["TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"]:
            if v in ["TLS1.0", "TLS1.1"]:
                check_icon = "✖" if s[v] else "✔"
            else:
                check_icon = ck(s[v])

            add(
                f"Support {v}",
                "Oui" if s[v] else "Non",
                check_icon,
                SPACER + (
                    "À désactiver" if v in ["TLS1.0", "TLS1.1"] and s[v]
                    else "OK" if s[v]
                    else "Non supporté"
                )
            )

    # --- TLS policy ---
    add("Politique TLS",
        "OK" if tls["policy"]["ok"] else "KO",
        ck(tls["policy"]["ok"]),
        SPACER + tls["policy"]["comment"])

    # --- Cipher Suite ---
    add("Cipher Suite", tls["cipher"]["name"], ck(tls["cipher"]["ok"]),
        SPACER + tls["cipher"]["comment"])
    add("Taille de clé (bits)", tls["cipher"]["bits"], "ⓘ")

    # --- Weak cipher legacy (TLS ≤ 1.2) ---
    add(
        "Ciphers faibles (legacy)",
        "OK" if tls.get("weak_cipher_ok") else "Faible" if tls.get("weak_cipher_ok") is False else "Non testé",
        ck(tls.get("weak_cipher_ok")),
        SPACER + tls.get("weak_cipher_comment", "")
    )


# ===============================================================
# FUNCTION : check_cookies()
# ===============================================================
def check_cookies(result):
    return None


# ===============================================================
# FUNCTION : display_cookies()
# ===============================================================
def display_cookies(result):
    return None


# ===============================================================
# FUNCTION : max_risk()
# ===============================================================
def max_risk(current, new): #CHECK OWASP
    """Compare deux niveaux de risque et renvoie le plus élevé"""
    levels = {"Low": 0, "Medium": 1, "High": 2}
    return new if levels[new] > levels[current] else current


# ===============================================================
# FUNCTION : start_scan()
# ===============================================================
def start_scan():
    clear_tables(http_table,ssl_table,cookies_table)
    url = url_entry.get().strip()
    if not url:
        messagebox.showwarning("Attention", "Veuillez entrer une URL")
        return
    
    # Disable buttons
    go_button.config(state="disabled")
    open_report_button.config(state="disabled")
    progress_bar["value"] = 0
    root.update_idletasks()

    def run_scan():
        result = {}

        def update_progress(value):
            progress_bar["value"] = value
            root.update_idletasks()

        try:
            # Step 1 : normalize URL
            time.sleep(0.05) 
            update_progress(5)

            # Step 2 : HTTP request
            update_progress(20)
            result_http = check_http_config(url)

            
            # Step 3 SSL / TLS 
            update_progress(40)
            result_ssl = check_ssl_tls_config(url)

            # Step 3 : Display results
            update_progress(80)
            display_http(result_http)
            display_ssl_tls(result_ssl)
            update_progress(90)

            # Final step
            time.sleep(0.1)  # petite pause pour montrer la barre à 100%
            update_progress(100)

        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur pendant le scan : {e}")

        finally:
            messagebox.showinfo("Terminé", "Scan terminé !")
            open_report_button.config(state="normal")
            go_button.config(state="normal")

    threading.Thread(target=run_scan, daemon=True).start()


# ===============================================================
# FUNCTION : open_settings()
# ===============================================================
def open_settings():
    messagebox.showinfo("Settings")


# ===============================================================
# FUNCTION : open_report()
# ===============================================================
def open_report():
    messagebox.showinfo("Report")

# ===============================================================
# -------------------------- UI ---------------------------------
# ===============================================================
root = ttk.Window(themename="cosmo")  
root.title("Scanner de sécurité Web")
root.geometry("1600x800")

# Title
title_label = ttk.Label(root, text="Scanner de configuration de sécurité Web", font=("Helvetica", 16, "bold"))
title_label.pack(pady=10)

# URL textbox
url_frame = ttk.Frame(root)
url_frame.pack(pady=5)
ttk.Label(url_frame, text="URL du site:", font=("Helvetica", 12)).pack(side="left", padx=5)
url_entry = ttk.Entry(url_frame, width=35)
url_entry.pack(side="left", padx=5)

# Checkboxes
checkbox_frame = ttk.LabelFrame(root, text="Sélection des vérifications")
checkbox_frame.pack(padx=10, pady=10, fill="x")

https_var = ttk.IntVar(value=1)
ssl_var = ttk.IntVar(value=1)
headers_var = ttk.IntVar(value=1)
cookies_var = ttk.IntVar(value=1)

ttk.Checkbutton(checkbox_frame, text="Vérifier HTTPS", variable=https_var).pack(anchor="w", pady=2, padx=5)
ttk.Checkbutton(checkbox_frame, text="Vérifier SSL/TLS", variable=ssl_var).pack(anchor="w", pady=2, padx=5)
ttk.Checkbutton(checkbox_frame, text="Vérifier headers HTTP", variable=headers_var).pack(anchor="w", pady=2, padx=5)
ttk.Checkbutton(checkbox_frame, text="Vérifier cookies", variable=cookies_var).pack(anchor="w", pady=2, padx=5)

# Buttons GO and Settings
button_frame = ttk.Frame(root)
button_frame.pack(pady=15)
go_button = ttk.Button(button_frame, text="GO", bootstyle=SUCCESS, width=12, command=start_scan)
go_button.pack(side="left", padx=10)
settings_button = ttk.Button(button_frame, text="Settings", bootstyle=INFO, width=12, command=open_settings)
settings_button.pack(side="left", padx=10)

# Loading bar
progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate", bootstyle="success-striped")
progress_bar.pack(pady=20)

# Button Open Report 
open_report_button = ttk.Button(root, text="Open Report", bootstyle=WARNING, width=25, state="disabled", command=open_report)
open_report_button.pack(pady=10)

# ------------------ Results ------------------
tables_frame = ttk.Frame(root)
tables_frame.pack(padx=10, pady=10, fill="both", expand=True)

# Tables creation
http_table = create_result_table(tables_frame, "HTTP")
ssl_table = create_result_table(tables_frame, "SSL/TLS")
cookies_table = create_result_table(tables_frame, "Cookies")

style = ttk.Style()
style.configure("Treeview", rowheight=18)
style.configure("Treeview.Heading",font=("Helvetica", 11, "bold"))
root.mainloop()
