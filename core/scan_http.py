import re
import ipaddress
import requests

from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

try:
    import httpx
except ImportError:
    httpx = None

from utils.url import normalize_url
from http_status_codes import HTTP_STATUS_CODES
from constants import SECURITY_HEADERS
from utils.http import map_http_version


# ===============================================================
# FUNCTION : check_http_security()
# ===============================================================
def scan_http_config(url: str) -> dict:
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