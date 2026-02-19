try:
    import httpx
except ImportError:
    httpx = None
import requests
from utils.url import normalize_url
from constants import SECURITY_HEADERS
from core.http.mixed_content import detect_mixed_content
from core.http.redirects import scan_redirections
from core.http.urls import analyze_url_transition
from core.http.headers_security import scan_security_headers
from core.http.result import init_http_result
from core.http.response_analysis import evaluate_status, detect_http_version, detect_https, evaluate_response_time



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
    
    # ------- STORE AND NORMALIZE URL --------
    raw_url = url
    url = normalize_url(url)

    # --------- DICT INITIALIZATION ----------
    result = init_http_result(raw_url, url)

    # ------------ REQUEST ON URL ------------
    try:
        response = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=5,
            allow_redirects=True,
        )

        # ------- HTTP CODE + MESSAGE --------
        (
            result["status_code"],
            result["status_message"],
            result["status_ok"],
         ) = evaluate_status(response)

        # ---------- URL ANALYSIS ------------
        (
            result["final_url"],
            result["url_ok"],
            result["url_comment"],
            result["url_findings"],
        ) = analyze_url_transition(result["original_url"], response.url)
        
        # ------ HTTP VERSION ANALYSIS -------
        (
            result["http_version"],
            result["http_ok"],
            result["http_comment"],
        ) = detect_http_version(result["final_url"], response, httpx)
        
        # -------------- HTTPS ---------------
        (
            result["uses_https"],
            result["https_comment"],
        ) = detect_https(result["final_url"])
        
        # ------ RESPONSE TIME ANALYSIS ------
        result["time"] = response.elapsed.total_seconds()
        result["time_ok"], result["time_comment"] = evaluate_response_time(result["time"])
        
        # ----- SECURITY HEADER ANALYSIS -----
        # result["missing_headers"], result["headers_comment"] = scan_security_headers
        # (
        #     response.headers,
        #     SECURITY_HEADERS,
        # )
        result["missing_headers"], result["header_findings"] = scan_security_headers(
            response.headers,
            SECURITY_HEADERS,
        )
        
        # ------ MIXED CONTENT ANALYSIS ------
        (
            result["mixed_content"],
            result["mixed_url"],
            result["mixed_comment"],
        ) = detect_mixed_content(
            response.text,
            result["final_url"],
            result["uses_https"],
        )
        
        # ------ REDIRECTIONS ANALYSIS -------
        result["redirects"] = scan_redirections(response, url)

    # --------- EXCEPTIONS MANAGMENT ---------
    except requests.exceptions.SSLError as e:
        txt = repr(e)
        if "CERTIFICATE_VERIFY_FAILED" in txt and "unable to get local issuer certificate" in txt:
            result["comment"] = (
                "Erreur TLS/SSL : vérification du certificat impossible "
                "(CA intermédiaire manquante / chaîne incomplète) "
                "Le navigateur peut réussir via cache, mais Python/OpenSSL échoue")
            
        elif "CERTIFICATE_VERIFY_FAILED" in txt:
            result["comment"] = (
                "Erreur TLS/SSL : vérification du certificat impossible "
                "(CERTIFICATE_VERIFY_FAILED)")
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
    

