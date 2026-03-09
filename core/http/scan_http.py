# core/http/scan_http.py

# ===============================================================
# IMPORTS
# ===============================================================
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
from core.http.exposure import scan_standard_files, scan_exposed_methods
from core.http.response_analysis import (
    evaluate_status,
    evaluate_status_risk,
    detect_http_version,
    evaluate_http_version_risk,
    evaluate_https_posture,
    adjust_url_risk_with_https_posture,
    evaluate_response_time,
    evaluate_response_time_risk,
)



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
    request_headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(
            url,
            headers=request_headers,
            timeout=5,
            allow_redirects=True,
        )

        # ------- HTTP CODE + MESSAGE --------
        (
            result["status_code"],
            result["status_message"],
            result["status_ok"],
         ) = evaluate_status(response)
        result["status_risk"] = evaluate_status_risk(result["status_code"])

        # ---------- URL ANALYSIS ------------
        (
            result["final_url"],
            result["url_ok"],
            result["url_comment"],
            result["url_findings"],
            result["url_risk"],
        ) = analyze_url_transition(result["original_url"], response.url)
        
        # ------ HTTP VERSION ANALYSIS -------
        (
            result["http_version"],
            result["http_ok"],
            result["http_comment"],
        ) = detect_http_version(result["final_url"], response, httpx)
        result["http_version_risk"] = evaluate_http_version_risk(result["http_version"])
        
        # -------------- HTTPS ---------------
        (
            result["uses_https"],
            result["https_value"],
            result["https_comment"],
            result["https_risk"],
        ) = evaluate_https_posture(
            original_url=result["original_url"],
            final_url=result["final_url"],
            response=response,
            requests_module=requests,
            headers=request_headers,
            timeout=5,
        )

        result["url_risk"], result["url_comment"] = adjust_url_risk_with_https_posture(
            url_risk=result.get("url_risk", "MEDIUM"),
            final_url=result.get("final_url", ""),
            https_value=result.get("https_value", "Non"),
            url_comment=result.get("url_comment", ""),
        )
        
        # ------ RESPONSE TIME ANALYSIS ------
        result["time"] = response.elapsed.total_seconds()
        result["time_ok"], result["time_comment"] = evaluate_response_time(result["time"])
        result["time_risk"] = evaluate_response_time_risk(result["time"])
        
        # ----- SECURITY HEADER ANALYSIS -----
        result["missing_headers"], result["header_findings"] = scan_security_headers(
            response.headers,
            SECURITY_HEADERS,
        )
        
        # ------ MIXED CONTENT ANALYSIS ------
        (
            result["mixed_content"],
            result["mixed_url"],
            result["mixed_comment"],
            result["mixed_content_level"],
        ) = detect_mixed_content(
            response.text,
            result["final_url"],
            result["uses_https"],
        )
        
        # ------ REDIRECTIONS ANALYSIS -------
        result["redirects"] = scan_redirections(response, url)

        # ------ STANDARD FILES ANALYSIS ------
        result["standard_files"] = scan_standard_files(
            result["final_url"],
            requests_module=requests,
            headers=request_headers,
            timeout=5,
        )

        # ------ EXPOSED METHODS ANALYSIS ------
        result["methods_exposure"] = scan_exposed_methods(
            result["final_url"],
            requests_module=requests,
            headers=request_headers,
            timeout=5,
        )

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
    

