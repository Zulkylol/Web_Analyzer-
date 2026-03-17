# core/http/scan_http.py

# ===============================================================
# IMPORTS
# ===============================================================
import httpx
import requests

from constants import HEADER, SECURITY_HEADERS
from core.http.errors import map_http_scan_error
from core.http.exposure import scan_exposed_methods, scan_standard_files
from core.http.security_headers import scan_security_headers
from core.http.mixed_content import detect_mixed_content, evaluate_mixed_content_risk
from core.http.report import build_http_report
from core.http.redirects import scan_redirections
from core.http.response_analysis import (
    analyze_url_transition,
    adjust_url_risk_with_https_posture,
    detect_http_version,
    evaluate_https_posture,
    evaluate_response_time,
    evaluate_status,
)
from core.http.result import init_http_result
from utils.url import normalize_url


# ===============================================================
# FUNCTION : scan_http_config
# ===============================================================
def scan_http_config(url: str) -> dict:
    """
    Complete HTTP pipeline: request, analysis, enrichment, then report building.

    Returns :
        dict : formatted output
    """
    normalized_url = normalize_url(url)
    result = init_http_result(normalized_url)
    target = result["target"]
    transport = result["transport"]
    content = result["content"]
    exposure = result["exposure"]
    request_headers = HEADER.copy()

    try:
        session = requests.Session()
        session.max_redirects = 101
        try:
            response = session.get(
                normalized_url,
                headers=request_headers,
                timeout=5,
                allow_redirects=True,
            )
        except requests.exceptions.SSLError:
            session.verify = False
            response = session.get(
                normalized_url,
                headers=request_headers,
                timeout=5,
                allow_redirects=True,
            )
            transport["tls_bypassed"] = True
            transport["tls_bypass_comment"] = (
                "Analyse HTTP poursuivie sans validation du certificat TLS "
                "après échec de la vérification stricte"
            )
        
        
        # Block 1: immediate response information
        (
            transport["status_code"],
            transport["status_message"],
            transport["status_ok"],
        ) = evaluate_status(response)

        transport["status_risk"] = "INFO"

        (
            target["final_url"],
            target["url_ok"],
            target["url_comment"],
            target["url_risk"],
            target["has_url_credentials"],
        ) = analyze_url_transition(target["original_url"], response.url)

        (
            transport["http_version"],
            transport["http_ok"],
            transport["http_comment"],
            transport["http_version_risk"],
        ) = detect_http_version(target["final_url"], httpx)


        # Block 2: HTTPS posture and its impact on final URL interpretation.
        (
            transport["uses_https"],
            transport["https_value"],
            transport["https_comment"],
            transport["https_risk"],
        ) = evaluate_https_posture(
            original_url=target["original_url"],
            final_url=target["final_url"],
            response=response,
            requests_module=session,
            headers=request_headers,
            timeout=5,
        )

        target["url_risk"], target["url_comment"] = adjust_url_risk_with_https_posture(
            url_risk=target.get("url_risk", "MEDIUM"),
            final_url=target.get("final_url", ""),
            https_value=transport.get("https_value", "Non"),
            url_comment=target.get("url_comment", ""),
        )

        transport["time"] = response.elapsed.total_seconds()
        (
            transport["time_ok"],
            transport["time_comment"],
            transport["time_risk"],
        ) = evaluate_response_time(transport["time"])

        
        # Block 3: analysis of headers and HTML content.
        content["header_findings"] = scan_security_headers(
            response.headers,
            SECURITY_HEADERS,
        )

        (
            content["mixed_content"],
            content["mixed_url"],
            content["mixed_comment"],
            content["mixed_content_level"],
        ) = detect_mixed_content(
            response.text,
            target["final_url"],
            transport["uses_https"],
        )
        content["mixed_content_risk"] = evaluate_mixed_content_risk(
            content["mixed_content"],
            content["mixed_content_level"],
        )


        # Block 4: additional exposure checks (redirects, standard files, HTTP methods).
        exposure["redirects"] = scan_redirections(response, normalized_url)
        exposure["standard_files"] = scan_standard_files(
            target["final_url"],
            requests_module=session,
            headers=request_headers,
            timeout=5,
        )
        exposure["methods_exposure"] = scan_exposed_methods(
            target["final_url"],
            requests_module=session,
            headers=request_headers,
            timeout=5,
        )

    except Exception as exc:
        result["errors"]["message"] = map_http_scan_error(exc)

    # The report is always built, even on error, to keep a stable contract for the UI.
    result["report"] = build_http_report(result)
    return result
