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
    evaluate_response_time_risk,
    evaluate_status,
)
from core.http.result import init_http_result
from utils.url import normalize_url


# ===============================================================
# FUNCTION : scan_http_config
# ===============================================================
def scan_http_config(url: str) -> dict:
    """Pipeline HTTP complet: requete, analyse, enrichissement, puis construction du report."""
    normalized_url = normalize_url(url)
    result = init_http_result(normalized_url)
    target = result["target"]
    transport = result["transport"]
    content = result["content"]
    exposure = result["exposure"]
    request_headers = HEADER.copy()

    try:
        response = requests.get(
            normalized_url,
            headers=request_headers,
            timeout=5,
            allow_redirects=True,
        )

        # Bloc 1: informations de reponse immediates.
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


        # Bloc 2: posture HTTPS et impact sur l'interpretation de l'URL finale.
        (
            transport["uses_https"],
            transport["https_value"],
            transport["https_comment"],
            transport["https_risk"],
        ) = evaluate_https_posture(
            original_url=target["original_url"],
            final_url=target["final_url"],
            response=response,
            requests_module=requests,
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
        transport["time_ok"], transport["time_comment"] = evaluate_response_time(transport["time"])
        transport["time_risk"] = evaluate_response_time_risk(transport["time"])

        # Bloc 3: analyse des headers et du contenu HTML.
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

        # Bloc 4: exposition annexe (redirections, fichiers standards, methodes HTTP).
        exposure["redirects"] = scan_redirections(response, normalized_url)
        exposure["standard_files"] = scan_standard_files(
            target["final_url"],
            requests_module=requests,
            headers=request_headers,
            timeout=5,
        )
        exposure["methods_exposure"] = scan_exposed_methods(
            target["final_url"],
            requests_module=requests,
            headers=request_headers,
            timeout=5,
        )

    except Exception as exc:
        result["errors"]["message"] = map_http_scan_error(exc)

    # Le report est toujours construit, meme en cas d'erreur, pour garder un contrat stable cote UI.
    result["report"] = build_http_report(result)
    return result
