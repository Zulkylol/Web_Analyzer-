try:
    import httpx
except ImportError:
    httpx = None

import requests

from constants import SECURITY_HEADERS
from core.http.client import fetch_http_response
from core.http.errors import map_http_scan_error
from core.http.exposure import scan_exposed_methods, scan_standard_files
from core.http.headers_security import scan_security_headers
from core.http.mixed_content import detect_mixed_content, evaluate_mixed_content_risk
from core.http.redirects import scan_redirections
from core.http.response_analysis import (
    adjust_url_risk_with_https_posture,
    detect_http_version,
    evaluate_http_version_risk,
    evaluate_https_posture,
    evaluate_response_time,
    evaluate_response_time_risk,
    evaluate_status,
    evaluate_status_risk,
)
from core.http.result import init_http_result
from core.http.urls import analyze_url_transition
from utils.url import normalize_url


def scan_http_config(url: str) -> dict:
    raw_url = url
    normalized_url = normalize_url(url)
    result = init_http_result(raw_url, normalized_url)
    request_headers = {"User-Agent": "Mozilla/5.0"}

    try:
        response = fetch_http_response(normalized_url, headers=request_headers, timeout=5)

        (
            result["status_code"],
            result["status_message"],
            result["status_ok"],
        ) = evaluate_status(response)
        result["status_risk"] = evaluate_status_risk(result["status_code"])

        (
            result["final_url"],
            result["url_ok"],
            result["url_comment"],
            result["url_findings"],
            result["url_risk"],
        ) = analyze_url_transition(result["original_url"], response.url)

        (
            result["http_version"],
            result["http_ok"],
            result["http_comment"],
        ) = detect_http_version(result["final_url"], response, httpx)
        result["http_version_risk"] = evaluate_http_version_risk(result["http_version"])

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

        result["time"] = response.elapsed.total_seconds()
        result["time_ok"], result["time_comment"] = evaluate_response_time(result["time"])
        result["time_risk"] = evaluate_response_time_risk(result["time"])

        result["missing_headers"], result["header_findings"] = scan_security_headers(
            response.headers,
            SECURITY_HEADERS,
        )

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
        result["mixed_content_risk"] = evaluate_mixed_content_risk(
            result["mixed_content"],
            result["mixed_content_level"],
        )

        result["redirects"] = scan_redirections(response, normalized_url)
        result["standard_files"] = scan_standard_files(
            result["final_url"],
            requests_module=requests,
            headers=request_headers,
            timeout=5,
        )
        result["methods_exposure"] = scan_exposed_methods(
            result["final_url"],
            requests_module=requests,
            headers=request_headers,
            timeout=5,
        )

    except Exception as exc:
        result["comment"] = map_http_scan_error(exc)

    return result
