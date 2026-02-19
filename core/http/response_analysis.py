from http_status_codes import HTTP_STATUS_CODES
from utils.http import map_http_version


# ===============================================================
# FUNCTION : evaluate_status(response)
# ===============================================================
def evaluate_status(response) -> tuple[int, str, bool | None]:
    """
    Evaluate the HTTP status code and classify it.

    Returns:
        tuple[int, str, bool | None]:
            (status_code, status_message, status_ok)
    """

    status_code = response.status_code
    status_message = HTTP_STATUS_CODES.get(status_code, "Code inconnu")

    if 200 <= status_code < 400:
        status_ok = True
    elif 400 <= status_code < 500:
        status_ok = None  # Client error
    else:
        status_ok = False  # 5xx server KO

    return status_code, status_message, status_ok


# ===============================================================
# FUNCTION : detect_http_version(url, response, httpx))
# ===============================================================
def detect_http_version(url: str, response, httpx_module) -> tuple[str, bool | None, str]:
    """
    Detect the HTTP protocol version (httpx first, then fallback).

    Returns:
        tuple[str, bool | None, str]:
            (http_version, http_ok, http_comment)
    """

    http_version = ""
    http_comment = ""
    http_ok = None

    # ------------------ TRY VIA HTTPX ---------------------
    if httpx_module:
        try:
            with httpx_module.Client(http2=True, timeout=5) as c:
                r2 = c.get(url)
                hv = getattr(r2, "http_version", "") or ""
                http_version = hv.upper()
        except Exception:
            pass
    
    # -------------- FALLBACK VIA REQUEST/RAW --------------
    if not http_version:
        v = getattr(getattr(response, "raw", None), "version", None)
        version_label, version_comment = map_http_version(v)
        http_version = version_label
        http_comment = version_comment

        if v in (11, 20):      # HTTP/1.1 or HTTP/2
            http_ok = True
        elif v in (9, 10):     # obsoletes
            http_ok = False
        else:
            http_ok = None
    else:
        if http_version in ("HTTP/2", "HTTP/1.1"):
            http_ok = True
        elif http_version in ("HTTP/1.0", "HTTP/0.9"):
            http_ok = False
        else:
            http_ok = None

    return http_version, http_ok, http_comment


# ===============================================================
# FUNCTION : detect_https(url)
# ===============================================================
def detect_https(final_url: str) -> tuple[bool, str]:
    """
    Check whether the final URL uses HTTPS.

    Returns:
        tuple[bool, str]:
            (uses_https, comment)
    """
    uses_https = final_url.startswith("https://")
    comment = "Site sécurisé (HTTPS)" if uses_https else "Site non sécurisé (HTTP)"
    
    return uses_https, comment


# ===============================================================
# FUNCTION : evaluate_response_time(seconds)
# ===============================================================
def evaluate_response_time(seconds: float) -> tuple[bool | None, str]:
    """
    Classify the response time performance.

    Returns:
        tuple[bool | None, str]:
            (time_ok, comment)
    """

    if seconds < 0.8:
        return True, "Temps de réponse rapide"
    elif seconds < 2:
        return True, "Temps correct"
    elif seconds < 5:
        return None, "Temps de réponse lent"
    else:
        return False, "Très lent ou proche timeout"
