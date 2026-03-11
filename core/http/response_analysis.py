# core/http/response_analysis.py

# ===============================================================
# IMPORTS
# ===============================================================
from http_status_codes import HTTP_STATUS_CODES
from utils.http import map_http_version
from urllib.parse import urlparse, urlunparse


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


def evaluate_status_risk(status_code: int) -> str:
    """
    Risk policy for HTTP status display.
    Current policy: status code is informational by default.
    """
    return "INFO"


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


def evaluate_http_version_risk(http_version: str) -> str:
    """
    Classify HTTP version risk.
    """
    v = (http_version or "").strip().upper()
    if v in {"HTTP/2", "HTTP/3", "H2", "H3", "HTTP/1.1"}:
        return "INFO"
    if v in {"HTTP/1.0", "HTTP/0.9"}:
        return "HIGH"
    return "MEDIUM"
def evaluate_https_posture(
    original_url: str,
    final_url: str,
    response,
    requests_module,
    headers: dict | None = None,
    timeout: int = 5,
) -> tuple[bool, str, str, str]:
    """
    Evaluate HTTPS posture with a browser-closer approach.

    Returns:
        tuple[bool, str, str, str]:
            (uses_https, https_value, https_comment, https_risk)
    """
    uses_https = str(final_url or "").lower().startswith("https://")
    https_value = "Oui" if uses_https else "Non"
    https_comment = "URL finale en HTTPS." if uses_https else "URL finale en HTTP."
    https_risk = "INFO" if uses_https else "MEDIUM"

    parsed_original = urlparse(original_url or "")
    parsed_final = urlparse(final_url or "")

    # Probe HTTPS directly on the final host/path (or original if final missing)
    target = parsed_final if parsed_final.netloc else parsed_original
    if target.netloc:
        probe = urlunparse(
            (
                "https",
                target.netloc,
                target.path or "/",
                target.params or "",
                target.query or "",
                target.fragment or "",
            )
        )
    else:
        probe = ""

    https_probe_ok = False
    if probe:
        try:
            probe_resp = requests_module.get(
                probe,
                headers=headers or {},
                timeout=timeout,
                allow_redirects=True,
            )
            https_probe_ok = str(getattr(probe_resp, "url", "")).lower().startswith("https://")
        except Exception:
            https_probe_ok = False

    # Detect HTTP->HTTPS upgrade through redirects seen by requests.
    redirect_upgrade = False
    try:
        history = list(getattr(response, "history", []) or [])
        if history:
            first_scheme = urlparse(history[0].url).scheme.lower()
            last_scheme = urlparse(getattr(response, "url", "")).scheme.lower()
            redirect_upgrade = first_scheme == "http" and last_scheme == "https"
        else:
            redirect_upgrade = (
                parsed_original.scheme.lower() == "http"
                and parsed_final.scheme.lower() == "https"
            )
    except Exception:
        redirect_upgrade = False

    if uses_https:
        if redirect_upgrade:
            https_comment = "HTTP redirige vers HTTPS (upgrade détecté)"
        else:
            https_comment = "HTTPS actif sur l'URL finale"
        https_value = "Oui"
        https_risk = "INFO"
    elif https_probe_ok:
        https_value = "Partiel"
        https_comment = "HTTPS est disponible, le navigateur devrait upgrade la connexion via HTTPS"
        https_risk = "LOW"
    else:
        https_value = "Non"
        https_comment = "HTTPS non detecte (ni URL finale HTTPS, ni probe HTTPS concluante)."
        https_risk = "MEDIUM"

    return uses_https, https_value, https_comment, https_risk


def adjust_url_risk_with_https_posture(
    url_risk: str,
    final_url: str,
    https_value: str,
    url_comment: str,
) -> tuple[str, str]:
    """
    Adjust URL risk when requests sees HTTP but HTTPS is available.
    """
    adjusted_risk = url_risk
    adjusted_comment = url_comment or ""

    if (
        adjusted_risk == "MEDIUM"
        and str(final_url or "").lower().startswith("http://")
        and https_value in {"Oui", "Partiel"}
    ):
        adjusted_risk = "LOW"
        extra = "HTTP observe par requests, mais HTTPS est disponible."
        if extra not in adjusted_comment:
            adjusted_comment = (adjusted_comment + " " + extra).strip()

    return adjusted_risk, adjusted_comment


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

def evaluate_response_time_risk(seconds: float) -> str:
    """
    Risk policy for response time.
    """
    if seconds < 0.8:
        return "INFO"
    if seconds < 2:
        return "LOW"
    if seconds < 5:
        return "MEDIUM"
    return "HIGH"
