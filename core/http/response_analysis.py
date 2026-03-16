# core/http/response_analysis.py

# ===============================================================
# IMPORTS
# ===============================================================
from http_status_codes import HTTP_STATUS_CODES
from urllib.parse import urlparse, urlunparse

from utils.http import is_apex_www_pair, normalize_hostname, shorten_url


# ===============================================================
# FUNCTION : evaluate_status
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
# FUNCTION : detect_http_version
# ===============================================================
def detect_http_version(url: str, httpx_module) -> tuple[str, bool | None, str, str]:
    """
    Detect the negotiated HTTP protocol version with httpx.

    Returns:
        tuple[str, bool | None, str, str]:
            (http_version, http_ok, http_comment, http_risk)
    """
    try:
        with httpx_module.Client(http2=True, timeout=5) as client:
            response = client.get(url)
            http_version = str(getattr(response, "http_version", "") or "").upper()
    except Exception as exc:
        return "Inconnue", None, f"Impossible de determiner la version HTTP via httpx: {exc}", "MEDIUM"

    if http_version in ("HTTP/3", "HTTP/2", "HTTP/1.1"):
        http_ok = True
        http_comment = "Version HTTP moderne et acceptable"
        http_risk = "INFO"
    elif http_version in ("HTTP/1.0", "HTTP/0.9"):
        http_ok = False
        http_comment = "Version HTTP obsolète"
        http_risk = "HIGH"
    else:
        http_version = "Inconnue"
        http_ok = None
        http_comment = "httpx n'a pas expose de version HTTP exploitable"
        http_risk = "MEDIUM"

    return http_version, http_ok, http_comment, http_risk


# ===============================================================
# FUNCTION : analyze_url_transition
# ===============================================================
def analyze_url_transition(original_url: str, final_url: str) -> tuple[str, bool | None, str, str, bool]:
    """
    Analyze the transition between the original URL and the final URL.

    Returns:
        tuple[str, bool | None, str, str, bool]:
            (final_url, url_ok, url_comment, url_risk, has_url_credentials)
    """

    original_parsed = urlparse(original_url)
    final_parsed = urlparse(final_url)
    original_host = normalize_hostname(original_parsed.hostname)
    final_host = normalize_hostname(final_parsed.hostname)
    has_host_change = bool(
        original_host and final_host and original_host != final_host and not is_apex_www_pair(original_host, final_host)
    )
    has_url_credentials = bool(
        original_parsed.username
        or original_parsed.password
        or final_parsed.username
        or final_parsed.password
    )
    host_change_message = f"Changement d'hote ({shorten_url(original_url)} ⇒ {shorten_url(final_url)})"

    url_ok = True
    url_comment = "OK"
    url_risk = "INFO"
    if has_host_change:
        url_ok = None
        url_comment = host_change_message

    if has_host_change:
        url_risk = "LOW"

    return final_url, url_ok, url_comment, url_risk, has_url_credentials


# ===============================================================
# FUNCTION : evaluate_https_posture
# ===============================================================
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
            pass

    # Detect HTTP->HTTPS upgrade through redirects seen by requests.
    redirect_upgrade = False
    redirect_downgrade = False
    try:
        history = list(getattr(response, "history", []) or [])
        if history:
            first_scheme = urlparse(history[0].url).scheme.lower()
            last_scheme = urlparse(getattr(response, "url", "")).scheme.lower()
            redirect_upgrade = first_scheme == "http" and last_scheme == "https"
            redirect_downgrade = first_scheme == "https" and last_scheme == "http"
        else:
            redirect_upgrade = (
                parsed_original.scheme.lower() == "http"
                and parsed_final.scheme.lower() == "https"
            )
            redirect_downgrade = (
                parsed_original.scheme.lower() == "https"
                and parsed_final.scheme.lower() == "http"
            )
    except Exception:
        redirect_upgrade = False
        redirect_downgrade = False

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
        if redirect_downgrade:
            https_comment = "HTTPS redirige vers HTTP (downgrade detecte)"
            https_risk = "HIGH"
        else:
            https_comment = "HTTPS non detecte (ni URL finale HTTPS, ni probe HTTPS concluante)."
            https_risk = "MEDIUM"

    return uses_https, https_value, https_comment, https_risk


# ===============================================================
# FUNCTION : adjust_url_risk_with_https_posture
# ===============================================================
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
# FUNCTION : evaluate_response_time
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

# ===============================================================
# FUNCTION : evaluate_response_time_risk
# ===============================================================
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
