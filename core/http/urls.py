# core/http/urls.py

# ===============================================================
# IMPORTS
# ===============================================================
from urllib.parse import urlparse

from utils.http import shorten_url


def _normalize_hostname(hostname: str | None) -> str:
    return (hostname or "").strip().lower().strip(".")


def _is_apex_www_pair(original_hostname: str | None, final_hostname: str | None) -> bool:
    original = _normalize_hostname(original_hostname)
    final = _normalize_hostname(final_hostname)
    if not original or not final or original == final:
        return False
    return original == f"www.{final}" or final == f"www.{original}"


# ===============================================================
# FUNCTION : analyze_url_transistion(original_url, final_url)
# ===============================================================
def analyze_url_transition(original_url: str, final_url: str) -> tuple[str, bool | None, str, list[str], str]:
    """
    Analyze the transition between the original URL and the final URL.

    Returns:
        tuple[str, bool | None, str, list[str], str]:
            (final_url, url_ok, url_comment, url_findings, url_risk)
    """

    original_parsed = urlparse(original_url)
    final_parsed = urlparse(final_url)
    original_host = _normalize_hostname(original_parsed.hostname)
    final_host = _normalize_hostname(final_parsed.hostname)

    findings = []

    def add_finding(ok_value, message, severity_weight):
        findings.append(
            {
                "ok": ok_value,
                "weight": severity_weight,
                "message": message,
            }
        )

    # a) Credentials in URL
    if (
        original_parsed.username
        or original_parsed.password
        or final_parsed.username
        or final_parsed.password
    ):
        add_finding(False, "Credentials detectes dans l'URL", 3)

    # b) Downgrade HTTPS -> HTTP
    if original_parsed.scheme == "https" and final_parsed.scheme == "http":
        add_finding(False, f"Downgrade HTTPS -> HTTP ({shorten_url(original_url)} -> {shorten_url(final_url)})", 3)

    # c) Upgrade HTTP -> HTTPS
    if original_parsed.scheme == "http" and final_parsed.scheme == "https":
        add_finding(True, f"Redirection HTTP -> HTTPS ({shorten_url(original_url)} -> {shorten_url(final_url)})", 1)

    # d) Host change (warning), excluding standard apex <-> www redirects
    if original_host and final_host and original_host != final_host and not _is_apex_www_pair(original_host, final_host):
        add_finding(None, f"Changement d'hote ({shorten_url(original_url)} -> {shorten_url(final_url)})", 2)

    # Default values
    url_ok = True
    url_comment = "OK"
    url_findings = []
    url_risk = "INFO"

    # If issues found
    if findings:
        order_ok = {False: 0, None: 1, True: 2}
        findings_sorted = sorted(
            findings,
            key=lambda f: (-f["weight"], order_ok.get(f["ok"], 99)),
        )

        top = findings_sorted[0]
        url_ok = top["ok"]
        url_comment = top["message"]
        url_findings = [f["message"] for f in findings_sorted]

    # ---------------- URL RISK POLICY ----------------
    original_scheme = (original_parsed.scheme or "").lower()
    final_scheme = (final_parsed.scheme or "").lower()
    host_changed = bool(
        original_host and final_host and original_host != final_host and not _is_apex_www_pair(original_host, final_host)
    )

    if original_scheme == "https" and final_scheme == "http":
        url_risk = "HIGH"
    elif final_scheme == "http":
        url_risk = "MEDIUM"
    elif final_scheme == "https" and host_changed:
        url_risk = "LOW"
    elif final_scheme == "https":
        url_risk = "INFO"
    else:
        url_risk = "MEDIUM"

    return final_url, url_ok, url_comment, url_findings, url_risk
