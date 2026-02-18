from urllib.parse import urlparse
from urllib.parse import urlparse

# ===============================================================
# FUNCTION : analyze_url_transistion(original_url, final_url)
# ===============================================================
def analyze_url_transition(original_url: str, final_url: str) -> tuple[str, bool | None, str, list[str]]:
    """
    Analyze the transition between the original URL and the final URL.

    Returns:
        tuple[str, bool | None, str, list[str]]:
            (final_url, url_ok, url_comment, url_findings)
    """

    original_parsed = urlparse(original_url)
    final_parsed = urlparse(final_url)

    findings = []

    def add_finding(ok_value, message, severity_weight):
        findings.append({
            "ok": ok_value,
            "weight": severity_weight,
            "message": message
        })

    # a) Credentials in URL 
    if (original_parsed.username or original_parsed.password or
        final_parsed.username or final_parsed.password):
        add_finding(False, "Credentials détectés dans l’URL", 3)

    # b) Downgrade HTTPS -> HTTP 
    if original_parsed.scheme == "https" and final_parsed.scheme == "http":
        add_finding(False, "Downgrade HTTPS → HTTP", 3)

    # c) Upgrade HTTP -> HTTPS 
    if original_parsed.scheme == "http" and final_parsed.scheme == "https":
        add_finding(True, "Redirection HTTP → HTTPS (sécurisé)", 1)

    # d) Host change (warning)
    if (original_parsed.hostname and final_parsed.hostname and
        original_parsed.hostname.lower() != final_parsed.hostname.lower()):
        add_finding(
            None,
            f"Changement d’hôte ({original_parsed.hostname} → {final_parsed.hostname})",
            2
        )

    # Default values
    url_ok = True
    url_comment = "OK"
    url_findings = []

    # If issues founds 
    if findings:
        order_ok = {False: 0, None: 1, True: 2}
        findings_sorted = sorted(
            findings,
            key=lambda f: (-f["weight"], order_ok.get(f["ok"], 99))
        )

        top = findings_sorted[0]
        url_ok = top["ok"]
        url_comment = top["message"]
        url_findings = [f["message"] for f in findings_sorted]

    return final_url, url_ok, url_comment, url_findings
