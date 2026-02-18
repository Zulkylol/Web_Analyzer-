from constants import SECURITY_HEADERS

def scan_security_headers(headers, required_headers: list[str]):
    """
    Analyse les en-têtes de sécurité.

    Args:
        headers: Mapping/dict-like (ex: response.headers)
        required_headers (list[str]): Liste des headers attendus.

    Returns:
        tuple[list[str], list[str]]: (missing_headers, headers_comment)
        headers_comment est aligné avec required_headers ("present"/"absent").
    """
    missing_headers: list[str] = []
    headers_comment: list[str] = []

    for h in required_headers:
        if h == "Content-Security-Policy":
            csp_value = (
                headers.get("Content-Security-Policy")
                or headers.get("Content-Security-Policy-Report-Only")
            )
            if csp_value:
                headers_comment.append("present")
            else:
                missing_headers.append(h)
                headers_comment.append("absent")
            continue

        if headers.get(h):
            headers_comment.append("present")
        else:
            missing_headers.append(h)
            headers_comment.append("absent")

    return missing_headers, headers_comment
