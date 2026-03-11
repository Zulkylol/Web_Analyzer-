# utils/http.py

# ===============================================================
# IMPORTS
# ===============================================================
from typing import Tuple
from urllib.parse import urlparse


# ===============================================================
# FUNCTION : map_http_version()
# ===============================================================
def map_http_version(version_number: int) -> Tuple[str, str]:
    """
    Map a numeric HTTP version code to its readable name and status.

    Returns:
        Tuple[str, str]:
            - Human-readable HTTP version label
            - Classification/status description
    """
    versions = {
        9: ("HTTP/0.9", "Protocole obsolete et non securise"),
        10: ("HTTP/1.0", "Version obsolete du protocole"),
        11: ("HTTP/1.1", "Protocole ancien encore largement repandu"),
        20: ("HTTP/2", "Version moderne et performante du protocole"),
    }
    return versions.get(version_number, (f"Unknown ({version_number})", "Inconnu"))


def shorten_url(url: str, path_limit: int = 28) -> str:
    parsed = urlparse(str(url or ""))
    if not parsed.scheme or not parsed.netloc:
        return str(url or "")

    path = parsed.path or ""
    if len(path) > path_limit:
        path = f"{path[:path_limit].rstrip('/')}..."
    return f"{parsed.scheme}://{parsed.netloc}{path}"
