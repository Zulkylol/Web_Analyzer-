# utils/http.py

# ===============================================================
# IMPORTS
# ===============================================================
from typing import Tuple
from urllib.parse import urlparse


# ===============================================================
# FUNCTION : map_http_version
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


# ===============================================================
# FUNCTION : shorten_url
# ===============================================================
def shorten_url(url: str, path_limit: int = 28) -> str:
    """Raccourcit une URL pour la vue table en supprimant les query params trop verbeux."""
    parsed = urlparse(str(url or ""))
    if not parsed.scheme or not parsed.netloc:
        return str(url or "")

    path = parsed.path or ""
    if len(path) > path_limit:
        path = f"{path[:path_limit].rstrip('/')}..."
    return f"{parsed.scheme}://{parsed.netloc}{path}"


# ===============================================================
# FUNCTION : normalize_hostname
# ===============================================================
def normalize_hostname(hostname: str | None) -> str:
    """
    Normalize a hostname for comparison.

    Returns :
        str : normalized hostname
    """
    return (hostname or "").strip().lower().strip(".")


# ===============================================================
# FUNCTION : is_apex_www_pair
# ===============================================================
def is_apex_www_pair(original_hostname: str | None, final_hostname: str | None) -> bool:
    """
    Check if hosts differ only by www.

    Returns :
        bool : apex/www match
    """
    original = normalize_hostname(original_hostname)
    final = normalize_hostname(final_hostname)
    if not original or not final or original == final:
        return False
    return original == f"www.{final}" or final == f"www.{original}"
