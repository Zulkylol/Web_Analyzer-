# utils/http.py

# ===============================================================
# IMPORTS
# ===============================================================
import ipaddress
from urllib.parse import urlparse, urlunparse


# ===============================================================
# FUNCTION : shorten_url
# ===============================================================
def shorten_url(url: str, path_limit: int = 28) -> str:
    """
    Shorten a URL for table display by trimming overly verbose query parameters.

    Returns :
        str : shortened URL
    """
    parsed = urlparse(str(url or ""))
    if not parsed.scheme or not parsed.netloc:
        return str(url or "")

    path = parsed.path or ""
    if len(path) > path_limit:
        path = f"{path[:path_limit].rstrip('/')}..."
    return f"{parsed.scheme}://{parsed.netloc}{path}"


# ===============================================================
# FUNCTION : base_origin
# ===============================================================
def base_origin(url: str) -> str:
    """
    Return the origin part of a URL without path, parameters, or query.

    Returns :
        str : base origin
    """
    parsed = urlparse(url or "")
    if not parsed.scheme or not parsed.netloc:
        return ""
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


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
# FUNCTION : base_domain
# ===============================================================
def base_domain(hostname: str | None) -> str:
    """
    Return the base domain of a hostname, or the IP as-is.

    Returns :
        str : base domain
    """
    hostname = normalize_hostname(hostname)
    if not hostname:
        return ""
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


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
