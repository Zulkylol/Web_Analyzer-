from __future__ import annotations

from http.cookies import SimpleCookie
from urllib.parse import urlparse

import requests


# ===============================================================
# FUNCTION : to_int
# ===============================================================
def to_int(value: str | None) -> int | None:
    """
    Convert a text value to an integer.

    Returns :
        int | None : parsed integer
    """
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except Exception:
        return None


# ===============================================================
# FUNCTION : extract_set_cookie_headers
# ===============================================================
def extract_set_cookie_headers(response: requests.Response) -> list[str]:
    """
    Extract Set-Cookie headers from a response.

    Returns :
        list[str] : cookie header lines
    """
    values = []
    raw_headers = getattr(response, "raw", None)
    raw_headers = getattr(raw_headers, "headers", None)

    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        values.extend(raw_headers.getlist("Set-Cookie"))

    if not values:
        merged = response.headers.get("Set-Cookie")
        if merged:
            values.append(merged)
    return [v for v in values if v]


# ===============================================================
# FUNCTION : parse_cookie_line
# ===============================================================
def parse_cookie_line(set_cookie_line: str) -> dict | None:
    """
    Parse a single Set-Cookie header line.

    Returns :
        dict | None : parsed cookie data
    """
    parts = [p.strip() for p in set_cookie_line.split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        return None

    name, value = parts[0].split("=", 1)
    attrs: dict[str, str | bool] = {}

    for token in parts[1:]:
        if "=" in token:
            key, attr_value = token.split("=", 1)
            attrs[key.strip().lower()] = attr_value.strip()
        else:
            attrs[token.strip().lower()] = True

    secure = bool(attrs.get("secure", False))
    httponly = bool(attrs.get("httponly", False))
    samesite = str(attrs.get("samesite", "")).strip().lower() if "samesite" in attrs else ""
    domain = str(attrs.get("domain", "")).strip()
    path = str(attrs.get("path", "")).strip() or "/"
    max_age = to_int(attrs.get("max-age")) if "max-age" in attrs else None
    expires = str(attrs.get("expires", "")).strip() if "expires" in attrs else ""
    persistent = bool(expires) or (max_age is not None)
    size = len(set_cookie_line.encode("utf-8"))

    return {
        "name": name.strip(),
        "value_len": len(value),
        "secure": secure,
        "httponly": httponly,
        "samesite": samesite,
        "domain": domain,
        "path": path,
        "max_age": max_age,
        "expires": expires,
        "persistent": persistent,
        "size": size,
        "priority": str(attrs.get("priority", "")).strip(),
        "partitioned": bool(attrs.get("partitioned", False)),
        "raw": set_cookie_line,
    }


# ===============================================================
# FUNCTION : deduplicate_cookies
# ===============================================================
def deduplicate_cookies(cookies: list[dict]) -> list[dict]:
    """
    Remove duplicate cookie entries.

    Returns :
        list[dict] : unique cookies
    """
    deduped: list[dict] = []
    seen: set[tuple] = set()

    for cookie in cookies:
        key = (
            (cookie.get("name") or "").strip().lower(),
            (cookie.get("domain") or "").strip().lower(),
            (cookie.get("path") or "/").strip() or "/",
            bool(cookie.get("secure")),
            bool(cookie.get("httponly")),
            (cookie.get("samesite") or "").strip().lower(),
            cookie.get("max_age"),
            bool(cookie.get("persistent")),
            int(cookie.get("size", 0) or 0),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(cookie)

    return deduped


# ===============================================================
# FUNCTION : collect_response_cookies
# ===============================================================
def collect_response_cookies(response: requests.Response) -> list[dict]:
    """
    Collect cookies from the full response chain.

    Returns :
        list[dict] : collected cookies
    """
    parsed_cookies = []
    all_responses = list(response.history) + [response]

    for resp in all_responses:
        parsed_resp = urlparse(resp.url)
        resp_scheme = (parsed_resp.scheme or "").lower()
        resp_host = (parsed_resp.hostname or "").lower()
        for line in extract_set_cookie_headers(resp):
            cookie = parse_cookie_line(line)
            if cookie is None:
                continue
            cookie["from_url"] = resp.url
            cookie["source_scheme"] = resp_scheme
            cookie["source_host"] = resp_host
            parsed_cookies.append(cookie)

    if parsed_cookies:
        return deduplicate_cookies(parsed_cookies)

    merged = response.headers.get("Set-Cookie", "")
    if not merged:
        return []

    tmp = SimpleCookie()
    try:
        tmp.load(merged)
    except Exception:
        return []

    response_url = response.url
    parsed_resp = urlparse(response_url)
    resp_scheme = (parsed_resp.scheme or "").lower()
    resp_host = (parsed_resp.hostname or "").lower()
    for name, morsel in tmp.items():
        parsed_cookies.append(
            {
                "name": name,
                "value_len": len(morsel.value),
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": (morsel["samesite"] or "").lower(),
                "domain": morsel["domain"] or "",
                "path": morsel["path"] or "/",
                "max_age": to_int(morsel["max-age"]),
                "expires": morsel["expires"] or "",
                "persistent": bool(morsel["expires"] or morsel["max-age"]),
                "size": len(str(morsel).encode("utf-8")),
                "priority": "",
                "partitioned": False,
                "raw": str(morsel),
                "from_url": response_url,
                "source_scheme": resp_scheme,
                "source_host": resp_host,
            }
        )

    return deduplicate_cookies(parsed_cookies)
