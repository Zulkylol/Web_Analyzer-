from __future__ import annotations

import requests


def fetch_http_response(url: str, headers: dict[str, str], timeout: int = 5) -> requests.Response:
    return requests.get(
        url,
        headers=headers,
        timeout=timeout,
        allow_redirects=True,
    )
