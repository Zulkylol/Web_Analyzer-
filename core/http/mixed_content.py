import re
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

# =========================================================
# 8)------------- MIXED CONTENT DETECTION -----------------
# =========================================================
def detect_mixed_content(html: str, final_url: str, uses_https: bool):
    """
    Detect mixed content (HTTP resources inside HTTPS page).

    Returns:
        mixed_content (bool)
        mixed_url (list[tuple[str, str]])
        mixed_comment (str)
    """

    if not uses_https:
        return False, [], "Aucun contenu mixte détecté"

    soup = BeautifulSoup(html, "html.parser")

    tags_attrs = {
        "img": ["src", "srcset"],
        "script": ["src"],
        "link": ["href"],
        "iframe": ["src"],
        "audio": ["src"],
        "video": ["src", "poster"],
        "source": ["src"],
        "form": ["action"],
    }

    mixed = []

    for tag, attrs in tags_attrs.items():
        for elem in soup.find_all(tag):
            for attr in attrs:
                val = elem.get(attr)
                if not val:
                    continue

                if attr == "srcset":
                    for part in val.split(","):
                        u = part.strip().split(" ")[0]
                        if u.startswith("http://"):
                            mixed.append((u, f"{tag}[srcset]"))

                elif isinstance(val, str) and val.startswith("http://"):
                    mixed.append((val, f"{tag}[{attr}]"))

    # Inline CSS
    for elem in soup.find_all(style=True):
        css = elem.get("style") or ""
        for u in re.findall(r'url\(\s*["\']?(http://[^"\')\s]+)', css):
            mixed.append((u, "inline-style"))

    # External CSS
    for link in soup.find_all("link", href=True):
        rel = link.get("rel") or []
        if any(r.lower() == "stylesheet" for r in rel):
            css_url = urljoin(final_url, link["href"])

            try:
                css_resp = requests.get(
                    css_url,
                    headers={"User-Agent": "Mozilla/5.0"},
                    timeout=3,
                )

                for u in re.findall(r'url\(\s*["\']?(http://[^"\')\s]+)', css_resp.text):
                    mixed.append((u, "external-css"))

            except Exception:
                pass

    if mixed:
        mixed = list(set(mixed))
        return True, mixed, f"{len(mixed)} ressources HTTP détectées"

    return False, [], "Aucun contenu mixte détecté"
