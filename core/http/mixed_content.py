# core/http/mixed_content.py

# ===============================================================
# IMPORTS
# ===============================================================
import re
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup

from constants import HEADER


# ===============================================================
# FUNCTION : evaluate_mixed_content_risk
# ===============================================================
def evaluate_mixed_content_risk(mixed_detected: bool, mixed_level: str) -> str:
    """
    Assess the risk associated with detected mixed content

    returns :
        str : risk level 
    """
    level = str(mixed_level or "").lower()
    if level == "active":
        return "HIGH"
    if mixed_detected:
        return "MEDIUM"
    return "INFO"


# ===============================================================
# FUNCTION : detect_mixed_content
# ===============================================================
def detect_mixed_content(
    html: str,
    final_url: str,
    uses_https: bool,
) -> tuple[bool, list[tuple[str, str]], str, str]:
    """
    Detect HTTP (mixed) resources in an HTTPS page.

    Returns:
        tuple[bool, list[tuple[str, str]], str, str]:
            - whether mixed content was detected
            - list of (resource_url, location)
            - summary message
            - mixed level: active / passive / ""
    """
    if not uses_https:
        return False, [], "Aucun contenu mixte détecté", ""

    # Turns the HTML into a navigable object
    soup = BeautifulSoup(html, "html.parser")

    # List of ressources we check
    tag_attributes = {
        "img": ["src", "srcset"],
        "script": ["src"],
        "link": ["href"],
        "iframe": ["src"],
        "audio": ["src"],
        "video": ["src", "poster"],
        "source": ["src"],
        "form": ["action"],
    }

    mixed: list[tuple[str, str]] = []
    active_tags = {"script", "iframe", "form"}
    active_attributes = {("link", "href")}
    has_active_mixed = False

    # Detect HTTP resources in HTML tag attributes
    for tag, attributes in tag_attributes.items():
        for element in soup.find_all(tag):
            for attribute in attributes:
                attribute_value = element.get(attribute)
                if not attribute_value:
                    continue

                if attribute == "srcset":
                    for srcset_entry in str(attribute_value).split(","):
                        url = srcset_entry.strip().split(" ")[0]
                        if url.startswith("http://"):
                            mixed.append((url, f"{tag}[srcset]"))
                            if tag in active_tags:
                                has_active_mixed = True
                elif isinstance(attribute_value, str) and attribute_value.startswith("http://"):
                    mixed.append((attribute_value, f"{tag}[{attribute}]"))
                    if tag in active_tags or (tag, attribute) in active_attributes:
                        has_active_mixed = True

    # Detect HTTP URLs in inline styles
    for element in soup.find_all(style=True):
        css = element.get("style") or ""
        for url in re.findall(r'url\(\s*["\']?(http://[^"\')\s]+)', css):
            mixed.append((url, "inline-style"))

    # Detect HTTP URLs in external stylesheets
    for link in soup.find_all("link", href=True):
        link_rel = link.get("rel") or []
        if any(str(r).lower() == "stylesheet" for r in link_rel):
            css_url = urljoin(final_url, link["href"])
            try:
                css_resp = requests.get(
                    css_url,
                    headers=HEADER.copy(),
                    timeout=3,
                )
                for found_url in re.findall(r'url\(\s*["\']?(http://[^"\')\s]+)', css_resp.text):
                    mixed.append((found_url, "external-css"))
            except Exception:
                pass

    if mixed:
        mixed = list(set(mixed))
        level = "active" if has_active_mixed else "passive"
        return True, mixed, f"{len(mixed)} ressources HTTP détectées", level

    return False, [], "Aucun contenu mixte détecté", ""
