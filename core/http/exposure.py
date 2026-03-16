# core/http/exposure.py

# ===============================================================
# IMPORTS
# ===============================================================
from urllib.parse import urlparse, urlunparse

# ===============================================================
# FUNCTION : _base_origin
# ===============================================================
def _base_origin(url: str) -> str:
    """
    Remove path, parameters and query from a URL

    Returns : 
        str : base URL 
    """
    p = urlparse(url or "")
    if not p.scheme or not p.netloc:
        return ""  
    return urlunparse((p.scheme, p.netloc, "", "", "", ""))

# ===============================================================
# FUNCTION : scan_standard_files
# ===============================================================
def scan_standard_files(
    final_url: str,
    requests_module,
    headers: dict | None = None,
    timeout: int = 5,
) -> list[dict[str, str]]:
    """
    Check whether standard files (robots.txt and security.txt) are present and accessible.
    
    Returns : 
        list[dict[str, str]] : list of findings
    """
    findings: list[dict[str, str]] = []
    origin = _base_origin(final_url)
    if not origin:
        return findings

    targets = [
        ("/robots.txt", "robots.txt"),
        ("/.well-known/security.txt", "security.txt"),
    ]

    for path, label in targets:
        url = f"{origin}{path}"
        try:
            resp = requests_module.get(
                url,
                headers=headers or {},
                timeout=timeout,
                allow_redirects=True,
            )
            code = int(getattr(resp, "status_code", 0) or 0)

            #HTTP OK
            if code == 200:
                findings.append(
                    {
                        "name": label,
                        "value": "Present",
                        "risk": "INFO",
                        "comment": f"{path} accessible (HTTP 200)",
                        "url": str(getattr(resp, "url", "") or url),
                    }
                )

            #HTTP UNAUTHORIZED
            elif code in (401, 403):
                findings.append(
                    {
                        "name": label,
                        "value": f"Protected ({code})",
                        "risk": "LOW",
                        "comment": f"{path} existe mais acces restreint",
                        "url": str(getattr(resp, "url", "") or url),
                    }
                )
            else:
                risk = "INFO" if label == "robots.txt" else "LOW"
                findings.append(
                    {
                        "name": label,
                        "value": f"Missing ({code})",
                        "risk": risk,
                        "comment": f"{path} introuvable",
                        "url": str(getattr(resp, "url", "") or url),
                    }
                )
        except Exception as e:
            findings.append(
                {
                    "name": label,
                    "value": "Unknown",
                    "risk": "LOW",
                    "comment": f"Echec de verification: {e}",
                    "url": url,
                }
            )
    return findings

# ===============================================================
# FUNCTION : scan_exposed_methods
# ===============================================================
def scan_exposed_methods(
    final_url: str,
    requests_module,
    headers: dict | None = None,
    timeout: int = 5,
) -> dict:
    """
    Detect exposed HTTP methods and classify the associated risk.

    Returns :
        dict : exposed methods with associated risk
    """
    result = {
        "value": "Unknown",
        "risk": "INFO",
        "comment": "",
    }

    if not final_url:
        result["comment"] = "URL finale indisponible"
        return result

    try:
        resp = requests_module.options(
            final_url,
            headers=headers or {},
            timeout=timeout,
            allow_redirects=True,
        )

        #Retrieve the allowed methods
        allow_raw = (
            resp.headers.get("Allow")
            or resp.headers.get("Access-Control-Allow-Methods")
            or ""
        )

        #Normalization
        methods = sorted(
            {
                m.strip().upper()
                for m in str(allow_raw).split(",")
                if m and m.strip()
            }
        )

        if not methods:
            result["value"] = "Not disclosed"
            result["risk"] = "INFO"
            result["comment"] = "Aucune methode exposee via en-tete Allow"
            return result

        risky_high = {"TRACE", "CONNECT"}
        risky_medium = {"PUT", "DELETE"}
        risky_low = {"PATCH"}

        present_high = sorted(m for m in methods if m in risky_high)
        present_medium = sorted(m for m in methods if m in risky_medium)
        present_low = sorted(m for m in methods if m in risky_low)

        if present_high:
            result["risk"] = "HIGH"
            result["comment"] = f"Methodes sensibles exposees: {', '.join(present_high)}"
        elif present_medium:
            result["risk"] = "MEDIUM"
            result["comment"] = f"Methodes d'ecriture exposees: {', '.join(present_medium)}"
        elif present_low:
            result["risk"] = "LOW"
            result["comment"] = f"Methode a surveiller: {', '.join(present_low)}"
        else:
            result["risk"] = "INFO"
            result["comment"] = "Seulement des methodes standard exposees"

        result["value"] = ", ".join(methods)
        return result

    except Exception as e:
        result["value"] = "Unknown"
        result["risk"] = "LOW"
        result["comment"] = f"OPTIONS indisponible: {e}"
        return result
