from urllib.parse import urlparse, urlunparse


def _base_origin(url: str) -> str:
    p = urlparse(url or "")
    if not p.scheme or not p.netloc:
        return ""
    return urlunparse((p.scheme, p.netloc, "", "", "", ""))


def scan_standard_files(
    final_url: str,
    requests_module,
    headers: dict | None = None,
    timeout: int = 5,
) -> list[dict[str, str]]:
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


def scan_exposed_methods(
    final_url: str,
    requests_module,
    headers: dict | None = None,
    timeout: int = 5,
) -> dict:
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
        allow_raw = (
            resp.headers.get("Allow")
            or resp.headers.get("allow")
            or resp.headers.get("Access-Control-Allow-Methods")
            or ""
        )
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
