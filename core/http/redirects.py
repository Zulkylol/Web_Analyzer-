# core/http/redirects.py

# ===============================================================
# IMPORTS
# ===============================================================
from urllib.parse import urlparse, urljoin

import ipaddress

from utils.http import base_domain, is_apex_www_pair, normalize_hostname, shorten_url


# ===============================================================
# FUNCTION : scan_redirections
# ===============================================================
def scan_redirections(response, original_url: str) -> dict:
    """
    Checks the redirects performed by the web server

    Returns:
        dict : dictionary that stores the analysis results of redirections
    """
    # ------------------ INITIALIZATION ---------------------
    history = response.history or []
    result = {
        "num_redirects": len(history),
        "num_ok": False,
        "num_risk": "INFO",
        "num_comment": "",
        "redirect_domains": [],
        "redirect_domain_findings": [],
        "redirect_chain": [],
        "redirect_ips": [],
        "ri_comment": "",
    }

    # ----------- STORE REDIRECT DOMAINS/IPS ----------------
    # Analyze each hop for chain display, domain findings, and raw IPs

    try:
        if not history:
            result["num_comment"] = "Aucune redirection"
            return result

        initial_domain = urlparse(original_url).hostname
        initial_base_domain = base_domain(initial_domain)

        for resp in history:
            loc = resp.headers.get("Location")
            target = urljoin(resp.url, loc) if loc else resp.url
            domain = urlparse(target).hostname

            if domain:
                result["redirect_domains"].append(domain)
                try:
                    ipaddress.ip_address(domain)
                    result["redirect_ips"].append(domain)
                except ValueError:
                    pass

        # Remove duplicates
        result["redirect_domains"] = list(dict.fromkeys(result["redirect_domains"]))
        result["redirect_ips"] = list(dict.fromkeys(result["redirect_ips"]))

        # ---------- PER-DOMAIN RISK CLASSIFICATION ----------
        domain_findings = []
        normalized_initial = normalize_hostname(initial_domain)

        for domain in result["redirect_domains"]:
            domain_base = base_domain(domain)
            normalized_domain = normalize_hostname(domain)

            if domain in result["redirect_ips"]:
                risk = "HIGH"
                comment = "Redirection vers IP brute (pas de nom de domaine)"
            elif domain_base == initial_base_domain:
                if normalized_domain == normalized_initial:
                    risk = "INFO"
                    comment = ""
                elif is_apex_www_pair(normalized_initial, normalized_domain):
                    risk = "INFO"
                    comment = ""
                else:
                    risk = "LOW"
                    comment = "Sous-domaine du même domaine"
            else:
                if "xn--" in domain:
                    risk = "HIGH"
                    comment = "Domaine externe en punycode (vérification manuelle recommandée)"
                else:
                    risk = "LOW"
                    comment = "Redirection vers un domaine externe"

            domain_findings.append(
                {
                    "domain": domain,
                    "risk": risk,
                    "comment": comment,
                }
            )

        result["redirect_domain_findings"] = domain_findings

        # ---------------- BUILD REDIRECT CHAIN -----------------
        # Ordered hops (from Location resolution) + final response URL
        chain = []

        for resp in history:
            loc = resp.headers.get("Location")
            target = urljoin(resp.url, loc) if loc else resp.url
            hop = {
                "from_url": str(getattr(resp, "url", "") or ""),
                "location": str(loc or ""),
                "url": str(target),
                "status": int(getattr(resp, "status_code", 0) or 0),
            }
            if hop["from_url"] and hop["location"]:
                hop["display_comment"] = (
                    f"{shorten_url(hop['from_url'])} -> Redirection: {shorten_url(hop['url'])}"
                )
            else:
                hop["display_comment"] = f"Reponse finale: {shorten_url(hop['url'])}"
            chain.append(hop)

        # final hop (what requests ended up on)
        final_hop = {
            "from_url": "",
            "location": "",
            "url": str(getattr(response, "url", "") or ""),
            "status": int(getattr(response, "status_code", 0) or 0),
        }
        final_hop["display_comment"] = f"Reponse finale: {shorten_url(final_hop['url'])}"
        chain.append(final_hop)

        result["redirect_chain"] = chain

        # --------------- REDIRECTIONS VOLUME -------------------
        if len(history) > 7:
            result["num_risk"] = "HIGH"
            result["num_comment"] = "Nombre excessif de redirections !"
            result["num_ok"] = False
        elif len(history) > 5:
            result["num_risk"] = "MEDIUM"
            result["num_comment"] = "Nombre de redirections eleve"
            result["num_ok"] = None
        elif len(history) > 3:
            result["num_risk"] = "LOW"
            result["num_comment"] = "Quelques redirections detectees"
            result["num_ok"] = None
        else:
            result["num_risk"] = "INFO"
            result["num_comment"] = "Nombre de redirection(s) normal"
            result["num_ok"] = True

        if result["redirect_ips"]:
            result["ri_comment"] = f"Redirection vers IP brute ({', '.join(result['redirect_ips'])})"

    except Exception as e:
        result["error"] = f"Erreur pendant l'analyse des redirections: {e}"

    return result
