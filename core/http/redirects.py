# core/http/redirects.py

# ===============================================================
# IMPORTS
# ===============================================================
import ipaddress
from urllib.parse import urlparse, urljoin

from utils.http import shorten_url
import traceback


def _base_domain(hostname: str | None) -> str:
    """
    Lightweight base-domain extraction (eTLD+1 approximation).
    Keeps localhost/IP untouched.
    """
    h = (hostname or "").strip().lower().strip(".")
    if not h:
        return ""
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass

    parts = h.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return h


def _format_redirect_chain_comment(hop: dict) -> str:
    """Construit un commentaire compact pour la table des redirections."""
    from_url = str(hop.get("from_url", "") or "")
    location = str(hop.get("location", "") or "")
    hop_url = str(hop.get("url", "") or "")

    if from_url and location:
        resolved_from_location = urljoin(from_url, location)
        if resolved_from_location == hop_url:
            return f"{shorten_url(from_url)} -> Redirection: {shorten_url(hop_url)}"
        return f"{shorten_url(from_url)} -> Redirection: {shorten_url(hop_url)}"

    return f"Reponse finale: {shorten_url(hop_url)}"

# ===============================================================
# FUNCTION : scan_redirections()
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
    # Chaque saut est analyse pour produire:
    # - une vue courte de la chaine
    # - des findings eventuels sur les domaines traverses
    # - un indicateur d'IP brute si necessaire


    try:
        if not history:
            result["num_comment"] = "Aucune redirection"
            return result

        initial_domain = urlparse(original_url).hostname
        initial_base_domain = _base_domain(initial_domain)

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

        # Keep unique order for display clarity
        result["redirect_domains"] = list(dict.fromkeys(result["redirect_domains"]))
        result["redirect_ips"] = list(dict.fromkeys(result["redirect_ips"]))

        # ---------- PER-DOMAIN RISK CLASSIFICATION ----------
        domain_findings = []
        for dom in result["redirect_domains"]:
            dom_base = _base_domain(dom)
            normalized_initial = (initial_domain or "").lower().strip(".")
            normalized_dom = (dom or "").lower().strip(".")
            apex_www_pair = {
                normalized_initial,
                normalized_dom,
            } == {initial_base_domain, f"www.{initial_base_domain}"} and bool(initial_base_domain)
            if dom in result["redirect_ips"]:
                risk = "HIGH"
                comment = "Redirection vers IP brute (pas de nom de domaine)"
            elif dom_base == initial_base_domain:
                if normalized_dom == normalized_initial:
                    risk = "INFO"
                    comment = ""
                elif apex_www_pair:
                    risk = "INFO"
                    comment = ""
                else:
                    risk = "LOW"
                    comment = "Sous-domaine du meme domaine"
            else:
                if "xn--" in dom:
                    risk = "HIGH"
                    comment = "Domaine externe en punycode (verification manuelle recommandee)"
                else:
                    risk = "LOW"
                    comment = "Redirection vers un domaine externe"

            domain_findings.append(
                {
                    "domain": dom,
                    "risk": risk,
                    "comment": comment,
                }
            )

        result["redirect_domain_findings"] = domain_findings

        # ---------------- BUILD REDIRECT CHAIN -----------------
        # Ordered hops (from Location resolution) + final response URL
        # This enables hop-by-hop downgrade/upgrade detection.
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
            hop["display_comment"] = _format_redirect_chain_comment(hop)
            chain.append(hop)

        # final hop (what requests ended up on)
        final_hop = {
            "from_url": "",
            "location": "",
            "url": str(getattr(response, "url", "") or ""),
            "status": int(getattr(response, "status_code", 0) or 0),
        }
        final_hop["display_comment"] = _format_redirect_chain_comment(final_hop)
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
        tb = traceback.format_exc()
        print(tb)  # dans la console
        # et/ou dans ta popup :
        ##print((f"Erreur pendant le scan: {e}\n\n{tb}"))

    return result
