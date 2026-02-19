import ipaddress
from urllib.parse import urlparse, urljoin

# ===============================================================
# FUNCTION : check_http_redirections()
# ===============================================================
def scan_redirections(response, original_url: str) -> dict:
    """
    Checks the redirects performed by the web server

    Returns:
        dict : dictionary that stores the analysis results of redirections

    Raises:
        
    """
   
    # ------------------ INITIALIZATION ---------------------
    history = response.history or []
    result = {
        "num_redirects": len(history),
        "num_ok" : False,
        "num_comment": "",
        "redirect_domains": [],
        "rd_comment": "",     
        "redirect_ips": [],
        "ri_comment": "",      
        "risk": "Low",
    }

    # ----------- STORE REDIRECT DOMAINS/IPS ----------------
    if not history:
        result["num_comment"] = "Aucune redirection"
        return result

    initial_domain = urlparse(original_url).hostname

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


    # --------------- REDIRECTIONS VOLUME -------------------
    if len(history) > 6:
        result["risk"] = "High"
        result["num_comment"] = "Nombre excessif de redirections !"
        result["num_ok"] = False
    elif len(history) > 2:
        result["risk"] = "Medium"
        result["num_comment"] = "Plusieurs redirections détectées."
        result["num_ok"] = None
    else:
        result["num_comment"] = "Nombre de redirection(s) normal"
        result["num_ok"] = True
    

    # --------------- SWITCHING DOMAIN/IP -------------------
    if initial_domain:
        for dom in result["redirect_domains"]:
            if dom != initial_domain and dom not in result["redirect_ips"]:
                result["rd_comment"] = f"Redirection vers un autre domaine ({dom})."
                if result["risk"] == "Low":
                    result["risk"] = "Medium"
                break

    if result["redirect_ips"]:
        result["ri_comment"] = f"Redirection vers IP brute ({', '.join(result['redirect_ips'])})."
        if result["risk"] == "Low":
            result["risk"] = "Medium"

    return result