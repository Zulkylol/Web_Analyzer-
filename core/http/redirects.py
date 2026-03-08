# core/http/redirects.py

# ===============================================================
# IMPORTS
# ===============================================================
import ipaddress
from urllib.parse import urlparse, urljoin

from core.http.urls import analyze_url_transition  # <-- NEW
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
        "num_comment": "",
        "redirect_domains": [],
        "redirect_chain": [],
        "hop_findings": [],
        "hop_worst_weight": 0,
        "rd_comment": "",
        "redirect_ips": [],
        "ri_comment": "",
        "risk": "Low",
    }

    # ----------- STORE REDIRECT DOMAINS/IPS ----------------


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

        # ---------------- BUILD REDIRECT CHAIN -----------------
        # Ordered hops (from Location resolution) + final response URL
        # This enables hop-by-hop downgrade/upgrade detection.
        chain = []

        for resp in history:
            loc = resp.headers.get("Location")
            target = urljoin(resp.url, loc) if loc else resp.url
            chain.append(
                {
                    "url": str(target),
                    "status": int(getattr(resp, "status_code", 0) or 0),
                }
            )

        # final hop (what requests ended up on)
        chain.append(
            {
                "url": str(getattr(response, "url", "") or ""),
                "status": int(getattr(response, "status_code", 0) or 0),
            }
        )

        result["redirect_chain"] = chain

        # ---------------- HOP-BY-HOP ANALYSIS ------------------
        worst_weight = 0

        for i in range(len(chain) - 1):
            src = chain[i]["url"]
            dst = chain[i + 1]["url"]

            try:
                hop_report = analyze_url_transition(src, dst)
            except Exception:
                continue

            # hop_report may be a dict OR a tuple (legacy return)
            if isinstance(hop_report, tuple):
                # Most common: (report_dict, ...) -> take first element if it's a dict
                report = hop_report[0] if hop_report else {}
                if not isinstance(report, dict):
                    report = {}
            elif isinstance(hop_report, dict):
                report = hop_report
            else:
                report = {}

            weight = int(report.get("final_weight", 0) or 0)
            worst_weight = max(worst_weight, weight)

            findings = report.get("findings", []) or []
            for f in findings:
                # keep hop context
                if isinstance(f, dict):
                    result["hop_findings"].append(
                        {
                            "hop_index": i,
                            "from": src,
                            "to": dst,
                            **f,
                        }
                    )
                else:
                    # fallback if a finding isn't a dict
                    result["hop_findings"].append(
                        {
                            "hop_index": i,
                            "from": src,
                            "to": dst,
                            "message": str(f),
                        }
                    )

        result["hop_worst_weight"] = worst_weight

        # Optional: bump overall risk if hop analysis found something severe
        # (keeps your existing volume/domain/ip risk logic, only escalates)
        if worst_weight >= 80:
            result["risk"] = "High"
        elif worst_weight >= 50 and result["risk"] == "Low":
            result["risk"] = "Medium"

        # --------------- REDIRECTIONS VOLUME -------------------
        if len(history) > 6:
            result["risk"] = "High"
            result["num_comment"] = "Nombre excessif de redirections !"
            result["num_ok"] = False
        elif len(history) > 2:
            if result["risk"] == "Low":
                result["risk"] = "Medium"
            result["num_comment"] = "Plusieurs redirections détectées."
            result["num_ok"] = None
        else:
            result["num_comment"] = "Nombre de redirection(s) normal"
            result["num_ok"] = True

        # --------------- SWITCHING DOMAIN/IP -------------------
        if initial_domain:
            for dom in result["redirect_domains"]:
                if _base_domain(dom) != initial_base_domain and dom not in result["redirect_ips"]:
                    result["rd_comment"] = f"Redirection vers un autre domaine ({dom})."
                    if result["risk"] == "Low":
                        result["risk"] = "Medium"
                    break

        if result["redirect_ips"]:
            result["ri_comment"] = f"Redirection vers IP brute ({', '.join(result['redirect_ips'])})."
            if result["risk"] == "Low":
                result["risk"] = "Medium"

    except Exception as e:
        tb = traceback.format_exc()
        print(tb)  # dans la console
        # et/ou dans ta popup :
        ##print((f"Erreur pendant le scan: {e}\n\n{tb}"))

    return result
