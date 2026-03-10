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


def _risk_weight(level: str) -> int:
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    return order.get(str(level).upper(), 0)


def _format_redirect_chain_comment(hop: dict) -> str:
    from_url = str(hop.get("from_url", "") or "")
    location = str(hop.get("location", "") or "")
    hop_url = str(hop.get("url", "") or "")

    if from_url and location:
        resolved_from_location = urljoin(from_url, location)
        if resolved_from_location == hop_url:
            return f"{from_url} -> Redirection: {location}"
        return f"{from_url} -> Redirection: {location} -> {hop_url}"

    return f"Reponse finale: {hop_url}"

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
        "hop_findings": [],
        "hop_worst_weight": 0,
        "rd_comment": "",
        "redirect_ips": [],
        "ri_comment": "",
        "risk": "Info",
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

        # ---------- PER-DOMAIN RISK CLASSIFICATION ----------
        domain_findings = []
        worst_domain_risk = "INFO"
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
                comment = "Redirection vers IP brute (pas de nom de domaine)."
            elif dom_base == initial_base_domain:
                if normalized_dom == normalized_initial:
                    risk = "INFO"
                    comment = "Meme domaine."
                elif apex_www_pair:
                    risk = "INFO"
                    comment = "Redirection standard entre domaine nu et www."
                else:
                    risk = "LOW"
                    comment = "Sous-domaine du meme domaine."
            else:
                if "xn--" in dom:
                    risk = "HIGH"
                    comment = "Domaine externe en punycode (verification manuelle recommandee)."
                else:
                    risk = "LOW"
                    comment = "Redirection vers un domaine externe."

            domain_findings.append(
                {
                    "domain": dom,
                    "risk": risk,
                    "comment": comment,
                }
            )
            if _risk_weight(risk) > _risk_weight(worst_domain_risk):
                worst_domain_risk = risk

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

        # ---------------- HOP-BY-HOP ANALYSIS ------------------
        worst_weight = 0

        for i in range(len(chain) - 1):
            src = chain[i]["url"]
            dst = chain[i + 1]["url"]

            try:
                hop_report = analyze_url_transition(src, dst)
            except Exception:
                continue

            # Current analyze_url_transition returns:
            # (final_url, url_ok, url_comment, url_findings, url_risk)
            if isinstance(hop_report, tuple) and len(hop_report) >= 5:
                _, hop_ok, hop_comment, hop_findings, hop_risk = hop_report[:5]
                weight = _risk_weight(hop_risk) * 30
                worst_weight = max(worst_weight, weight)

                findings = hop_findings or []
                if not findings and hop_ok is not True and hop_comment:
                    findings = [hop_comment]

                for msg in findings:
                    result["hop_findings"].append(
                        {
                            "hop_index": i,
                            "from": src,
                            "to": dst,
                            "message": str(msg),
                            "risk": str(hop_risk).upper(),
                        }
                    )
            elif isinstance(hop_report, dict):
                # Backward compatibility if a dict-based report is introduced later.
                weight = int(hop_report.get("final_weight", 0) or 0)
                worst_weight = max(worst_weight, weight)
                findings = hop_report.get("findings", []) or []
                for f in findings:
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
        if len(history) > 7:
            result["risk"] = "High"
            result["num_risk"] = "HIGH"
            result["num_comment"] = "Nombre excessif de redirections !"
            result["num_ok"] = False
        elif len(history) > 5:
            if result["risk"] == "Low":
                result["risk"] = "Medium"
            result["num_risk"] = "MEDIUM"
            result["num_comment"] = "Nombre de redirections eleve."
            result["num_ok"] = None
        elif len(history) > 3:
            result["num_risk"] = "LOW"
            result["num_comment"] = "Quelques redirections detectees."
            result["num_ok"] = None
        else:
            result["num_risk"] = "INFO"
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

        if worst_domain_risk in ("HIGH", "MEDIUM"):
            if worst_domain_risk == "HIGH":
                result["risk"] = "High"
            elif result["risk"] == "Low":
                result["risk"] = "Medium"

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
