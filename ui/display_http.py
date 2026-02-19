# ui/display_http.py

# ===============================================================
# IMPORTS
# ===============================================================
from constants import SPACER, STATUS_ICON
from utils.url import ck

# ===============================================================
# FUNCTION : display_http()
# ===============================================================
def display_http(result, http_table):

    # Helper function to reduce text
    def add_row(param, value="", check=STATUS_ICON["info"], comment=""):
        http_table.insert("", "end", values=(param, value, check, comment))

    # ------------------- DATA CLEANING ---------------------
    redirects = result.get("redirects") or {}
    missing_headers = result.get("missing_headers") or []
    headers_comment = result.get("headers_comment") or []
    mixed_urls = result.get("mixed_url") or []


    # -------------- HTTP VERSION + HTTPS -------------------
    # If HTTP error -> display and stop
    if result.get("comment"):
        add_row("Erreur HTTP", result.get("status_message", ""), STATUS_ICON["ok"], result.get("comment", ""))
        return

    # Status 
    add_row("Code de statut", str(result.get("status_code", "")), ck(result["status_ok"]),
            result.get("status_message", ""))

    # HTTP version
    http_version = result.get("http_version") or ""
    if http_version:
        add_row("Version HTTP", http_version, ck(result["http_ok"]), result["http_comment"])
    else:
        add_row("Version HTTP", "Inconnue", STATUS_ICON["invalid"], "Impossible de déterminer la version HTTP")

    # HTTPS
    uses_https = bool(result.get("uses_https"))
    add_row("HTTPS activé", "Oui" if uses_https else "Non",
            ck(result["uses_https"]),
            result.get("https_comment", ""))

    # ---------------------- URLS ---------------------------
    add_row("URL saisie", result.get("original_url", ""), STATUS_ICON["info"], "")
    add_row("URL finale", result.get("final_url", ""), ck(result["url_ok"]),result["url_comment"])

    extra = result.get("url_findings") or []
    for msg in extra[1:]:
        add_row("", "", STATUS_ICON["info"], msg)   

    # ---------------------- TIME ---------------------------
    t = result.get("time", 0.0)
    add_row("Temps de réponse",result["time"] ,ck(result["time_ok"]), result["time_comment"])

    # ----------------- MIXED CONTENT -----------------------
    if uses_https:
        mixed = bool(result.get("mixed_content"))
        add_row("Contenu mixte", "Oui" if mixed else "Non",
                STATUS_ICON["warning"] if mixed else STATUS_ICON["ok"],
                result.get("mixed_comment", ""))

        if mixed_urls:
            # 1ère ligne avec label, puis lignes vides
            for i, item in enumerate(mixed_urls, start=1):
                # item peut être (url, origin)
                try:
                    url_m, origin = item
                except Exception:
                    url_m, origin = str(item), ""

                param = "URL mixte" if i == 1 else ""
                add_row(param, url_m, STATUS_ICON["warning"], origin)

    # ---------------- SECURITY HEADERS----------------------
    if result.get("header_findings"):
        for i, f in enumerate(result["header_findings"], start=1):
            param = "Headers de sécurité" if i == 1 else ""
            header = f["header"]
            icon = STATUS_ICON.get(f["status"], STATUS_ICON["info"])

            comment = f'{f["status"]} ({f["severity"]}) — {f["issue"]}'
            add_row(param, header, icon, comment)

            if f.get("recommendation"):
                add_row("", "↳ Recommandation", STATUS_ICON["info"], f'{f["recommendation"]}')


    # ------------------ REDIRECTIONS ----------------------
    num_redir = redirects.get("num_redirects", 0)
    risk = redirects.get("risk", "Low")

    risk_icon = {"Low": STATUS_ICON["ok"], "Medium": STATUS_ICON["warning"], "High": STATUS_ICON["high"]}.get(risk, STATUS_ICON["info"])
    add_row("Nombre de redirections", str(num_redir), ck(redirects["num_ok"]), redirects.get("num_comment", ""))

    # Domains
    r_domains = redirects.get("redirect_domains") or []
    if r_domains:
        add_row("Domaines de redirection", r_domains[0], STATUS_ICON["info"], redirects.get("rd_comment", ""))
        for dom in r_domains[1:]:
            add_row("", dom, STATUS_ICON["info"], "")

    # IPs
    r_ips = redirects.get("redirect_ips") or []
    if r_ips:
        add_row("IPs de redirection", r_ips[0], STATUS_ICON["warning"], redirects.get("ri_comment", ""))
        for ip in r_ips[1:]:
            add_row("", ip, STATUS_ICON["warining"], "")



