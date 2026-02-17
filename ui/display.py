from constants import SPACER
from utils.url import ck

# ===============================================================
# FUNCTION : display_http()
# ===============================================================
def display_http(result, http_table):

    # Helper function to reduce text
    def add_row(param, value="", check="ⓘ", comment=""):
        http_table.insert("", "end", values=(param, value, check, comment))

    # =========================================================
    # 1)------------------- DATA CLEANING ---------------------
    # =========================================================
    redirects = result.get("redirects") or {}
    missing_headers = result.get("missing_headers") or []
    headers_comment = result.get("headers_comment") or []
    mixed_urls = result.get("mixed_url") or []


    # =========================================================
    # 2)-------------- HTTP VERSION + HTTPS -------------------
    # =========================================================
    # Si erreur HTTP → afficher uniquement l'erreur et stop
    if result.get("comment"):
        add_row("Erreur HTTP", result.get("status_message", ""), "❌", result.get("comment", ""))
        return

    # Status / HTTP version / HTTPS
    add_row("Code de statut", str(result.get("status_code", "")), ck(result["status_ok"]),
            result.get("status_message", ""))

    http_version = result.get("http_version") or ""
    if http_version:
        # si tu stockes "HTTP/2" directement
        add_row("Version HTTP", http_version, ck(result["http_ok"]), result["http_comment"])
    else:
        add_row("Version HTTP", "Inconnue", "⚠️", "Impossible de déterminer la version HTTP")

    uses_https = bool(result.get("uses_https"))
    add_row("HTTPS activé", "Oui" if uses_https else "Non",
            ck(result["uses_https"]),
            result.get("https_comment", ""))

    # =========================================================
    # 3)---------------------- URLS ---------------------------
    # =========================================================
    add_row("URL saisie", result.get("original_url", ""), "ⓘ", "")
    add_row("URL finale", result.get("final_url", ""), ck(result["url_ok"]),result["url_comment"])

    extra = result.get("url_findings") or []
    for msg in extra[1:]:
        add_row("", "", "ⓘ", msg)   


    # =========================================================
    # 4)---------------------- TIME ---------------------------
    # =========================================================
    t = result.get("time", 0.0)
    add_row("Temps de réponse",result["time"] ,ck(result["time_ok"]), result["time_comment"])


    # =========================================================
    # 5)----------------- MIXED CONTENT -----------------------
    # =========================================================
    if uses_https:
        mixed = bool(result.get("mixed_content"))
        add_row("Contenu mixte", "Oui" if mixed else "Non",
                "⚠️" if mixed else "✅",
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
                add_row(param, url_m, "⚠️", origin)


    # =========================================================
    # 6)---------------- SECURITY HEADERS----------------------
    # =========================================================
    # Dans ton result actuel: missing_headers liste des noms, headers_comment = ["present"/"absent"] pour CHAQUE header checké
    # => Si tu veux un affichage propre, mieux vaut reconstruire: tous les headers absents avec commentaire "absent".
    if missing_headers:
        for i, header in enumerate(missing_headers, start=1):
            param = "Headers sécu manquants" if i == 1 else ""
            add_row(param, header, "❌", "absent")
            

    # =========================================================
    # 6)------------------ REDIRECTIONS ----------------------
    # =========================================================
    num_redir = redirects.get("num_redirects", 0)
    risk = redirects.get("risk", "Low")

    risk_icon = {"Low": "✅", "Medium": "⚠️", "High": "❌"}.get(risk, "ⓘ")
    add_row("Nombre de redirections", str(num_redir), ck(redirects["num_ok"]), redirects.get("num_comment", ""))

    # Domaines
    r_domains = redirects.get("redirect_domains") or []
    if r_domains:
        add_row("Domaines de redirection", r_domains[0], "ⓘ", redirects.get("rd_comment", ""))
        for dom in r_domains[1:]:
            add_row("", dom, "ⓘ", "")

    # IPs
    r_ips = redirects.get("redirect_ips") or []
    if r_ips:
        add_row("IPs de redirection", r_ips[0], "⚠️", redirects.get("ri_comment", ""))
        for ip in r_ips[1:]:
            add_row("", ip, "⚠️", "")

# ===============================================================
# FUNCTION : display_ssl_tls()
# ===============================================================
def display_ssl_tls(result, ssl_table):

    def add(p, v, c="", com=""):
        ssl_table.insert("", "end", values=(p, v, c, com))

    cert = result["certificate"]
    tls = result["tls"]
    trust = result["trust"]

    # --- Common name ----
    add("Nom", cert["subject"]["common_name"])

    # --- SAN(s) ----
    san = cert["subject"]["san_dns"]

    if san:
        add("Subject Alternative Name", san[0], ck(result["hostname_check"]["match"]),
            SPACER + result["hostname_check"]["comment"])
        for s in san[1:]:
            add("", s)
    else:
        add("Subject Alternative Name", "Aucun SAN", "⚠️",
            SPACER + "Extension SAN absente (certificat legacy / config atypique)")

    # --- SAN number ---
    add("Nombre de SAN", len(san), ck(result["hostname_check"]["ok"]),
        SPACER + result["hostname_check"]["warnings"]["multi_domain"])

    # --- Certificat validity ---
    add("Début de validité", cert["validity"]["not_before"],
        ck(cert["validity"]["is_valid_now"]),
        SPACER + ("Certificat valide" if cert["validity"]["is_valid_now"] else "Certificat expiré"))
    
    add("Fin de validité", cert["validity"]["not_after"],
        ck(cert["validity"]["expires_ok"]),
        SPACER + cert["validity"]["expires_soon_comment"])

    # --- Certificat version ---
    add("Version du certificat", cert["version"]["id"],
        ck(cert["version"]["ok"]),
        SPACER + cert["version"]["comment"])

    # --- Certificat serial num ---
    add("Serial number", cert["serial"]["hex"],
        ck(cert["serial"]["ok"]),
        SPACER + cert["serial"]["comment"])

    # --- Certificat hash algorithm ---
    add("Algorithme", cert["signature"]["hash_algorithm"],
        ck(cert["signature"]["ok"]),
        SPACER + cert["signature"]["comment"])

    # --- Fingerprint ---
    add("Empreinte", cert["signature"]["fingerprint_sha256"], "ⓘ")

    # --- Authority ---
    add("Autorité certifiante", cert["issuer"]["common_name"],
        ck(trust["is_trusted"]),
        SPACER + ("Autorité reconnue" if trust["is_trusted"] else "Autorité non reconnue"))

    # --- Auto-signed ---
    add("Auto-signé", trust["is_self_signed"],
        "✖" if trust["is_self_signed"] else "✅",
        SPACER + ("Certificat autosigné" if trust["is_self_signed"] else "Certificat non autosigné"))

    # --- Public Key ---
    add("Clé publique", cert["public_key"].get("summary", ""),
        ck(cert["public_key"]["ok"]),
        SPACER + cert["public_key"]["comment"])

    # --- Extensions (basic constraint) ---
    add("Basic constraints", cert["extensions"]["basic_constraints"],
        ck(cert["extensions"]["basic_constraints_ok"]),
        SPACER + cert["extensions"]["basic_constraints_comment"])
    
    # --- Extensions (EKU) ---
    add("KU étendu", cert["extensions"]["extended_key_usage"],
        ck(cert["extensions"]["eku_ok"]),
        SPACER + cert["extensions"]["eku_comment"])

    # --- Extensions (KU) ---
    add("Key usage (KU)", cert["extensions"]["key_usage"],
        ck(cert["extensions"]["ku_ok"]),
        SPACER + cert["extensions"]["ku_comment"])

    # --- Extensions (CRL) ---
    add("Liste de révocation", cert["extensions"]["crl_distribution_points"],
        ck(cert["extensions"]["crl_ok"]),
        SPACER + cert["extensions"]["crl_comment"])

    # --- TLS actual version ---
    add("Version TLS", tls["negotiated_version"], ck(tls["nv_ok"]),
        SPACER + tls["nv_comment"])

    # --- TLS supported version ---
    if tls["supported_versions"]:
        s = tls["supported_versions"]
        for v in ["TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"]:
            if v in ["TLS1.0", "TLS1.1"]:
                check_icon = "✖" if s[v] else "✅"
            else:
                check_icon = ck(s[v])

            add(
                f"Support {v}",
                "Oui" if s[v] else "Non",
                check_icon,
                SPACER + (
                    "À désactiver" if v in ["TLS1.0", "TLS1.1"] and s[v]
                    else "OK" if s[v]
                    else "Non supporté"
                )
            )

    # --- TLS policy ---
    add("Politique TLS",
        "OK" if tls["policy"]["ok"] else "KO",
        ck(tls["policy"]["ok"]),
        SPACER + tls["policy"]["comment"])

    # --- Cipher Suite ---
    add("Cipher Suite", tls["cipher"]["name"], ck(tls["cipher"]["ok"]),
        SPACER + tls["cipher"]["comment"])
    add("Taille de clé (bits)", tls["cipher"]["bits"], "ⓘ")

    # --- Weak cipher legacy (TLS ≤ 1.2) ---
    add(
        "Ciphers faibles (legacy)",
        "OK" if tls.get("weak_cipher_ok") else "Faible" if tls.get("weak_cipher_ok") is False else "Non testé",
        ck(tls.get("weak_cipher_ok")),
        SPACER + tls.get("weak_cipher_comment", "")
    )

# ===============================================================
# FUNCTION : display_cookies()
# ===============================================================
def display_cookies(result):
    return None