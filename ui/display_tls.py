from constants import SPACER, STATUS_ICON
from utils.url import ck

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
        add("Subject Alternative Name", "Aucun SAN", STATUS_ICON["missing"],
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
    add("Empreinte", cert["signature"]["fingerprint_sha256"], STATUS_ICON["info"])

    # --- Authority ---
    add("Autorité certifiante", cert["issuer"]["common_name"],
        ck(trust["is_trusted"]),
        SPACER + ("Autorité reconnue" if trust["is_trusted"] else "Autorité non reconnue"))

    # --- Auto-signed ---
    add("Auto-signé", trust["is_self_signed"],
        "✖" if trust["is_self_signed"] else STATUS_ICON["ok"],
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
                check_icon = "✖" if s[v] else STATUS_ICON["ok"]
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
    add("Taille de clé (bits)", tls["cipher"]["bits"], STATUS_ICON["info"])

    # --- Weak cipher legacy (TLS ≤ 1.2) ---
    add(
        "Ciphers faibles (legacy)",
        "OK" if tls.get("weak_cipher_ok") else "Faible" if tls.get("weak_cipher_ok") is False else "Non testé",
        ck(tls.get("weak_cipher_ok")),
        SPACER + tls.get("weak_cipher_comment", "")
    )