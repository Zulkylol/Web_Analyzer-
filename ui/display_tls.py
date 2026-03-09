# ui/display_tls.py

# ===============================================================
# IMPORTS
# ===============================================================
from constants import SPACER, STATUS_ICON
from utils.url import ck


# ===============================================================
# FUNCTION : display_ssl_tls()
# ===============================================================
def display_ssl_tls(result, ssl_table):
    row_idx = 0
    risks = result.get("risks", {}) or {}

    def r(key: str, default: str = "INFO") -> str:
        return str(risks.get(key, default)).upper()

    def add(p, v, c="", com="", risk=""):
        nonlocal row_idx
        zebra_tag = "zebra_even" if row_idx % 2 == 0 else "zebra_odd"
        risk_value = str(risk or "").upper()
        ssl_table.insert("", "end", values=(p, v, c, risk_value, com), tags=(zebra_tag,))
        row_idx += 1

    cert = result["certificate"]
    tls = result["tls"]
    trust = result["trust"]

    add("Nom", cert["subject"]["common_name"], risk=r("name"))

    san = cert["subject"]["san_dns"]
    if san:
        add(
            "Subject Alternative Name",
            san[0],
            ck(result["hostname_check"]["match"]),
            SPACER + result["hostname_check"]["comment"],
            risk=r("san"),
        )
        for s in san[1:]:
            add("", s, risk="INFO")
    else:
        add(
            "Subject Alternative Name",
            "Aucun SAN",
            STATUS_ICON["missing"],
            SPACER + "Extension SAN absente (certificat legacy / config atypique)",
            risk="HIGH",
        )

    add(
        "Nombre de SAN",
        len(san),
        ck(result["hostname_check"]["ok"]),
        SPACER + result["hostname_check"]["warnings"]["multi_domain"],
        risk=r("san_count"),
    )

    add(
        "Debut de validite",
        cert["validity"]["not_before"],
        ck(cert["validity"]["is_valid_now"]),
        SPACER + ("Certificat valide" if cert["validity"]["is_valid_now"] else "Certificat expire"),
        risk=r("valid_from"),
    )
    add(
        "Fin de validite",
        cert["validity"]["not_after"],
        ck(cert["validity"]["expires_ok"]),
        SPACER + cert["validity"]["expires_soon_comment"],
        risk=r("valid_to"),
    )

    add(
        "Version du certificat",
        cert["version"]["id"],
        ck(cert["version"]["ok"]),
        SPACER + cert["version"]["comment"],
        risk=r("cert_version"),
    )
    add(
        "Serial number",
        cert["serial"]["hex"],
        ck(cert["serial"]["ok"]),
        SPACER + cert["serial"]["comment"],
        risk=r("serial"),
    )
    add(
        "Algorithme",
        cert["signature"]["hash_algorithm"],
        ck(cert["signature"]["ok"]),
        SPACER + cert["signature"]["comment"],
        risk=r("signature"),
    )

    add("Empreinte", cert["signature"]["fingerprint_sha256"], STATUS_ICON["info"], risk=r("fingerprint"))

    add(
        "Autorite certifiante",
        cert["issuer"]["common_name"],
        ck(trust["is_trusted"]),
        SPACER + ("Autorite reconnue" if trust["is_trusted"] else "Autorite non reconnue"),
        risk=r("authority"),
    )
    add(
        "Auto-signe",
        trust["is_self_signed"],
        STATUS_ICON["ko"] if trust["is_self_signed"] else STATUS_ICON["ok"],
        SPACER + ("Certificat autosigne" if trust["is_self_signed"] else "Certificat non autosigne"),
        risk=r("self_signed"),
    )

    add(
        "Cle publique",
        cert["public_key"].get("summary", ""),
        ck(cert["public_key"]["ok"]),
        SPACER + cert["public_key"]["comment"],
        risk=r("public_key"),
    )

    add(
        "Basic constraints",
        cert["extensions"]["basic_constraints"],
        ck(cert["extensions"]["basic_constraints_ok"]),
        SPACER + cert["extensions"]["basic_constraints_comment"],
        risk=r("basic_constraints"),
    )
    add(
        "KU etendu",
        cert["extensions"]["extended_key_usage"],
        ck(cert["extensions"]["eku_ok"]),
        SPACER + cert["extensions"]["eku_comment"],
        risk=r("eku"),
    )
    add(
        "Key usage (KU)",
        cert["extensions"]["key_usage"],
        ck(cert["extensions"]["ku_ok"]),
        SPACER + cert["extensions"]["ku_comment"],
        risk=r("ku"),
    )
    add(
        "Liste de revocation",
        cert["extensions"]["crl_distribution_points"],
        ck(cert["extensions"]["crl_ok"]),
        SPACER + cert["extensions"]["crl_comment"],
        risk=r("crl"),
    )

    add(
        "Version TLS",
        tls["negotiated_version"],
        ck(tls["nv_ok"]),
        SPACER + tls["nv_comment"],
        risk=r("tls_version"),
    )

    if tls["supported_versions"]:
        s = tls["supported_versions"]
        for v in ["TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"]:
            if v in ["TLS1.0", "TLS1.1"]:
                check_icon = STATUS_ICON["ko"] if s[v] else STATUS_ICON["ok"]
            else:
                check_icon = ck(s[v])
            risk_key = f"support_{v.lower().replace('.', '')}"
            add(
                f"Support {v}",
                "Oui" if s[v] else "Non",
                check_icon,
                SPACER
                + (
                    "A desactiver"
                    if v in ["TLS1.0", "TLS1.1"] and s[v]
                    else "OK"
                    if s[v]
                    else "Non supporte"
                ),
                risk=r(risk_key),
            )

    add(
        "Politique TLS",
        "OK" if tls["policy"]["ok"] else "KO",
        ck(tls["policy"]["ok"]),
        SPACER + tls["policy"]["comment"],
        risk=r("tls_policy"),
    )

    add(
        "Cipher Suite",
        tls["cipher"]["name"],
        ck(tls["cipher"]["ok"]),
        SPACER + tls["cipher"]["comment"],
        risk=r("cipher"),
    )
    add("Taille de cle (bits)", tls["cipher"]["bits"], STATUS_ICON["info"], risk=r("cipher_bits"))

    add(
        "Ciphers faibles (legacy)",
        "OK" if tls.get("weak_cipher_ok") else "Faible" if tls.get("weak_cipher_ok") is False else "Non teste",
        ck(tls.get("weak_cipher_ok")),
        SPACER + tls.get("weak_cipher_comment", ""),
        risk=r("weak_ciphers"),
    )
