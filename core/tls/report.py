from __future__ import annotations

from constants import STATUS_ICON
from core.reporting import build_report, make_row, make_section_row


# ===============================================================
# FUNCTION : build_tls_report
# ===============================================================
def build_tls_report(result: dict) -> dict:
    """Transforme le resultat TLS brut en lignes ordonnees pour l'UI."""
    rows: list[dict] = []
    risks = result.get("risks", {}) or {}
    error_message = str((result.get("errors") or {}).get("message", "") or "")

    # ===============================================================
    # FUNCTION : r
    # ===============================================================
    def r(key: str, default: str = "INFO") -> str:
        """
        Read a normalized risk value.

        Returns :
            str : normalized risk
        """
        return str(risks.get(key, default)).upper()

    # ===============================================================
    # FUNCTION : add_row
    # ===============================================================
    def add_row(param, value="", *, risk="INFO", comment="", ok_when_info=False, check=None, tags=(), include=False):
        """
        Append a report row.

        Returns :
            None : no return
        """
        rows.append(
            make_row(
                param,
                value,
                risk=risk,
                comment=comment,
                ok_when_info=ok_when_info,
                check=check,
                tags=tags,
                include_in_findings=include,
            )
        )

    # ===============================================================
    # FUNCTION : add_section
    # ===============================================================
    def add_section(title: str):
        """
        Append a section row.

        Returns :
            None : no return
        """
        rows.append(make_section_row(title))

    if error_message:
        add_row("Erreur TLS", "-", risk="HIGH", comment=error_message, check=STATUS_ICON["high"], include=True)
        return build_report("SSL/TLS", rows, error_message=error_message)

    cert = result.get("certificate", {})
    tls = result.get("tls", {})
    trust = result.get("trust", {})
    hostname_check = result.get("hostname_check", {})

    # Section 1: identite du certificat presentee par le serveur.
    add_section("Identité du certificat")
    add_row(
        "Nom", 
        cert.get("subject", {}).get("common_name", ""), 
        risk=r("name"), 
        comment ="Nom commun (CN) du certificat",
        include=r("name") != "INFO")

    san = cert.get("subject", {}).get("san_dns", []) or []
    if san:
        add_row(
            "Subject Alternative Name",
            san[0],
            risk=r("san"),
            comment=hostname_check.get("comment", ""),
            ok_when_info=bool(hostname_check.get("match")),
            include=r("san") != "INFO",
        )
        for item in san[1:]:
            add_row("", item)
    else:
        add_row(
            "Subject Alternative Name",
            "Aucun SAN",
            risk="HIGH",
            comment="Extension SAN absente (certificat legacy / configuration atypique)",
            check=STATUS_ICON["missing"],
            include=True,
        )

    add_row(
        "Nombre de SAN",
        len(san),
        risk="INFO",
        comment=hostname_check.get("warnings", {}).get("multi_domain", ""),
    )

    # Section 2: confiance de la chaine et statut autosigne.
    add_section("Confiance")
    add_row(
        "Autorité certifiante",
        cert.get("issuer", {}).get("common_name", ""),
        risk=r("authority"),
        comment="Autorité reconnue" if trust.get("is_trusted") else "Autorité non reconnue",
        ok_when_info=bool(trust.get("is_trusted")),
        include=r("authority") != "INFO",
    )
    add_row(
        "Autosigné",
        trust.get("is_self_signed"),
        risk=r("self_signed"),
        comment="Certificat autosigné" if trust.get("is_self_signed") else "Certificat non autosigné",
        ok_when_info=not trust.get("is_self_signed"),
        include=r("self_signed") != "INFO",
    )

    # Section 3: metadonnees generales du certificat.
    add_section("Metadonnees du certificat")
    add_row(
        "Debut de validité",
        cert.get("validity", {}).get("not_before", ""),
        risk=r("valid_from"),
        comment="Certificat valide" if cert.get("validity", {}).get("is_valid_now") else "Certificat expiré",
        ok_when_info=bool(cert.get("validity", {}).get("is_valid_now")),
        include=r("valid_from") != "INFO",
    )
    add_row(
        "Fin de validité",
        cert.get("validity", {}).get("not_after", ""),
        risk=r("valid_to"),
        comment=cert.get("validity", {}).get("expires_soon_comment", ""),
        ok_when_info=bool(cert.get("validity", {}).get("expires_ok")),
        include=r("valid_to") != "INFO",
    )
    add_row(
        "Version du certificat",
        cert.get("version", {}).get("id", ""),
        risk=r("cert_version"),
        comment=cert.get("version", {}).get("comment", ""),
        ok_when_info=bool(cert.get("version", {}).get("ok")),
        include=r("cert_version") != "INFO",
    )
    add_row(
        "Numéro de série",
        cert.get("serial", {}).get("hex", ""),
        risk="INFO",
        comment=cert.get("serial", {}).get("comment", ""),
    )
    add_row(
        "Algorithme",
        cert.get("signature", {}).get("hash_algorithm", ""),
        risk=r("signature"),
        comment=cert.get("signature", {}).get("comment", ""),
        ok_when_info=bool(cert.get("signature", {}).get("ok")),
        include=r("signature") != "INFO",
    )
    add_row(
        "Empreinte",
        cert.get("signature", {}).get("fingerprint_sha256", ""),
        risk=r("fingerprint"),
        comment="Hash SHA-256 du certificat",
        include=r("fingerprint") != "INFO",
    )
    add_row(
        "Clé publique",
        cert.get("public_key", {}).get("summary", ""),
        risk=r("public_key"),
        comment=cert.get("public_key", {}).get("comment", ""),
        ok_when_info=bool(cert.get("public_key", {}).get("ok")),
        include=r("public_key") != "INFO",
    )

    # Section 4: extensions X509 utilisees pour l'usage du certificat.
    add_section("Extensions du certificat")
    add_row(
        "Basic constraints",
        cert.get("extensions", {}).get("basic_constraints", ""),
        risk=r("basic_constraints"),
        comment=cert.get("extensions", {}).get("basic_constraints_comment", ""),
        ok_when_info=bool(cert.get("extensions", {}).get("basic_constraints_ok")),
        include=r("basic_constraints") != "INFO",
    )
    add_row(
        "Key usage (KU)",
        cert.get("extensions", {}).get("key_usage", ""),
        risk=r("ku"),
        comment=cert.get("extensions", {}).get("ku_comment", ""),
        ok_when_info=bool(cert.get("extensions", {}).get("ku_ok")),
        include=r("ku") != "INFO",
    )
    add_row(
        "KU étendu",
        cert.get("extensions", {}).get("extended_key_usage", ""),
        risk=r("eku"),
        comment=cert.get("extensions", {}).get("eku_comment", ""),
        ok_when_info=bool(cert.get("extensions", {}).get("eku_ok")),
        include=r("eku") != "INFO",
    )
    add_row(
        "Liste de révocation",
        cert.get("extensions", {}).get("crl_distribution_points", ""),
        risk=r("crl"),
        comment=cert.get("extensions", {}).get("crl_comment", ""),
        ok_when_info=bool(cert.get("extensions", {}).get("crl_ok")),
        include=r("crl") != "INFO",
    )

    # Section 5: versions TLS, politique et chiffrement negocie.
    add_section("Protocole et chiffrement")
    add_row(
        "Version TLS",
        tls.get("negotiated_version", ""),
        risk=r("tls_version"),
        comment=tls.get("nv_comment", ""),
        ok_when_info=bool(tls.get("nv_ok")),
        include=r("tls_version") != "INFO",
    )

    supported_versions = tls.get("supported_versions", {}) or {}
    if supported_versions:
        for version in ["TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"]:
            risk_key = f"support_{version.lower().replace('.', '')}"
            supported = bool(supported_versions.get(version))
            row_risk = "INFO" if version in {"TLS1.2", "TLS1.3"} else r(risk_key)
            add_row(
                f"Support {version}",
                "Oui" if supported else "Non",
                risk=row_risk,
                comment=(
                    "A desactiver"
                    if version in {"TLS1.0", "TLS1.1"} and supported
                    else "OK"
                    if supported
                    else "Non supporte"
                ),
                ok_when_info=(not supported if version in {"TLS1.0", "TLS1.1"} else supported),
                include=row_risk != "INFO",
            )

    add_row(
        "Politique TLS",
        "OK" if tls.get("policy", {}).get("ok") else "KO",
        risk=r("tls_policy"),
        comment=tls.get("policy", {}).get("comment", ""),
        ok_when_info=bool(tls.get("policy", {}).get("ok")),
        include=r("tls_policy") != "INFO",
    )
    add_row(
        "Cipher Suite",
        tls.get("cipher", {}).get("name", ""),
        risk=r("cipher"),
        comment=tls.get("cipher", {}).get("comment", ""),
        ok_when_info=bool(tls.get("cipher", {}).get("ok")),
        include=r("cipher") != "INFO",
    )
    add_row(
        "Taille de clé (bits)",
        tls.get("cipher", {}).get("bits", 0),
        risk=r("cipher_bits"),
        comment="Taille de la clé publique du certificat",
        include=r("cipher_bits") != "INFO",
    )
    add_row(
        "Ciphers faibles (legacy)",
        "OK" if tls.get("weak_cipher_ok") else "Faible" if tls.get("weak_cipher_ok") is False else "Non teste",
        risk=r("weak_ciphers"),
        comment=tls.get("weak_cipher_comment", ""),
        ok_when_info=bool(tls.get("weak_cipher_ok")),
        include=r("weak_ciphers") != "INFO",
    )

    return build_report("SSL/TLS", rows, error_message=error_message)
