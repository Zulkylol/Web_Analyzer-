from __future__ import annotations

from constants import STATUS_ICON
from core.reporting import build_report, make_row, make_section_row


# ===============================================================
# FUNCTION : build_tls_report
# ===============================================================
def build_tls_report(result: dict) -> dict:
    """Transform the raw TLS result into ordered UI rows."""
    rows: list[dict] = []
    identity = result.get("identity", {}) or {}
    trust = result.get("trust", {}) or {}
    certificate = result.get("certificate", {}) or {}
    protocol = result.get("protocol", {}) or {}
    error_message = str((result.get("errors") or {}).get("message", "") or "")

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

    # Section 1: identite du certificat presentee par le serveur.
    add_section("Identite du certificat")
    add_row(
        "Nom",
        identity.get("common_name", ""),
        risk=str(identity.get("common_name_risk", "INFO")).upper(),
        comment=identity.get("common_name_comment", ""),
        include=str(identity.get("common_name_risk", "INFO")).upper() != "INFO",
    )

    san_dns = identity.get("san_dns", []) or []
    if san_dns:
        add_row(
            "Subject Alternative Name",
            san_dns[0],
            risk=str(identity.get("san_risk", "INFO")).upper(),
            comment=identity.get("san_comment", ""),
            ok_when_info=bool(identity.get("san_ok")),
            include=str(identity.get("san_risk", "INFO")).upper() != "INFO",
        )
        for item in san_dns[1:]:
            add_row("", item)
    else:
        add_row(
            "Subject Alternative Name",
            "Aucun SAN",
            risk="HIGH",
            comment="L'extension SAN est absente, ce qui correspond à un certificat legacy ou à une configuration atypique",
            check=STATUS_ICON["missing"],
            include=True,
        )

    add_row(
        "Nombre de SAN",
        len(san_dns),
        risk="INFO",
        comment=identity.get("san_warning", ""),
    )

    # Section 2: confiance de la chaine et statut autosigne.
    add_section("Confiance")
    add_row(
        "Autorite certifiante",
        trust.get("authority_name", ""),
        risk=str(trust.get("authority_risk", "INFO")).upper(),
        comment=trust.get("authority_comment", ""),
        ok_when_info=bool(trust.get("authority_ok")),
        include=str(trust.get("authority_risk", "INFO")).upper() != "INFO",
    )
    add_row(
        "Auto-signe",
        trust.get("is_self_signed"),
        risk=str(trust.get("self_signed_risk", "INFO")).upper(),
        comment=trust.get("self_signed_comment", ""),
        ok_when_info=bool(trust.get("self_signed_ok")),
        include=str(trust.get("self_signed_risk", "INFO")).upper() != "INFO",
    )

    # Section 3: metadonnees generales du certificat.
    add_section("Metadonnees du certificat")
    valid_from = certificate.get("valid_from", {}) or {}
    add_row(
        "Debut de validite",
        valid_from.get("value", ""),
        risk=str(valid_from.get("risk", "INFO")).upper(),
        comment=valid_from.get("comment", ""),
        ok_when_info=bool(valid_from.get("ok")),
        include=str(valid_from.get("risk", "INFO")).upper() != "INFO",
    )

    valid_to = certificate.get("valid_to", {}) or {}
    add_row(
        "Fin de validite",
        valid_to.get("value", ""),
        risk=str(valid_to.get("risk", "INFO")).upper(),
        comment=valid_to.get("comment", ""),
        ok_when_info=bool(valid_to.get("ok")),
        include=str(valid_to.get("risk", "INFO")).upper() != "INFO",
    )

    cert_version = certificate.get("version", {}) or {}
    add_row(
        "Version du certificat",
        cert_version.get("value", ""),
        risk=str(cert_version.get("risk", "INFO")).upper(),
        comment=cert_version.get("comment", ""),
        ok_when_info=bool(cert_version.get("ok")),
        include=str(cert_version.get("risk", "INFO")).upper() != "INFO",
    )

    serial = certificate.get("serial", {}) or {}
    add_row(
        "Numero de serie",
        serial.get("value", ""),
        risk=str(serial.get("risk", "INFO")).upper(),
        comment=serial.get("comment", ""),
    )

    signature = certificate.get("signature", {}) or {}
    add_row(
        "Algorithme",
        signature.get("value", ""),
        risk=str(signature.get("risk", "INFO")).upper(),
        comment=signature.get("comment", ""),
        ok_when_info=bool(signature.get("ok")),
        include=str(signature.get("risk", "INFO")).upper() != "INFO",
    )

    fingerprint = certificate.get("fingerprint", {}) or {}
    add_row(
        "Empreinte",
        fingerprint.get("value", ""),
        risk=str(fingerprint.get("risk", "INFO")).upper(),
        comment=fingerprint.get("comment", ""),
        include=str(fingerprint.get("risk", "INFO")).upper() != "INFO",
    )

    public_key = certificate.get("public_key", {}) or {}
    add_row(
        "Cle publique",
        public_key.get("value", ""),
        risk=str(public_key.get("risk", "INFO")).upper(),
        comment=public_key.get("comment", ""),
        ok_when_info=bool(public_key.get("ok")),
        include=str(public_key.get("risk", "INFO")).upper() != "INFO",
    )

    # Section 4: extensions X509 utilisees pour l'usage du certificat.
    add_section("Extensions du certificat")
    extensions = certificate.get("extensions", {}) or {}

    basic_constraints = extensions.get("basic_constraints", {}) or {}
    add_row(
        "Basic constraints",
        basic_constraints.get("value", ""),
        risk=str(basic_constraints.get("risk", "INFO")).upper(),
        comment=basic_constraints.get("comment", ""),
        ok_when_info=bool(basic_constraints.get("ok")),
        include=str(basic_constraints.get("risk", "INFO")).upper() != "INFO",
    )

    key_usage = extensions.get("key_usage", {}) or {}
    add_row(
        "Key usage (KU)",
        key_usage.get("value", ""),
        risk=str(key_usage.get("risk", "INFO")).upper(),
        comment=key_usage.get("comment", ""),
        ok_when_info=bool(key_usage.get("ok")),
        include=str(key_usage.get("risk", "INFO")).upper() != "INFO",
    )

    extended_key_usage = extensions.get("extended_key_usage", {}) or {}
    add_row(
        "KU etendu",
        extended_key_usage.get("value", ""),
        risk=str(extended_key_usage.get("risk", "INFO")).upper(),
        comment=extended_key_usage.get("comment", ""),
        ok_when_info=bool(extended_key_usage.get("ok")),
        include=str(extended_key_usage.get("risk", "INFO")).upper() != "INFO",
    )

    crl_distribution_points = extensions.get("crl_distribution_points", {}) or {}
    add_row(
        "Liste de revocation",
        crl_distribution_points.get("value", ""),
        risk=str(crl_distribution_points.get("risk", "INFO")).upper(),
        comment=crl_distribution_points.get("comment", ""),
        ok_when_info=bool(crl_distribution_points.get("ok")),
        include=str(crl_distribution_points.get("risk", "INFO")).upper() != "INFO",
    )

    # Section 5: versions TLS, politique et chiffrement negocie.
    add_section("Protocole et chiffrement")
    tls_version = protocol.get("version", {}) or {}
    add_row(
        "Version TLS",
        tls_version.get("value", ""),
        risk=str(tls_version.get("risk", "INFO")).upper(),
        comment=tls_version.get("comment", ""),
        ok_when_info=bool(tls_version.get("ok")),
        include=str(tls_version.get("risk", "INFO")).upper() != "INFO",
    )

    supported_versions = protocol.get("supported_versions", {}) or {}
    if supported_versions:
        for version_name in ["TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"]:
            version_info = supported_versions.get(version_name, {}) or {}
            row_risk = str(version_info.get("risk", "INFO")).upper()
            add_row(
                f"Support {version_name}",
                "Oui" if version_info.get("supported") else "Non",
                risk=row_risk,
                comment=version_info.get("comment", ""),
                ok_when_info=bool(version_info.get("ok")),
                include=row_risk != "INFO",
            )

    policy = protocol.get("policy", {}) or {}
    add_row(
        "Politique TLS",
        policy.get("value", ""),
        risk=str(policy.get("risk", "INFO")).upper(),
        comment=policy.get("comment", ""),
        ok_when_info=bool(policy.get("ok")),
        include=str(policy.get("risk", "INFO")).upper() != "INFO",
    )

    cipher = protocol.get("cipher", {}) or {}
    add_row(
        "Cipher Suite",
        cipher.get("value", ""),
        risk=str(cipher.get("risk", "INFO")).upper(),
        comment=cipher.get("comment", ""),
        ok_when_info=bool(cipher.get("ok")),
        include=str(cipher.get("risk", "INFO")).upper() != "INFO",
    )
    add_row(
        "Taille de cle (bits)",
        cipher.get("bits", 0),
        risk=str(cipher.get("bits_risk", "INFO")).upper(),
        comment="Taille de clé de la suite cryptographique négociée par le serveur",
        include=str(cipher.get("bits_risk", "INFO")).upper() != "INFO",
    )

    weak_ciphers = protocol.get("weak_ciphers", {}) or {}
    add_row(
        "Ciphers faibles (legacy)",
        weak_ciphers.get("value", "OK"),
        risk=str(weak_ciphers.get("risk", "INFO")).upper(),
        comment=weak_ciphers.get("comment", ""),
        ok_when_info=bool(weak_ciphers.get("ok")),
        include=str(weak_ciphers.get("risk", "INFO")).upper() != "INFO",
    )

    return build_report("SSL/TLS", rows, error_message=error_message)
