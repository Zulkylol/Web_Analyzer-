# core/tls/tls_policy.py

# ===============================================================
# IMPORTS
# ===============================================================
from __future__ import annotations

import ssl

from utils.tls import server_supports_tls_version


# ===============================================================
# FUNCTION : analyze_tls_versions_and_policy
# ===============================================================
def analyze_tls_versions_and_policy(negotiated_version: str, url: str) -> tuple[bool | None, str, dict, dict]:
    """
    Evaluate negotiated TLS version and server protocol support.

    Returns:
        tuple[bool | None, str, dict, dict]:
            - nv_ok
            - nv_comment
            - supported_versions
            - policy block
    """
    if negotiated_version == "TLSv1":
        nv_ok = False
        nv_comment = "TLS 1.0 est obsolete et vulnerable."
    elif negotiated_version == "TLSv1.1":
        nv_ok = False
        nv_comment = "TLS 1.1 est obsolete (a desactiver)."
    elif negotiated_version == "TLSv1.2":
        nv_ok = True
        nv_comment = "TLS 1.2 est encore securise mais progressivement remplace par TLS 1.3."
    elif negotiated_version == "TLSv1.3":
        nv_ok = True
        nv_comment = "TLS 1.3 est la version la plus moderne et recommandee."
    else:
        nv_ok = None
        nv_comment = "Version TLS inconnue ou non analysee."

    supported_versions = {
        "TLS1.0": server_supports_tls_version(url, ssl.TLSVersion.TLSv1),
        "TLS1.1": server_supports_tls_version(url, ssl.TLSVersion.TLSv1_1),
        "TLS1.2": server_supports_tls_version(url, ssl.TLSVersion.TLSv1_2),
        "TLS1.3": server_supports_tls_version(url, ssl.TLSVersion.TLSv1_3),
    }

    policy = {"ok": True, "comment": ""}
    if supported_versions["TLS1.0"] or supported_versions["TLS1.1"]:
        disabled_legacy_versions = []
        if supported_versions["TLS1.0"]:
            disabled_legacy_versions.append("TLS 1.0")
        if supported_versions["TLS1.1"]:
            disabled_legacy_versions.append("TLS 1.1")
        policy["ok"] = False
        policy["comment"] = f"Le serveur accepte encore {', '.join(disabled_legacy_versions)} (obsolete)."
    elif supported_versions["TLS1.3"]:
        policy["ok"] = True
        policy["comment"] = "TLS 1.0/1.1 desactives. TLS 1.3 supporte."
    elif supported_versions["TLS1.2"]:
        policy["ok"] = True
        policy["comment"] = "TLS 1.0/1.1 desactives. TLS 1.2 supporte."
    else:
        policy["ok"] = True
        policy["comment"] = "TLS 1.2+ non supporte (probleme)."

    return nv_ok, nv_comment, supported_versions, policy
