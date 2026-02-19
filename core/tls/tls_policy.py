# core/tls/tls_policy.py
from __future__ import annotations

import ssl

from utils.tls import server_supports_tls_version


def analyze_tls_versions_and_policy(result: dict, url: str) -> None:
    tls = result["tls"]
    tls_policy = tls["policy"]

    nv = tls.get("negotiated_version", "")

    if nv == "TLSv1":
        tls["nv_ok"] = False
        tls["nv_comment"] = "TLS 1.0 est obsolète et vulnérable."
    elif nv == "TLSv1.1":
        tls["nv_ok"] = False
        tls["nv_comment"] = "TLS 1.1 est obsolète (à désactiver)."
    elif nv == "TLSv1.2":
        tls["nv_ok"] = True
        tls["nv_comment"] = "TLS 1.2 est encore sécurisé mais progressivement remplacé par TLS 1.3."
    elif nv == "TLSv1.3":
        tls["nv_ok"] = True
        tls["nv_comment"] = "TLS 1.3 est la version la plus moderne et recommandée."
    else:
        tls["nv_ok"] = None
        tls["nv_comment"] = "Version TLS inconnue ou non analysée."

    support = {
        "TLS1.0": server_supports_tls_version(url, ssl.TLSVersion.TLSv1),
        "TLS1.1": server_supports_tls_version(url, ssl.TLSVersion.TLSv1_1),
        "TLS1.2": server_supports_tls_version(url, ssl.TLSVersion.TLSv1_2),
        "TLS1.3": server_supports_tls_version(url, ssl.TLSVersion.TLSv1_3),
    }
    tls["supported_versions"] = support

    if support["TLS1.0"] or support["TLS1.1"]:
        tls_policy["ok"] = False
        bad = []
        if support["TLS1.0"]:
            bad.append("TLS 1.0")
        if support["TLS1.1"]:
            bad.append("TLS 1.1")
        tls_policy["comment"] = f"Le serveur accepte encore {', '.join(bad)} (obsolète)."
    else:
        tls_policy["ok"] = True
        if support["TLS1.3"]:
            tls_policy["comment"] = "TLS 1.0/1.1 désactivés. TLS 1.3 supporté."
        elif support["TLS1.2"]:
            tls_policy["comment"] = "TLS 1.0/1.1 désactivés. TLS 1.2 supporté."
        else:
            tls_policy["comment"] = "TLS 1.2+ non supporté (problème)."
