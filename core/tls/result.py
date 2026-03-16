# core/tls/result.py

# ===============================================================
# FUNCTION : init_tls_result
# ===============================================================
def init_tls_result() -> dict:
    """
    Initialize the default result dictionary for TLS analysis.

    Returns:
        dict: Default TLS result structure.
    """

    result = {
        "identity": {
            "common_name": "",
            "common_name_comment": "Nom commun (CN) présenté par le certificat du serveur",
            "common_name_risk": "INFO",
            "san_dns": [],
            "san_ok": False,
            "san_comment": "",
            "san_risk": "HIGH",
            "san_warning": "",
        },
        "trust": {
            "authority_name": "",
            "authority_ok": False,
            "authority_comment": "",
            "authority_risk": "HIGH",
            "is_self_signed": False,
            "self_signed_ok": True,
            "self_signed_comment": "",
            "self_signed_risk": "INFO",
        },
        "certificate": {
            "valid_from": {"value": "", "ok": False, "comment": "", "risk": "HIGH"},
            "valid_to": {"value": "", "ok": False, "comment": "", "risk": "HIGH"},
            "version": {"value": "", "ok": False, "comment": "", "risk": "MEDIUM"},
            "serial": {"value": "", "ok": True, "comment": "", "risk": "INFO"},
            "signature": {"value": "", "ok": True, "comment": "", "risk": "INFO"},
            "fingerprint": {"value": "", "comment": "Empreinte SHA-256 du certificat présenté par le serveur", "risk": "INFO"},
            "public_key": {
                "value": "",
                "type": "",
                "size": None,
                "curve": "",
                "ok": True,
                "comment": "",
                "risk": "INFO",
            },
            "extensions": {
                "basic_constraints": {"value": "", "ok": None, "comment": "", "risk": "MEDIUM"},
                "key_usage": {"value": "", "ok": None, "comment": "", "risk": "MEDIUM"},
                "extended_key_usage": {"value": "", "ok": None, "comment": "", "risk": "MEDIUM"},
                "crl_distribution_points": {"value": "", "ok": None, "comment": "", "risk": "LOW"},
            },
        },
        "protocol": {
            "version": {"value": "", "ok": False, "comment": "", "risk": "MEDIUM"},
            "supported_versions": {},
            "policy": {"value": "", "ok": True, "comment": "", "risk": "INFO"},
            "cipher": {
                "value": "",
                "name": "",
                "bits": 0,
                "ok": True,
                "comment": "",
                "risk": "INFO",
                "bits_risk": "INFO",
            },
            "weak_ciphers": {
                "value": "OK",
                "support": {},
                "ok": True,
                "comment": "",
                "risk": "INFO",
            },
        },
        "errors": {"message": ""},
        "report": {},
    }

    return result
