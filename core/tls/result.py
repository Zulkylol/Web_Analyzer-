# core/tls/result.py

# ===============================================================
# FUNCTION : init_tls_result(input_url, normalized_url)
# ===============================================================
def init_tls_result() -> dict:
    """
    Initialize and return the default result dictionary used for TLS security analysis.

    Returns:
        dict: A pre-structured dictionary containing all fields required
            for the TLS analysis workflow, initialized with default values.
    """

    result = {
        "target": {"hostname": "", "port": 443, "url": ""},
        "certificate": {
            "subject": {"common_name": "", "san_dns": []},
            "issuer": {"common_name": ""},
            "version": {"id": "", "ok": False, "comment": ""},
            "validity": {
                "not_before": "",
                "not_after": "",
                "is_valid_now": False,
                "expires_ok": False,
                "expires_soon_comment": "",
            },
            "serial": {"hex": "", "ok": True, "comment": "", "bitlen": 0},
            "signature": {
                "hash_algorithm": "",
                "fingerprint_sha256": "",
                "ok": True,
                "comment": "",
            },
            "public_key": {
                "pem": "",
                "type": "",
                "size": None,
                "curve": "",
                "ok": True,
                "comment": "",
                "summary": "",
            },
            "extensions": {
                "key_usage": "",
                "extended_key_usage": "",
                "basic_constraints": "",
                "crl_distribution_points": "",
                "basic_constraints_ok": None,
                "basic_constraints_comment": "",
                "eku_ok": None,
                "eku_comment": "",
                "ku_ok": None,
                "ku_comment": "",
                "crl_ok": None,
                "crl_comment": "",
            },
        },
        "trust": {"is_trusted": False, "is_self_signed": False},
        "hostname_check": {
            "match": False,
            "comment": "",
            "ok": False,
            "warnings": {"wildcard": "", "multi_domain": ""},
        },
        "tls": {
            "negotiated_version": "",
            "nv_ok": False,
            "nv_comment": "",
            "supported_versions": {},
            "weak_cipher_support": {},
            "weak_cipher_ok": True,
            "weak_cipher_comment": "",
            "policy": {"ok": True, "comment": ""},
            "cipher": {"name": "", "protocol": "", "bits": 0, "ok": True, "comment": ""},
        },
        "risks": {},
        "errors": {"message": ""},
    }

    return result
