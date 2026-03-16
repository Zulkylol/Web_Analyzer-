# ===============================================================
# FUNCTION : _risk_from_bool
# ===============================================================
def _risk_from_bool(status, true_risk="INFO", false_risk="HIGH", none_risk="MEDIUM"):
    """
    Map a boolean-like status to a risk.

    Returns :
        str : risk level
    """
    if status is True:
        return true_risk
    if status is False:
        return false_risk
    return none_risk


# ===============================================================
# FUNCTION : compute_tls_risks
# ===============================================================
def compute_tls_risks(result: dict) -> dict:
    """
    Compute all TLS risk levels.

    Returns :
        dict : risk mapping
    """
    cert = result.get("certificate", {})
    tls = result.get("tls", {})
    trust = result.get("trust", {})
    host = result.get("hostname_check", {})
    ext = cert.get("extensions", {})
    validity = cert.get("validity", {})

    risks = {
        "name": "INFO",
        "san": _risk_from_bool(host.get("match"), true_risk="INFO", false_risk="HIGH"),
        "valid_from": _risk_from_bool(validity.get("is_valid_now")),
        "valid_to": _risk_from_bool(validity.get("expires_ok"), true_risk="INFO", false_risk="HIGH"),
        "cert_version": _risk_from_bool(cert.get("version", {}).get("ok"), true_risk="INFO", false_risk="MEDIUM"),
        "serial": "INFO",
        "signature": _risk_from_bool(cert.get("signature", {}).get("ok")),
        "fingerprint": "INFO",
        "authority": _risk_from_bool(trust.get("is_trusted")),
        "self_signed": "HIGH" if trust.get("is_self_signed") else "INFO",
        "public_key": _risk_from_bool(cert.get("public_key", {}).get("ok")),
        "basic_constraints": _risk_from_bool(ext.get("basic_constraints_ok"), true_risk="INFO", false_risk="HIGH"),
        "eku": _risk_from_bool(ext.get("eku_ok"), true_risk="INFO", false_risk="MEDIUM"),
        "ku": _risk_from_bool(ext.get("ku_ok"), true_risk="INFO", false_risk="MEDIUM"),
        "crl": _risk_from_bool(ext.get("crl_ok"), true_risk="INFO", false_risk="LOW", none_risk="LOW"),
        "tls_version": "MEDIUM",
        "tls_policy": _risk_from_bool(tls.get("policy", {}).get("ok"), true_risk="INFO", false_risk="HIGH"),
        "cipher": _risk_from_bool(tls.get("cipher", {}).get("ok")),
        "cipher_bits": "HIGH" if (tls.get("cipher", {}).get("bits") or 0) < 128 else "INFO",
        "weak_ciphers": "INFO",
    }
    weak_cipher_support = tls.get("weak_cipher_support", {}) or {}
    if tls.get("weak_cipher_ok") is None:
        risks["weak_ciphers"] = "LOW"
    elif tls.get("weak_cipher_ok") is False:
        if any(weak_cipher_support.get(k) for k in ("3DES", "RC4", "MD5")):
            risks["weak_ciphers"] = "HIGH"
        elif weak_cipher_support.get("AES-CBC"):
            risks["weak_ciphers"] = "LOW"

    negotiated_version = str(tls.get("negotiated_version") or "")
    if negotiated_version == "TLSv1.3":
        risks["tls_version"] = "INFO"
    elif negotiated_version == "TLSv1.2":
        risks["tls_version"] = "LOW"
    elif negotiated_version in ("TLSv1.1", "TLSv1"):
        risks["tls_version"] = "HIGH"

    s = tls.get("supported_versions", {}) or {}
    for v in ("TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"):
        key = f"support_{v.lower().replace('.', '')}"
        supported = bool(s.get(v))
        if v in ("TLS1.0", "TLS1.1"):
            risks[key] = "HIGH" if supported else "INFO"
        elif v in ("TLS1.2", "TLS1.3"):
            risks[key] = "INFO"
        else:
            risks[key] = "INFO"

    return risks
