def _risk_from_bool(status, true_risk="INFO", false_risk="HIGH", none_risk="MEDIUM"):
    if status is True:
        return true_risk
    if status is False:
        return false_risk
    return none_risk


def compute_tls_risks(result: dict) -> dict:
    cert = result.get("certificate", {})
    tls = result.get("tls", {})
    trust = result.get("trust", {})
    host = result.get("hostname_check", {})
    ext = cert.get("extensions", {})
    validity = cert.get("validity", {})

    risks = {
        "name": "INFO",
        "san": _risk_from_bool(host.get("match"), true_risk="INFO", false_risk="HIGH"),
        "san_count": "LOW" if host.get("warnings", {}).get("multi_domain") else "INFO",
        "valid_from": _risk_from_bool(validity.get("is_valid_now")),
        "valid_to": _risk_from_bool(validity.get("expires_ok"), true_risk="LOW", false_risk="HIGH"),
        "cert_version": _risk_from_bool(cert.get("version", {}).get("ok"), true_risk="INFO", false_risk="MEDIUM"),
        "serial": _risk_from_bool(cert.get("serial", {}).get("ok"), true_risk="INFO", false_risk="LOW"),
        "signature": _risk_from_bool(cert.get("signature", {}).get("ok")),
        "fingerprint": "INFO",
        "authority": _risk_from_bool(trust.get("is_trusted")),
        "self_signed": "HIGH" if trust.get("is_self_signed") else "INFO",
        "public_key": _risk_from_bool(cert.get("public_key", {}).get("ok")),
        "basic_constraints": _risk_from_bool(ext.get("basic_constraints_ok"), true_risk="INFO", false_risk="MEDIUM"),
        "eku": _risk_from_bool(ext.get("eku_ok"), true_risk="INFO", false_risk="MEDIUM"),
        "ku": _risk_from_bool(ext.get("ku_ok"), true_risk="INFO", false_risk="MEDIUM"),
        "crl": _risk_from_bool(ext.get("crl_ok"), true_risk="LOW", false_risk="MEDIUM"),
        "tls_version": _risk_from_bool(tls.get("nv_ok"), true_risk="LOW", false_risk="HIGH"),
        "tls_policy": _risk_from_bool(tls.get("policy", {}).get("ok"), true_risk="INFO", false_risk="HIGH"),
        "cipher": _risk_from_bool(tls.get("cipher", {}).get("ok")),
        "cipher_bits": "HIGH" if (tls.get("cipher", {}).get("bits") or 0) < 128 else "INFO",
        "weak_ciphers": _risk_from_bool(
            tls.get("weak_cipher_ok"), true_risk="INFO", false_risk="HIGH", none_risk="LOW"
        ),
    }

    s = tls.get("supported_versions", {}) or {}
    for v in ("TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"):
        key = f"support_{v.lower().replace('.', '')}"
        supported = bool(s.get(v))
        if v in ("TLS1.0", "TLS1.1"):
            risks[key] = "HIGH" if supported else "INFO"
        elif v == "TLS1.2":
            risks[key] = "LOW" if supported else "MEDIUM"
        else:
            risks[key] = "INFO" if supported else "LOW"

    return risks
