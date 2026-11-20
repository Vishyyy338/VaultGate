"""
Unit tests for the sequential identity contract checks.
"""
from core.keystore import KeyStore
from core.models import KeyContract, hash_key
from core.scanner import VaultGateScanner

def test_check_1_key_missing():
    ks = KeyStore()
    scanner = VaultGateScanner(ks)
    d = scanner.evaluate_request("GET", "/api/suppliers", "127.0.0.1", {}, {})
    assert d.status_code == 401
    assert d.error_code == "KEY_MISSING"
    assert d.check_failed == "Key present"

def test_check_2_key_unknown():
    ks = KeyStore()
    scanner = VaultGateScanner(ks)
    d = scanner.evaluate_request("GET", "/api/suppliers", "127.0.0.1", {"X-API-Key": "vg_live_unknown_forged_key"}, {})
    assert d.status_code == 401
    assert d.error_code == "KEY_UNKNOWN"
    assert d.check_failed == "Key known"

def test_check_3_vendor_mismatch():
    ks = KeyStore()
    scanner = VaultGateScanner(ks)
    d = scanner.evaluate_request(
        "GET", "/api/suppliers", "127.0.0.1",
        {"X-API-Key": "vg_live_shipping_swift_a18b2c", "X-Vendor-ID": "imposter-vendor"}, {}
    )
    assert d.status_code == 403
    assert d.error_code == "VENDOR_MISMATCH"
    assert d.check_failed == "Vendor matches"

def test_check_4_key_expired():
    ks = KeyStore()
    exp_key = "vg_test_expired_key_sample"
    exp_hash = hash_key(exp_key)
    ks.contracts[exp_hash] = KeyContract(
        vendor_name="Expired Test Vendor",
        vendor_id="expired-vendor",
        hashed_api_key=exp_hash,
        scopes=["general:read"],
        allowed_ips=["127.0.0.1"],
        expires_at="2025-01-01T00:00:00"
    )
    scanner = VaultGateScanner(ks)
    d = scanner.evaluate_request(
        "GET", "/api/suppliers", "127.0.0.1",
        {"X-API-Key": exp_key, "X-Vendor-ID": "expired-vendor"}, {}
    )
    assert d.status_code == 401
    assert d.error_code == "KEY_EXPIRED"
    assert d.check_failed == "Not expired"

def test_check_5_scope_denied():
    ks = KeyStore()
    scanner = VaultGateScanner(ks)
    d = scanner.evaluate_request(
        "POST", "/api/payments/run", "127.0.0.1",
        {"X-API-Key": "vg_live_shipping_swift_a18b2c", "X-Vendor-ID": "swift-carrier"}, {}
    )
    assert d.status_code == 403
    assert d.error_code == "SCOPE_DENIED"
    assert d.check_failed == "Scope allowed"

def test_check_6_source_ip_blocked():
    ks = KeyStore()
    scanner = VaultGateScanner(ks)
    d = scanner.evaluate_request(
        "GET", "/api/suppliers", "198.18.7.41",
        {"X-API-Key": "vg_live_shipping_swift_a18b2c", "X-Vendor-ID": "swift-carrier"}, {}
    )
    assert d.status_code == 403
    assert d.error_code == "IP_BLOCKED"
    assert d.check_failed == "Source IP"

def test_check_7_payload_suspect():
    ks = KeyStore()
    scanner = VaultGateScanner(ks)
    d = scanner.evaluate_request(
        "GET", "/api/suppliers", "127.0.0.1",
        {"X-API-Key": "vg_live_shipping_swift_a18b2c", "X-Vendor-ID": "swift-carrier"},
        {"q": "' UNION SELECT * FROM users--"}
    )
    assert d.status_code == 400
    assert d.error_code == "PAYLOAD_SUSPECT"
    assert d.check_failed == "Payload clean"

def test_check_8_rate_limit_exceeded():
    ks = KeyStore()
    scanner = VaultGateScanner(ks, default_rate_limit=60)
    scanner.rate_history.clear()
    
    for _ in range(60):
        d = scanner.evaluate_request(
            "GET", "/api/suppliers", "127.0.0.1",
            {"X-API-Key": "vg_live_shipping_swift_a18b2c", "X-Vendor-ID": "swift-carrier"}, {}
        )
        assert d.allowed is True
    
    d61 = scanner.evaluate_request(
        "GET", "/api/suppliers", "127.0.0.1",
        {"X-API-Key": "vg_live_shipping_swift_a18b2c", "X-Vendor-ID": "swift-carrier"}, {}
    )
    assert d61.status_code == 429
    assert d61.error_code == "RATE_LIMIT"
    assert d61.check_failed == "Rate normal"

def test_anti_header_forgery():
    ks = KeyStore()
    scanner = VaultGateScanner(ks)
    d = scanner.evaluate_request(
        "GET", "/api/suppliers", "127.0.0.1",
        {
            "X-API-Key": "vg_live_shipping_swift_a18b2c",
            "X-Vendor-ID": "swift-carrier",
            "X-Approval-Reference": "VG_AUTH_fake_operator_forgedsig123"
        }, {}
    )
    assert d.status_code == 403
    assert d.error_code == "FORGED_APPROVAL_REFERENCE"
    assert d.check_failed == "Anti-Header Forgery"

if __name__ == "__main__":
    test_check_1_key_missing()
    test_check_2_key_known()
    test_check_3_vendor_mismatch()
    test_check_4_key_expired()
    test_check_5_scope_denied()
    test_check_6_source_ip_blocked()
    test_check_7_payload_suspect()
    test_check_8_rate_limit_exceeded()
    test_anti_header_forgery()
    print("Identity check tests passed.")
