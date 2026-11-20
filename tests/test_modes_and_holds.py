"""
Unit tests for operating modes and clearance holds.
"""
from core.keystore import KeyStore
from core.models import sign_approval_reference
from core.scanner import VaultGateScanner

def test_automatic_mode_normal_request():
    ks = KeyStore()
    scanner = VaultGateScanner(ks)
    scanner.enforcement_mode = "automatic"
    
    d = scanner.evaluate_request(
        "GET", "/api/suppliers", "127.0.0.1",
        {"X-API-Key": "vg_live_shipping_swift_a18b2c", "X-Vendor-ID": "swift-carrier"}, {}
    )
    assert d.allowed is True
    assert d.is_held is False
    assert d.status_code == 200

def test_sensitive_action_held_in_auto_mode():
    ks = KeyStore()
    scanner = VaultGateScanner(ks)
    scanner.enforcement_mode = "automatic"
    
    d = scanner.evaluate_request(
        "POST", "/api/suppliers/sup_001/payout-config", "127.0.0.1",
        {"X-API-Key": "vg_live_key_app_12_payments", "X-Vendor-ID": "finance-console"}, {},
        body_text='{"contact_email": "ops@apex.com", "routing_code": "ROUTE_APAC_NORTH"}'
    )
    assert d.allowed is False
    assert d.is_held is True
    assert d.status_code == 202
    assert d.error_code == "ACTION_HELD_FOR_APPROVAL"
    assert d.hold_id is not None

def test_sensitive_action_with_valid_approval_signature():
    ks = KeyStore()
    scanner = VaultGateScanner(ks)
    scanner.enforcement_mode = "automatic"
    
    valid_sig = sign_approval_reference("hold_9921", "security-operator")
    
    d = scanner.evaluate_request(
        "POST", "/api/suppliers/sup_001/payout-config", "127.0.0.1",
        {
            "X-API-Key": "vg_live_key_app_12_payments",
            "X-Vendor-ID": "finance-console",
            "X-Approval-Reference": valid_sig
        }, {},
        body_text='{"contact_email": "ops@apex.com", "routing_code": "ROUTE_APAC_NORTH"}'
    )
    assert d.allowed is True
    assert d.is_held is False
    assert d.status_code == 200

def test_manual_mode_holds_all_requests():
    ks = KeyStore()
    scanner = VaultGateScanner(ks)
    scanner.enforcement_mode = "manual"
    
    d = scanner.evaluate_request(
        "GET", "/api/suppliers", "127.0.0.1",
        {"X-API-Key": "vg_live_shipping_swift_a18b2c", "X-Vendor-ID": "swift-carrier"}, {}
    )
    assert d.allowed is False
    assert d.is_held is True
    assert d.status_code == 202
    assert d.error_code == "PENDING_MANUAL_CLEARANCE"
    assert d.hold_id is not None

if __name__ == "__main__":
    test_automatic_mode_normal_request()
    test_sensitive_action_held_in_auto_mode()
    test_sensitive_action_with_valid_approval_signature()
    test_manual_mode_holds_all_requests()
    print("Operating mode and hold tests passed.")
