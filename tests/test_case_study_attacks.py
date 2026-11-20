"""
Integration tests for incident attack scenario vectors.
"""
from core.keystore import KeyStore
from core.scanner import VaultGateScanner

ks = KeyStore()
scanner = VaultGateScanner(ks)

def test_attack_step_1_unauthorized_record_export():
    d = scanner.evaluate_request(
        "GET", "/api/records/export", "198.18.7.41",
        {"X-API-Key": "vg_live_key_tb_07_c91a", "X-Vendor-ID": "tallybridge"}, {}
    )
    assert d.allowed is False
    assert d.status_code == 403
    assert d.error_code == "SCOPE_DENIED"

    d_ip = scanner.evaluate_request(
        "GET", "/api/shipments", "198.18.7.41",
        {"X-API-Key": "vg_live_key_tb_07_c91a", "X-Vendor-ID": "tallybridge"}, {}
    )
    assert d_ip.allowed is False
    assert d_ip.status_code == 403
    assert d_ip.error_code == "IP_BLOCKED"

def test_attack_step_2_credential_hunting_in_tickets():
    d = scanner.evaluate_request(
        "GET", "/api/records/export", "127.0.0.1",
        {"X-API-Key": "vg_live_tb_sync_svc_44b", "X-Vendor-ID": "tallybridge"}, {}
    )
    assert d.allowed is False
    assert d.status_code == 403
    assert d.error_code == "SCOPE_DENIED"

def test_attack_step_3_unauthorized_payout_tampering():
    d_attacker = scanner.evaluate_request(
        "POST", "/api/suppliers/sup_001/payout-config", "10.20.4.77",
        {"X-API-Key": "vg_live_key_tb_07_c91a", "X-Vendor-ID": "tallybridge"}, {},
        body_text='{"contact_email": "attacker@darknet.io", "routing_code": "ROUTE_MALICIOUS"}'
    )
    assert d_attacker.allowed is False
    assert d_attacker.status_code == 403
    assert d_attacker.error_code == "SCOPE_DENIED"

    d_held = scanner.evaluate_request(
        "POST", "/api/suppliers/sup_001/payout-config", "172.16.8.50",
        {"X-API-Key": "vg_live_key_app_12_payments", "X-Vendor-ID": "finance-console"}, {},
        body_text='{"contact_email": "finance@coastal.com", "routing_code": "ROUTE_APAC_NORTH"}'
    )
    assert d_held.allowed is False
    assert d_held.is_held is True
    assert d_held.status_code == 202
    assert d_held.error_code == "ACTION_HELD_FOR_APPROVAL"

if __name__ == "__main__":
    test_attack_step_1_unauthorized_record_export()
    test_attack_step_2_credential_hunting_in_tickets()
    test_attack_step_3_unauthorized_payout_tampering()
    print("Attack scenario tests passed.")
