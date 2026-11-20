"""
Test runner for VaultGate test suites.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests import test_eight_checks
from tests import test_payload_defenses
from tests import test_modes_and_holds
from tests import test_case_study_attacks

def run_all():
    print("Running Suite 1: Identity checks...")
    test_eight_checks.test_check_1_key_missing()
    test_eight_checks.test_check_2_key_unknown()
    test_eight_checks.test_check_3_vendor_mismatch()
    test_eight_checks.test_check_4_key_expired()
    test_eight_checks.test_check_5_scope_denied()
    test_eight_checks.test_check_6_source_ip_blocked()
    test_eight_checks.test_check_7_payload_suspect()
    test_eight_checks.test_check_8_rate_limit_exceeded()
    test_eight_checks.test_anti_header_forgery()
    print("  Suite 1 passed.")

    print("Running Suite 2: Threat and payload inspection...")
    test_payload_defenses.test_sql_injections()
    test_payload_defenses.test_nosql_injections()
    test_payload_defenses.test_path_traversal()
    test_payload_defenses.test_database_probing()
    test_payload_defenses.test_command_injection_and_rce()
    test_payload_defenses.test_xss_and_xml()
    print("  Suite 2 passed.")

    print("Running Suite 3: Operating modes and hold clearances...")
    test_modes_and_holds.test_automatic_mode_normal_request()
    test_modes_and_holds.test_sensitive_action_held_in_auto_mode()
    test_modes_and_holds.test_sensitive_action_with_valid_approval_signature()
    test_modes_and_holds.test_manual_mode_holds_all_requests()
    print("  Suite 3 passed.")

    print("Running Suite 4: Incident attack vectors...")
    test_case_study_attacks.test_attack_step_1_unauthorized_record_export()
    test_case_study_attacks.test_attack_step_2_credential_hunting_in_tickets()
    test_case_study_attacks.test_attack_step_3_unauthorized_payout_tampering()
    print("  Suite 4 passed.")

    print("\nAll tests passed successfully.")

if __name__ == "__main__":
    run_all()
