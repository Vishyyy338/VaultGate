"""
Unit tests for payload inspection and threat defense.
"""
from core.keystore import KeyStore
from core.scanner import VaultGateScanner

ks = KeyStore()
scanner = VaultGateScanner(ks)
KEY = "vg_live_shipping_swift_a18b2c"
VENDOR = "swift-carrier"

def run_payload_test(name, path, query_dict, body_str=""):
    d = scanner.evaluate_request(
        "POST" if body_str else "GET",
        path,
        "127.0.0.1",
        {"X-API-Key": KEY, "X-Vendor-ID": VENDOR},
        query_dict,
        body_text=body_str
    )
    assert d.status_code == 400, f"[{name}] Expected 400, got {d.status_code}"
    assert d.error_code == "PAYLOAD_SUSPECT", f"[{name}] Expected PAYLOAD_SUSPECT, got {d.error_code}"

def test_sql_injections():
    run_payload_test("SQL Tautology", "/api/suppliers", {"filter": "1' OR '1'='1"})
    run_payload_test("SQL Union", "/api/suppliers", {"cat": "tech UNION SELECT credit_card FROM accounts--"})
    run_payload_test("SQL Waitfor", "/api/suppliers", {"id": "1; WAITFOR DELAY '0:0:5'--"})
    run_payload_test("MySQL Sleep", "/api/suppliers", {"user": "admin' AND SLEEP(5)--"})
    run_payload_test("SQL Drop Table", "/api/suppliers", {"cmd": "1; DROP TABLE vendor_keys"})
    run_payload_test("Schema enumeration", "/api/suppliers", {"q": "information_schema.tables"})

def test_nosql_injections():
    run_payload_test("NoSQL Where", "/api/shipments", {}, body_str='{"$where": "this.name.length > 0"}')
    run_payload_test("NoSQL Ne operator", "/api/shipments", {}, body_str='{"user": {"$ne": null}}')
    run_payload_test("NoSQL Regex", "/api/shipments", {}, body_str='{"email": {"$regex": "^admin.*"}}')

def test_path_traversal():
    run_payload_test("Path traversal unix", "/api/shipments", {"file": "../../../../etc/passwd"})
    run_payload_test("Path traversal windows", "/api/shipments", {"path": "..\\..\\..\\windows\\win.ini"})
    run_payload_test("Double-encoded traversal", "/api/shipments", {"file": "%252e%252e%252fetc/shadow"})

def test_database_probing():
    run_payload_test("Database JSON probe", "/api/shipments", {"download": "/database/vendor_keys.json"})
    run_payload_test("Database SIG probe", "/api/shipments", {"target": "vendor_keys.json.sig"})
    run_payload_test("Environment probe", "/api/shipments", {"env": ".env"})

def test_command_injection_and_rce():
    run_payload_test("Semicolon RCE", "/api/shipments", {"run": "status; cat /etc/passwd"})
    run_payload_test("Pipe RCE", "/api/shipments", {"input": "test | whoami"})
    run_payload_test("Subshell RCE", "/api/shipments", {"name": "$(whoami)"})
    run_payload_test("Backtick RCE", "/api/shipments", {"name": "`id`"})

def test_xss_and_xml():
    run_payload_test("XSS script", "/api/shipments", {"msg": "<script>alert(document.cookie)</script>"})
    run_payload_test("XSS onerror", "/api/shipments", {"avatar": "<img src=x onerror=alert(1)>"})
    run_payload_test("XXE Entity", "/api/shipments", {}, body_str='<!ENTITY xxe SYSTEM "file:///etc/passwd">')

if __name__ == "__main__":
    test_sql_injections()
    test_nosql_injections()
    test_path_traversal()
    test_database_probing()
    test_command_injection_and_rce()
    test_xss_and_xml()
    print("Payload defense tests passed.")
