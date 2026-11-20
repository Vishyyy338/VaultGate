"""
VaultGate request evaluation pipeline and threat inspection engine.
"""
import ipaddress
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.keystore import KeyStore
from core.models import GateDecision, hash_key, verify_approval_reference

SUSPICIOUS_PATTERNS = [
    (r"(?i)(\bunion\b\s+(?:all\s+)?\bselect\b|\bselect\b.+?\bfrom\b.+?\bwhere\b|'\s*or\s*['\d\w]+\s*=\s*['\d\w]+|\bor\s+['\d\w]+\s*=\s*['\d\w]+|--|/\*.*?\*/|;\s*drop\s+table|;\s*delete\s+from|;\s*update\s+\w+\s+set|;\s*insert\s+into)", "SQL Injection detected"),
    (r"(?i)(\bwaitfor\s+delay\b|\bbenchmark\s*\(\s*\d+|\bsleep\s*\(\s*\d+\s*\)|\bextractvalue\s*\(|\bupdatexml\s*\(|\binformation_schema\b|\bsys\.tables\b|\bpg_catalog\b)", "Blind SQL Injection / Database Enumeration detected"),
    (r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|%252e%252e%252f|\.\.%2f|\.\.%5c)", "Path Traversal / Directory Escape detected"),
    (r"(?i)(vendor_keys\.json|\.sig\b|\.env\b|/database/|\\database\\|/etc/passwd|/proc/self|/var/log|web\.config)", "Direct Database / Critical Config Access Probing detected"),
    (r"([;&|`$]\s*(?:cat|ls|rm|wget|curl|bash|sh|powershell|cmd|powershell\.exe|cmd\.exe|whoami|id|uname)\b|\$\(.*?\)|`.*?`)", "Command Injection / RCE attempt detected"),
    (r"(?i)(<script\b[^>]*>|javascript:\s*|\bonerror\s*=|\bonload\s*=|\beval\s*\(|\balert\s*\()", "Script Injection / XSS detected"),
    (r"(?i)(\$where|\$ne|\$regex|\$gt|\$gte|\$in|\$nin|\$lookup)", "NoSQL Injection detected"),
    (r"(?i)(<!ENTITY\b|SYSTEM\s+[\"']file:|ldap://|\bobjectClass\s*=)", "XML/LDAP/Entity Injection detected"),
    (r"(?i)(select\s+\*?\s*from\s+credentials|select\s+\*?\s*from\s+admin_keys|select\s+\*?\s*from\s+vendor_keys)", "Database Exfiltration Probe detected")
]

GATEWAY_SENSITIVE_ACTIONS = {"suppliers:payout_update", "payments:execute"}
DEFAULT_RATE_LIMIT = 60

class VaultGateScanner:
    def __init__(self, keystore: KeyStore, default_rate_limit: int = DEFAULT_RATE_LIMIT):
        self.keystore = keystore
        self.default_rate_limit = default_rate_limit
        self.rate_history: Dict[str, List[float]] = defaultdict(list)
        self.held_actions: Dict[str, Dict[str, Any]] = {}
        self.enforcement_mode: str = "automatic"

    def extract_api_key(self, headers: Dict[str, str], query_params: Dict[str, str]) -> Optional[str]:
        for h, v in headers.items():
            if h.lower() == "x-api-key":
                return v.strip()
        for h, v in headers.items():
            if h.lower() == "authorization":
                parts = v.strip().split(" ")
                if len(parts) == 2 and parts[0].lower() in ["bearer", "apikey", "key"]:
                    return parts[1].strip()
                return v.strip()
        for q, v in query_params.items():
            if q.lower() in ["api_key", "apikey", "key"]:
                return v.strip()
        return None

    def determine_required_scope(self, method: str, path: str) -> str:
        method = method.upper()
        p = path.lower()
        
        if "payout-config" in p or "settings" in p or "config" in p:
            if method in ["POST", "PUT", "PATCH"]:
                return "suppliers:payout_update"
            return "suppliers:read"
            
        if "payment" in p:
            if method in ["POST", "PUT"]:
                return "payments:execute"
            return "payments:read"
            
        if "supplier" in p:
            if method in ["POST", "PUT", "PATCH", "DELETE"]:
                return "suppliers:write"
            return "suppliers:read"
            
        if "record" in p:
            if "export" in p or method in ["POST", "PUT", "PATCH", "DELETE"]:
                return "records:export"
            return "records:read"

        if "ticket" in p:
            if method in ["POST", "PUT", "PATCH", "DELETE"]:
                return "tickets:write"
            return "tickets:read"

        parts = [seg for seg in p.split("/") if seg and seg != "api"]
        if parts:
            resource = parts[0]
            action = "write" if method in ["POST", "PUT", "PATCH", "DELETE"] else "read"
            return f"{resource}:{action}"

        if method == "GET":
            return "general:read"
        return "general:write"

    def is_ip_allowed(self, client_ip: str, allowed_ips: List[str]) -> bool:
        if not allowed_ips:
            return True

        if client_ip.startswith("::ffff:"):
            client_ip = client_ip.replace("::ffff:", "")

        try:
            c_ip = ipaddress.ip_address(client_ip)
        except ValueError:
            return False

        for rule in allowed_ips:
            rule = rule.strip()
            try:
                if "/" in rule:
                    net = ipaddress.ip_network(rule, strict=False)
                    if c_ip in net:
                        return True
                else:
                    if c_ip == ipaddress.ip_address(rule):
                        return True
            except ValueError:
                continue

        return False

    def scan_payload(self, text_to_scan: str) -> Optional[str]:
        for pattern, desc in SUSPICIOUS_PATTERNS:
            if re.search(pattern, text_to_scan):
                return desc
        return None

    def check_rate_limit(self, key_hash: str, max_per_min: Optional[int] = None) -> bool:
        limit = max_per_min or self.default_rate_limit
        now = time.time()
        window_start = now - 60.0
        self.rate_history[key_hash] = [t for t in self.rate_history[key_hash] if t > window_start]
        if len(self.rate_history[key_hash]) >= limit:
            return False
        self.rate_history[key_hash].append(now)
        return True

    def evaluate_request(
        self,
        method: str,
        path: str,
        client_ip: str,
        headers: Dict[str, str],
        query_params: Dict[str, str],
        body_text: str = ""
    ) -> GateDecision:
        checks_log: List[Dict[str, Any]] = []

        # Anti-forgery validation for internal clearance headers
        for h, v in headers.items():
            if h.lower() == "x-approval-reference":
                if not verify_approval_reference(v.strip()):
                    checks_log.append({"check": "Anti-Header Forgery", "status": "FAIL", "code": "FORGED_APPROVAL_REFERENCE"})
                    return GateDecision(
                        allowed=False,
                        status_code=403,
                        error_code="FORGED_APPROVAL_REFERENCE",
                        message="Security Violation: Forged X-Approval-Reference header detected. Approval references must be HMAC-signed by VaultGate.",
                        check_failed="Anti-Header Forgery",
                        checks_evaluated=checks_log
                    )

        # 1. Key presence check
        raw_key = self.extract_api_key(headers, query_params)
        if not raw_key:
            checks_log.append({"check": "Key present", "status": "FAIL", "code": "KEY_MISSING"})
            return GateDecision(
                allowed=False,
                status_code=401,
                error_code="KEY_MISSING",
                message="No API key sent. Include 'X-API-Key' header or 'Authorization: ApiKey <key>'.",
                check_failed="Key present",
                checks_evaluated=checks_log
            )
        checks_log.append({"check": "Key present", "status": "PASS"})

        inputted_hash = hash_key(raw_key)

        # 2. Key identity verification
        contract = self.keystore.get_by_hash(inputted_hash)
        if not contract or not contract.is_active:
            checks_log.append({"check": "Key known", "status": "FAIL", "code": "KEY_UNKNOWN"})
            return GateDecision(
                allowed=False,
                status_code=401,
                error_code="KEY_UNKNOWN",
                message="Key not recognized in authorized database vendor store (SHA-256 hash mismatch).",
                check_failed="Key known",
                checks_evaluated=checks_log
            )
        checks_log.append({
            "check": "Key known", 
            "status": "PASS", 
            "key_hash": inputted_hash[:12] + "..."
        })

        # 3. Vendor match validation
        claimed_vendor = None
        for h, v in headers.items():
            if h.lower() in ["x-vendor-id", "x-vendor", "vendor-id"]:
                claimed_vendor = v.strip()
                break

        if claimed_vendor and claimed_vendor.lower() != contract.vendor_id.lower():
            checks_log.append({"check": "Vendor matches", "status": "FAIL", "code": "VENDOR_MISMATCH"})
            return GateDecision(
                allowed=False,
                status_code=403,
                error_code="VENDOR_MISMATCH",
                message=f"Key belongs to vendor '{contract.vendor_id}', but request claimed vendor '{claimed_vendor}'.",
                check_failed="Vendor matches",
                contract=contract,
                checks_evaluated=checks_log
            )
        checks_log.append({"check": "Vendor matches", "status": "PASS"})

        # 4. Expiration check
        if not contract.expires_at:
            checks_log.append({"check": "Not expired", "status": "FAIL", "code": "KEY_EXPIRED"})
            return GateDecision(
                allowed=False,
                status_code=401,
                error_code="KEY_EXPIRED",
                message="Security Policy Violation: Every API key must have an expiry limit. Key lacks expiration date.",
                check_failed="Not expired",
                contract=contract,
                checks_evaluated=checks_log
            )
        try:
            exp_clean = contract.expires_at.replace("Z", "+00:00")
            exp_dt = datetime.fromisoformat(exp_clean)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            now_dt = datetime.now(timezone.utc)
            if now_dt > exp_dt:
                checks_log.append({"check": "Not expired", "status": "FAIL", "code": "KEY_EXPIRED"})
                return GateDecision(
                    allowed=False,
                    status_code=401,
                    error_code="KEY_EXPIRED",
                    message=f"API key expired on {contract.expires_at}.",
                    check_failed="Not expired",
                    contract=contract,
                    checks_evaluated=checks_log
                )
        except Exception:
            checks_log.append({"check": "Not expired", "status": "FAIL", "code": "KEY_EXPIRED"})
            return GateDecision(
                allowed=False,
                status_code=401,
                error_code="KEY_EXPIRED",
                message=f"Invalid expiration timestamp format: {contract.expires_at}.",
                check_failed="Not expired",
                contract=contract,
                checks_evaluated=checks_log
            )
        checks_log.append({"check": "Not expired", "status": "PASS"})

        # 5. Permission scope check
        required_scope = self.determine_required_scope(method, path)
        has_scope = False
        if "*" in contract.scopes:
            has_scope = True
        else:
            for s in contract.scopes:
                if s == required_scope:
                    has_scope = True
                    break
                if s.endswith(":*") and required_scope.startswith(s[:-2]):
                    has_scope = True
                    break
                if s in ["general:read", "read"] and method in ["GET", "HEAD", "OPTIONS"]:
                    has_scope = True
                    break
                if s in ["general:write", "write"] and method in ["POST", "PUT", "PATCH", "DELETE"]:
                    has_scope = True
                    break

        if not has_scope:
            checks_log.append({"check": "Scope allowed", "status": "FAIL", "code": "SCOPE_DENIED"})
            return GateDecision(
                allowed=False,
                status_code=403,
                error_code="SCOPE_DENIED",
                message=f"Scope '{required_scope}' denied. Key only holds: {contract.scopes}.",
                check_failed="Scope allowed",
                contract=contract,
                checks_evaluated=checks_log
            )
        checks_log.append({"check": "Scope allowed", "status": "PASS", "scope": required_scope})

        # 6. Source IP network check
        effective_ip = client_ip
        for h, v in headers.items():
            if h.lower() == "x-forwarded-for":
                effective_ip = v.split(",")[0].strip()
                break

        if not self.is_ip_allowed(effective_ip, contract.allowed_ips):
            checks_log.append({"check": "Source IP", "status": "FAIL", "code": "IP_BLOCKED"})
            return GateDecision(
                allowed=False,
                status_code=403,
                error_code="IP_BLOCKED",
                message=f"Client IP '{effective_ip}' is not in approved address list for this key contract.",
                check_failed="Source IP",
                contract=contract,
                checks_evaluated=checks_log
            )
        checks_log.append({"check": "Source IP", "status": "PASS", "ip": effective_ip})

        # 7. Payload and pattern inspection
        combined_payload = f"{path}\n" + "\n".join(f"{k}={v}" for k, v in query_params.items()) + f"\n{body_text}"
        threat = self.scan_payload(combined_payload)
        if threat:
            checks_log.append({"check": "Payload clean", "status": "FAIL", "code": "PAYLOAD_SUSPECT", "threat": threat})
            return GateDecision(
                allowed=False,
                status_code=400,
                error_code="PAYLOAD_SUSPECT",
                message=f"Suspicious payload pattern detected: {threat}.",
                check_failed="Payload clean",
                contract=contract,
                checks_evaluated=checks_log
            )
        checks_log.append({"check": "Payload clean", "status": "PASS"})

        # 8. Sliding window rate check
        if not self.check_rate_limit(inputted_hash, self.default_rate_limit):
            checks_log.append({"check": "Rate normal", "status": "FAIL", "code": "RATE_LIMIT"})
            return GateDecision(
                allowed=False,
                status_code=429,
                error_code="RATE_LIMIT",
                message=f"Rate limit exceeded: {self.default_rate_limit} requests/min allowed.",
                check_failed="Rate normal",
                contract=contract,
                checks_evaluated=checks_log
            )
        checks_log.append({"check": "Rate normal", "status": "PASS"})

        # Sensitive operation hold verification
        is_sensitive = required_scope in GATEWAY_SENSITIVE_ACTIONS
        has_verified_approval = any(
            h.lower() == "x-approval-reference" and verify_approval_reference(v.strip())
            for h, v in headers.items()
        )

        if is_sensitive and not has_verified_approval:
            import uuid
            hold_id = f"hold_{uuid.uuid4().hex[:8]}"
            checks_log.append({
                "check": "Sensitive-Action Hold", 
                "status": "HELD", 
                "hold_id": hold_id,
                "reason": f"Sensitive operation '{required_scope}' requires human finance approval."
            })
            return GateDecision(
                allowed=False,
                is_held=True,
                hold_id=hold_id,
                status_code=202,
                error_code="ACTION_HELD_FOR_APPROVAL",
                message="Sensitive operation intercepted: held for mandatory human review/approval.",
                check_failed=None,
                contract=contract,
                checks_evaluated=checks_log
            )

        # Supervised mode hold verification
        if self.enforcement_mode == "manual" and not has_verified_approval:
            import uuid
            hold_id = f"airgap_{uuid.uuid4().hex[:8]}"
            checks_log.append({
                "check": "Manual Air-Gap Supervision", 
                "status": "HELD", 
                "hold_id": hold_id,
                "reason": "Gateway running in Manual Supervised Mode. Awaiting operator clearance in UI."
            })
            return GateDecision(
                allowed=False,
                is_held=True,
                hold_id=hold_id,
                status_code=202,
                error_code="PENDING_MANUAL_CLEARANCE",
                message="Manual Air-Gap Supervision: Request verified and held awaiting operator authorization in console.",
                check_failed=None,
                contract=contract,
                checks_evaluated=checks_log
            )

        return GateDecision(
            allowed=True,
            status_code=200,
            contract=contract,
            checks_evaluated=checks_log
        )
