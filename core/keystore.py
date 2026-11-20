"""
Keystore for vendor identity contracts and integrity verification.
"""
import hashlib
import hmac
import json
import os
from typing import Any, Dict, List, Optional

from core.models import GATEWAY_SECRET_PEPPER, KeyContract, hash_key

DEFAULT_DB_PATH = os.path.join("database", "vendor_keys.json")


class KeyStore:
    def __init__(self, filepath: Optional[str] = None):
        self.filepath = filepath or DEFAULT_DB_PATH
        self.sig_path = self.filepath + ".sig"
        self.contracts: Dict[str, KeyContract] = {}
        if os.path.exists(self.filepath):
            self.load()
        else:
            self._seed_default_keys()
            self.save()

    def _compute_db_signature(self, raw_bytes: bytes) -> str:
        return hmac.new(GATEWAY_SECRET_PEPPER.encode("utf-8"), raw_bytes, hashlib.sha256).hexdigest()

    def _seed_default_keys(self):
        raw_seeds = [
            ("vg_live_key_tb_07_c91a", "tallybridge", "TallyBridge Connect (LedgerOne ERP)", ["invoices:read", "shipments:read"], ["10.20.4.0/24", "127.0.0.1"], "2027-06-12T00:00:00"),
            ("vg_live_shipping_swift_a18b2c", "swift-carrier", "Swift Global Freight (Customer Portal)", ["suppliers:read", "shipments:read", "shipments:write", "invoices:read"], ["192.168.1.0/24", "10.0.0.0/16", "127.0.0.1", "172.16.0.0/16"], "2027-12-31T23:59:59"),
            ("vg_live_key_tb_03_legacy", "tallybridge", "TallyBridge Connect (Legacy Unreviewed)", ["invoices:read"], ["10.20.4.0/24", "127.0.0.1"], "2026-01-01T00:00:00"),
            ("vg_live_key_bk_02_backup", "internal-backup", "Nightly Backup Agent", ["records:read", "backup:read"], ["172.16.0.0/16", "127.0.0.1"], "2027-02-01T00:00:00"),
            ("vg_live_tb_sync_svc_44b", "tallybridge", "TallyBridge HelpDeskr Sync Service", ["tickets:read"], ["10.20.4.0/24", "127.0.0.1"], "2027-06-12T00:00:00"),
            ("vg_live_key_app_12_payments", "finance-console", "Internal Payments Console", ["payments:read", "payments:write", "suppliers:payout_update"], ["172.16.8.0/24", "127.0.0.1"], "2027-10-17T00:00:00"),
            ("vg_live_key_rpt_03_reports", "reporting-service", "Executive BI & Reporting Service", ["invoices:read", "shipments:read", "reports:read"], ["172.16.9.0/24", "127.0.0.1"], "2027-06-30T23:59:59"),
            ("vg_live_bvk_7f3a_bluevault", "bluevault-partner", "BlueVault Document Portal", ["documents:read", "manifests:read"], ["172.16.0.0/16", "127.0.0.1"], "2027-02-18T00:00:00")
        ]

        for raw_key, vendor_id, vendor_name, scopes, allowed_ips, expires_at in raw_seeds:
            h = hash_key(raw_key)
            contract = KeyContract(
                vendor_name=vendor_name,
                vendor_id=vendor_id,
                hashed_api_key=h,
                description=f"Identity contract for {vendor_name}",
                scopes=scopes,
                allowed_ips=allowed_ips,
                expires_at=expires_at
            )
            self.contracts[h] = contract

    def load(self):
        if not os.path.exists(self.filepath):
            return
        with open(self.filepath, "rb") as f:
            raw_bytes = f.read()

        if os.path.exists(self.sig_path):
            with open(self.sig_path, "r", encoding="utf-8") as sf:
                stored_sig = sf.read().strip()
            current_sig = self._compute_db_signature(raw_bytes)
            if not hmac.compare_digest(stored_sig, current_sig):
                print("Warning: database integrity verification failed.")

        data = json.loads(raw_bytes.decode("utf-8"))
        self.contracts = {item["hashed_api_key"]: KeyContract(**item) for item in data}

    def save(self):
        os.makedirs(os.path.dirname(self.filepath) or ".", exist_ok=True)
        dump_bytes = json.dumps([c.model_dump() for c in self.contracts.values()], indent=2).encode("utf-8")
        with open(self.filepath, "wb") as f:
            f.write(dump_bytes)
        
        sig = self._compute_db_signature(dump_bytes)
        with open(self.sig_path, "w", encoding="utf-8") as sf:
            sf.write(sig)

    def get_by_hash(self, key_hash: str) -> Optional[KeyContract]:
        for stored_hash, contract in self.contracts.items():
            if hmac.compare_digest(stored_hash, key_hash):
                return contract
        return None

    def add_or_update(self, contract: KeyContract):
        self.contracts[contract.hashed_api_key] = contract
        self.save()

    def delete(self, key_hash: str) -> bool:
        if key_hash in self.contracts:
            del self.contracts[key_hash]
            self.save()
            return True
        return False

    def list_all(self) -> List[KeyContract]:
        return list(self.contracts.values())

    def get_posture_report(self) -> Dict[str, Any]:
        total = len(self.contracts)
        no_expiry_and_no_ip = 0
        has_wildcard = 0
        vulnerable_keys = []

        for c in self.contracts.values():
            warnings = c.get_posture_warnings()
            has_no_ip = not c.allowed_ips or len(c.allowed_ips) == 0
            has_no_expiry = c.expires_at is None
            
            if has_no_ip and has_no_expiry:
                no_expiry_and_no_ip += 1
                vulnerable_keys.append({
                    "key_hash": c.hashed_api_key[:12] + "...",
                    "vendor_id": c.vendor_id,
                    "vendor_name": c.vendor_name,
                    "warnings": warnings
                })
            elif warnings:
                vulnerable_keys.append({
                    "key_hash": c.hashed_api_key[:12] + "...",
                    "vendor_id": c.vendor_id,
                    "vendor_name": c.vendor_name,
                    "warnings": warnings
                })

            if "*" in c.scopes:
                has_wildcard += 1

        return {
            "total_keys": total,
            "no_expiry_and_no_ip_count": no_expiry_and_no_ip,
            "wildcard_keys_count": has_wildcard,
            "posture_score": max(0, int(100 - (no_expiry_and_no_ip / max(total, 1) * 80) - (has_wildcard * 10))),
            "vulnerable_keys": vulnerable_keys
        }
