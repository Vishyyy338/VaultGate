"""
Data models for key contracts, decisions, and audit entries.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid
import hashlib
import hmac
import os

GATEWAY_SECRET_PEPPER = os.environ.get("VAULTGATE_SECRET_PEPPER", "vg_sec_pepper_7fa918b3e04c4f92a1d2e8b60389c72e")

def hash_key(raw_key: str) -> str:
    return hmac.new(
        GATEWAY_SECRET_PEPPER.encode("utf-8"),
        raw_key.strip().encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

def sign_approval_reference(hold_id: str, reviewer: str) -> str:
    payload = f"{hold_id}:{reviewer}"
    signature = hmac.new(
        GATEWAY_SECRET_PEPPER.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()[:16]
    return f"VG_AUTH_{hold_id}_{reviewer}_{signature}"

def verify_approval_reference(reference: str) -> bool:
    if not reference or not reference.startswith("VG_AUTH_"):
        return False
    parts = reference.split("_")
    if len(parts) < 4:
        return False
    provided_sig = parts[-1]
    reviewer = parts[-2]
    hold_id = "_".join(parts[2:-2])
    
    expected_ref = sign_approval_reference(hold_id, reviewer)
    expected_sig = expected_ref.split("_")[-1]
    return hmac.compare_digest(provided_sig, expected_sig)


class KeyContract(BaseModel):
    vendor_name: str = Field(..., description="Vendor company name")
    vendor_id: str = Field(..., description="Vendor identifier")
    hashed_api_key: str = Field(..., description="Cryptographic hash of the API key")
    description: str = ""
    scopes: List[str] = Field(default_factory=list, description="Allowed scopes")
    allowed_ips: List[str] = Field(default_factory=list, description="Allowed CIDRs/IPs")
    allowed_hosts: List[str] = Field(default_factory=list, description="Allowed Host headers")
    expires_at: str = Field(..., description="ISO expiration timestamp")
    is_active: bool = True
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def get_posture_warnings(self) -> List[str]:
        warnings = []
        has_write_scope = any("*" in s or "write" in s or "admin" in s or "update" in s for s in self.scopes)
        if has_write_scope:
            if not self.allowed_ips or len(self.allowed_ips) == 0:
                warnings.append("Key has write privileges but no IP limits configured.")
        if "*" in self.scopes:
            warnings.append("Key has wildcard '*' scope.")
        
        try:
            exp_clean = self.expires_at.replace("Z", "+00:00")
            exp_dt = datetime.fromisoformat(exp_clean)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp_dt:
                warnings.append(f"Key expired on {self.expires_at}.")
        except Exception:
            warnings.append(f"Invalid expiration timestamp format: {self.expires_at}.")
            
        return warnings


class GateDecision(BaseModel):
    allowed: bool
    status_code: int = 200
    error_code: Optional[str] = None
    message: Optional[str] = None
    check_failed: Optional[str] = None
    is_held: bool = False
    hold_id: Optional[str] = None
    contract: Optional[KeyContract] = None
    checks_evaluated: List[Dict[str, Any]] = Field(default_factory=list)


class AuditLogEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    client_ip: str
    method: str
    path: str
    vendor_id: Optional[str] = None
    key_hash: Optional[str] = None
    allowed: bool
    is_held: bool = False
    status_code: int
    error_code: Optional[str] = None
    message: Optional[str] = None
    duration_ms: float = 0.0
    payload_snippet: Optional[str] = None


class HeldAction(BaseModel):
    id: str = Field(default_factory=lambda: "hold_" + str(uuid.uuid4())[:8])
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    vendor_id: str
    key_hash: str = ""
    client_ip: str
    method: str
    path: str
    headers: Dict[str, str]
    body: str
    scope_matched: str
    status: str = "PENDING_APPROVAL"
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None
