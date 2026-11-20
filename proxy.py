"""
VaultGate reverse proxy implementation with operator access controls.
"""
import asyncio
import hmac
import os
import time
from typing import Any, Dict, Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from core.audit import AuditManager
from core.keystore import KeyStore
from core.models import AuditLogEntry, HeldAction, KeyContract, sign_approval_reference
from core.scanner import VaultGateScanner

UPSTREAM_URL = os.environ.get("VAULTGATE_UPSTREAM_URL", "http://127.0.0.1:8000")
KEYSTORE_PATH = os.environ.get("VAULTGATE_KEYSTORE_PATH", os.path.join("database", "vendor_keys.json"))
ADMIN_KEY = os.environ.get("VAULTGATE_ADMIN_KEY", "vg_admin_sec_2026_defense")

keystore = KeyStore(filepath=KEYSTORE_PATH)
scanner = VaultGateScanner(keystore=keystore)
audit_mgr = AuditManager(log_dir="logs", rotation_minutes=30)

pending_signals: Dict[str, asyncio.Event] = {}
pending_verdicts: Dict[str, Dict[str, Any]] = {}

app = FastAPI(
    title="VaultGate Security Proxy",
    description="Reverse proxy gateway with operator clearance controls.",
    version="1.0.0"
)


def verify_admin_key(request: Request) -> bool:
    key = request.headers.get("x-admin-key")
    if not key:
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("ApiKey "):
            key = auth_header.split(" ", 1)[1].strip()
        elif auth_header.startswith("Bearer "):
            key = auth_header.split(" ", 1)[1].strip()
    if not key:
        key = request.cookies.get("vg_admin_key")
    if not key:
        return False
    current_admin_key = os.environ.get("VAULTGATE_ADMIN_KEY", ADMIN_KEY)
    return hmac.compare_digest(key.strip(), current_admin_key.strip())


def require_admin(request: Request):
    if not verify_admin_key(request):
        raise HTTPException(
            status_code=401,
            detail="Operator authorization required. Provide valid X-Admin-Key."
        )


class AuthCheckPayload(BaseModel):
    admin_key: str


@app.post("/vaultgate/api/auth/verify")
def verify_operator_auth(payload: AuthCheckPayload):
    if hmac.compare_digest(payload.admin_key.strip(), ADMIN_KEY.strip()):
        return {"authenticated": True, "message": "Operator clearance authorized."}
    raise HTTPException(status_code=401, detail="Invalid Operator API Key.")


@app.get("/vaultgate/console", response_class=HTMLResponse)
async def get_console():
    index_path = os.path.join("templates", "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>VaultGate Console (templates/index.html not found)</h1>")


class ModeUpdatePayload(BaseModel):
    mode: str


@app.get("/vaultgate/api/mode", dependencies=[Depends(require_admin)])
def get_enforcement_mode():
    return {
        "mode": scanner.enforcement_mode,
        "description": "Autonomous Gate (Auto-Forward)" if scanner.enforcement_mode == "automatic" else "Supervised Air-Gap (Manual Release)"
    }


@app.post("/vaultgate/api/mode", dependencies=[Depends(require_admin)])
def set_enforcement_mode(payload: ModeUpdatePayload):
    if payload.mode in ["automatic", "manual"]:
        scanner.enforcement_mode = payload.mode
        return {
            "status": "MODE_SWITCHED",
            "mode": scanner.enforcement_mode,
            "description": "Autonomous Gate (Auto-Forward)" if scanner.enforcement_mode == "automatic" else "Supervised Air-Gap (Manual Release)"
        }
    raise HTTPException(status_code=400, detail="Mode must be 'automatic' or 'manual'")


@app.get("/vaultgate/api/posture", dependencies=[Depends(require_admin)])
def get_key_posture():
    return keystore.get_posture_report()


@app.get("/vaultgate/api/keys", dependencies=[Depends(require_admin)])
def list_keys():
    return [c.model_dump() for c in keystore.list_all()]


@app.post("/vaultgate/api/keys", dependencies=[Depends(require_admin)])
def create_or_update_key(contract: KeyContract, dependencies=[Depends(require_admin)]):
    keystore.add_or_update(contract)
    return {"status": "SUCCESS", "contract": contract.model_dump()}


@app.delete("/vaultgate/api/keys/{key_hash}", dependencies=[Depends(require_admin)])
def delete_key(key_hash: str):
    success = keystore.delete(key_hash)
    if not success:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"status": "REVOKED"}


@app.get("/vaultgate/api/audit", dependencies=[Depends(require_admin)])
def get_audit_logs(limit: int = 60):
    recent = [e.model_dump() for e in audit_mgr.get_recent(limit=limit)]
    stats = audit_mgr.get_statistics()
    return {
        "statistics": stats,
        "logs": recent,
        "enforcement_mode": scanner.enforcement_mode
    }


@app.get("/vaultgate/api/holds", dependencies=[Depends(require_admin)])
def get_held_actions(status: Optional[str] = None):
    return [h.model_dump() for h in audit_mgr.get_held_actions(status_filter=status)]


class HoldResolvePayload(BaseModel):
    approved: bool
    reviewer: str = "security-operator"


@app.post("/vaultgate/api/holds/{hold_id}/resolve", dependencies=[Depends(require_admin)])
async def resolve_hold(hold_id: str, payload: HoldResolvePayload):
    action = audit_mgr.resolve_held_action(hold_id, payload.approved, payload.reviewer)
    if not action:
        raise HTTPException(status_code=404, detail="Record not found in hold registry")

    if hold_id in pending_signals:
        pending_verdicts[hold_id] = {
            "approved": payload.approved,
            "reviewer": payload.reviewer
        }
        pending_signals[hold_id].set()
        return {
            "status": action.status,
            "hold_id": hold_id,
            "reviewed_by": payload.reviewer,
            "reviewed_at": action.reviewed_at,
            "message": "Hold resolved and forwarded upstream."
        }

    dispatch_result = None
    if payload.approved:
        headers = dict(action.headers)
        headers["x-approval-reference"] = sign_approval_reference(hold_id, payload.reviewer)
        target_url = f"{UPSTREAM_URL}{action.path}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.request(
                    method=action.method,
                    url=target_url,
                    headers=headers,
                    content=action.body.encode("utf-8")
                )
                try:
                    upstream_json = res.json()
                except Exception:
                    upstream_json = res.text

                dispatch_result = {
                    "upstream_status": res.status_code,
                    "upstream_body": upstream_json
                }
        except Exception as e:
            dispatch_result = {"error": f"Failed to forward to upstream: {str(e)}"}

    return {
        "status": action.status,
        "hold_id": hold_id,
        "reviewed_by": action.reviewed_by,
        "reviewed_at": action.reviewed_at,
        "dispatch_result": dispatch_result
    }


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def reverse_proxy_gateway(request: Request, path: str):
    start_time = time.time()
    formatted_path = "/" + path
    if formatted_path == "/favicon.ico":
        return Response(status_code=204)
    method = request.method
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    headers_dict = dict(request.headers)
    query_params_dict = dict(request.query_params)
    
    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="replace")

    decision = scanner.evaluate_request(
        method=method,
        path=formatted_path,
        client_ip=client_ip,
        headers=headers_dict,
        query_params=query_params_dict,
        body_text=body_text
    )

    duration_ms = round((time.time() - start_time) * 1000, 2)
    key_hash = (decision.contract.hashed_api_key[:12] + "...") if decision.contract else None
    vendor_id = decision.contract.vendor_id if decision.contract else None

    if decision.is_held:
        hold_id = decision.hold_id or "hold_unknown"
        held_action = HeldAction(
            id=hold_id,
            vendor_id=vendor_id or "unknown",
            key_hash=key_hash or "none",
            client_ip=client_ip,
            method=method,
            path=formatted_path,
            headers=headers_dict,
            body=body_text,
            scope_matched=decision.checks_evaluated[-1].get("reason", decision.error_code or "held")
        )
        audit_mgr.register_held_action(held_action)

        audit_mgr.log_entry(AuditLogEntry(
            client_ip=client_ip,
            method=method,
            path=formatted_path,
            vendor_id=vendor_id,
            key_hash=key_hash,
            allowed=False,
            is_held=True,
            status_code=202,
            error_code=decision.error_code,
            message=decision.message,
            duration_ms=duration_ms,
            payload_snippet=body_text[:120] if body_text else None
        ))

        sig = asyncio.Event()
        pending_signals[hold_id] = sig

        try:
            await asyncio.wait_for(sig.wait(), timeout=180.0)
        except asyncio.TimeoutError:
            pending_signals.pop(hold_id, None)
            pending_verdicts.pop(hold_id, None)
            return JSONResponse(
                status_code=408,
                content={
                    "vaultgate_verdict": "HOLD_TIMEOUT",
                    "status_code": 408,
                    "error_code": "OPERATOR_CLEARANCE_TIMEOUT",
                    "message": "Operator clearance timed out after 180 seconds."
                }
            )

        verdict_data = pending_verdicts.pop(hold_id, {"approved": False, "reviewer": "operator"})
        pending_signals.pop(hold_id, None)

        if not verdict_data.get("approved"):
            return JSONResponse(
                status_code=403,
                content={
                    "vaultgate_verdict": "REJECTED_BY_OPERATOR",
                    "status_code": 403,
                    "error_code": "OPERATOR_DENIED",
                    "message": f"Request rejected by {verdict_data.get('reviewer', 'operator')} in clearance desk."
                }
            )

        target_url = f"{UPSTREAM_URL}{formatted_path}"
        if request.url.query:
            target_url += f"?{request.url.query}"

        forward_headers = {
            k: v for k, v in headers_dict.items()
            if k.lower() not in ["host", "content-length", "transfer-encoding", "connection"]
        }
        forward_headers["X-VaultGate-Verified"] = "true"
        forward_headers["X-VaultGate-Vendor"] = vendor_id or "authorized"
        forward_headers["X-Approval-Reference"] = sign_approval_reference(hold_id, verdict_data.get('reviewer', 'operator'))

        async with httpx.AsyncClient(timeout=15.0) as client:
            upstream_resp = await client.request(
                method=method,
                url=target_url,
                headers=forward_headers,
                content=body_bytes
            )

        duration_ms = round((time.time() - start_time) * 1000, 2)
        audit_mgr.log_entry(AuditLogEntry(
            client_ip=client_ip,
            method=method,
            path=formatted_path,
            vendor_id=vendor_id,
            key_hash=key_hash,
            allowed=True,
            is_held=False,
            status_code=upstream_resp.status_code,
            duration_ms=duration_ms,
            payload_snippet=body_text[:120] if body_text else None
        ))

        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers={k: v for k, v in upstream_resp.headers.items() if k.lower() not in ["content-encoding", "transfer-encoding"]}
        )

    if not decision.allowed:
        audit_mgr.log_entry(AuditLogEntry(
            client_ip=client_ip,
            method=method,
            path=formatted_path,
            vendor_id=vendor_id,
            key_hash=key_hash,
            allowed=False,
            is_held=False,
            status_code=decision.status_code,
            error_code=decision.error_code,
            message=decision.message,
            duration_ms=duration_ms,
            payload_snippet=body_text[:120] if body_text else None
        ))

        return JSONResponse(
            status_code=decision.status_code,
            content={
                "vaultgate_verdict": "BLOCKED",
                "status_code": decision.status_code,
                "error_code": decision.error_code,
                "check_failed": decision.check_failed,
                "message": decision.message,
                "checks_evaluated": decision.checks_evaluated
            }
        )

    target_url = f"{UPSTREAM_URL}{formatted_path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    forward_headers = {
        k: v for k, v in headers_dict.items()
        if k.lower() not in ["host", "content-length", "transfer-encoding", "connection"]
    }
    forward_headers["X-VaultGate-Verified"] = "true"
    forward_headers["X-VaultGate-Vendor"] = vendor_id or "authorized"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            upstream_resp = await client.request(
                method=method,
                url=target_url,
                headers=forward_headers,
                content=body_bytes
            )

        duration_ms = round((time.time() - start_time) * 1000, 2)
        
        audit_mgr.log_entry(AuditLogEntry(
            client_ip=client_ip,
            method=method,
            path=formatted_path,
            vendor_id=vendor_id,
            key_hash=key_hash,
            allowed=True,
            is_held=False,
            status_code=upstream_resp.status_code,
            duration_ms=duration_ms,
            payload_snippet=body_text[:120] if body_text else None
        ))

        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers={k: v for k, v in upstream_resp.headers.items() if k.lower() not in ["content-encoding", "transfer-encoding"]}
        )

    except httpx.ConnectError:
        return JSONResponse(
            status_code=502,
            content={
                "vaultgate_verdict": "ALLOWED_BUT_UPSTREAM_UNREACHABLE",
                "status_code": 502,
                "message": f"VaultGate checks passed, but the target server at {UPSTREAM_URL} is offline or unreachable."
            }
        )
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={
                "vaultgate_verdict": "PROXY_ERROR",
                "status_code": 500,
                "error": str(exc)
            }
        )
