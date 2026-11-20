"""
Upstream backend service mock for integration testing and local proxy routing.
"""
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="Protected Backend Server", version="1.0.0")

SUPPLIERS = {
    "sup_001": {
        "id": "sup_001",
        "name": "Apex Component Sourcing",
        "contact_email": "procurement@apexcomponents.com",
        "routing_code": "ROUTE_APAC_NORTH",
        "service_tier": "PLATINUM",
        "last_updated": "2026-10-15T09:00:00Z"
    },
    "sup_002": {
        "id": "sup_002",
        "name": "Global Cargo Freight",
        "contact_email": "ops@globalcargofreight.net",
        "routing_code": "ROUTE_EMEA_CENTRAL",
        "service_tier": "GOLD",
        "last_updated": "2026-11-01T14:30:00Z"
    }
}

class SupplierConfigPayload(BaseModel):
    contact_email: str
    routing_code: str
    service_tier: str = "PLATINUM"

@app.get("/")
def root():
    return {
        "service": "Internal Core Server",
        "status": "ONLINE",
        "protected_by": "VaultGate"
    }

@app.get("/api/records/export")
def export_records(limit: int = 100):
    return {
        "export_status": "SUCCESS",
        "total_records_exported": limit,
        "records": [
            {"record_id": f"REC_{i:04d}", "customer": f"Client {i}", "balance": 4500 + i * 10}
            for i in range(1, min(limit + 1, 10))
        ]
    }

@app.get("/api/tickets/search")
def search_tickets(q: str = ""):
    return {
        "query": q,
        "results": [
            {"ticket_id": "TICK-402", "subject": "VPN Configuration details", "status": "CLOSED"},
            {"ticket_id": "TICK-891", "subject": "Supplier onboarding form", "status": "RESOLVED"}
        ]
    }

@app.get("/api/suppliers")
def get_suppliers():
    return {"suppliers": list(SUPPLIERS.values())}

@app.get("/api/suppliers/{supplier_id}")
def get_supplier_detail(supplier_id: str):
    if supplier_id not in SUPPLIERS:
        raise HTTPException(status_code=404, detail="Supplier not found")
    return SUPPLIERS[supplier_id]

@app.post("/api/suppliers/{supplier_id}/payout-config")
def update_supplier_config(supplier_id: str, payload: SupplierConfigPayload):
    if supplier_id not in SUPPLIERS:
        raise HTTPException(status_code=404, detail="Supplier not found")
    
    SUPPLIERS[supplier_id]["contact_email"] = payload.contact_email
    SUPPLIERS[supplier_id]["routing_code"] = payload.routing_code
    SUPPLIERS[supplier_id]["service_tier"] = payload.service_tier
    SUPPLIERS[supplier_id]["last_updated"] = "2026-11-19T23:40:00Z"

    return {
        "status": "CONFIG_DETAILS_UPDATED",
        "supplier_id": supplier_id,
        "updated_details": SUPPLIERS[supplier_id]
    }

@app.post("/api/payments/run")
def execute_payment_run():
    return {
        "run_id": "PAY_RUN_2026_11",
        "status": "DISPATCHED",
        "total_suppliers_paid": len(SUPPLIERS),
        "total_amount_gbp": 842500.00
    }

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def catch_all_upstream(request: Request, full_path: str):
    body = await request.body()
    try:
        body_json = await request.json()
    except Exception:
        body_json = body.decode("utf-8", errors="replace") if body else None

    return {
        "server_response": "REQUEST_ACCEPTED_BY_BACKEND_SERVER",
        "path": f"/{full_path}",
        "method": request.method,
        "query_params": dict(request.query_params),
        "received_payload": body_json,
        "verified_by_vaultgate": request.headers.get("x-vaultgate-verified", "false"),
        "vendor_caller": request.headers.get("x-vaultgate-vendor", "unknown")
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
