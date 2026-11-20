# VaultGate
**Security Reverse Proxy & API Gateway**  
*Crimeathon ’26 | Defense | Team - The Abyss*

---

## Executive Summary

VaultGate is a security reverse proxy sitting between external clients or vendors and internal backend services. 

Rather than routing incoming API traffic directly to production application servers, VaultGate intercepts every inbound HTTP transaction, validates vendor credentials against a cryptographically signed identity database (`vendor_keys.json.sig`), and enforces eight deterministic security railguards before allowing traffic to proceed upstream.

```
External Clients / Vendors
       │
       ▼
┌────────────────────────────────────────────────────────────────────────┐
│ VaultGate Reverse Proxy (:8080)                                        │
│                                                                        │
│  [1] Key Present      ──► 401 KEY_MISSING                              │
│  [2] Key Known        ──► 401 KEY_UNKNOWN                              │
│  [3] Vendor Matches   ──► 403 VENDOR_MISMATCH                          │
│  [4] Expiration Check ──► 401 KEY_EXPIRED                              │
│  [5] Scope & Method   ──► 403 SCOPE_DENIED                             │
│  [6] Source IP/CIDR   ──► 403 IP_BLOCKED                               │
│  [7] Payload Analysis ──► 400 PAYLOAD_SUSPECT                          │
│  [8] Sliding Rate     ──► 429 RATE_LIMIT                               │
│  [+] Dual-Control Hold──► 202 ACTION_HELD_FOR_APPROVAL                 │
└────────────────────────────────────────────────────────────────────────┘
       │                                     │
       ▼ (Compliant)                         ▼ (Non-Compliant)
Protected Upstream Service (:8000)     Terminated at Perimeter
```

---

## Security Railguards: 8 Sequential Checks

VaultGate evaluates requests in a strict fail-fast pipeline:

| # | Inspection Stage | HTTP Status | Error Code | Description |
|:---:|---|:---:|:---:|---|
| **1** | **Key Presence** | `401` | `KEY_MISSING` | Rejects requests missing credentials (`X-API-Key` or `Authorization: ApiKey`). |
| **2** | **Key Recognition** | `401` | `KEY_UNKNOWN` | Validates API key using constant-time HMAC-SHA256 lookup against keystore. |
| **3** | **Vendor Binding** | `403` | `VENDOR_MISMATCH` | Ensures caller identity matches key contract (`X-Vendor-ID` or path parameter). |
| **4** | **Lifecycle / Expiry** | `401` | `KEY_EXPIRED` | Enforces contract expiration timestamps in UTC. |
| **5** | **Scope Authorization** | `403` | `SCOPE_DENIED` | Validates HTTP method and resource path against allowed vendor permissions. |
| **6** | **Network Perimeter** | `403` | `IP_BLOCKED` | Restricts access to contracted source IPv4/IPv6 addresses and CIDR blocks. |
| **7** | **Payload Inspection** | `400` | `PAYLOAD_SUSPECT` | Detects SQL injection, directory traversal, command injection, and probe signatures. |
| **8** | **Rate Limiting** | `429` | `RATE_LIMIT` | Sliding 60-second window rate enforcement per vendor contract. |
| **+** | **Sensitive Action Hold**| `202` | `ACTION_HELD_FOR_APPROVAL`| Sensitive operations are halted for dual-control operator authorization. |

---

## Gateway Enforcement Modes

VaultGate supports dual operational modes configurable on the fly via the console or administrative API:

1. **Automatic Mode (Default - Autonomous Gate)**:
   - Inbound requests are analyzed across all 8 checks in sub-milliseconds.
   - Fully compliant requests are transparently proxied to upstream backend services.
   - High-risk operations (e.g., batch payouts, configuration edits) are held for dual-control clearance.

2. **Manual Mode (Supervised Air-Gap Inspection)**:
   - All inbound requests passing syntax verification are placed into the Operator Clearance Desk.
   - Zero traffic reaches the protected upstream service without explicit cryptographic release from an authorized operator.

---

## Quick Start & Deployment

##### *Use `python`, `py`, or `python3`, whichever is available.*

### 1. Prerequisites & Environment Setup
Clone the repository and install runtime dependencies:
```bash
python3 -m venv venv
```

**Linux / macOS:**
```bash
source venv/bin/activate
```

**Windows (cmd):**
```bat
venv\Scripts\activate
```

**Windows (PowerShell):**
```powershell
venv\Scripts\Activate.ps1
```

Then install dependencies:
```bash
pip install -r requirements.txt
```

### 2. Start VaultGate
Run the unified supervisor to launch both the VaultGate proxy on port `8080` and the mock upstream backend on port `8000`:
```bash
python3 main.py
```

To configure custom network bindings or credentials:
```bash
python3 main.py \
  --proxy-host 0.0.0.0 \
  --proxy-port 8080 \
  --upstream-host 127.0.0.1 \
  --upstream-port 8000 \
  --admin-key "vg_admin_sec_2026_defense"
```

### 3. Service Endpoints
Once started, the following services are live:
- **VaultGate Proxy**: `http://<server-ip>:8080` (External perimeter)
- **Operations Console**: `http://<server-ip>:8080/vaultgate/console` (Administrative dashboard)
- **Protected Upstream**: `http://127.0.0.1:8000` (Internal loopback only)

---

## Operations Console & Operator Clearance

The live web console (`/vaultgate/console`) provides real-time situational awareness and perimeter controls:

- **Operator Authentication Gate**: Requires the `VAULTGATE_ADMIN_KEY` before granting access to controls or metrics.
- **Live Interception Stream**: Continuous event feed with UTC timestamps, vendor IDs, client IPs, and policy outcomes.
- **Dynamic Railguard Counters**: Real-time counters showing passing state (`ACTIVE`) or tripped counts (`BLOCKED`) per check.
- **Operator Clearance Desk**: Dual-control approval station to review, inspect, and approve or reject held requests.
- **Enforcement Mode Switch**: One-click toggle between Autonomous and Supervised Air-Gap operation.
- **Posture Deficit Scan**: Identifies unmonitored keys lacking IP boundaries or expiration limits.
- **Theme Controls**: Pitch-black defense terminal mode with ambient background lighting and high-contrast day mode.

---

## Verification & Test Suites

The automated test framework comprehensively verifies all railguards, evasion countermeasures, and operational modes:

### Run Full Test Suite
```bash
python3 tests/run_all_tests.py
```

### Individual Test Suites
- **Check Pipeline**: `python3 -m unittest tests/test_eight_checks.py`
- **Payload Threat Defenses**: `python3 -m unittest tests/test_payload_defenses.py`
- **Modes & Hold Approvals**: `python3 -m unittest tests/test_modes_and_holds.py`
- **Case Incident Vectors**: `python3 -m unittest tests/test_case_study_attacks.py`

### Quick cURL Smoke Tests
Verify perimeter enforcement from the command line:

```bash
# Missing Key (Check 1) -> 401 KEY_MISSING
curl -i http://localhost:8080/api/shipments

# Valid Key -> 200 OK (Forwarded to upstream)
curl -i http://localhost:8080/api/shipments \
  -H "X-API-Key: vg_live_shipping_swift_a18b2c" \
  -H "X-Vendor-ID: swift-carrier"

# Malicious SQL Payload (Check 7) -> 400 PAYLOAD_SUSPECT
curl -i "http://localhost:8080/api/shipments?search=1%27%20OR%201=1--" \
  -H "X-API-Key: vg_live_shipping_swift_a18b2c" \
  -H "X-Vendor-ID: swift-carrier"
```

---

## Configuration Reference

| Environment Variable | CLI Argument | Default | Description |
|---|---|---|---|
| `VAULTGATE_PROXY_HOST` | `--proxy-host` | `0.0.0.0` | Host interface for the VaultGate reverse proxy. |
| `VAULTGATE_PROXY_PORT` | `--proxy-port` | `8080` | Port for incoming perimeter traffic and console. |
| `VAULTGATE_UPSTREAM_URL` | `--upstream-host/port` | `http://127.0.0.1:8000` | Address of protected internal backend server. |
| `VAULTGATE_ADMIN_KEY` | `--admin-key` | `vg_admin_sec_2026_defense` | Secret key required for console & administrative APIs. |
| `VAULTGATE_KEYSTORE_PATH`| N/A | `database/vendor_keys.json` | Path to signed vendor identity database. |
