import os
import time
from typing import List, Optional
from fastapi import Depends, FastAPI, Header, HTTPException
import httpx
import jwt
from pydantic import BaseModel

app = FastAPI(title="ajmax76 HQ — License & Signature Service", version="1.0.0")

POLAR_API_KEY = os.environ.get("POLAR_API_KEY", "")
POLAR_ORGANIZATION_ID = os.environ.get("POLAR_ORGANIZATION_ID", "")
JWT_SIGNING_SECRET = os.environ.get("JWT_SIGNING_SECRET", "ajmax76_dev_secret_key_change_in_prod")


class LicenseActivationRequest(BaseModel):
    license_key: str
    machine_id: str
    client_version: str


class LicenseActivationResponse(BaseModel):
    tier: str
    capabilities: List[str]
    signed_token: str
    expires_at: str
    machine_id: str


@app.post("/v1/license/activate", response_model=LicenseActivationResponse)
async def activate_license(req: LicenseActivationRequest):
    key = req.license_key.strip()

    # 1. Validation Logic (Verify key against Polar.sh API or local test bypass)
    if key.startswith("lr_test_pro_"):
        tier = "solo"
        capabilities = ["pdf_export", "h1_markdown", "cloud_rules"]
    elif key.startswith("lr_live_"):
        # Real Polar.sh API verification
        async with httpx.AsyncClient() as client:
            polar_resp = await client.get(
                f"https://api.polar.sh/v1/licenses/validate?key={key}",
                headers={"Authorization": f"Bearer {POLAR_API_KEY}"}
            )
            if polar_resp.status_code != 200:
                raise HTTPException(status_code=403, detail="Invalid or expired Polar.sh license key.")
            tier = "solo"
            capabilities = ["pdf_export", "h1_markdown", "cloud_rules"]
    else:
        raise HTTPException(status_code=403, detail="Invalid license key format.")

    # 2. Issue 30-day Signed JWT Capability Envelope
    now = int(time.time())
    expires_in_seconds = 30 * 86400
    exp_timestamp = now + expires_in_seconds

    payload = {
        "sub": req.license_key,
        "machine_id": req.machine_id,
        "tier": tier,
        "capabilities": capabilities,
        "iat": now,
        "exp": exp_timestamp,
    }

    signed_jwt = jwt.encode(payload, JWT_SIGNING_SECRET, algorithm="HS256")

    return LicenseActivationResponse(
        tier=tier,
        capabilities=capabilities,
        signed_token=signed_jwt,
        expires_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp_timestamp)),
        machine_id=req.machine_id,
    )


@app.get("/v1/rules/sync")
async def sync_rules(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header.")

    token = authorization.split(" ", 1)[1]
    try:
        decoded = jwt.decode(token, JWT_SIGNING_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=403, detail="Invalid or expired signed license token.")

    if "cloud_rules" not in decoded.get("capabilities", []):
        raise HTTPException(status_code=403, detail="License tier does not permit cloud signature feeds.")

    # Return Live Cloud Detection Signatures
    return {
        "version": "2026.03.1",
        "rules": [
            {"id": "RULE-AWS-SECRET", "pattern": r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}", "severity": "CRITICAL"},
            {"id": "RULE-JWT-NONE", "pattern": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.\s*$", "severity": "HIGH"},
            {"id": "RULE-FIREBASE-DB", "pattern": r"https://[a-z0-9-]+\.firebaseio\.com", "severity": "HIGH"},
        ]
    }
