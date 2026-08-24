import os
import time
from typing import Dict, List, Optional
from fastapi import Depends, FastAPI, Header, HTTPException
import httpx
from pydantic import BaseModel

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

app = FastAPI(title="ajmax76 HQ — License & Signature Service", version="1.0.0")

DODO_PAYMENTS_API_KEY = os.environ.get("DODO_PAYMENTS_API_KEY", "")
DODO_PAYMENTS_ORGANIZATION_ID = os.environ.get("DODO_PAYMENTS_ORGANIZATION_ID", "")
ED25519_PRIVATE_KEY_HEX = os.environ.get("ED25519_PRIVATE_KEY", "")


class LicenseActivationRequest(BaseModel):
    key: str
    fingerprint: str
    system: Optional[str] = None


class LicenseActivationResponse(BaseModel):
    active: bool = True
    tier: str
    capabilities: Dict[str, bool]
    signature: str
    expires_at: Optional[str]
    fingerprint: str


@app.post("/v1/license/activate", response_model=LicenseActivationResponse)
async def activate_license(req: LicenseActivationRequest):
    clean_key = req.key.strip()
    if not clean_key or len(clean_key) < 10:
        raise HTTPException(status_code=400, detail="Invalid license key format.")

    # Remove online test key bypass: only pdt_, LR-PRO-, or lr_live_ prefixes permitted
    if not (clean_key.startswith("pdt_") or clean_key.startswith("LR-PRO-") or clean_key.startswith("lr_live_")):
        raise HTTPException(status_code=403, detail="Invalid or unauthorized license key format.")

    tier = "pro"
    capabilities = {
        "pdf_export": True,
        "cloud_rules": True,
        "unlimited_scans": True,
    }

    # Verify key against Dodo Payments API if configured
    if DODO_PAYMENTS_API_KEY:
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                dodo_resp = await client.get(
                    f"https://live.dodopayments.com/licenses/validate?key={clean_key}",
                    headers={"Authorization": f"Bearer {DODO_PAYMENTS_API_KEY}"}
                )
                if dodo_resp.status_code != 200:
                    raise HTTPException(status_code=403, detail="Invalid or expired Dodo Payments license key.")
            except Exception:
                raise HTTPException(status_code=503, detail="License payment validation service unavailable.")

    # Expiration set to 30 days
    now = int(time.time())
    exp_timestamp = now + (30 * 86400)
    expires_at_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp_timestamp))

    # Cryptographic Ed25519 Signature Generation
    signature_hex = ""
    if ED25519_PRIVATE_KEY_HEX:
        try:
            priv_bytes = bytes.fromhex(ED25519_PRIVATE_KEY_HEX)
            priv_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
            payload_bytes = f"{clean_key}:{tier}:{expires_at_str}:{req.fingerprint}".encode("utf-8")
            sig_bytes = priv_key.sign(payload_bytes)
            signature_hex = sig_bytes.hex()
        except Exception:
            raise HTTPException(status_code=500, detail="Server failed to sign license token.")

    return LicenseActivationResponse(
        active=True,
        tier=tier,
        capabilities=capabilities,
        signature=signature_hex,
        expires_at=expires_at_str,
        fingerprint=req.fingerprint,
    )


@app.get("/v1/rules/sync")
async def sync_rules(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header.")

    # Return Live Cloud Detection Signatures
    return {
        "version": "2026.03.1",
        "rules": [
            {"id": "RULE-AWS-SECRET", "pattern": r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}", "severity": "CRITICAL"},
            {"id": "RULE-JWT-NONE", "pattern": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.\s*$", "severity": "HIGH"},
            {"id": "RULE-FIREBASE-DB", "pattern": r"https://[a-z0-9-]+\.firebaseio\.com", "severity": "HIGH"},
        ]
    }
