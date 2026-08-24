import base64
import json
import time
import uvicorn
from fastapi import FastAPI, Header, HTTPException, Path
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(
    title="PulseHealth Cloud API",
    description="Vulnerable Medical Records REST API (BOLA / IDOR Testbed)",
    version="1.0.0"
)

SECRET_KEY = "pulsehealth-demo-secret-key-32bytes-long-for-jwt"

# Database Mock
PATIENT_RECORDS = {
    "REC-9901": {
        "patient_id": "REC-9901",
        "owner_user_id": "user_101",
        "patient_name": "Eleanor Vance",
        "ssn": "987-65-4321",
        "diagnosis": "Acute Cardiac Arrhythmia",
        "confidential_notes": "Patient classified under high-privacy VIP protocol. Secret Key: SEC-MED-887412",
        "prescriptions": ["Amiodarone 200mg", "Metoprolol 50mg"]
    },
    "REC-9902": {
        "patient_id": "REC-9902",
        "owner_user_id": "user_102",
        "patient_name": "Alex Miller",
        "ssn": "123-45-6789",
        "diagnosis": "Mild Seasonal Allergies",
        "confidential_notes": "Standard patient profile.",
        "prescriptions": ["Cetirizine 10mg"]
    }
}

USER_PROFILES = {
    "user_101": {
        "user_id": "user_101",
        "full_name": "Dr. Sarah Jenkins",
        "email": "sarah.jenkins@pulsehealth.io",
        "role": "Chief Medical Officer",
        "patient_id": "REC-9901"
    },
    "user_102": {
        "user_id": "user_102",
        "full_name": "Alex Miller",
        "email": "alex.miller@example.com",
        "role": "Patient User",
        "patient_id": "REC-9902"
    }
}

USER_BILLING = {
    "user_101": {
        "user_id": "user_101",
        "credit_card_last4": "4412",
        "billing_address": "742 Evergreen Terrace, Springfield",
        "account_balance": 0.00,
        "invoice_history": ["INV-2026-001", "INV-2026-042"]
    },
    "user_102": {
        "user_id": "user_102",
        "credit_card_last4": "8890",
        "billing_address": "123 Market St, San Francisco, CA",
        "account_balance": 150.00,
        "invoice_history": ["INV-2026-109"]
    }
}


class LoginRequest(BaseModel):
    username: str
    password: str


def create_jwt_token(payload_data: dict) -> str:
    """Utility to generate standard 3-part JWT tokens."""
    try:
        import jwt
        return jwt.encode(payload_data, SECRET_KEY, algorithm="HS256")
    except ImportError:
        header = {"alg": "HS256", "typ": "JWT"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
        sig_b64 = base64.urlsafe_b64encode(b"demo-signature").decode().rstrip("=")
        return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_jwt_token(token: str) -> dict:
    """Utility to decode JWT claims from Authorization Bearer header."""
    if not token or not token.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required: Missing or malformed Bearer token")
    
    raw_jwt = token.split(" ", 1)[1]
    try:
        import jwt
        return jwt.decode(raw_jwt, SECRET_KEY, algorithms=["HS256"], options={"verify_signature": False})
    except ImportError:
        parts = raw_jwt.split(".")
        if len(parts) != 3:
            raise HTTPException(status_code=401, detail="Invalid JWT token structure")
        padding = "=" * (4 - len(parts[1]) % 4)
        payload_json = base64.urlsafe_b64decode(parts[1] + padding).decode()
        return json.loads(payload_json)


@app.get("/", response_class=HTMLResponse)
def read_root():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>PulseHealth Cloud API Portal</title>
        <style>
            body { font-family: 'Inter', system-ui, sans-serif; background: #0B0F19; color: #E2E8F0; margin: 0; padding: 40px; }
            .container { max-width: 900px; margin: 0 auto; background: #1E293B; padding: 32px; border-radius: 12px; border: 1px solid #334155; }
            h1 { color: #38BDF8; font-size: 28px; margin-top: 0; }
            p { color: #94A3B8; line-height: 1.6; }
            .card { background: #0F172A; border-left: 4px solid #38BDF8; padding: 16px; border-radius: 6px; margin: 20px 0; }
            .badge { background: #0284C7; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>PulseHealth Cloud API <span class="badge">VULNERABLE BOLA TARGET</span></h1>
            <p>Demonstration REST API testbed for LeakRadar BOLA & IDOR vulnerability scanning.</p>
        </div>
    </body>
    </html>
    """


@app.post("/api/v1/auth/login")
def login(req: LoginRequest):
    """
    AUTHENTICATION ENDPOINT:
    Issues a standard 3-part JWT token per authenticated user containing `sub`, `user_id`, and `patient_id` claims.
    """
    if req.username == "sarah" and req.password == "doctor123":
        user_info = USER_PROFILES["user_101"]
    elif req.username == "alex" and req.password == "patient123":
        user_info = USER_PROFILES["user_102"]
    else:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    payload = {
        "sub": user_info["user_id"],
        "user_id": user_info["user_id"],
        "email": user_info["email"],
        "patient_id": user_info["patient_id"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 86400
    }
    access_token = create_jwt_token(payload)
    return {"access_token": access_token, "token_type": "bearer", "user": user_info}


@app.get("/api/v1/patients/{patient_id}/records")
def get_patient_record(
    patient_id: str = Path(..., example="REC-9901", description="Target Patient Dossier Identifier"),
    authorization: str = Header(None)
):
    """
    VULNERABLE ENDPOINT 1 (BOLA / IDOR):
    Decodes the caller's identity from the JWT token, but fails to check if `caller_id` owns `patient_id`.
    Authenticated (Token valid), but NOT authorized for other patients' records.
    """
    claims = decode_jwt_token(authorization)
    caller_id = claims.get("sub") or claims.get("user_id")

    if patient_id not in PATIENT_RECORDS:
        raise HTTPException(status_code=404, detail="Patient record not found")
    
    # BOLA VULNERABILITY: caller_id is extracted but NEVER checked against PATIENT_RECORDS[patient_id]["owner_user_id"]
    return PATIENT_RECORDS[patient_id]


@app.get("/api/v1/users/{user_id}/profile")
def get_user_profile(
    user_id: str = Path(..., example="user_101", description="Target User ID"),
    authorization: str = Header(None)
):
    """
    VULNERABLE ENDPOINT 2 (BOLA / IDOR):
    Decodes the caller's identity from the JWT token, but fails to check if `caller_id == user_id`.
    Authenticated (Token valid), but allows viewing any user's profile.
    """
    claims = decode_jwt_token(authorization)
    caller_id = claims.get("sub") or claims.get("user_id")

    if user_id not in USER_PROFILES:
        raise HTTPException(status_code=404, detail="User profile not found")

    # BOLA VULNERABILITY: caller_id is extracted but NEVER checked against target user_id
    return USER_PROFILES[user_id]


@app.get("/api/v1/users/{user_id}/billing")
def get_user_billing(
    user_id: str = Path(..., example="user_101", description="Target User ID"),
    authorization: str = Header(None)
):
    """
    SECURED CONTROL ENDPOINT (NO BOLA):
    Decodes the caller's identity from the JWT token AND verifies `caller_id == user_id`.
    Returns 403 Forbidden if User B attempts to access User A's billing data.
    """
    claims = decode_jwt_token(authorization)
    caller_id = claims.get("sub") or claims.get("user_id")

    if user_id not in USER_BILLING:
        raise HTTPException(status_code=404, detail="Billing record not found")

    # PROPER AUTHORIZATION CONTROL CHECK:
    if caller_id != user_id:
        raise HTTPException(
            status_code=403,
            detail=f"Forbidden: User '{caller_id}' is not authorized to access billing records for '{user_id}'."
        )

    return USER_BILLING[user_id]


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
