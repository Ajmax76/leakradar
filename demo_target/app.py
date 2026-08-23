import uvicorn
from fastapi import FastAPI, Header, HTTPException, Path
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(
    title="PulseHealth Cloud API",
    description="Vulnerable Medical Records REST API (BOLA / IDOR Testbed)",
    version="1.0.0"
)

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
            <p>Demonstration target REST API for LeakRadar BOLA & IDOR vulnerability scanning.</p>
        </div>
    </body>
    </html>
    """


@app.get("/api/v1/patients/{patient_id}/records")
def get_patient_record(
    patient_id: str = Path(..., example="REC-9901", description="Target Patient Dossier Identifier"),
    authorization: str = Header(None)
):
    """
    VULNERABLE BOLA ENDPOINT:
    Validates that an Authorization token is provided, but fails to check if the caller owns `patient_id`.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    if patient_id not in PATIENT_RECORDS:
        raise HTTPException(status_code=404, detail="Patient record not found")
        
    return PATIENT_RECORDS[patient_id]


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
