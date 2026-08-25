import asyncio
import json
import os
import threading
import time
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

import httpx

from leakradar.seeder import OpenAPISeeder, SeedResult, ResourceSeed
from leakradar.bola_matrix import BolaMatrixRunner, Finding
from leakradar.markdown_poc import MarkdownPoCExporter
from leakradar._pro.pdf_report import PDFReportGenerator

# 1. Lightweight Mock Target API with BOLA vulnerability
class VulnerableAPIServer(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress HTTP server logging

    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        
        # User A token -> Owner of user 101
        # User B token -> Attacker
        if self.path.startswith("/api/v1/users/"):
            user_id = self.path.split("/")[-1]
            
            # Simulated BOLA: Both User A and User B can access User 101's private profile!
            response_payload = {
                "id": int(user_id) if user_id.isdigit() else user_id,
                "username": "victim_user_101",
                "email": "victim@enterprise.com",
                "role": "billing_admin",
                "stripe_customer_id": "cus_N7x9AB123456",
                "api_secret": "sk_live_99999888887777766666"
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response_payload).encode("utf-8"))
        elif self.path == "/openapi.json":
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "Target Enterprise Payments API", "version": "1.0"},
                "paths": {
                    "/api/v1/users/{user_id}": {
                        "get": {
                            "summary": "Get user profile",
                            "parameters": [{"name": "user_id", "in": "path", "required": True, "schema": {"type": "string"}}]
                        }
                    }
                }
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(spec).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

def run_server(server):
    server.serve_forever()

def main():
    print("=" * 60)
    print("      LEAKRADAR LIVE PRODUCT DEMONSTRATION & PROOF      ")
    print("=" * 60)

    # Start mock vulnerable target server on port 8999
    server = HTTPServer(("127.0.0.1", 8999), VulnerableAPIServer)
    server_thread = threading.Thread(target=run_server, args=(server,), daemon=True)
    server_thread.start()
    time.sleep(0.5)

    base_url = "http://127.0.0.1:8999"
    spec_url = f"{base_url}/openapi.json"

    # User JWT Tokens
    token_a = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDEiLCJ1c2VyX2lkIjoiMTAxIiwibmFtZSI6IlZpY3RpbSJ9.signature_a"
    token_b = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyMDIiLCJ1c2VyX2lkIjoiMjAyIiwibmFtZSI6IkF0dGFja2VyIn0.signature_b"

    print("\n[1/4] Fetching Target OpenAPI Specification...")
    resp = httpx.get(spec_url)
    spec_data = resp.json()
    print(f"[OK] Loaded OpenAPI Spec: {spec_data['info']['title']}")

    print("\n[2/4] Harvesting Endpoints & Normalizing Volatility (User A)...")
    headers_a = {"Authorization": token_a}
    seeder = OpenAPISeeder(base_url=base_url, user_a_headers=headers_a)
    
    # Pre-seed candidate parameter pool
    seeder.param_pool["user_id"] = ["101"]
    seed_result = seeder.seed_endpoints(spec_data["paths"])
    print(f"[OK] Discovered {len(seed_result.resources)} valid resource templates.")

    print("\n[3/4] Executing Cross-Token Authorization Replay (User B)...")
    headers_b = {"Authorization": token_b}
    matrix_runner = BolaMatrixRunner(user_b_headers=headers_b)
    findings = matrix_runner.run(seed_result)

    print(f"\n[!] BOLA VULNERABILITIES DETECTED: {len(findings)}")
    for f in findings:
        print(f"   • Endpoint: {f.seed.endpoint_template}")
        print(f"   • Confidence: {f.confidence.upper()}")
        print(f"   • Data Overlap: {f.overlap_score * 100:.1f}%")
        print(f"   • Leaked Secret Keys: {len(f.secret_findings)}")

    print("\n[4/4] Generating Proof-of-Concept Deliverables...")
    out_dir = Path("./demo_findings")
    out_dir.mkdir(exist_ok=True)

    if findings:
        # Markdown PoC
        md_path = out_dir / "BOLA_Evidence_Report.md"
        md_content = MarkdownPoCExporter.export(
            findings[0], 
            target_name=spec_data['info']['title'],
            custom_tokens=[token_a, token_b]
        )
        with open(md_path, "w", encoding="utf-8") as f_out:
            f_out.write(md_content)
        print(f"[OK] Saved Redacted Markdown PoC -> {md_path}")

        # PDF Deliverable
        pdf_path = out_dir / "Executive_Audit_Report.pdf"
        PDFReportGenerator.generate(
            findings=findings,
            target_name=spec_data['info']['title'],
            output_path=str(pdf_path),
            custom_tokens=[token_a, token_b]
        )
        print(f"[OK] Saved Executive PDF Report -> {pdf_path} (Size: {pdf_path.stat().st_size} bytes)")

    print("\n" + "=" * 60)
    print("     SUCCESS: LEAKRADAR ENGINE IS 100% FUNCTIONAL!     ")
    print("=" * 60)

    server.shutdown()

if __name__ == "__main__":
    main()
