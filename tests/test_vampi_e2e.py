import os
import uuid
from pathlib import Path
import httpx
import pytest

from leakradar.bola_matrix import BolaMatrixRunner, Finding
from leakradar.markdown_poc import MarkdownPoCExporter
from leakradar.pdf_report import PDFReportGenerator
from leakradar.seeder import OpenAPISeeder, SeedResult

BASE_URL = os.environ.get("VAMPI_BASE_URL", "http://localhost:5000")


@pytest.mark.asyncio
async def test_vampi_full_e2e():
    uid = uuid.uuid4().hex[:6]
    user_a_name = f"victim_{uid}"
    user_b_name = f"attacker_{uid}"

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=15.0) as client:
        # 0. Initialize VAmPI Database (Creates required tables)
        try:
            await client.get("/users/v1/createdb")
            await client.get("/createdb")
        except Exception:
            pass

        # 1. Register & Login User A (Victim)
        await client.post(
            "/users/v1/register",
            json={"username": user_a_name, "password": "Password123!", "email": f"{user_a_name}@test.com"}
        )
        login_a = await client.post(
            "/users/v1/login",
            json={"username": user_a_name, "password": "Password123!"}
        )
        assert login_a.status_code == 200, f"Login A HTTP status error: {login_a.status_code} - {login_a.text}"
        res_a = login_a.json()
        token_a = res_a.get("auth_token") or res_a.get("token") or res_a.get("access_token")
        assert token_a is not None, f"Failed to acquire auth_token for User A. Response: {res_a}"

        # 2. Register & Login User B (Attacker)
        await client.post(
            "/users/v1/register",
            json={"username": user_b_name, "password": "Password123!", "email": f"{user_b_name}@test.com"}
        )
        login_b = await client.post(
            "/users/v1/login",
            json={"username": user_b_name, "password": "Password123!"}
        )
        assert login_b.status_code == 200, f"Login B HTTP status error: {login_b.status_code} - {login_b.text}"
        res_b = login_b.json()
        token_b = res_b.get("auth_token") or res_b.get("token") or res_b.get("access_token")
        assert token_b is not None, f"Failed to acquire auth_token for User B. Response: {res_b}"

        # 3. Fetch OpenAPI Spec
        spec_resp = await client.get("/openapi.json")
        assert spec_resp.status_code == 200, f"Failed to fetch openapi.json: {spec_resp.status_code}"
        spec_data = spec_resp.json()
        get_paths = {p: methods for p, methods in spec_data.get("paths", {}).items() if "get" in methods}
        assert len(get_paths) > 0, "No GET endpoints found in openapi.json spec"

        # 4. Seed Resources as User A
        headers_a = {"Authorization": f"Bearer {token_a}", "Accept": "application/json"}
        seeder = OpenAPISeeder(base_url=BASE_URL, user_a_headers=headers_a)
        seed_result: SeedResult = seeder.seed_endpoints(get_paths)
        assert len(seed_result.resources) > 0, "No seed resources harvested"

        # 5. Cross-Token Replay as User B
        headers_b = {"Authorization": f"Bearer {token_b}", "Accept": "application/json"}
        runner = BolaMatrixRunner(user_b_headers=headers_b)
        findings = runner.run(seed_result)
        assert isinstance(findings, list)

        # 6. Verify Markdown and PDF Deliverable Generation
        out_dir = Path("./tmp_findings_test")
        out_dir.mkdir(exist_ok=True)

        for f in findings:
            md = MarkdownPoCExporter.export(f, target_name="VAmPI E2E", custom_tokens=[token_a, token_b])
            assert "Bearer <REDACTED_USER_B_TOKEN>" in md
            assert user_a_name not in md or "<REDACTED" in md

        pdf_path = out_dir / "test_report.pdf"
        PDFReportGenerator.generate(
            findings=findings,
            target_name="VAmPI E2E",
            output_path=str(pdf_path),
            custom_tokens=[token_a, token_b],
        )
        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 500

        # Cleanup
        if pdf_path.exists():
            pdf_path.unlink()
        if out_dir.exists():
            out_dir.rmdir()
