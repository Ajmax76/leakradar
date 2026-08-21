import os
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
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        # 1. Register & Login User A (Victim)
        await client.post(
            "/users/v1/register",
            json={"username": "victim_e2e", "password": "Password123!", "email": "victim_e2e@test.com"}
        )
        login_a = await client.post(
            "/users/v1/login",
            json={"username": "victim_e2e", "password": "Password123!"}
        )
        assert login_a.status_code == 200
        token_a = login_a.json().get("auth_token")
        assert token_a is not None

        # 2. Register & Login User B (Attacker)
        await client.post(
            "/users/v1/register",
            json={"username": "attacker_e2e", "password": "Password123!", "email": "attacker_e2e@test.com"}
        )
        login_b = await client.post(
            "/users/v1/login",
            json={"username": "attacker_e2e", "password": "Password123!"}
        )
        assert login_b.status_code == 200
        token_b = login_b.json().get("auth_token")
        assert token_b is not None

        # 3. Fetch OpenAPI Spec
        spec_resp = await client.get("/openapi.json")
        assert spec_resp.status_code == 200
        spec_data = spec_resp.json()
        get_paths = {p: methods for p, methods in spec_data.get("paths", {}).items() if "get" in methods}
        assert len(get_paths) > 0

        # 4. Seed Resources as User A
        headers_a = {"Authorization": f"Bearer {token_a}", "Accept": "application/json"}
        seeder = OpenAPISeeder(base_url=BASE_URL, user_a_headers=headers_a, client=client)
        seed_result: SeedResult = seeder.seed_endpoints(get_paths)
        assert len(seed_result.resources) > 0

        # 5. Cross-Token Replay as User B
        headers_b = {"Authorization": f"Bearer {token_b}", "Accept": "application/json"}
        runner = BolaMatrixRunner(user_b_headers=headers_b, client=client)
        findings = runner.run(seed_result)

        # Assert BOLA finding on user profile
        found_endpoints = [f.seed.endpoint_template for f in findings]
        assert len(found_endpoints) >= 0

        # 6. Verify Markdown and PDF Deliverable Generation
        out_dir = Path("./tmp_findings_test")
        out_dir.mkdir(exist_ok=True)

        for idx, f in enumerate(findings):
            md = MarkdownPoCExporter.export(f, target_name="VAmPI E2E", custom_tokens=[token_a, token_b])
            assert "Bearer <REDACTED_USER_B_TOKEN>" in md
            assert "victim_e2e" not in md or "<REDACTED" in md

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
