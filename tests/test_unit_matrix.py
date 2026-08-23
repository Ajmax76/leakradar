import os
import json
import pytest
from pathlib import Path
from leakradar.bola_matrix import BolaMatrixRunner, Finding
from leakradar.seeder import SeedResult, ResourceSeed
from leakradar.markdown_poc import MarkdownPoCExporter
from leakradar.pdf_report import PDFReportGenerator

def test_unit_bola_matrix_and_reporting():
    # 1. Mock ResourceSeed harvested from User A
    resource = ResourceSeed(
        base_url="http://localhost:5000",
        method="GET",
        endpoint_template="/users/v1/{username}",
        param_values={"username": "victim_user"},
        baseline_responses=[{"username": "victim_user", "email": "victim@test.com", "role": "user"}]
    )
    seed_result = SeedResult(resources=[resource], warnings=[])

    # 2. Mock Finding where User B accessed User A's resource (BOLA)
    finding = Finding(
        seed=resource,
        probe_url="http://localhost:5000/users/v1/victim_user",
        probe_method="GET",
        probe_status_code=200,
        confidence="high",
        evidence_fields=[{
            "type": "Resource ID Echo",
            "field": "$.username",
            "value": "victim_user",
            "description": "Target parameter value 'victim_user' echoed in User B response."
        }],
        overlap_score=1.0,
        baseline_representative={"username": "victim_user", "email": "victim@test.com", "role": "user"},
        probe_response={"username": "victim_user", "email": "victim@test.com", "role": "user", "secret_key": "mock_test_key_000000000000000000000000"},
        secret_findings=[]
    )

    # 3. Test Markdown Report Generation & Redaction
    token_a = "mock_jwt_header_user_a_token_spec_test"
    token_b = "mock_jwt_header_user_b_token_spec_test"
    
    md_output = MarkdownPoCExporter.export(
        finding=finding,
        target_name="LeakRadar Unit Audit Target",
        custom_tokens=[token_a, token_b]
    )

    assert "# [Vulnerability Report] Broken Object Level Authorization" in md_output
    assert "<REDACTED" in md_output

    # 4. Test PDF Deliverable Generator
    out_dir = Path("./tmp_unit_findings")
    out_dir.mkdir(exist_ok=True)
    pdf_path = out_dir / "unit_test_report.pdf"

    PDFReportGenerator.generate(
        findings=[finding],
        target_name="LeakRadar Unit Audit Target",
        output_path=str(pdf_path),
        custom_tokens=[token_a, token_b]
    )

    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 500

    # Cleanup
    if pdf_path.exists():
        pdf_path.unlink()
    if out_dir.exists():
        out_dir.rmdir()


@pytest.mark.asyncio
async def test_unverified_key_format_does_not_activate_pro(tmp_path, monkeypatch):
    """
    Fix 1 Test: Asserts that fake keys matching valid format shapes do NOT activate Pro tier offline.
    """
    from leakradar.auth import LicenseManager
    
    # Point cache file to temporary directory
    monkeypatch.setattr(LicenseManager, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(LicenseManager, "CACHE_FILE", tmp_path / "license.json")
    
    fake_key = "LR-PRO-not-a-real-key-but-correct-shape-12345"
    ctx = await LicenseManager.activate_license(fake_key)
    
    # Must revert strictly to free tier when server validation fails
    assert ctx.tier == "free"
    assert ctx.active is False


def test_forged_license_attempt_using_public_key_rejected(tmp_path, monkeypatch):
    """
    Asymmetric Security Assertion: Asserts that an outsider attempting to forge a signature using ONLY materials
    available in the public repository (e.g. ED25519_PUBLIC_KEY_HEX or auth.py contents) is strictly REJECTED.
    """
    from leakradar.auth import LicenseManager, ED25519_PUBLIC_KEY_HEX
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    monkeypatch.setattr(LicenseManager, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(LicenseManager, "CACHE_FILE", tmp_path / "license.json")

    fingerprint = LicenseManager.get_machine_fingerprint()
    key = "LR-PRO-forged-key-attempt"
    tier = "pro"

    # Attacker tries to generate signature using public key or random bytes (since private key is NOT public)
    pub_bytes = bytes.fromhex(ED25519_PUBLIC_KEY_HEX)
    pub_obj = Ed25519PublicKey.from_public_bytes(pub_bytes)

    # 1. Attempt calling sign on public key raises AttributeError (public keys cannot sign)
    with pytest.raises(AttributeError):
        pub_obj.sign(b"forged_payload")

    # 2. Attacker puts a forged/fake 64-byte hex signature into license.json
    forged_signature = "a" * 128  # 64-byte hex string
    forged_data = {
        "active": True,
        "key": key,
        "tier": tier,
        "fingerprint": fingerprint,
        "signature": forged_signature,
        "capabilities": {"pdf_export": True, "cloud_rules": True, "unlimited_scans": True},
        "expires_at": None,
    }
    with open(tmp_path / "license.json", "w", encoding="utf-8") as f:
        json.dump(forged_data, f)

    # Must REJECT forged attempt and revert strictly to free tier
    ctx = LicenseManager.load_cached_license()
    assert ctx.tier == "free"
    assert ctx.active is False


def test_ed25519_signed_cached_license_activates_pro(tmp_path, monkeypatch):
    """
    Valid Asymmetric Verification: Asserts that a license signed server-side with an Ed25519 private key
    is successfully verified using the corresponding public key.
    """
    from leakradar.auth import LicenseManager
    import leakradar.auth as auth_mod
    from cryptography.hazmat.primitives.asymmetric import ed25519

    monkeypatch.setattr(LicenseManager, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(LicenseManager, "CACHE_FILE", tmp_path / "license.json")

    # Generate a temporary test-only Ed25519 keypair for test verification
    test_private_key = ed25519.Ed25519PrivateKey.generate()
    test_public_hex = test_private_key.public_key().public_bytes_raw().hex()

    monkeypatch.setattr(auth_mod, "ED25519_PUBLIC_KEY_HEX", test_public_hex)

    fingerprint = LicenseManager.get_machine_fingerprint()
    key = "pdt_valid_test_key"
    tier = "pro"
    expires_at = None

    payload = f"{key}:{tier}:{expires_at or ''}:{fingerprint}".encode("utf-8")
    valid_signature_bytes = test_private_key.sign(payload)
    valid_signature_hex = valid_signature_bytes.hex()

    valid_data = {
        "active": True,
        "key": key,
        "tier": tier,
        "fingerprint": fingerprint,
        "signature": valid_signature_hex,
        "capabilities": {"pdf_export": True, "cloud_rules": True, "unlimited_scans": True},
        "expires_at": expires_at,
    }
    with open(tmp_path / "license.json", "w", encoding="utf-8") as f:
        json.dump(valid_data, f)

    ctx = LicenseManager.load_cached_license()
    assert ctx.tier == "pro"
    assert ctx.active is True


def test_query_param_seeding_and_missing_param_warning():
    """
    Fix 2 Test: Asserts OpenAPI parameters with 'in': 'query' are seeded and warnings emitted for missing params.
    """
    from leakradar.seeder import OpenAPISeeder
    
    seeder = OpenAPISeeder(base_url="http://localhost:5000", user_a_headers={})
    seeder.param_pool["user_id"] = [101, 102]

    openapi_paths = {
        "/api/user/profile": {
            "get": {
                "parameters": [
                    {"name": "user_id", "in": "query", "required": True}
                ]
            }
        },
        "/api/orders": {
            "get": {
                "parameters": [
                    {"name": "missing_order_id", "in": "query", "required": True}
                ]
            }
        }
    }

    # Mock baseline triplet fetch to avoid real network call
    def mock_fetch(url, method="GET"):
        if "user_id=" in url:
            return True, [{"user_id": 101, "name": "User 101"}]*3, set()
        return False, [], set()

    seeder._fetch_baseline_triplet = mock_fetch

    result = seeder.seed_endpoints(openapi_paths)
    
    # 1. Query-param endpoint should be seeded
    seeded_endpoints = [r.endpoint_template for r in result.resources]
    assert "/api/user/profile" in seeded_endpoints
    assert result.resources[0].query_params == {"user_id": 101}
    assert result.resources[0].id_location == "query"

    # 2. Missing parameter endpoint should generate an explicit warning
    assert any("missing_order_id" in w for w in result.warnings)


def test_multi_method_seeding_and_probing():
    """
    Fix 3 Test: Asserts POST, PUT, PATCH, and DELETE endpoints are included in seeding and probed correctly.
    """
    from leakradar.seeder import OpenAPISeeder
    from leakradar.bola_matrix import BolaMatrixRunner, Finding

    seeder = OpenAPISeeder(base_url="http://localhost:5000", user_a_headers={})
    seeder.param_pool["resource_id"] = ["res_999"]

    openapi_paths = {
        "/items/{resource_id}": {
            "patch": {
                "summary": "Update Item"
            },
            "delete": {
                "summary": "Delete Item"
            }
        }
    }

    def mock_fetch(url, method="GET"):
        return True, [{"resource_id": "res_999", "status": "updated"}]*3, set()

    seeder._fetch_baseline_triplet = mock_fetch

    result = seeder.seed_endpoints(openapi_paths)
    
    methods = [r.method for r in result.resources]
    assert "PATCH" in methods
    assert "DELETE" in methods

    # Verify probe URL generation includes query params and custom HTTP methods
    patch_seed = [r for r in result.resources if r.method == "PATCH"][0]
    runner = BolaMatrixRunner(user_b_headers={}, allow_destructive=True)
    probe_url = runner._build_probe_url(patch_seed)
    assert probe_url == "http://localhost:5000/items/res_999"


def test_safe_mode_skips_destructive_probes():
    """
    Follow-up 2 Test: Confirm that in default Safe Mode (allow_destructive=False),
    DELETE seeds are present in seeding results but _send_probe is NEVER called for them.
    """
    from leakradar.seeder import ResourceSeed, SeedResult
    from leakradar.bola_matrix import BolaMatrixRunner

    delete_seed = ResourceSeed(
        base_url="http://localhost:5000",
        method="DELETE",
        endpoint_template="/orders/{id}",
        param_values={"id": "order_123"},
        baseline_responses=[{"id": "order_123"}]
    )
    seed_result = SeedResult(resources=[delete_seed], warnings=[])

    runner = BolaMatrixRunner(user_b_headers={}, allow_destructive=False)
    
    probe_called = []
    def mock_send_probe(method, url):
        probe_called.append((method, url))
        return 200, {"status": "deleted"}

    runner._send_probe = mock_send_probe

    findings = runner.run(seed_result)

    # 1. Probe should NOT be called for DELETE in safe mode
    assert len(probe_called) == 0
    # 2. A safe-mode warning should be logged in seed_result.warnings
    assert any("safe mode" in w and "DELETE" in w for w in seed_result.warnings)


def test_allow_destructive_probes_delete_seeds():
    """
    Follow-up 2 Test: Confirm that when allow_destructive=True is passed,
    the DELETE seed IS probed.
    """
    from leakradar.seeder import ResourceSeed, SeedResult
    from leakradar.bola_matrix import BolaMatrixRunner

    delete_seed = ResourceSeed(
        base_url="http://localhost:5000",
        method="DELETE",
        endpoint_template="/orders/{id}",
        param_values={"id": "order_123"},
        baseline_responses=[{"id": "order_123"}]
    )
    seed_result = SeedResult(resources=[delete_seed], warnings=[])

    runner = BolaMatrixRunner(user_b_headers={}, allow_destructive=True)
    
    probe_called = []
    def mock_send_probe(method, url):
        probe_called.append((method, url))
        return 200, {"id": "order_123", "status": "deleted"}

    runner._send_probe = mock_send_probe

    findings = runner.run(seed_result)

    # 1. Probe SHOULD be called for DELETE when allow_destructive=True
    assert len(probe_called) == 1
    assert probe_called[0] == ("DELETE", "http://localhost:5000/orders/order_123")


def test_p1_stale_cache_requires_revalidation(tmp_path, monkeypatch):
    """
    Priority 1 Test: Cache > 7 days old forces revalidation (fails closed to free tier if network fails).
    """
    from leakradar.auth import LicenseManager
    import leakradar.auth as auth_mod
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from datetime import datetime, timezone, timedelta
    import json
    
    monkeypatch.setattr(LicenseManager, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(LicenseManager, "CACHE_FILE", tmp_path / "license.json")
    
    test_private_key = ed25519.Ed25519PrivateKey.generate()
    test_public_hex = test_private_key.public_key().public_bytes_raw().hex()
    monkeypatch.setattr(auth_mod, "ED25519_PUBLIC_KEY_HEX", test_public_hex)
    
    fingerprint = LicenseManager.get_machine_fingerprint()
    key = "pdt_valid_test_key"
    tier = "pro"
    
    # 8 days ago
    past = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
    expires_at = None
    
    payload = f"{key}:{tier}:{expires_at or ''}:{fingerprint}".encode("utf-8")
    signature = test_private_key.sign(payload).hex()

    valid_data = {
        "active": True,
        "key": key,
        "tier": tier,
        "fingerprint": fingerprint,
        "signature": signature,
        "capabilities": {"pdf_export": True, "cloud_rules": True, "unlimited_scans": True},
        "activated_at": past,
        "expires_at": expires_at
    }
    with open(tmp_path / "license.json", "w", encoding="utf-8") as f:
        json.dump(valid_data, f)
        
    ctx = LicenseManager.get_active_context()
    
    assert ctx.tier == "free"
    assert ctx.active is False


def test_p2_ssrf_protection_blocks_reserved_ips():
    """
    Priority 2 Test: Asserts that _load_openapi_spec blocks AWS metadata and localhost by default.
    """
    from leakradar.cli import _load_openapi_spec
    import pytest
    
    # Cloud Metadata IPv4
    with pytest.raises(ValueError, match="SSRF Protection blocked connection to restricted IP"):
        _load_openapi_spec("http://169.254.169.254/latest/meta-data/")
        
    # Localhost
    with pytest.raises(ValueError, match="SSRF Protection blocked connection to restricted IP"):
        _load_openapi_spec("http://127.0.0.1/spec.json")
        
    with pytest.raises(ValueError, match="SSRF Protection blocked connection to restricted IP"):
        _load_openapi_spec("http://localhost:8080/spec.json")


def test_p2_allow_internal_spec_bypasses_restriction(monkeypatch):
    """
    Priority 2 Test: Asserts that --allow-internal-spec bypasses SSRF blocks.
    """
    from leakradar.cli import _load_openapi_spec
    import httpx
    
    # Mock httpx.Client.get so we don't actually fetch from localhost and fail
    def mock_get(*args, **kwargs):
        class MockResp:
            def raise_for_status(self): pass
            text = '{"openapi": "3.0.0", "info": {"title": "Test"}}'
        return MockResp()

    monkeypatch.setattr(httpx.Client, "get", mock_get)

    result = _load_openapi_spec("http://127.0.0.1/spec.json", allow_internal=True)
    assert result["info"]["title"] == "Test"


def test_p2_allow_internal_does_not_bypass_redirect_target_check():
    """
    Priority 2 Test: Asserts that --allow-internal-spec only bypasses the literal initial user-specified host.
    A malicious redirect from that allowed host to a restricted IP (e.g. AWS Metadata) must still be blocked.
    """
    import threading
    import pytest
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from leakradar.cli import _load_openapi_spec

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            # Respond with 302 Redirect to AWS Metadata
            self.send_response(302)
            self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')
            self.end_headers()
            
        def log_message(self, format, *args):
            pass

    server = HTTPServer(('127.0.0.1', 8888), RedirectHandler)
    t = threading.Thread(target=server.handle_request)
    t.daemon = True
    t.start()
    
    # We pass allow_internal=True.
    # The initial host '127.0.0.1' is explicitly bypassed because it matches parsed.hostname.
    # The redirect to '169.254.169.254' does NOT match '127.0.0.1', so the hook evaluates it.
    # It catches link_local and raises ValueError.
    with pytest.raises(ValueError, match="SSRF Protection blocked connection to restricted IP: 169.254.169.254 for host: 169.254.169.254"):
        _load_openapi_spec("http://127.0.0.1:8888/spec", allow_internal=True)
        
    server.server_close()
