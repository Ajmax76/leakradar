from httpx import ASGITransport, AsyncClient
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from backend.main import app, ED25519_PRIVATE_KEY_HEX
from leakradar.auth import verify_license_signature


@pytest.mark.asyncio
async def test_backend_activation_rejects_unauthorized_and_test_keys():
    """
    Backend Security Assertion: Test key prefixes like lr_test_pro_ are strictly REJECTED online.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Test key bypass attempt
        resp = await client.post(
            "/v1/license/activate",
            json={"key": "lr_test_pro_bypass12345", "fingerprint": "machine_fp_123"}
        )
        assert resp.status_code == 403
        assert "Invalid or unauthorized" in resp.json()["detail"]

        # 2. Invalid shape key attempt
        resp2 = await client.post(
            "/v1/license/activate",
            json={"key": "invalid_shape", "fingerprint": "machine_fp_123"}
        )
        assert resp2.status_code == 403


@pytest.mark.asyncio
async def test_backend_activation_returns_valid_ed25519_signature(monkeypatch):
    """
    Backend Integration Assertion: Server signs license response with Ed25519 private key,
    which client verify_license_signature validates successfully.
    """
    # Generate test Ed25519 keypair
    priv_key = ed25519.Ed25519PrivateKey.generate()
    priv_hex = priv_key.private_bytes_raw().hex()
    pub_hex = priv_key.public_key().public_bytes_raw().hex()

    monkeypatch.setattr("backend.main.ED25519_PRIVATE_KEY_HEX", priv_hex)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(
            "/v1/license/activate",
            json={"key": "pdt_valid_server_key_12345", "fingerprint": "target_machine_fp"}
        )
        assert resp.status_code == 200
        data = resp.json()

        assert data["tier"] == "pro"
        assert data["active"] is True
        assert "signature" in data
        assert len(data["signature"]) == 128  # 64-byte Ed25519 signature in hex

        # Client-side signature verification
        is_valid = verify_license_signature(
            key="pdt_valid_server_key_12345",
            tier="pro",
            expires_at=data["expires_at"],
            fingerprint="target_machine_fp",
            signature_hex=data["signature"],
            public_key_hex=pub_hex,
        )
        assert is_valid is True
