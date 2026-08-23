import hashlib
import json
import os
import platform
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
import httpx

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# Server's public key constant (32 bytes hex) used ONLY to verify server-issued signatures client-side.
# The corresponding private key is held strictly server-side and does NOT exist in this codebase.
ED25519_PUBLIC_KEY_HEX = "08c1646bf6b8398ff9aff6d9e565617479a083db2fae86da680dfb6365570406"


def verify_license_signature(
    key: str,
    tier: str,
    expires_at: Optional[str],
    fingerprint: str,
    signature_hex: str,
    public_key_hex: Optional[str] = None,
) -> bool:
    """
    Verifies payload signature using Ed25519 public key.
    """
    if not signature_hex:
        return False
    try:
        pub_hex = public_key_hex or ED25519_PUBLIC_KEY_HEX
        pub_bytes = bytes.fromhex(pub_hex)
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)

        payload = f"{key}:{tier}:{expires_at or ''}:{fingerprint}".encode("utf-8")
        sig_bytes = bytes.fromhex(signature_hex)

        public_key.verify(sig_bytes, payload)
        return True
    except Exception:
        return False


@dataclass
class LicenseContext:
    active: bool = False
    key: Optional[str] = None
    tier: str = "free"  # "free" | "paid" | "enterprise"
    capabilities: Dict[str, bool] = field(default_factory=lambda: {
        "pdf_export": False,
        "cloud_rules": False,
        "unlimited_scans": True,
    })
    expires_at: Optional[str] = None


class LicenseManager:
    """
    Manages Dodo Payments license key activation, machine fingerprinting, and local cache.
    Validates license keys directly against Dodo Payments official API (zero custom cloud server needed).
    """

    DODO_LIVE_URL = "https://live.dodopayments.com/licenses/validate"
    DODO_TEST_URL = "https://test.dodopayments.com/licenses/validate"
    CACHE_DIR = Path.home() / ".leakradar"
    CACHE_FILE = CACHE_DIR / "license.json"

    @classmethod
    def get_machine_fingerprint(cls) -> str:
        """
        Generate a unique hardware fingerprint using platform node, system, machine, and processor.
        """
        raw_info = f"{platform.node()}-{platform.system()}-{platform.machine()}-{platform.processor()}"
        return hashlib.sha256(raw_info.encode("utf-8")).hexdigest()

    @classmethod
    def load_cached_license(cls) -> LicenseContext:
        """
        Reads cached license from ~/.leakradar/license.json, verifies machine fingerprint binding, and checks expiration.
        """
        if not cls.CACHE_FILE.exists():
            return LicenseContext(active=False, tier="free")

        try:
            with open(cls.CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            key = data.get("key", "")
            tier = data.get("tier", "free")
            expires_at_str = data.get("expires_at")
            cached_fingerprint = data.get("fingerprint", "")
            stored_signature = data.get("signature", "")

            # If tier is paid/pro/enterprise, verify machine fingerprint binding
            if tier.lower() in ("paid", "pro", "enterprise"):
                current_fingerprint = cls.get_machine_fingerprint()
                if cached_fingerprint != current_fingerprint:
                    return LicenseContext(active=False, tier="free")
                if stored_signature and not verify_license_signature(key, tier, expires_at_str, current_fingerprint, stored_signature):
                    return LicenseContext(active=False, tier="free")

            if expires_at_str:
                try:
                    exp_dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
                    if datetime.now(timezone.utc) > exp_dt:
                        return LicenseContext(active=False, tier="free")
                except Exception:
                    pass

            is_paid = tier.lower() in ("paid", "pro", "enterprise")
            return LicenseContext(
                active=data.get("active", True),
                key=key,
                tier=tier,
                capabilities={
                    "pdf_export": is_paid or data.get("capabilities", {}).get("pdf_export", False),
                    "cloud_rules": is_paid or data.get("capabilities", {}).get("cloud_rules", False),
                    "unlimited_scans": True,
                },
                expires_at=expires_at_str,
            )
        except Exception:
            return LicenseContext(active=False, tier="free")

    @classmethod
    async def activate_license(cls, license_key: str) -> LicenseContext:
        """
        Activates a Dodo Payments license key against Dodo Payments official API and caches response locally.
        """
        clean_key = license_key.strip()
        if not clean_key or len(clean_key) < 10:
            return LicenseContext(active=False, tier="free")

        fingerprint = cls.get_machine_fingerprint()
        cls.CACHE_DIR.mkdir(parents=True, exist_ok=True)

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                # 1. Try Dodo Payments Live API validation endpoint
                resp = await client.get(f"{cls.DODO_LIVE_URL}?key={clean_key}")
                if resp.status_code != 200:
                    # 2. Try Dodo Payments Test Sandbox API validation endpoint
                    resp = await client.get(f"{cls.DODO_TEST_URL}?key={clean_key}")

                if resp.status_code == 200:
                    data = resp.json()
                    is_valid = data.get("valid", True) if isinstance(data, dict) else True
                    if is_valid:
                        tier = data.get("tier", "pro") if isinstance(data, dict) else "pro"
                        expires_at = data.get("expires_at") if isinstance(data, dict) else None

                        context_data = {
                            "active": True,
                            "key": clean_key,
                            "tier": tier,
                            "fingerprint": fingerprint,
                            "signature": "",
                            "capabilities": {
                                "pdf_export": True,
                                "cloud_rules": True,
                                "unlimited_scans": True,
                            },
                            "expires_at": expires_at,
                            "activated_at": datetime.now(timezone.utc).isoformat(),
                        }
                        with open(cls.CACHE_FILE, "w", encoding="utf-8") as f:
                            json.dump(context_data, f, indent=2)

                        return LicenseContext(
                            active=True,
                            key=clean_key,
                            tier=tier,
                            capabilities=context_data["capabilities"],
                            expires_at=expires_at,
                        )
            except Exception:
                pass

        # If Dodo Payments validation fails, fall back strictly to free tier
        return LicenseContext(active=False, tier="free")

    @classmethod
    def get_active_context(cls) -> LicenseContext:
        ctx = cls.load_cached_license()
        
        # Check maximum cache validity independent of expires_at (7-day cap)
        if ctx.active and ctx.tier.lower() in ("paid", "pro", "enterprise"):
            try:
                with open(cls.CACHE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                cached_at_str = data.get("cached_at") or data.get("activated_at")
                if not cached_at_str:
                    return LicenseContext(active=False, tier="free")
                
                cached_dt = datetime.fromisoformat(cached_at_str.replace("Z", "+00:00"))
                days_since_cache = (datetime.now(timezone.utc) - cached_dt).days
                
                if days_since_cache >= 7:
                    import asyncio
                    from rich.console import Console
                    Console().print("[dim]License cache older than 7 days. Re-validating with Dodo Payments...[/dim]")
                    # If this fails (e.g. network down), activate_license explicitly fails closed to free tier.
                    ctx = asyncio.run(cls.activate_license(ctx.key))
            except Exception:
                return LicenseContext(active=False, tier="free")
                
        return ctx
