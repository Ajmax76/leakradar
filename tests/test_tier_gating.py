import pytest
from leakradar.auth import LicenseContext

def test_tier_capabilities_gating():
    # 1. Free Tier Context
    free_ctx = LicenseContext(active=False, tier="free")
    assert not free_ctx.capabilities.get("pdf_export")
    assert not free_ctx.capabilities.get("white_label")

    # 2. Tier 1 (Pro Auditor) Context
    pro_ctx = LicenseContext(
        active=True,
        tier="pro",
        capabilities={"pdf_export": True, "white_label": False, "cloud_rules": True, "unlimited_scans": True}
    )
    assert pro_ctx.capabilities.get("pdf_export") is True
    assert pro_ctx.capabilities.get("white_label") is False

    # 3. Tier 2 (Agency & vCISO Suite) Context
    agency_ctx = LicenseContext(
        active=True,
        tier="agency",
        capabilities={"pdf_export": True, "white_label": True, "cloud_rules": True, "unlimited_scans": True}
    )
    assert agency_ctx.capabilities.get("pdf_export") is True
    assert agency_ctx.capabilities.get("white_label") is True

    # 4. Tier 3 (Enterprise Suite) Context
    ent_ctx = LicenseContext(
        active=True,
        tier="enterprise",
        capabilities={"pdf_export": True, "white_label": True, "cloud_rules": True, "unlimited_scans": True}
    )
    assert ent_ctx.capabilities.get("pdf_export") is True
    assert ent_ctx.capabilities.get("white_label") is True
