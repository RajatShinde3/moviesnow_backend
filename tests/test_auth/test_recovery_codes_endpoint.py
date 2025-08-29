# tests/test_auth/test_recovery_codes_endpoint.py

import re
import pytest
import pyotp
from httpx import AsyncClient
from unittest.mock import patch

from app.core.redis_client import redis_wrapper

BASE_MFA = "/api/v1/auth/mfa"
BASE_REAUTH = "/api/v1/auth/reauth"
BASE_RECOV = "/api/v1/auth/mfa/recovery-codes"

CODE_RE = re.compile(r"^[A-Z2-9]{5}-[A-Z2-9]{5}$")  # XXXXX-XXXXX, no 0/O/1/I


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _with_ip(headers: dict, ip: str) -> dict:
    """Return a copy of headers with a spoofed client IP for rate limiting."""
    out = dict(headers or {})
    out["X-Forwarded-For"] = ip
    return out

async def _enable_and_verify(async_client: AsyncClient, access_headers) -> str:
    """Enable MFA and verify once; return the Base32 secret."""
    en = await async_client.post(f"{BASE_MFA}/enable", headers=access_headers)
    assert en.status_code == 200, en.text
    secret = en.json()["secret"]
    code = pyotp.TOTP(secret).now()
    vr = await async_client.post(f"{BASE_MFA}/verify", headers=access_headers, json={"code": code})
    assert vr.status_code == 200, vr.text
    return secret


async def _mint_reauth_mfa(async_client: AsyncClient, access_headers, secret: str) -> str:
    """Step-up with TOTP to get a short-lived **reauth** bearer."""
    code = pyotp.TOTP(secret).now()
    r = await async_client.post(f"{BASE_REAUTH}/mfa", headers=access_headers, json={"code": code})
    assert r.status_code == 200, r.text
    return r.json()["reauth_token"]


def _ensure_scard_monkeypatch(monkeypatch):
    """
    Some test Redis doubles don’t provide SCARD; add a shim:
    SCARD -> len(SMEMBERS(key))
    """
    r = redis_wrapper.client
    if not hasattr(r, "scard"):
        async def _scard(key: str) -> int:
            try:
                members = await r.smembers(key)
                return len(members or [])
            except Exception:
                return 0
        monkeypatch.setattr(r, "scard", _scard, raising=False)


# ─────────────────────────────────────────────────────────────
# /mfa/recovery-codes/generate
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_generate_happy_path_returns_batch_only_once(async_client: AsyncClient, user_with_headers, monkeypatch):
    """
    ✅ After enabling MFA, generating recovery codes returns:
       - batch_id, created_at, total, codes (codes only returned once)
       - valid format & uniqueness
       - preview shows masked set and remaining count
    """
    _, access_headers = await user_with_headers(email="rc1@example.com", password="Secret123!")
    secret = await _enable_and_verify(async_client, access_headers)

    # Must use a **reauth** bearer for MFA-gated generation
    reauth = await _mint_reauth_mfa(async_client, access_headers, secret)
    reauth_headers = {"Authorization": f"Bearer {reauth}"}

    # Use unique IPs so 3/hour per-IP limiter never trips across tests
    gen_headers = _with_ip(reauth_headers, "203.0.113.1")

    r = await async_client.post(f"{BASE_RECOV}/generate", headers=gen_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"batch_id", "created_at", "total", "codes"}
    assert body["total"] == 10
    assert len(body["codes"]) == 10
    assert len(set(body["codes"])) == 10
    for c in body["codes"]:
        assert CODE_RE.match(c)

    # Preview with ACCESS bearer
    _ensure_scard_monkeypatch(monkeypatch)
    pv = await async_client.get(f"{BASE_RECOV}", headers=access_headers)
    assert pv.status_code == 200, pv.text
    preview = pv.json()
    assert preview["batch_id"] == body["batch_id"]
    assert preview["remaining"] == 10
    assert len(preview["preview"]) == 10
    assert any("*" in m for m in preview["preview"])

    # Rotate (new reauth + different IP)
    reauth2 = await _mint_reauth_mfa(async_client, access_headers, secret)
    gen_headers2 = _with_ip({"Authorization": f"Bearer {reauth2}"}, "203.0.113.2")
    r2 = await async_client.post(f"{BASE_RECOV}/generate", headers=gen_headers2)
    assert r2.status_code == 200, r2.text
    assert r2.json()["batch_id"] != body["batch_id"]


@pytest.mark.anyio
async def test_generate_requires_auth(async_client: AsyncClient):
    """❌ Missing bearer → 401/403."""
    r = await async_client.post(f"{BASE_RECOV}/generate")
    assert r.status_code in (401, 403)


# ─────────────────────────────────────────────────────────────
# /mfa/recovery-codes (GET preview)
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_preview_shows_masked_codes_and_remaining(async_client: AsyncClient, user_with_headers, monkeypatch):
    """
    ✅ Preview returns {batch_id, created_at, remaining, preview[]} with masked codes.
    """
    _, access_headers = await user_with_headers(email="rc2@example.com", password="Secret123!")
    secret = await _enable_and_verify(async_client, access_headers)

    # Before generation: should be safe if SCARD exists; add shim for mocks
    _ensure_scard_monkeypatch(monkeypatch)
    pv0 = await async_client.get(f"{BASE_RECOV}", headers=access_headers)
    assert pv0.status_code == 200, pv0.text
    body0 = pv0.json()
    assert body0["remaining"] in (0, 0)

    # Generate with reauth + unique IP
    reauth = await _mint_reauth_mfa(async_client, access_headers, secret)
    gen_headers = _with_ip({"Authorization": f"Bearer {reauth}"}, "203.0.113.3")
    r = await async_client.post(f"{BASE_RECOV}/generate", headers=gen_headers)
    assert r.status_code == 200, r.text

    pv = await async_client.get(f"{BASE_RECOV}", headers=access_headers)
    assert pv.status_code == 200
    body = pv.json()
    assert body["remaining"] == 10
    assert len(body["preview"]) == 10
    assert any("*" in m for m in body["preview"])


@pytest.mark.anyio
async def test_preview_requires_auth(async_client: AsyncClient):
    """❌ Missing bearer → 401/403."""
    r = await async_client.get(f"{BASE_RECOV}")
    assert r.status_code in (401, 403)


# ─────────────────────────────────────────────────────────────
# /mfa/recovery-codes/redeem
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_redeem_happy_path_mints_reauth_and_consumes_code(async_client: AsyncClient, user_with_headers, monkeypatch):
    """
    ✅ Redeeming a current code:
       - returns {reauth_token, expires_in}
       - decrements remaining by 1
       - cannot be redeemed twice
    """
    _, access_headers = await user_with_headers(email="rc3@example.com", password="Secret123!")
    secret = await _enable_and_verify(async_client, access_headers)
    reauth = await _mint_reauth_mfa(async_client, access_headers, secret)

    # Generate with reauth + unique IP, take first code
    gen_headers = _with_ip({"Authorization": f"Bearer {reauth}"}, "203.0.113.4")
    gen = await async_client.post(f"{BASE_RECOV}/generate", headers=gen_headers)
    assert gen.status_code == 200, gen.text
    code = gen.json()["codes"][0]

    _ensure_scard_monkeypatch(monkeypatch)
    pv_before = await async_client.get(f"{BASE_RECOV}", headers=access_headers)
    assert pv_before.json()["remaining"] == 10

    # Redeem with ACCESS bearer
    rd = await async_client.post(f"{BASE_RECOV}/redeem", headers=access_headers, json={"code": code})
    assert rd.status_code == 200, rd.text
    body = rd.json()
    assert "reauth_token" in body and body["expires_in"] > 0

    pv_after = await async_client.get(f"{BASE_RECOV}", headers=access_headers)
    assert pv_after.json()["remaining"] == 9

    # Same code again → 401
    rd2 = await async_client.post(f"{BASE_RECOV}/redeem", headers=access_headers, json={"code": code})
    assert rd2.status_code == 401
    assert "invalid" in rd2.json()["detail"].lower()


@pytest.mark.anyio
async def test_redeem_invalid_format_400_or_422(async_client: AsyncClient, user_with_headers):
    """
    ❌ Garbage format → 422 from Pydantic schema (constr pattern).
    (If your schema is looser and handler rejects, it could be 400.)
    """
    _, access_headers = await user_with_headers(email="rc4@example.com", password="Secret123!")
    secret = await _enable_and_verify(async_client, access_headers)
    reauth = await _mint_reauth_mfa(async_client, access_headers, secret)
    gen_headers = _with_ip({"Authorization": f"Bearer {reauth}"}, "203.0.113.5")
    await async_client.post(f"{BASE_RECOV}/generate", headers=gen_headers)

    bad = await async_client.post(f"{BASE_RECOV}/redeem", headers=access_headers, json={"code": "!!!!!"})
    assert bad.status_code in (400, 422)


@pytest.mark.anyio
async def test_redeem_unknown_code_401(async_client: AsyncClient, user_with_headers):
    """
    ❌ Correct format but unknown code → 401 (invalid recovery code).
    """
    _, access_headers = await user_with_headers(email="rc5@example.com", password="Secret123!")
    secret = await _enable_and_verify(async_client, access_headers)
    reauth = await _mint_reauth_mfa(async_client, access_headers, secret)
    gen_headers = _with_ip({"Authorization": f"Bearer {reauth}"}, "203.0.113.6")
    await async_client.post(f"{BASE_RECOV}/generate", headers=gen_headers)

    fake = "ZZZZZ-ZZZZZ"  # valid charset/shape, but not issued
    resp = await async_client.post(f"{BASE_RECOV}/redeem", headers=access_headers, json={"code": fake})
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_redeem_after_rotation_old_codes_invalid(async_client: AsyncClient, user_with_headers):
    """
    ✅ Rotating (re-generating) codes invalidates earlier batch.
    """
    _, access_headers = await user_with_headers(email="rc6@example.com", password="Secret123!")
    secret = await _enable_and_verify(async_client, access_headers)
    reauth1 = await _mint_reauth_mfa(async_client, access_headers, secret)

    gen1_headers = _with_ip({"Authorization": f"Bearer {reauth1}"}, "203.0.113.7")
    gen1 = await async_client.post(f"{BASE_RECOV}/generate", headers=gen1_headers)
    assert gen1.status_code == 200, gen1.text
    old_code = gen1.json()["codes"][0]

    reauth2 = await _mint_reauth_mfa(async_client, access_headers, secret)
    gen2_headers = _with_ip({"Authorization": f"Bearer {reauth2}"}, "203.0.113.8")
    gen2 = await async_client.post(f"{BASE_RECOV}/generate", headers=gen2_headers)
    assert gen2.status_code == 200, gen2.text

    # Old code should fail now
    resp = await async_client.post(f"{BASE_RECOV}/redeem", headers=access_headers, json={"code": old_code})
    assert resp.status_code == 401


@pytest.mark.anyio
@patch("app.api.v1.auth.recovery_codes._incr_with_ttl", return_value=10_000)
async def test_redeem_rate_limited(mock_incr, async_client: AsyncClient, user_with_headers):
    """
    ❌ Anti-bruteforce counters exceeded → 429.
    """
    _, access_headers = await user_with_headers(email="rc7@example.com", password="Secret123!")
    secret = await _enable_and_verify(async_client, access_headers)
    reauth = await _mint_reauth_mfa(async_client, access_headers, secret)
    gen_headers = _with_ip({"Authorization": f"Bearer {reauth}"}, "203.0.113.9")
    await async_client.post(f"{BASE_RECOV}/generate", headers=gen_headers)

    resp = await async_client.post(f"{BASE_RECOV}/redeem", headers=access_headers, json={"code": "ABCDE-FGHIJ"})
    assert resp.status_code == 429


@pytest.mark.anyio
async def test_redeem_requires_auth(async_client: AsyncClient):
    """❌ Missing bearer → 401/403."""
    resp = await async_client.post(f"{BASE_RECOV}/redeem", json={"code": "ABCDE-FGHIJ"})
    assert resp.status_code in (401, 403)
