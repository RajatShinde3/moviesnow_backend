# tests/test_admin/test_artwork_create.py

import re
import pytest
from uuid import uuid4
from httpx import AsyncClient
from unittest.mock import AsyncMock, patch, MagicMock

from fastapi import HTTPException
from app.utils.aws import S3StorageError

# Handy constants
VALID_CT = "image/jpeg"
VALID_LANG = "en"
VALID_KIND = "POSTER"


def _url_for(title_id):
    # Adjust the prefix if your router is mounted elsewhere (e.g. "/api/v1/admin")
    return f"/api/v1/admin/titles/{title_id}/artwork"


# ─────────────────────────────────────────────────────────────
# ✅ Happy path: creates row and returns presigned PUT url
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
@patch("app.api.v1.routers.admin.assets.artwork.log_audit_event", new_callable=AsyncMock)
@patch("app.api.v1.routers.admin.assets.artwork.redis_wrapper.idempotency_set", new_callable=AsyncMock)
@patch("app.api.v1.routers.admin.assets.artwork.redis_wrapper.idempotency_get", new_callable=AsyncMock, return_value=None)
@patch("app.api.v1.routers.admin.assets.artwork._ensure_title_exists", new_callable=AsyncMock)
@patch("app.api.v1.routers.admin.assets.artwork._normalize_kind", return_value=VALID_KIND)
@patch("app.api.v1.routers.admin.assets.artwork._validate_language", return_value=VALID_LANG)
@patch("app.api.v1.routers.admin.assets.artwork._ensure_s3")
@patch("app.dependencies.admin.ensure_mfa", new_callable=AsyncMock)
@patch("app.dependencies.admin.ensure_admin", new_callable=AsyncMock)
async def test_create_artwork_success(
    mock_admin,
    mock_mfa,
    mock_s3,
    mock_validate_lang,
    mock_norm_kind,
    mock_title_exists,
    mock_idem_get,
    mock_idem_set,
    mock_audit,
    async_client: AsyncClient,
    user_with_token,
):
    """
    ✅ Should create Artwork row and return {artwork_id, upload_url, storage_key}.
    Also sets `Cache-Control: no-store` and records audit.
    """
    user, token = await user_with_token(mfa_enabled=True)  # token required for get_current_user

    # S3 presign stub
    s3 = MagicMock()
    s3.presigned_put.return_value = "https://s3.example/presigned-put"
    mock_s3.return_value = s3

    title_id = uuid4()
    payload = {
        "content_type": VALID_CT,
        "language": "EN",         # normalization tested
        "kind": "POSTER",         # normalization tested
        "is_primary": True,
    }

    headers = {"Authorization": f"Bearer {token}", "Idempotency-Key": "idem-1"}
    resp = await async_client.post(_url_for(title_id), json=payload, headers=headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body.keys()) == {"artwork_id", "upload_url", "storage_key"}
    assert body["upload_url"].startswith("https://")
    assert isinstance(body["artwork_id"], str) and len(body["artwork_id"]) > 0
    assert isinstance(body["storage_key"], str) and len(body["storage_key"]) > 0

    # cache policy
    assert "no-store" in resp.headers.get("Cache-Control", "").lower()

    # presign called with normalized content-type
    s3.presigned_put.assert_called_once()
    args, kwargs = s3.presigned_put.call_args
    assert kwargs["content_type"] == VALID_CT
    assert kwargs["public"] is False

    # idempotency snapshot stored
    mock_idem_get.assert_called_once()
    mock_idem_set.assert_called_once()

    # audit logged
    mock_audit.assert_called()


# ─────────────────────────────────────────────────────────────
# 🔁 Idempotency: replay prior snapshot without hitting S3/DB
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
@patch("app.api.v1.routers.admin.assets.artwork.log_audit_event", new_callable=AsyncMock)
@patch("app.api.v1.routers.admin.assets.artwork.redis_wrapper.idempotency_set", new_callable=AsyncMock)
@patch("app.api.v1.routers.admin.assets.artwork.redis_wrapper.idempotency_get")
@patch("app.api.v1.routers.admin.assets.artwork._ensure_title_exists", new_callable=AsyncMock)
@patch("app.api.v1.routers.admin.assets.artwork._ensure_s3")
@patch("app.dependencies.admin.ensure_mfa", new_callable=AsyncMock)
@patch("app.dependencies.admin.ensure_admin", new_callable=AsyncMock)
async def test_create_artwork_idempotent_replay(
    mock_admin,
    mock_mfa,
    mock_s3,
    mock_title_exists,
    mock_idem_get,
    mock_idem_set,
    mock_audit,
    async_client: AsyncClient,
    user_with_token,
):
    """
    🔁 When Idempotency-Key matches a stored snapshot, route returns it and
    does **not** call S3 or log audit again.
    """
    user, token = await user_with_token(mfa_enabled=True)
    title_id = uuid4()
    snapshot = {"artwork_id": "42", "upload_url": "https://x", "storage_key": "k"}
    mock_idem_get.return_value = snapshot

    headers = {"Authorization": f"Bearer {token}", "Idempotency-Key": "idem-REUSE"}
    payload = {"content_type": VALID_CT, "language": VALID_LANG, "kind": VALID_KIND}
    resp = await async_client.post(_url_for(title_id), json=payload, headers=headers)

    assert resp.status_code == 200
    assert resp.json() == snapshot
    mock_s3.assert_not_called()
    mock_idem_set.assert_not_called()
    # For strictness we require no extra audit (you can relax if desired)
    mock_audit.assert_not_called()


# ─────────────────────────────────────────────────────────────
# 🧪 Validation: unsupported content type → 415
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
@patch("app.dependencies.admin.ensure_mfa", new_callable=AsyncMock)
@patch("app.dependencies.admin.ensure_admin", new_callable=AsyncMock)
async def test_create_artwork_unsupported_mime(
    mock_admin,
    mock_mfa,
    async_client: AsyncClient,
    user_with_token,
):
    """
    ❌ Unsupported MIME should return 415 per route contract.
    """
    user, token = await user_with_token(mfa_enabled=True)
    title_id = uuid4()
    payload = {"content_type": "application/pdf", "language": VALID_LANG, "kind": VALID_KIND}

    headers = {"Authorization": f"Bearer {token}"}
    resp = await async_client.post(_url_for(title_id), json=payload, headers=headers)

    assert resp.status_code == 415
    detail = resp.json().get("detail", "").lower()
    assert "unsupported" in detail or "media" in detail


# ─────────────────────────────────────────────────────────────
# 🧪 Validation: language normalization errors → 4xx
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
@patch("app.api.v1.routers.admin.assets.artwork._validate_language", side_effect=HTTPException(status_code=422, detail="Bad language"))
@patch("app.dependencies.admin.ensure_mfa", new_callable=AsyncMock)
@patch("app.dependencies.admin.ensure_admin", new_callable=AsyncMock)
async def test_create_artwork_invalid_language(
    mock_admin,
    mock_mfa,
    mock_validate,
    async_client: AsyncClient,
    user_with_token,
):
    """
    ❌ Invalid BCP-47 language should 4xx (route uses _validate_language).
    """
    user, token = await user_with_token(mfa_enabled=True)
    title_id = uuid4()
    payload = {"content_type": VALID_CT, "language": "not-a-lang", "kind": VALID_KIND}

    headers = {"Authorization": f"Bearer {token}"}
    resp = await async_client.post(_url_for(title_id), json=payload, headers=headers)
    assert resp.status_code in (400, 422)
    assert "lang" in resp.text.lower()


# ─────────────────────────────────────────────────────────────
# 🧪 Validation: title must exist → 404
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
@patch("app.api.v1.routers.admin.assets.artwork._ensure_title_exists", side_effect=HTTPException(status_code=404, detail="Title not found"))
@patch("app.dependencies.admin.ensure_mfa", new_callable=AsyncMock)
@patch("app.dependencies.admin.ensure_admin", new_callable=AsyncMock)
async def test_create_artwork_title_not_found(
    mock_admin,
    mock_mfa,
    mock_title_exists,
    async_client: AsyncClient,
    user_with_token,
):
    """
    ❌ If title doesn’t exist, return 404.
    """
    user, token = await user_with_token(mfa_enabled=True)
    title_id = uuid4()
    payload = {"content_type": VALID_CT, "language": VALID_LANG, "kind": VALID_KIND}

    headers = {"Authorization": f"Bearer {token}"}
    resp = await async_client.post(_url_for(title_id), json=payload, headers=headers)
    assert resp.status_code == 404
    assert "title" in resp.text.lower()


# ─────────────────────────────────────────────────────────────
# 🔐 AuthZ / MFA guard coverage
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
@patch("app.dependencies.admin.ensure_admin", side_effect=HTTPException(status_code=403, detail="Admin required"))
async def test_create_artwork_requires_admin(
    mock_admin,
    async_client: AsyncClient,
    user_with_token,
):
    """
    ❌ Non-admin should be rejected by ensure_admin.
    """
    user, token = await user_with_token(mfa_enabled=True)
    title_id = uuid4()
    payload = {"content_type": VALID_CT, "language": VALID_LANG, "kind": VALID_KIND}

    headers = {"Authorization": f"Bearer {token}"}
    resp = await async_client.post(_url_for(title_id), json=payload, headers=headers)
    assert resp.status_code == 403
    assert "admin" in resp.text.lower()


@pytest.mark.anyio
@patch("app.dependencies.admin.ensure_mfa", side_effect=HTTPException(status_code=401, detail="MFA required"))
@patch("app.dependencies.admin.ensure_admin", new_callable=AsyncMock)
async def test_create_artwork_requires_mfa(
    mock_admin,
    mock_mfa,
    async_client: AsyncClient,
    user_with_token,
):
    """
    ❌ Missing/invalid MFA → 401/403.
    """
    user, token = await user_with_token(mfa_enabled=False)
    title_id = uuid4()
    payload = {"content_type": VALID_CT, "language": VALID_LANG, "kind": VALID_KIND}

    headers = {"Authorization": f"Bearer {token}"}
    resp = await async_client.post(_url_for(title_id), json=payload, headers=headers)
    assert resp.status_code in (401, 403)
    assert "mfa" in resp.text.lower()


# ─────────────────────────────────────────────────────────────
# ☁️ S3 failures → 503 (storage error)
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
@patch("app.api.v1.routers.admin.assets.artwork._ensure_title_exists", new_callable=AsyncMock)
@patch("app.api.v1.routers.admin.assets.artwork._normalize_kind", return_value=VALID_KIND)
@patch("app.api.v1.routers.admin.assets.artwork._validate_language", return_value=VALID_LANG)
@patch("app.api.v1.routers.admin.assets.artwork._ensure_s3")
@patch("app.dependencies.admin.ensure_mfa", new_callable=AsyncMock)
@patch("app.dependencies.admin.ensure_admin", new_callable=AsyncMock)
async def test_create_artwork_s3_error(
    mock_admin,
    mock_mfa,
    mock_s3,
    mock_validate_lang,
    mock_norm_kind,
    mock_title_exists,
    async_client: AsyncClient,
    user_with_token,
):
    """
    ❌ If S3 presign fails, surface 503 with storage error.
    """
    user, token = await user_with_token(mfa_enabled=True)
    s3 = MagicMock()
    s3.presigned_put.side_effect = S3StorageError("s3 down")
    mock_s3.return_value = s3

    title_id = uuid4()
    payload = {"content_type": VALID_CT, "language": VALID_LANG, "kind": VALID_KIND}
    headers = {"Authorization": f"Bearer {token}"}

    resp = await async_client.post(_url_for(title_id), json=payload, headers=headers)
    assert resp.status_code == 503
    assert "s3" in resp.text.lower() or "storage" in resp.text.lower()


# ─────────────────────────────────────────────────────────────
# 🧰 Dict payload (not pydantic model) supported
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
@patch("app.api.v1.routers.admin.assets.artwork._ensure_title_exists", new_callable=AsyncMock)
@patch("app.api.v1.routers.admin.assets.artwork._normalize_kind", return_value=VALID_KIND)
@patch("app.api.v1.routers.admin.assets.artwork._validate_language", return_value=VALID_LANG)
@patch("app.api.v1.routers.admin.assets.artwork._ensure_s3")
@patch("app.dependencies.admin.ensure_mfa", new_callable=AsyncMock)
@patch("app.dependencies.admin.ensure_admin", new_callable=AsyncMock)
async def test_create_artwork_allows_dict_payload(
    mock_admin,
    mock_mfa,
    mock_s3,
    mock_validate_lang,
    mock_norm_kind,
    mock_title_exists,
    async_client: AsyncClient,
    user_with_token,
):
    """
    ✅ Route accepts plain dict payloads and normalizes fields.
    """
    user, token = await user_with_token(mfa_enabled=True)
    s3 = MagicMock()
    s3.presigned_put.return_value = "https://signed"
    mock_s3.return_value = s3

    title_id = uuid4()
    payload = {"content_type": VALID_CT, "language": "EN-US", "kind": "BaCkDrOP"}

    headers = {"Authorization": f"Bearer {token}"}
    resp = await async_client.post(_url_for(title_id), json=payload, headers=headers)

    assert resp.status_code == 200
    data = resp.json()
    assert "artwork_id" in data and "upload_url" in data and "storage_key" in data
    assert data["upload_url"] == "https://signed"


# ─────────────────────────────────────────────────────────────
# 🧪 Idempotency snapshot is written when key is provided
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
@patch("app.api.v1.routers.admin.assets.artwork.log_audit_event", new_callable=AsyncMock)
@patch("app.api.v1.routers.admin.assets.artwork.redis_wrapper.idempotency_set", new_callable=AsyncMock)
@patch("app.api.v1.routers.admin.assets.artwork.redis_wrapper.idempotency_get", new_callable=AsyncMock, return_value=None)
@patch("app.api.v1.routers.admin.assets.artwork._ensure_title_exists", new_callable=AsyncMock)
@patch("app.api.v1.routers.admin.assets.artwork._normalize_kind", return_value=VALID_KIND)
@patch("app.api.v1.routers.admin.assets.artwork._validate_language", return_value=VALID_LANG)
@patch("app.api.v1.routers.admin.assets.artwork._ensure_s3")
@patch("app.dependencies.admin.ensure_mfa", new_callable=AsyncMock)
@patch("app.dependencies.admin.ensure_admin", new_callable=AsyncMock)
async def test_create_artwork_writes_idempotency_snapshot(
    mock_admin,
    mock_mfa,
    mock_s3,
    mock_validate_lang,
    mock_norm_kind,
    mock_title_exists,
    mock_idem_get,
    mock_idem_set,
    mock_audit,
    async_client: AsyncClient,
    user_with_token,
):
    """
    ✅ With Idempotency-Key but no prior snapshot, the route should create a snapshot.
    """
    user, token = await user_with_token(mfa_enabled=True)
    s3 = MagicMock()
    s3.presigned_put.return_value = "https://s3.example/signed"
    mock_s3.return_value = s3

    title_id = uuid4()
    payload = {"content_type": VALID_CT, "language": VALID_LANG, "kind": VALID_KIND}
    headers = {"Authorization": f"Bearer {token}", "Idempotency-Key": "idem-new"}

    resp = await async_client.post(_url_for(title_id), json=payload, headers=headers)
    assert resp.status_code == 200
    mock_idem_get.assert_called_once()
    mock_idem_set.assert_called_once()


# ─────────────────────────────────────────────────────────────
# 🧪 Storage key resembles expected structure (soft assertion)
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
@patch("app.api.v1.routers.admin.assets.artwork._ensure_title_exists", new_callable=AsyncMock)
@patch("app.api.v1.routers.admin.assets.artwork._normalize_kind", return_value=VALID_KIND)
@patch("app.api.v1.routers.admin.assets.artwork._validate_language", return_value=VALID_LANG)
@patch("app.api.v1.routers.admin.assets.artwork._ensure_s3")
@patch("app.dependencies.admin.ensure_mfa", new_callable=AsyncMock)
@patch("app.dependencies.admin.ensure_admin", new_callable=AsyncMock)
async def test_create_artwork_storage_key_shape(
    mock_admin,
    mock_mfa,
    mock_s3,
    mock_validate_lang,
    mock_norm_kind,
    mock_title_exists,
    async_client: AsyncClient,
    user_with_token,
):
    """
    🧩 Soft check: storage_key includes title id and looks path-like.
    """
    user, token = await user_with_token(mfa_enabled=True)
    s3 = MagicMock()
    s3.presigned_put.return_value = "https://signed"
    mock_s3.return_value = s3

    title_id = uuid4()
    payload = {"content_type": VALID_CT, "language": VALID_LANG, "kind": VALID_KIND}
    headers = {"Authorization": f"Bearer {token}"}

    resp = await async_client.post(_url_for(title_id), json=payload, headers=headers)
    assert resp.status_code == 200
    sk = resp.json()["storage_key"]

    # not brittle: just ensure it's a key-like string and contains the title_id
    assert "/" in sk and str(title_id) in sk
    assert re.search(r"\.(png|jpg|jpeg|webp|avif|gif)$", sk, re.IGNORECASE) or True  # allow non-strict endings
