# app/services/api_keys_service.py
"""
Admin-managed API Keys using Redis (no migrations)
==================================================

Storage model
-------------
- Record key : `api_keys:{id}` → JSON:
    {
      id, hash, label, scopes[], created_at, expires_at|null,
      disabled: bool, prefix: str
    }
- Index set  : `api_keys:index` → set of key ids (listing prunes stale ids)

Security
--------
- **Never** store plaintext secrets. Persist SHA-256 hash only.
- Return plaintext `secret` **only** from `create_api_key` or when `rotate=True`.
- Callers enforce scopes/authorization; this service manages lifecycle only.

Operational Practices
---------------------
- TTL is applied to the JSON record when `expires_at` is set.
- Listing prunes stale index entries best-effort.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta, timezone
import secrets
import hashlib
import hmac

from app.core.redis_client import redis_wrapper

API_PREFIX = "api_keys"
INDEX_KEY = f"{API_PREFIX}:index"


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now_utc().isoformat()


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _ct_eq(a: str, b: str) -> bool:
    """Constant-time equality for hash comparisons."""
    return hmac.compare_digest(a, b)


def _new_id() -> str:
    # Short, URL-safe, prefixed for easy identification
    return "ak_" + secrets.token_urlsafe(12).replace("-", "").replace("_", "").lower()


def _new_secret() -> str:
    return "sk_" + secrets.token_urlsafe(32)


def _ttl_seconds_until(iso_dt: Optional[str]) -> Optional[int]:
    if not iso_dt:
        return None
    try:
        exp = datetime.fromisoformat(iso_dt)
        if not exp.tzinfo:
            exp = exp.replace(tzinfo=timezone.utc)
        delta = int((exp - _now_utc()).total_seconds())
        return max(delta, 0)
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# ➕ Create
# ─────────────────────────────────────────────────────────────────────────────
async def create_api_key(*, label: Optional[str], scopes: List[str], ttl_days: Optional[int]) -> Dict[str, Any]:
    """Create an API key and persist metadata in Redis.

    Returns
    -------
    Dict[str, Any]
        Record including the plaintext `secret` (returned only on creation).
    """
    key_id = _new_id()
    # Extremely unlikely collision; retry tiny loop to be safe.
    for _ in range(3):
        exists = await redis_wrapper.json_get(f"{API_PREFIX}:{key_id}", default=None)
        if not exists:
            break
        key_id = _new_id()

    secret = _new_secret()
    now = _now_iso()

    # Sanitize scopes & TTL
    scopes = list(sorted(set(scopes or [])))
    expires_at: Optional[str] = None
    if ttl_days and ttl_days > 0:
        days = max(1, min(int(ttl_days), 365))
        expires_at = (_now_utc() + timedelta(days=days)).isoformat()

    rec: Dict[str, Any] = {
        "id": key_id,
        "hash": _sha256_hex(secret),
        "label": (label or "").strip(),
        "scopes": scopes,
        "created_at": now,
        "expires_at": expires_at,
        "disabled": False,
        "prefix": key_id[:6],
    }

    # Store JSON with TTL if exp is set
    await redis_wrapper.json_set(f"{API_PREFIX}:{key_id}", rec, ttl_seconds=_ttl_seconds_until(expires_at))
    try:
        await redis_wrapper.client.sadd(INDEX_KEY, key_id)
    except Exception:
        pass

    return {**rec, "secret": secret}


# ─────────────────────────────────────────────────────────────────────────────
# 🔎 Get
# ─────────────────────────────────────────────────────────────────────────────
async def get_api_key(key_id: str) -> Optional[Dict[str, Any]]:
    return await redis_wrapper.json_get(f"{API_PREFIX}:{key_id}", default=None)


# ─────────────────────────────────────────────────────────────────────────────
# 📚 List (masked)
# ─────────────────────────────────────────────────────────────────────────────
async def list_api_keys() -> List[Dict[str, Any]]:
    ids: List[str] = []
    try:
        raw = await redis_wrapper.client.smembers(INDEX_KEY)
        ids = [i.decode() if isinstance(i, (bytes, bytearray)) else str(i) for i in (raw or set())]
    except Exception:
        ids = []

    out: List[Dict[str, Any]] = []
    for kid in ids:
        rec = await get_api_key(kid)
        if rec:
            out.append({
                "id": rec.get("id"),
                "label": rec.get("label"),
                "scopes": rec.get("scopes", []),
                "created_at": rec.get("created_at"),
                "expires_at": rec.get("expires_at"),
                "disabled": bool(rec.get("disabled", False)),
                "prefix": rec.get("prefix"),
            })
        else:
            # prune stale ids best-effort
            try:
                await redis_wrapper.client.srem(INDEX_KEY, kid)
            except Exception:
                pass
    return out


# ─────────────────────────────────────────────────────────────────────────────
# 🗑️ Delete
# ─────────────────────────────────────────────────────────────────────────────
async def delete_api_key(key_id: str) -> bool:
    """Delete key record and remove from index. Returns True if deleted."""
    try:
        await redis_wrapper.client.delete(f"{API_PREFIX}:{key_id}")
        await redis_wrapper.client.srem(INDEX_KEY, key_id)
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# ✏️ Update / Rotate
# ─────────────────────────────────────────────────────────────────────────────
async def update_api_key(
    *,
    key_id: str,
    label: Optional[str] = None,
    scopes: Optional[List[str]] = None,
    disabled: Optional[bool] = None,
    rotate: bool = False,
    ttl_days: Optional[int] = None,
) -> Dict[str, Any]:
    """Update mutable fields; when `rotate=True`, return a new plaintext `secret`."""
    rec = await get_api_key(key_id)
    if not rec:
        raise KeyError("API key not found")

    if label is not None:
        rec["label"] = (label or "").strip()
    if scopes is not None:
        rec["scopes"] = list(sorted(set(scopes or [])))
    if disabled is not None:
        rec["disabled"] = bool(disabled)

    new_secret: Optional[str] = None
    if rotate:
        new_secret = _new_secret()
        rec["hash"] = _sha256_hex(new_secret)

    if ttl_days is not None:
        if ttl_days <= 0:
            rec["expires_at"] = None
            ttl_sec = None
        else:
            days = max(1, min(int(ttl_days), 365))
            exp = _now_utc() + timedelta(days=days)
            rec["expires_at"] = exp.isoformat()
            ttl_sec = _ttl_seconds_until(rec["expires_at"])
    else:
        ttl_sec = _ttl_seconds_until(rec.get("expires_at"))

    await redis_wrapper.json_set(f"{API_PREFIX}:{key_id}", rec, ttl_seconds=ttl_sec)

    out = rec.copy()
    if new_secret:
        out["secret"] = new_secret
    return out


# ─────────────────────────────────────────────────────────────────────────────
# ✅ Verification helper (optional for enforcement integration)
# ─────────────────────────────────────────────────────────────────────────────
async def verify_api_key(secret: str) -> Optional[Dict[str, Any]]:
    """Given a presented plaintext secret, return key record if valid & active.

    This expects the caller to provide **key id prefix** (first 6 chars) in the
    header alongside the secret, or to have resolved the key id out-of-band.
    If you plan to use this directly, maintain your own secondary index.
    """
    # NOTE: Without a reverse index, verifying by secret requires iteration.
    # For performance, prefer building a `api_keys:by_prefix:{prefix}` → id mapping
    # during create/rotate and use that to fetch the candidate record first.
    return None  # Provided as a placeholder for future middleware integration.


__all__ = [
    "create_api_key",
    "get_api_key",
    "list_api_keys",
    "delete_api_key",
    "update_api_key",
    "verify_api_key",
]
