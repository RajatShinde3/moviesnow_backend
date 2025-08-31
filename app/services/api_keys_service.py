from __future__ import annotations

"""
Admin-managed API Keys using Redis (no DB migration required).

Storage model
-------------
- Key record: `api_keys:{id}` -> JSON { id, hash, label, scopes, created_at, expires_at, disabled, prefix }
- Index set : `api_keys:index` -> Set of key ids (may accumulate stale ids; listing prunes)

Security
--------
- Store only SHA-256 of the secret; the plaintext is returned on creation/rotation only.
- Key id is a random URL-safe token with `ak_` prefix for easy identification.
- Scopes are arbitrary strings decided by admins; enforcement is up to callers.
"""

from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta, timezone
import secrets
import hashlib

from app.core.redis_client import redis_wrapper


API_PREFIX = "api_keys"
INDEX_KEY = f"{API_PREFIX}:index"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _new_id() -> str:
    return "ak_" + secrets.token_urlsafe(12).replace("-", "").replace("_", "").lower()


def _new_secret() -> str:
    return "sk_" + secrets.token_urlsafe(32)


async def create_api_key(*, label: Optional[str], scopes: List[str], ttl_days: Optional[int]) -> Dict[str, Any]:
    """Create an API key and persist metadata in Redis.

    Returns a record including the plaintext `secret` only on creation.
    """
    key_id = _new_id()
    secret = _new_secret()
    record_key = f"{API_PREFIX}:{key_id}"
    now = _now_iso()
    expires_at: Optional[str] = None
    if ttl_days and ttl_days > 0:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=int(ttl_days))).isoformat()

    rec: Dict[str, Any] = {
        "id": key_id,
        "hash": _sha256_hex(secret),
        "label": label or "",
        "scopes": list(sorted(set(scopes or []))),
        "created_at": now,
        "expires_at": expires_at,
        "disabled": False,
        "prefix": key_id[:6],
    }

    # Store JSON with TTL if exp is set
    ttl_sec = None
    if expires_at:
        try:
            ttl_sec = int((datetime.fromisoformat(expires_at) - datetime.now(timezone.utc)).total_seconds())
        except Exception:
            ttl_sec = None
    await redis_wrapper.json_set(record_key, rec, ttl_seconds=ttl_sec)
    try:
        await redis_wrapper.client.sadd(INDEX_KEY, key_id)
    except Exception:
        pass

    return {**rec, "secret": secret}


async def get_api_key(key_id: str) -> Optional[Dict[str, Any]]:
    rec = await redis_wrapper.json_get(f"{API_PREFIX}:{key_id}", default=None)
    return rec


async def list_api_keys() -> List[Dict[str, Any]]:
    # Get ids from index, then load existing ones
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
            # mask secret; only show prefix
            out.append({
                "id": rec.get("id"),
                "label": rec.get("label"),
                "scopes": rec.get("scopes", []),
                "created_at": rec.get("created_at"),
                "expires_at": rec.get("expires_at"),
                "disabled": rec.get("disabled", False),
                "prefix": rec.get("prefix"),
            })
        else:
            # prune stale ids best-effort
            try:
                await redis_wrapper.client.srem(INDEX_KEY, kid)
            except Exception:
                pass
    return out


async def delete_api_key(key_id: str) -> bool:
    try:
        await redis_wrapper.client.delete(f"{API_PREFIX}:{key_id}")
        await redis_wrapper.client.srem(INDEX_KEY, key_id)
        return True
    except Exception:
        return False


async def update_api_key(
    *,
    key_id: str,
    label: Optional[str] = None,
    scopes: Optional[List[str]] = None,
    disabled: Optional[bool] = None,
    rotate: bool = False,
    ttl_days: Optional[int] = None,
) -> Dict[str, Any]:
    rec = await get_api_key(key_id)
    if not rec:
        raise KeyError("API key not found")

    if label is not None:
        rec["label"] = label
    if scopes is not None:
        rec["scopes"] = list(sorted(set(scopes)))
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
            exp = datetime.now(timezone.utc) + timedelta(days=int(ttl_days))
            rec["expires_at"] = exp.isoformat()
            ttl_sec = int((exp - datetime.now(timezone.utc)).total_seconds())
    else:
        ttl_sec = None

    await redis_wrapper.json_set(f"{API_PREFIX}:{key_id}", rec, ttl_seconds=ttl_sec)
    out = rec.copy()
    if new_secret:
        out["secret"] = new_secret
    return out


__all__ = [
    "create_api_key",
    "get_api_key",
    "list_api_keys",
    "delete_api_key",
    "update_api_key",
]

