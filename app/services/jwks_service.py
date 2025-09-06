from __future__ import annotations

"""
JWKS service (Redis-backed, safe fallbacks)
-------------------------------------------
Provides helpers to manage JSON Web Keys for signature verification and
exposure under `/.well-known/jwks.json`.

Design
------
- Store: Redis JSON under key `jwks:store` with fields:
  { "active_kid": str | None, "keys": [ {meta..., public_jwk, private_jwk?} ] }
- Fallback: in-process memory store when Redis is unavailable (non-persistent).
- Key types: prefer RSA (RS256) if `cryptography` is available; otherwise
  generate an `oct` key (HS256) with a clear warning. Public JWKS will include
  only public parts; `oct` keys are included as-is (not recommended for third
  party verification).

Notes
-----
- This service does not sign tokens; it only manages keys and metadata.
  Signing can later consume `get_active_private_jwk()` when integrated.
"""

from typing import Any, Dict, List, Optional, Tuple
import base64
import json
import os
import time
import secrets
import logging

from app.core.redis_client import redis_wrapper

logger = logging.getLogger("jwks")

_STORE_KEY = "jwks:store"
_MEM_STORE: Dict[str, Any] = {"active_kid": None, "keys": []}


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _now() -> int:
    return int(time.time())


async def _load_store() -> Dict[str, Any]:
    try:
        store = await redis_wrapper.json_get(_STORE_KEY, default=None)
        if isinstance(store, dict) and "keys" in store:
            return store
    except Exception:
        pass
    return dict(_MEM_STORE)


async def _save_store(store: Dict[str, Any]) -> None:
    _MEM_STORE.update(store)
    try:
        await redis_wrapper.json_set(_STORE_KEY, store)
    except Exception:
        # Non-fatal: keep in-memory copy so the process continues to serve
        logger.debug("JWKS: failed to persist to Redis; using in-memory store.")


def _try_gen_rsa(bits: int = 2048) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        key = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
        numbers = key.private_numbers()
        pub = numbers.public_numbers

        n = _b64u(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big"))
        e = _b64u(pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big"))
        d = _b64u(numbers.d.to_bytes((numbers.d.bit_length() + 7) // 8, "big"))
        p = _b64u(numbers.p.to_bytes((numbers.p.bit_length() + 7) // 8, "big"))
        q = _b64u(numbers.q.to_bytes((numbers.q.bit_length() + 7) // 8, "big"))
        dp = _b64u(numbers.dmp1.to_bytes((numbers.dmp1.bit_length() + 7) // 8, "big"))
        dq = _b64u(numbers.dmq1.to_bytes((numbers.dmq1.bit_length() + 7) // 8, "big"))
        qi = _b64u(numbers.iqmp.to_bytes((numbers.iqmp.bit_length() + 7) // 8, "big"))

        pub_jwk = {"kty": "RSA", "n": n, "e": e, "alg": "RS256", "use": "sig"}
        priv_jwk = {**pub_jwk, "d": d, "p": p, "q": q, "dp": dp, "dq": dq, "qi": qi}
        return pub_jwk, priv_jwk
    except Exception:
        return None


def _gen_oct_k() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    raw = secrets.token_bytes(32)  # 256-bit
    k = _b64u(raw)
    jwk = {"kty": "oct", "k": k, "use": "sig", "alg": "HS256"}
    return jwk, jwk


async def rotate_key(*, alg: Optional[str] = None, use: str = "sig", retire_after_seconds: int = 30 * 24 * 3600) -> Dict[str, Any]:
    """Generate a new key (prefer RSA), mark old active as retiring, set new active.

    Returns a dict with metadata and the new public JWK.
    """
    store = await _load_store()

    # prefer RSA (RS256), else fallback to OCT (HS256)
    pair = _try_gen_rsa()
    if pair:
        pub_jwk, priv_jwk = pair
    else:
        logger.warning("JWKS rotate: falling back to symmetric key (oct/HS256); consider installing 'cryptography'.")
        pub_jwk, priv_jwk = _gen_oct_k()

    if alg:
        pub_jwk["alg"] = alg
        priv_jwk["alg"] = alg
    pub_jwk["use"] = use
    priv_jwk["use"] = use

    # kid: random urlsafe
    kid = secrets.token_urlsafe(12)
    pub_jwk["kid"] = kid
    priv_jwk["kid"] = kid

    now = _now()
    # retire existing active
    active_kid = store.get("active_kid")
    for k in store.get("keys", []):
        if k.get("kid") == active_kid and k.get("status") == "active":
            k["status"] = "retiring"
            k["retire_at"] = now + int(retire_after_seconds)

    entry = {
        "kid": kid,
        "use": use,
        "alg": pub_jwk.get("alg"),
        "public_jwk": pub_jwk,
        "private_jwk": priv_jwk,
        "created_at": now,
        "status": "active",
    }
    store.setdefault("keys", []).append(entry)
    store["active_kid"] = kid
    await _save_store(store)
    return {"kid": kid, "public_jwk": pub_jwk}


async def list_keys() -> List[Dict[str, Any]]:
    store = await _load_store()
    out: List[Dict[str, Any]] = []
    for k in store.get("keys", []):
        out.append({
            "kid": k.get("kid"),
            "use": k.get("use"),
            "alg": k.get("alg"),
            "status": k.get("status"),
            "created_at": k.get("created_at"),
            "retire_at": k.get("retire_at"),
        })
    return out


async def delete_key(kid: str) -> bool:
    store = await _load_store()
    if kid == store.get("active_kid"):
        raise ValueError("Cannot delete the active key")
    before = len(store.get("keys", []))
    store["keys"] = [k for k in store.get("keys", []) if k.get("kid") != kid]
    await _save_store(store)
    return len(store.get("keys", [])) < before


async def prune_retired() -> int:
    """Remove keys whose retire_at is in the past or status is retired.
    Returns number of keys removed.
    """
    store = await _load_store()
    now = _now()
    keep: List[Dict[str, Any]] = []
    removed = 0
    for k in store.get("keys", []):
        if k.get("status") == "retired":
            removed += 1
            continue
        ra = k.get("retire_at")
        if isinstance(ra, int) and ra <= now and k.get("kid") != store.get("active_kid"):
            removed += 1
            continue
        keep.append(k)
    store["keys"] = keep
    await _save_store(store)
    return removed


async def get_public_jwks() -> Dict[str, Any]:
    store = await _load_store()
    keys = [k.get("public_jwk") for k in store.get("keys", []) if isinstance(k.get("public_jwk"), dict)]
    return {"keys": keys}


async def get_active_private_jwk() -> Optional[Dict[str, Any]]:
    store = await _load_store()
    active = store.get("active_kid")
    for k in store.get("keys", []):
        if k.get("kid") == active:
            return k.get("private_jwk")
    return None

