# app/services/auth/webauthn_service.py
from __future__ import annotations

"""
WebAuthn Service Adapter
========================

A small façade over your chosen WebAuthn library, so routers don’t depend on
vendor APIs. Swap implementations without touching your endpoints.

- begin_registration(...)  → PublicKeyCredentialCreationOptions dict
- finish_registration(...) → { credential_id, public_key, sign_count, transports?, aaguid? }
- begin_assertion(...)     → PublicKeyCredentialRequestOptions dict
- finish_assertion(...)    → { new_sign_count }

Notes
-----
- This file shows a **python-fido2** style implementation. If you prefer
  Duo's `webauthn` library, you can replace the guts while preserving
  function signatures.
"""

import base64
import json
from typing import Any, Dict, List, Optional

# Utility: URL-safe base64 without padding
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    s_bytes = s.encode()
    s_bytes += b"=" * ((4 - len(s_bytes) % 4) % 4)
    return base64.urlsafe_b64decode(s_bytes)

def extract_challenge_from_client_data(response_dict: Dict[str, Any]) -> Optional[str]:
    """
    Pull challenge from `clientDataJSON`.
    response_dict is the sub-object under credential.response (with clientDataJSON).
    """
    cdata_b64 = response_dict.get("clientDataJSON")
    if not isinstance(cdata_b64, str):
        return None
    try:
        cdata = json.loads(b64url_decode(cdata_b64))
        chall_b64 = cdata.get("challenge")
        if isinstance(chall_b64, str):
            # Some libs encode challenge in base64url again. Accept both direct and b64url.
            try:
                # If it decodes cleanly, re-encode normalized form for Redis keys
                return b64url(b64url_decode(chall_b64))
            except Exception:
                # Already a normalized challenge string
                return chall_b64
        return None
    except Exception:
        return None

# ---------------------------
# Core operations (python-fido2)
# ---------------------------
def _ensure_fido2():
    try:
        # typed imports only when needed
        from fido2.server import Fido2Server
        from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
        from fido2 import cbor
        from fido2.utils import websafe_decode, websafe_encode
        return True
    except Exception:
        return False


def begin_registration(
    *,
    user_id: str,
    username: str,
    rp_id: str,
    rp_name: str,
    origin: str,
    exclude_credential_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Prepare PublicKeyCredentialCreationOptions.
    """
    if not _ensure_fido2():
        # Fall back to a minimal, vendor-neutral structure (for dev/demo)
        import os, secrets
        challenge = b64url(secrets.token_bytes(32))
        exclude_credentials = [{"type": "public-key", "id": cid} for cid in (exclude_credential_ids or [])]
        return {
            "challenge": challenge,
            "rp": {"id": rp_id, "name": rp_name},
            "user": {
                "id": b64url(user_id.encode()),
                "name": username,
                "displayName": username,
            },
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
            "timeout": 60000,
            "attestation": "none",
            "excludeCredentials": exclude_credentials,
            "authenticatorSelection": {"residentKey": "preferred", "userVerification": "preferred"},
        }

    # Real python-fido2 path
    from fido2.server import Fido2Server
    from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

    rp = PublicKeyCredentialRpEntity(id=rp_id, name=rp_name)
    user = PublicKeyCredentialUserEntity(id=user_id.encode(), name=username, display_name=username)
    server = Fido2Server(rp)
    registration_data, state = server.register_begin(
        user,
        credentials=[{"id": b64url_decode(cid), "type": "public-key"} for cid in (exclude_credential_ids or [])],
        user_verification="preferred",
        authenticator_attachment=None,
        resident_key_requirement="preferred",
    )
    # Normalize: ensure challenge is base64url string
    options = registration_data
    options["challenge"] = b64url(options["challenge"])
    options["user"]["id"] = b64url(options["user"]["id"])
    # keep 'state' in caller if you prefer; we do stateless server with challenge instead
    return options


def finish_registration(
    *,
    credential: Dict[str, Any],
    rp_id: str,
    origin: str,
) -> Dict[str, Any]:
    """
    Validate attestation and return a canonical credential record.
    """
    if not _ensure_fido2():
        # Trusting client is NOT secure; use only for offline dev.
        # We’ll parse minimal fields and return.
        cred_id = credential.get("id")
        resp = credential.get("response", {})
        att = resp.get("attestationObject")
        if not (cred_id and att):
            raise ValueError("Invalid credential")
        return {
            "credential_id": cred_id,
            "public_key": "<set-with-real-lib>",
            "sign_count": 0,
            "aaguid": None,
            "transports": credential.get("transports") or [],
        }

    from fido2.server import Fido2Server
    from fido2.webauthn import PublicKeyCredentialRpEntity, AttestedCredentialData
    from fido2.utils import websafe_decode

    rp = PublicKeyCredentialRpEntity(id=rp_id, name="MoviesNow")
    server = Fido2Server(rp)

    client_data = websafe_decode(credential["response"]["clientDataJSON"])
    att_obj = websafe_decode(credential["response"]["attestationObject"])
    auth_data = server.register_complete(
        state=None,  # we are storing by challenge, not using fido2 state
        client_data=client_data,
        attestation_object=att_obj,
    )
    # Extract
    acd: AttestedCredentialData = auth_data.credential_data
    return {
        "credential_id": b64url(acd.credential_id),
        "public_key": acd.public_key,  # COSE key (bytes); store per your model
        "sign_count": auth_data.sign_count or 0,
        "aaguid": str(acd.aaguid) if getattr(acd, "aaguid", None) else None,
        "transports": credential.get("transports") or [],
    }


def begin_assertion(
    *,
    rp_id: str,
    origin: str,
    allow_credential_ids: Optional[List[str]],
    user_verification: str = "preferred",
) -> Dict[str, Any]:
    """
    Prepare PublicKeyCredentialRequestOptions.
    """
    if not _ensure_fido2():
        import secrets
        challenge = b64url(secrets.token_bytes(32))
        allow = [{"type": "public-key", "id": cid} for cid in (allow_credential_ids or [])]
        return {
            "challenge": challenge,
            "rpId": rp_id,
            "timeout": 60000,
            "allowCredentials": allow,
            "userVerification": user_verification, 
        }

    from fido2.server import Fido2Server
    from fido2.webauthn import PublicKeyCredentialRpEntity

    rp = PublicKeyCredentialRpEntity(id=rp_id, name="MoviesNow")
    server = Fido2Server(rp)
    assertion_data, state = server.authenticate_begin(
        credentials=[{"id": b64url_decode(cid), "type": "public-key"} for cid in (allow_credential_ids or [])],
        user_verification=user_verification,
    )
    options = assertion_data
    options["challenge"] = b64url(options["challenge"])
    # Also normalize allowCredentials ids
    for a in options.get("allowCredentials", []):
        try:
            a["id"] = b64url(a["id"])
        except Exception:
            pass
    return options


def finish_assertion(
    *,
    credential: Dict[str, Any],
    rp_id: str,
    origin: str,
    stored_public_key: Any,
    stored_sign_count: int,
) -> Dict[str, Any]:
    """
    Validate an assertion and return updated sign counter.
    """
    if not _ensure_fido2():
        # Dev-only: blindly bump sign count
        return {"new_sign_count": int(stored_sign_count) + 1}

    from fido2.server import Fido2Server
    from fido2.webauthn import PublicKeyCredentialRpEntity
    from fido2.utils import websafe_decode

    rp = PublicKeyCredentialRpEntity(id=rp_id, name="MoviesNow")
    server = Fido2Server(rp)

    # Build "credential_data" as library expects; python-fido2 typically wants an object created at registration.
    # Since we store only pubkey/sign_count, we rely on verify method that accepts those (implementation specific).
    client_data = websafe_decode(credential["response"]["clientDataJSON"])
    authenticator_data = websafe_decode(credential["response"]["authenticatorData"])
    signature = websafe_decode(credential["response"]["signature"])
    # userHandle is optional; may be None
    _ = credential["response"].get("userHandle")

    auth_data = server.authenticate_complete(
        state=None,
        credentials=[{"id": b64url_decode(credential["id"]), "public_key": stored_public_key, "sign_count": stored_sign_count}],
        credential_id=b64url_decode(credential["id"]),
        client_data=client_data,
        auth_data=authenticator_data,
        signature=signature,
    )
    return {"new_sign_count": auth_data.new_sign_count}
