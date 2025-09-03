from __future__ import annotations

"""
MoviesNow • Media Schemas & Enums
=================================

Purpose
-------
- Centralize media-related Pydantic enums used by models and APIs.
- Keep values stable for DB enums (uppercase strings).

Design
------
- Asset container separate from stream container to allow MKV originals.
- Simple stereoscopic mode enum for 3D assets.
- Lifecycle class enum to hint storage tiers (hot/warm/archive).

Security / Performance / Failure Modes
--------------------------------------
- Only string-backed enums (safe JSON+DB serialization).
- Do not rename enum values once deployed (DB type depends on them).
- Any API accepting these should validate inputs early and return 400 on bad values.
"""

from enum import Enum as PyEnum
from pydantic import BaseModel
from typing import Optional


# === Enums ================================================================

class AssetContainer(str, PyEnum):
    """Container used by stored assets (originals/downloads).

    Note: Separate from stream container to allow MKV for originals.
    """
    MKV = "MKV"
    MP4 = "MP4"
    TS = "TS"


class StereoscopicMode(str, PyEnum):
    """Stereoscopic encoding for 3D video assets."""
    MONO = "MONO"
    SBS = "SBS"   # Side-by-side
    TB = "TB"     # Top/bottom


class LifecycleClass(str, PyEnum):
    """Desired storage lifecycle hint for the object."""
    HOT = "HOT"
    WARM = "WARM"
    ARCHIVE = "ARCHIVE"


# === Minimal API models (shared) ==========================================

class BundleCreate(BaseModel):
    """Input for creating a season bundle (ZIP) upload slot."""
    season_number: Optional[int] = None
    episode_ids: Optional[list[str]] = None
    ttl_days: Optional[int] = None  # override default expiry (guarded in router)


class BundleOut(BaseModel):
    """Public view of a bundle for listings."""
    id: str
    title_id: str
    season_number: Optional[int] = None
    storage_key: str
    size_bytes: Optional[int] = None
    sha256: Optional[str] = None
    expires_at: Optional[str] = None
    label: Optional[str] = None

