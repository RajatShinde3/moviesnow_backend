# app/db/base.py
"""
MoviesNow — SQLAlchemy Base registry
====================================

Import all ORM models so their tables are registered on `Base.metadata`.
This is useful for Alembic autogeneration and ensures relationship
backrefs resolve at import time.

Tip: Keep this file import-only; no runtime logic.
"""

from app.db.base_class import Base

# ───────────────────────────────────────────────────────────────
# Core: Users, Auth, Profile, Audit
# ───────────────────────────────────────────────────────────────
from app.db.models.user import User
from app.db.models.token import RefreshToken
from app.db.models.otp import OTP
from app.db.models.mfa_reset_token import MFAResetToken
from app.db.models.profile import Profile
from app.db.models.audit_log import AuditLog
# ───────────────────────────────────────────────────────────────
# Catalog: Titles, Structure, Media, People, Credits
# ───────────────────────────────────────────────────────────────
from app.db.models.title import Title
from app.db.models.season import Season
from app.db.models.episode import Episode
from app.db.models.genre import Genre
from app.db.models.title_genres import TitleGenre  # M2M association

from app.db.models.media_asset import MediaAsset
from app.db.models.stream_variant import StreamVariant
from app.db.models.artwork import Artwork
from app.db.models.bundle import Bundle

from app.db.models.person import Person
from app.db.models.credit import Credit

# ───────────────────────────────────────────────────────────────
# Rights, Compliance, Localization
# ───────────────────────────────────────────────────────────────
from app.db.models.availability import Availability
from app.db.models.compliance import Certification, ContentAdvisory
from app.db.models.subtitle import Subtitle

# ───────────────────────────────────────────────────────────────
# Engagement, Playback, Social
# ───────────────────────────────────────────────────────────────
from app.db.models.progress import Progress
from app.db.models.playback_session import PlaybackSession
from app.db.models.review import Review
from app.db.models.watchlist import WatchlistItem
from app.db.models.collection import Collection, CollectionItem

# ───────────────────────────────────────────────────────────────
# Public exports (helps linters; clarifies registry)
# ───────────────────────────────────────────────────────────────
__all__ = [
    # Base
    "Base",
    # Core
    "User",
    "RefreshToken",
    "OTP",
    "MFAResetToken",
    "Profile",
    "AuditLog",
    "WebAuthnCredential",
    # Catalog
    "Title",
    "Season",
    "Episode",
    "Genre",
    "TitleGenre",
    "MediaAsset",
    "StreamVariant",
    "Artwork",
    "Bundle",
    "Person",
    "Credit",
    # Rights/Compliance/Localization
    "Availability",
    "Certification",
    "ContentAdvisory",
    "Subtitle",
    # Engagement/Playback/Social
    "Progress",
    "PlaybackSession",
    "Review",
    "WatchlistItem",
    "Collection",
    "CollectionItem",
]
