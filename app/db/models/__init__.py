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
from .user import User
from .token import RefreshToken
from .otp import OTP
from .mfa_reset_token import MFAResetToken
from .profile import Profile
from .audit_log import AuditLog

# ───────────────────────────────────────────────────────────────
# Catalog: Titles, Structure, Media, People, Credits
# ───────────────────────────────────────────────────────────────
from .title import Title
from .season import Season
from .episode import Episode
from .genre import Genre
from .title_genres import TitleGenre  # M2M association

from .media_asset import MediaAsset
from .stream_variant import StreamVariant
from .artwork import Artwork

from .person import Person
from .credit import Credit

# ───────────────────────────────────────────────────────────────
# Rights, Compliance, Localization
# ───────────────────────────────────────────────────────────────
from .availability import Availability
from .compliance import Certification, ContentAdvisory
from .subtitle import Subtitle

# ───────────────────────────────────────────────────────────────
# Engagement, Playback, Social
# ───────────────────────────────────────────────────────────────
from .progress import Progress
from .playback_session import PlaybackSession
from .review import Review
from .watchlist import WatchlistItem
from .collection import Collection, CollectionItem
