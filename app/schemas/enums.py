# app/schemas/enums.py
from __future__ import annotations

"""
Central enum definitions used across MoviesNow.

Design notes
------------
• All enums subclass `str, PyEnum` for JSON-friendly serialization.
• Keep VALUE STRINGS stable once deployed (DB enums depend on them).
• Grouped by domain for clarity; add to `__all__` when introducing new enums.
"""

from enum import Enum as PyEnum


# ──────────────────────────────────────────────────────────────
# Auth / Org
# ──────────────────────────────────────────────────────────────
class LoginMode(str, PyEnum):
    """Mode of login: personal account vs organization context."""
    PERSONAL = "personal"
    ORGANIZATION = "organization"


class OrgRole(str, PyEnum):
    """User role within an organization."""
    ADMIN = "ADMIN"
    USER = "USER"


class ExportFormat(str, PyEnum):
    """Supported export formats for reports/exports."""
    csv = "csv"
    xlsx = "xlsx"


# ──────────────────────────────────────────────────────────────
# Streaming Delivery Stack (unified)
# ──────────────────────────────────────────────────────────────
class StreamProtocol(str, PyEnum):
    """Primary streaming protocol used for playback."""
    HLS = "HLS"   # HTTP Live Streaming
    DASH = "DASH" # MPEG-DASH
    MP4 = "MP4"   # Progressive (direct file) — also used for downloads


class Container(str, PyEnum):
    """Container used by a stream/asset."""
    TS = "TS"       # MPEG-TS (legacy HLS)
    FMP4 = "FMP4"   # CMAF / fragmented MP4 (HLS/DASH)
    MP4 = "MP4"     # Progressive MP4


class VideoCodec(str, PyEnum):
    """Video codec identifiers."""
    H264 = "H264"
    H265 = "H265"   # HEVC
    VP9  = "VP9"
    AV1  = "AV1"
    NONE = "NONE"   # audio-only stream


class AudioCodec(str, PyEnum):
    """Audio codec identifiers."""
    AAC  = "AAC"
    AC3  = "AC3"
    EAC3 = "EAC3"   # Dolby Digital Plus
    OPUS = "OPUS"
    NONE = "NONE"   # video-only stream


class DRMType(str, PyEnum):
    """DRM system negotiated for playback."""
    NONE = "NONE"
    WIDEVINE = "WIDEVINE"
    FAIRPLAY = "FAIRPLAY"
    PLAYREADY = "PLAYREADY"


class HDRFormat(str, PyEnum):
    """High Dynamic Range format."""
    SDR = "SDR"
    HDR10 = "HDR10"
    HLG = "HLG"
    DOLBY_VISION = "DOLBY_VISION"


# ──────────────────────────────────────────────────────────────
# Artwork / Imagery
# ──────────────────────────────────────────────────────────────
class ArtworkKind(str, PyEnum):
    """Classifier for image usage/placement."""
    POSTER = "POSTER"
    BACKDROP = "BACKDROP"
    LOGO = "LOGO"
    THUMBNAIL = "THUMBNAIL"
    STILL = "STILL"
    BANNER = "BANNER"
    CARD = "CARD"


# ──────────────────────────────────────────────────────────────
# Rights / Availability
# ──────────────────────────────────────────────────────────────
class TerritoryMode(str, PyEnum):
    GLOBAL  = "GLOBAL"   # worldwide, no country filtering
    INCLUDE = "INCLUDE"  # only in listed countries
    EXCLUDE = "EXCLUDE"  # everywhere except listed countries


class DistributionKind(str, PyEnum):
    SVOD = "SVOD"   # subscription VOD
    AVOD = "AVOD"   # ad-supported VOD
    TVOD = "TVOD"   # transactional (rental)
    EST  = "EST"    # electronic sell-through (purchase)
    FREE = "FREE"   # free (often with ads)


class DeviceClass(str, PyEnum):
    WEB = "WEB"
    MOBILE = "MOBILE"
    TV = "TV"
    TABLET = "TABLET"
    CONSOLE = "CONSOLE"
    OTHER = "OTHER"


# ──────────────────────────────────────────────────────────────
# Collections
# ──────────────────────────────────────────────────────────────
class CollectionVisibility(str, PyEnum):
    PUBLIC = "PUBLIC"
    UNLISTED = "UNLISTED"
    PRIVATE = "PRIVATE"


class CollectionKind(str, PyEnum):
    FRANCHISE = "FRANCHISE"
    THEME = "THEME"
    EDITORIAL = "EDITORIAL"
    PLAYLIST = "PLAYLIST"
    SERIES_SET = "SERIES_SET"


# ──────────────────────────────────────────────────────────────
# Compliance (Certifications & Advisories)
# ──────────────────────────────────────────────────────────────
class CertificationSystem(str, PyEnum):
    """Common rating boards (extend as needed)."""
    MPAA_US = "MPAA_US"   # films: G/PG/PG-13/R/NC-17
    TVPG_US = "TVPG_US"   # TV: TV-Y/TV-PG/TV-MA
    BBFC_UK = "BBFC_UK"   # U/PG/12A/15/18
    CBFC_IN = "CBFC_IN"   # U/U-A/A/S
    FSK_DE = "FSK_DE"     # 0/6/12/16/18
    ACB_AU = "ACB_AU"     # G/PG/M/MA15+/R18+
    OFLC_NZ = "OFLC_NZ"
    EIRIN_JP = "EIRIN_JP"
    CNC_FR = "CNC_FR"
    IFCO_IE = "IFCO_IE"
    OTHER = "OTHER"


class AdvisoryKind(str, PyEnum):
    """High-level advisory categories."""
    VIOLENCE = "VIOLENCE"
    SEXUAL_CONTENT = "SEXUAL_CONTENT"
    NUDITY = "NUDITY"
    LANGUAGE = "LANGUAGE"
    DRUGS = "DRUGS"
    ALCOHOL_TOBACCO = "ALCOHOL_TOBACCO"
    HORROR_FRIGHTENING = "HORROR_FRIGHTENING"
    SUICIDE_SELF_HARM = "SUICIDE_SELF_HARM"
    DISCRIMINATION = "DISCRIMINATION"
    BLOOD_GORE = "BLOOD_GORE"
    MATURE_THEMES = "MATURE_THEMES"
    GAMBLING = "GAMBLING"
    SPOILERS = "SPOILERS"
    OTHER = "OTHER"


class AdvisorySeverity(str, PyEnum):
    """Simple intensity scale."""
    NONE = "NONE"
    MILD = "MILD"
    MODERATE = "MODERATE"
    SEVERE = "SEVERE"


# ──────────────────────────────────────────────────────────────
# Credits / People
# ──────────────────────────────────────────────────────────────
class CreditKind(str, PyEnum):
    """Top-level credit category."""
    CAST = "cast"
    CREW = "crew"


class CreditRole(str, PyEnum):
    """Common credit roles (expand pragmatically as catalog grows)."""
    # Cast
    ACTOR = "actor"
    VOICE = "voice"
    GUEST_STAR = "guest_star"
    CAMEO = "cameo"

    # Crew
    DIRECTOR = "director"
    WRITER = "writer"
    PRODUCER = "producer"
    EXECUTIVE_PRODUCER = "executive_producer"
    SHOWRUNNER = "showrunner"
    CREATOR = "creator"
    COMPOSER = "composer"
    EDITOR = "editor"
    CINEMATOGRAPHER = "cinematographer"
    COSTUME_DESIGNER = "costume_designer"
    VFX_SUPERVISOR = "vfx_supervisor"
    SOUND_MIXER = "sound_mixer"
    MUSIC_SUPERVISOR = "music_supervisor"
    STUNT_COORDINATOR = "stunt_coordinator"
    OTHER = "other"


class PersonGender(str, PyEnum):
    """Lightweight gender taxonomy for display & filtering."""
    MALE = "male"
    FEMALE = "female"
    NON_BINARY = "non_binary"
    OTHER = "other"
    UNKNOWN = "unknown"


# ──────────────────────────────────────────────────────────────
# Asset Taxonomy
# ──────────────────────────────────────────────────────────────
class MediaAssetKind(str, PyEnum):
    """Classifier for asset kind."""
    POSTER = "poster"
    BACKDROP = "backdrop"
    BANNER = "banner"
    THUMBNAIL = "thumbnail"
    STILL = "still"
    TRAILER = "trailer"
    TEASER = "teaser"
    CLIP = "clip"
    VIDEO = "video"
    IMAGE = "image"
    SUBTITLE = "subtitle"
    CAPTION = "caption"
    AUDIO = "audio"


# ──────────────────────────────────────────────────────────────
# Playback / Telemetry
# ──────────────────────────────────────────────────────────────
class PlaybackStatus(str, PyEnum):
    """Session lifecycle state."""
    INITIATED = "INITIATED"  # created, before first render
    PLAYING   = "PLAYING"    # actively rendering frames
    PAUSED    = "PAUSED"     # paused by user/app
    ENDED     = "ENDED"      # ended normally or with a reason
    ABORTED   = "ABORTED"    # crashed/closed without graceful end


class EndReason(str, PyEnum):
    """Why a playback session ended."""
    COMPLETED = "COMPLETED"   # reached end of content
    USER_EXIT = "USER_EXIT"   # user navigated away/closed
    ERROR     = "ERROR"       # unrecoverable playback error
    TIMEOUT   = "TIMEOUT"     # idle/pause timeout
    NETWORK   = "NETWORK"     # network loss or congestion
    DRM       = "DRM"         # license/DRM failure
    UNKNOWN   = "UNKNOWN"


class ProgressStatus(str, PyEnum):
    """High-level per-item progress state."""
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    RESET = "RESET"           # user scrubbed back / started over
    ABANDONED = "ABANDONED"   # explicitly abandoned or long-idle


# ──────────────────────────────────────────────────────────────
# Moderation / Reviews
# ──────────────────────────────────────────────────────────────
class ModerationStatus(str, PyEnum):
    """Lifecycle of a review in the moderation system."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REMOVED = "REMOVED"  # admin hard-remove but keep row for audit


# ──────────────────────────────────────────────────────────────
# Subtitles
# ──────────────────────────────────────────────────────────────
class SubtitleFormat(str, PyEnum):
    """Subtitle/caption file formats."""
    SRT = "SRT"
    VTT = "VTT"        # WebVTT
    ASS = "ASS"
    TTML = "TTML"      # IMSC/TTML/DFXP family
    SCC = "SCC"
    SMI = "SMI"
    UNKNOWN = "UNKNOWN"


# ──────────────────────────────────────────────────────────────
# Titles
# ──────────────────────────────────────────────────────────────
class TitleType(str, PyEnum):
    MOVIE = "MOVIE"
    SERIES = "SERIES"


class TitleStatus(str, PyEnum):
    ANNOUNCED = "ANNOUNCED"
    IN_PRODUCTION = "IN_PRODUCTION"
    RELEASED = "RELEASED"
    ENDED = "ENDED"
    CANCELED = "CANCELED"
    HIATUS = "HIATUS"


__all__ = [
    # Auth / Org
    "LoginMode", "OrgRole", "ExportFormat",
    # Streaming
    "StreamProtocol", "Container", "VideoCodec", "AudioCodec", "DRMType", "HDRFormat",
    # Artwork
    "ArtworkKind",
    # Rights
    "TerritoryMode", "DistributionKind", "DeviceClass",
    # Collections
    "CollectionVisibility", "CollectionKind",
    # Compliance
    "CertificationSystem", "AdvisoryKind", "AdvisorySeverity",
    # Credits / People
    "CreditKind", "CreditRole", "PersonGender",
    # Assets
    "MediaAssetKind",
    # Playback / Progress
    "PlaybackStatus", "EndReason", "ProgressStatus",
    # Moderation
    "ModerationStatus",
    # Subtitles
    "SubtitleFormat",
    # Titles
    "TitleType", "TitleStatus",
]
