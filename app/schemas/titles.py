from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class QualityEnum(str, Enum):
    auto = "auto"
    q240p = "240p"
    q480p = "480p"
    q720p = "720p"
    q1080p = "1080p"
    q2160p = "2160p"


class TitleSummary(BaseModel):
    id: str
    name: str
    year: Optional[int] = None
    poster_url: Optional[str] = None
    genres: List[str] = []
    rating: Optional[float] = None


class TitleDetail(TitleSummary):
    synopsis: Optional[str] = None
    runtime_minutes: Optional[int] = None
    released_at: Optional[int] = None  # epoch seconds
    backdrop_url: Optional[str] = None
    tags: List[str] = []


class StreamVariant(BaseModel):
    quality: QualityEnum
    bitrate_kbps: Optional[int] = None
    codec: Optional[str] = Field(None, description="e.g., h264, h265")
    container: Optional[str] = Field(None, description="e.g., mp4, m3u8")
    drm: Optional[bool] = False


class SubtitleTrack(BaseModel):
    lang: str
    label: Optional[str] = None
    format: Optional[str] = Field("vtt", description="vtt, srt, ttml, ...")


class Credit(BaseModel):
    name: str
    role: str  # actor, director, writer, etc.
    character: Optional[str] = None
    order: Optional[int] = None


class PaginatedTitles(BaseModel):
    items: List[TitleSummary]
    page: int
    page_size: int
    total: int
    facets: Optional[Dict[str, Any]] = None
