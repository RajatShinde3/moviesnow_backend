from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field

from app.schemas.enums import TitleType


class ScheduleItem(BaseModel):
    id: str
    type: TitleType
    name: str
    slug: Optional[str] = None
    release_at: int = Field(..., description="UTC epoch seconds when it releases in the region")
    region: str = Field(..., description="ISO-3166-1 alpha-2 country code or 'WW' for worldwide")
    is_worldwide: bool = False
    poster_url: Optional[str] = None
    trailer_url: Optional[str] = None


class ScheduleResponse(BaseModel):
    items: List[ScheduleItem]
    total: int

