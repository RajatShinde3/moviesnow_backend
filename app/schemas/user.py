from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, constr


class UserProfile(BaseModel):
    id: str
    email: Optional[str] = None
    display_name: Optional[constr(strip_whitespace=True, min_length=1, max_length=64)] = None
    avatar_url: Optional[constr(strip_whitespace=True, min_length=1, max_length=2048)] = None
    bio: Optional[constr(strip_whitespace=True, min_length=1, max_length=280)] = None


class UserUpdate(BaseModel):
    display_name: Optional[constr(strip_whitespace=True, min_length=1, max_length=64)] = None
    avatar_url: Optional[constr(strip_whitespace=True, min_length=1, max_length=2048)] = None
    bio: Optional[constr(strip_whitespace=True, min_length=1, max_length=280)] = None


class ActivityEntry(BaseModel):
    type: str
    at: int
    title_id: Optional[str] = None
    review_id: Optional[str] = None
    rating: Optional[float] = None
    patch: Optional[List[str]] = None


class PaginatedActivity(BaseModel):
    items: List[ActivityEntry]
    page: int
    page_size: int
    total: int


class SessionInfo(BaseModel):
    id: str
    created_at: Optional[int] = None
    last_seen_at: Optional[int] = None
    current: bool = False
    ip: Optional[str] = None
    ua: Optional[str] = None


class Watchlist(BaseModel):
    items: List[str]


class Favorites(BaseModel):
    items: List[str]


class RatingInput(BaseModel):
    rating: float = Field(..., ge=0.0, le=10.0)


class ReviewInput(BaseModel):
    title_id: str = Field(..., description="Target title ID")
    content: constr(strip_whitespace=True, min_length=3, max_length=5000)
    rating: Optional[float] = Field(None, ge=0.0, le=10.0)


class Review(BaseModel):
    id: str
    user_id: str
    title_id: str
    content: str
    rating: Optional[float] = None
    created_at: int


class PaginatedReviews(BaseModel):
    items: List[Review]
    page: int
    page_size: int
    total: int

