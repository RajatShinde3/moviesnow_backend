from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response, status

from app.api.http_utils import enforce_public_api_key, json_no_store, rate_limit, resolve_get_current_user, sanitize_title_id
from app.repositories.titles import get_titles_repository
from app.repositories.user import get_user_repository
from app.schemas.user import (
    ActivityEntry,
    Favorites,
    PaginatedActivity,
    PaginatedReviews,
    RatingInput,
    Review,
    ReviewInput,
    SessionInfo,
    UserProfile,
    UserUpdate,
    Watchlist,
)


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/me", tags=["User"], responses={404: {"description": "Not found"}})

get_current_user = resolve_get_current_user()


@router.get("", response_model=UserProfile)
def get_me(request: Request, user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Return the current user's profile (no-store)."""
    repo = get_user_repository()
    profile = repo.get_profile(str(user.get("id")))
    if "email" not in profile and user.get("email"):
        profile["email"] = user.get("email")
    return json_no_store(profile)


@router.patch("", response_model=UserProfile)
def patch_me(patch: UserUpdate, user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Update profile fields (display_name, avatar_url, bio)."""
    repo = get_user_repository()
    updated = repo.update_profile(str(user.get("id")), patch.dict(exclude_unset=True))
    return json_no_store(updated)


@router.get("/activity", response_model=PaginatedActivity)
def get_activity(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100), user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """List recent activity for current user (paginated, no-store)."""
    repo = get_user_repository()
    items, total = repo.get_activity(str(user.get("id")), page, page_size)
    payload = PaginatedActivity(items=[ActivityEntry(**i) for i in items], page=page, page_size=page_size, total=total)
    return json_no_store(payload.dict())


@router.get("/sessions", response_model=List[SessionInfo])
def get_sessions(request: Request, user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Return active sessions for current user (no-store)."""
    repo = get_user_repository()
    sess_id = request.headers.get("x-session-id")
    sessions = repo.get_sessions(str(user.get("id")), sess_id)
    return json_no_store([SessionInfo(**s).dict() for s in sessions])


@router.post("/sessions/revoke-others", status_code=202)
def revoke_other_sessions(request: Request, user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Revoke all sessions except the current (requires X-Session-Id)."""
    sess_id = request.headers.get("x-session-id")
    if not sess_id:
        raise HTTPException(status_code=400, detail="Missing X-Session-Id header")
    repo = get_user_repository()
    count = repo.revoke_other_sessions(str(user.get("id")), sess_id)
    return json_no_store({"revoked": count}, status_code=202)


@router.post("/sessions/revoke-all", status_code=202)
def revoke_all_sessions(user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Revoke all sessions for current user (including current)."""
    repo = get_user_repository()
    count = repo.revoke_all_sessions(str(user.get("id")))
    return json_no_store({"revoked": count}, status_code=202)


@router.get("/watchlist", response_model=Watchlist)
def get_watchlist(user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Get user's watchlist."""
    repo = get_user_repository()
    return json_no_store(Watchlist(items=repo.get_watchlist(str(user.get("id")))).dict())


@router.post("/watchlist/{title_id}", status_code=204)
def add_watchlist(title_id: str = Path(...), user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Add a title to watchlist (validates ID format)."""
    tid = sanitize_title_id(title_id)
    titles_repo = get_titles_repository()
    try:
        _ = titles_repo.get_title(tid)
    except Exception:
        pass
    repo = get_user_repository()
    repo.add_watchlist(str(user.get("id")), tid)
    return Response(status_code=204)


@router.delete("/watchlist/{title_id}", status_code=204)
def remove_watchlist(title_id: str = Path(...), user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Remove a title from watchlist."""
    tid = sanitize_title_id(title_id)
    repo = get_user_repository()
    repo.remove_watchlist(str(user.get("id")), tid)
    return Response(status_code=204)


@router.get("/favorites", response_model=Favorites)
def get_favorites(user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Get user's favorites."""
    repo = get_user_repository()
    return json_no_store(Favorites(items=repo.get_favorites(str(user.get("id")))).dict())


@router.post("/favorites/{title_id}", status_code=204)
def add_favorite(title_id: str = Path(...), user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Add to favorites (ID format validated)."""
    tid = sanitize_title_id(title_id)
    repo = get_user_repository()
    repo.add_favorite(str(user.get("id")), tid)
    return Response(status_code=204)


@router.delete("/favorites/{title_id}", status_code=204)
def remove_favorite(title_id: str = Path(...), user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Remove from favorites."""
    tid = sanitize_title_id(title_id)
    repo = get_user_repository()
    repo.remove_favorite(str(user.get("id")), tid)
    return Response(status_code=204)


@router.post("/ratings/{title_id}", status_code=204)
def set_rating(rating: RatingInput, title_id: str = Path(...), user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Set rating (0–10)."""
    tid = sanitize_title_id(title_id)
    repo = get_user_repository()
    repo.set_rating(str(user.get("id")), tid, rating.rating)
    return Response(status_code=204)


@router.delete("/ratings/{title_id}", status_code=204)
def delete_rating(title_id: str = Path(...), user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Delete rating for title."""
    tid = sanitize_title_id(title_id)
    repo = get_user_repository()
    repo.delete_rating(str(user.get("id")), tid)
    return Response(status_code=204)


@router.post("/reviews", response_model=Review, status_code=201)
def create_review(body: ReviewInput, user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Create a review for a title (optionally with rating)."""
    tid = sanitize_title_id(body.title_id)
    repo = get_user_repository()
    review = repo.create_review(str(user.get("id")), tid, body.content, body.rating)
    return json_no_store(Review(**review).dict(), status_code=201)


@router.get("/reviews", response_model=PaginatedReviews)
def list_reviews(title_id: Optional[str] = Query(None), page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100), user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """List reviews: by title (if provided) or by current user."""
    tid = sanitize_title_id(title_id) if title_id else None
    repo = get_user_repository()
    items, total = repo.list_reviews(title_id=tid, user_id=None if tid else str(user.get("id")), page=page, page_size=page_size)
    payload = PaginatedReviews(items=[Review(**i) for i in items], page=page, page_size=page_size, total=total)
    return json_no_store(payload.dict())


@router.delete("/reviews/{review_id}", status_code=204)
def delete_review(review_id: str = Path(...), user=Depends(get_current_user), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Delete a review authored by current user."""
    repo = get_user_repository()
    ok = repo.delete_review(str(user.get("id")), review_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Review not found or not owned")
    return Response(status_code=204)

