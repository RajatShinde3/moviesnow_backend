
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ MoviesNow · User API (Profile, Sessions, Watchlist, Favorites, Ratings,  ║
# ║                                  Reviews)                                 ║
# ╠──────────────────────────────────────────────────────────────────────────╣
# ║ Endpoints (user-authenticated):                                           ║
# ║  - GET    /me                              → Current user profile         ║
# ║  - PATCH  /me                              → Update profile fields        ║
# ║  - GET    /me/activity                     → Recent activity (paginated)  ║
# ║  - GET    /me/sessions                     → Active sessions              ║
# ║  - POST   /me/sessions/revoke-others       → Revoke all except current    ║
# ║  - POST   /me/sessions/revoke-all          → Revoke all (incl. current)   ║
# ║  - GET    /me/watchlist                    → Get watchlist                ║
# ║  - POST   /me/watchlist/{title_id}         → Add to watchlist             ║
# ║  - DELETE /me/watchlist/{title_id}         → Remove from watchlist        ║
# ║  - GET    /me/favorites                    → Get favorites                ║
# ║  - POST   /me/favorites/{title_id}         → Add to favorites             ║
# ║  - DELETE /me/favorites/{title_id}         → Remove from favorites        ║
# ║  - POST   /me/ratings/{title_id}           → Set rating (0–10)            ║
# ║  - DELETE /me/ratings/{title_id}           → Delete rating                ║
# ║  - POST   /me/reviews                      → Create review (201 + body)   ║
# ║  - GET    /me/reviews                      → List reviews (paginated)     ║
# ╠──────────────────────────────────────────────────────────────────────────╣
# ║ Security & Operational Practices                                          
# ║  - Auth: requires an authenticated user from `get_current_user`.          
# ║  - Optional public API key enforcement via `enforce_public_api_key`.      
# ║  - Rate limiting on all routes via `rate_limit` dependency.               
# ║  - Cache control: responses return `Cache-Control: no-store` consistently. 
# ║  - Pagination: responses include `X-Total-Count` and RFC 5988 `Link` (when
# ║    applicable).                                                           
# ║  - Neutral errors: avoid leaking internal state or IDs where not needed.  
# ║  - Idempotent semantics for add/remove mutations (repos should de-dupe).  
# ║  - Structured logging: best-effort non-blocking logs per action.          
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
User-facing endpoints for profile, sessions, watchlist, favorites, ratings, and reviews.

All endpoints assume an authenticated user resolved by `get_current_user`.
Light rate-limiting and optional public API key enforcement apply consistently.
"""

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)

from app.api.http_utils import (
    enforce_public_api_key,
    json_no_store,
    rate_limit,
    resolve_get_current_user,
    sanitize_title_id,
)
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

# Provide a patch-friendly current-user dependency.
# The routes use `Depends(get_current_user)` where `get_current_user` is this proxy.
# Tests that monkeypatch `mod.get_current_user = <fake>` before including the router
# will be honored because the proxy delegates to the current module attribute when
# it is not itself; otherwise it falls back to the resolved project dependency.
try:
    import inspect, sys  # lightweight and always available

    class _UserDepProxy:
        def __init__(self, fallback):
            self._fallback = fallback

        async def __call__(self, *args, **kwargs):
            mod = sys.modules.get(__name__)
            target = getattr(mod, "get_current_user", None)
            if target is None or target is self:
                target = self._fallback
            result = target(*args, **kwargs)
            if inspect.isawaitable(result):
                return await result
            return result

    # Resolve once, delegate on call to allow monkeypatching the name later
    get_current_user = _UserDepProxy(resolve_get_current_user())

    # Wrapper dependency that defers to current module attribute at call time
    async def current_user_dep(request: Request):  # type: ignore[name-defined]
        # Delegate to the current module's get_current_user (proxy or patched)
        try:
            result = get_current_user(request)  # may be awaitable
        except TypeError:
            # Support test fakes with zero-arg signature
            result = get_current_user()  # type: ignore[misc]
        if inspect.isawaitable(result):
            return await result
        return result
except Exception:  # pragma: no cover
    # In extremely constrained environments, fall back directly
    get_current_user = resolve_get_current_user()  # type: ignore

router = APIRouter(
    tags=["User"],
    responses={
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        409: {"description": "Conflict"},
        413: {"description": "Payload Too Large"},
        429: {"description": "Too Many Requests"},
        500: {"description": "Internal Server Error"},
    },
)

# ─────────────────────────────────────────────────────────────────────────────
# Dependencies
# ─────────────────────────────────────────────────────────────────────────────

get_current_user = resolve_get_current_user()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers (pagination headers, safe logging)
# ─────────────────────────────────────────────────────────────────────────────

def _set_pagination_headers(
    request: Request,
    response: Response,
    *,
    page: int,
    page_size: int,
    total: int,
) -> None:
    """Attach `X-Total-Count` and RFC 5988 `Link` headers for paginated endpoints."""
    try:
        response.headers["X-Total-Count"] = str(total)
        # Build Link header (prev/next) if applicable
        base_url = str(request.url).split("?")[0]
        links: List[str] = []

        def _q(p: int) -> str:
            # preserve other query params but replace page/page_size
            qd = dict(request.query_params)
            qd["page"] = str(p)
            qd["page_size"] = str(page_size)
            return urlencode(qd)

        last_page = max(1, (total + page_size - 1) // page_size)
        if page > 1:
            links.append(f'<{base_url}?{_q(1)}>; rel="first"')
            links.append(f'<{base_url}?{_q(page - 1)}>; rel="prev"')
        if page < last_page:
            links.append(f'<{base_url}?{_q(page + 1)}>; rel="next"')
            links.append(f'<{base_url}?{_q(last_page)}>; rel="last"')
        if links:
            response.headers["Link"] = ", ".join(links)
    except Exception as e:
        # Never block the request on header building
        logger.debug("pagination header build skipped: %s", e)


def _log_user_action(request: Request, user_id: str, action: str, **meta: Any) -> None:
    """Best-effort structured log for user actions."""
    try:
        logger.info(
            "user_action",
            extra={
                "action": action,
                "user_id": user_id,
                "ip": request.client.host if request and request.client else None,
                "ua": request.headers.get("user-agent") if request else None,
                "meta": meta or {},
            },
        )
    except Exception:
        pass


# ╭───────────────────────────────────────────────────────────────────────────╮
# │ Profile                                                                    │
# ╰───────────────────────────────────────────────────────────────────────────╯

@router.get(
    "/me",
    response_model=UserProfile,
    response_model_exclude_none=True,
    summary="Get current user profile",
)
def get_me(
    request: Request,
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Return the current user's profile.

    Security
    --------
    - Requires authenticated user.
    - Cached responses are disabled (`Cache-Control: no-store`).

    Returns
    -------
    UserProfile
        Full profile including server-known email if missing from repo.
    """
    # 1) Load profile
    repo = get_user_repository()
    try:
        profile = repo.get_profile(str(user.get("id")))
    except Exception as e:
        logger.exception("get_me failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch profile")

    # 2) Fill known email if repo omits it (non-breaking enrichment)
    if "email" not in profile and user.get("email"):
        profile["email"] = user.get("email")

    # 3) Log and return (no-store)
    _log_user_action(request, str(user.get("id")), "PROFILE_GET")
    return json_no_store(profile)


@router.patch(
    "/me",
    response_model=UserProfile,
    response_model_exclude_none=True,
    summary="Update profile fields",
)
def patch_me(
    patch: UserUpdate,
    request: Request,
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Update profile fields (e.g., `display_name`, `avatar_url`, `bio`).

    Validation
    ----------
    - Empty bodies are rejected at the schema layer; here we also ensure there
      is at least one update to apply.

    Returns
    -------
    UserProfile
        Updated profile snapshot.
    """
    # 1) Extract changes
    changes = patch.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="No changes provided")

    # 2) Persist
    repo = get_user_repository()
    try:
        updated = repo.update_profile(str(user.get("id")), changes)
    except Exception as e:
        logger.exception("patch_me failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to update profile")

    # 3) Log & return
    _log_user_action(request, str(user.get("id")), "PROFILE_PATCH", fields=list(changes.keys()))
    return json_no_store(updated)


# ╭───────────────────────────────────────────────────────────────────────────╮
# │ Activity (paginated)                                                       │
# ╰───────────────────────────────────────────────────────────────────────────╯

@router.get(
    "/activity",
    response_model=PaginatedActivity,
    response_model_exclude_none=True,
    summary="List recent activity (paginated)",
)
def get_activity(
    request: Request,
    response: Response,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    List recent activity for the current user.

    Pagination
    ----------
    - `page` (1-based), `page_size` (≤100).
    - Response headers: `X-Total-Count` and RFC 5988 `Link`.

    Returns
    -------
    PaginatedActivity
        Items plus paging metadata.
    """
    # 1) Fetch page
    repo = get_user_repository()
    try:
        items, total = repo.get_activity(str(user.get("id")), page, page_size)
    except Exception as e:
        logger.exception("get_activity failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch activity")

    # 2) Build payload
    payload = PaginatedActivity(
        items=[ActivityEntry(**i) for i in items],
        page=page,
        page_size=page_size,
        total=total,
    )

    # 3) Headers + log + return
    _set_pagination_headers(request, response, page=page, page_size=page_size, total=total)
    _log_user_action(request, str(user.get("id")), "ACTIVITY_LIST", page=page, page_size=page_size)
    return json_no_store(payload, response=response)


# ╭───────────────────────────────────────────────────────────────────────────╮
# │ Sessions                                                                   │
# ╰───────────────────────────────────────────────────────────────────────────╯

@router.get(
    "/sessions",
    response_model=List[SessionInfo],
    response_model_exclude_none=True,
    summary="List active sessions",
)
def get_sessions(
    request: Request,
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Return active sessions for the current user.

    Notes
    -----
    - If the gateway supplies `X-Session-Id`, it is echoed in repo logic to
      allow highlighting the current session server-side.
    """
    # 1) Identify current session (header set by auth layer / gateway)
    sess_id = request.headers.get("x-session-id")

    # 2) Fetch sessions & return
    repo = get_user_repository()
    try:
        sessions = repo.get_sessions(str(user.get("id")), sess_id)
    except Exception as e:
        logger.exception("get_sessions failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch sessions")

    _log_user_action(request, str(user.get("id")), "SESSIONS_LIST", current_session_id=sess_id)
    return json_no_store([SessionInfo(**s) for s in sessions])


@router.post(
    "/sessions/revoke-others",
    status_code=202,
    summary="Revoke all sessions except the current",
)
def revoke_other_sessions(
    request: Request,
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Revoke all sessions **except** the current one.

    Requirements
    ------------
    - Header `X-Session-Id` must be present to identify the current session.

    Responses
    ---------
    - 202 Accepted with `{"revoked": <count>}`.
    - 400 if header missing.
    """
    # 1) Validate current session id
    sess_id = request.headers.get("x-session-id")
    if not sess_id:
        raise HTTPException(status_code=400, detail="Missing X-Session-Id header")

    # 2) Revoke & return
    repo = get_user_repository()
    try:
        count = repo.revoke_other_sessions(str(user.get("id")), sess_id)
    except Exception as e:
        logger.exception("revoke_other_sessions failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to revoke sessions")

    _log_user_action(request, str(user.get("id")), "SESSIONS_REVOKE_OTHERS", kept=sess_id, revoked=count)
    return json_no_store({"revoked": count}, status_code=202)


@router.post(
    "/sessions/revoke-all",
    status_code=202,
    summary="Revoke all sessions (including current)",
)
def revoke_all_sessions(
    request: Request,
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Revoke **all** sessions for the current user (including the current one).

    Response
    --------
    - 202 Accepted with `{"revoked": <count>}`.
    """
    # 1) Revoke & return
    repo = get_user_repository()
    try:
        count = repo.revoke_all_sessions(str(user.get("id")))
    except Exception as e:
        logger.exception("revoke_all_sessions failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to revoke sessions")

    _log_user_action(request, str(user.get("id")), "SESSIONS_REVOKE_ALL", revoked=count)
    return json_no_store({"revoked": count}, status_code=202)


# ╭───────────────────────────────────────────────────────────────────────────╮
# │ Watchlist                                                                  │
# ╰───────────────────────────────────────────────────────────────────────────╯

@router.get(
    "/watchlist",
    response_model=Watchlist,
    response_model_exclude_none=True,
    summary="Get watchlist",
)
def get_watchlist(
    request: Request,
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Get the user's watchlist.

    Returns
    -------
    Watchlist
        Ordered list of title IDs (server-defined order).
    """
    # 1) Load & shape
    repo = get_user_repository()
    try:
        payload = Watchlist(items=repo.get_watchlist(str(user.get("id"))))
    except Exception as e:
        logger.exception("get_watchlist failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch watchlist")

    _log_user_action(request, str(user.get("id")), "WATCHLIST_GET", count=len(payload.items))
    return json_no_store(payload)


@router.post(
    "/watchlist/{title_id}",
    status_code=204,
    summary="Add a title to watchlist",
)
def add_watchlist(
    title_id: str = Path(..., min_length=1, description="Title ID (sanitized)"),
    request: Request = None,
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Add a title to the watchlist.

    Notes
    -----
    - Idempotent: adding an existing item is a no-op with 204.
    - Title existence is optionally probed (best-effort) and ignored if errors.
    """
    # 1) Sanitize/validate title ID
    tid = sanitize_title_id(title_id)

    # 2) (Optional) probe title existence (non-fatal)
    try:
        get_titles_repository().get_title(tid)
    except Exception:
        pass

    # 3) Persist
    repo = get_user_repository()
    try:
        repo.add_watchlist(str(user.get("id")), tid)
    except Exception as e:
        logger.exception("add_watchlist failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to add to watchlist")

    _log_user_action(request, str(user.get("id")), "WATCHLIST_ADD", title_id=tid)
    return Response(status_code=204)


@router.delete(
    "/watchlist/{title_id}",
    status_code=204,
    summary="Remove a title from watchlist",
)
def remove_watchlist(
    title_id: str = Path(..., min_length=1, description="Title ID (sanitized)"),
    request: Request = None,
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Remove a title from the watchlist.

    Notes
    -----
    - Idempotent: removing a non-existing item is a no-op with 204.
    """
    # 1) Sanitize ID
    tid = sanitize_title_id(title_id)

    # 2) Persist
    repo = get_user_repository()
    try:
        repo.remove_watchlist(str(user.get("id")), tid)
    except Exception as e:
        logger.exception("remove_watchlist failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to remove from watchlist")

    _log_user_action(request, str(user.get("id")), "WATCHLIST_REMOVE", title_id=tid)
    return Response(status_code=204)


# ╭───────────────────────────────────────────────────────────────────────────╮
# │ Favorites                                                                  │
# ╰───────────────────────────────────────────────────────────────────────────╯

@router.get(
    "/favorites",
    response_model=Favorites,
    response_model_exclude_none=True,
    summary="Get favorites",
)
def get_favorites(
    request: Request,
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Get the user's favorites list.
    """
    # 1) Load & shape
    repo = get_user_repository()
    try:
        payload = Favorites(items=repo.get_favorites(str(user.get("id"))))
    except Exception as e:
        logger.exception("get_favorites failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch favorites")

    _log_user_action(request, str(user.get("id")), "FAVORITES_GET", count=len(payload.items))
    return json_no_store(payload)


@router.post(
    "/favorites/{title_id}",
    status_code=204,
    summary="Add a title to favorites",
)
def add_favorite(
    title_id: str = Path(..., min_length=1),
    request: Request = None,
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Add a title to favorites.

    Notes
    -----
    - Idempotent: adding duplicates returns 204 without error.
    """
    # 1) Sanitize ID
    tid = sanitize_title_id(title_id)

    # 2) Persist
    repo = get_user_repository()
    try:
        repo.add_favorite(str(user.get("id")), tid)
    except Exception as e:
        logger.exception("add_favorite failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to add favorite")

    _log_user_action(request, str(user.get("id")), "FAVORITES_ADD", title_id=tid)
    return Response(status_code=204)


@router.delete(
    "/favorites/{title_id}",
    status_code=204,
    summary="Remove a title from favorites",
)
def remove_favorite(
    title_id: str = Path(..., min_length=1),
    request: Request = None,
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Remove a title from favorites.

    Notes
    -----
    - Idempotent: removing a non-existing favorite returns 204.
    """
    # 1) Sanitize ID
    tid = sanitize_title_id(title_id)

    # 2) Persist
    repo = get_user_repository()
    try:
        repo.remove_favorite(str(user.get("id")), tid)
    except Exception as e:
        logger.exception("remove_favorite failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to remove favorite")

    _log_user_action(request, str(user.get("id")), "FAVORITES_REMOVE", title_id=tid)
    return Response(status_code=204)


# ╭───────────────────────────────────────────────────────────────────────────╮
# │ Ratings                                                                    │
# ╰───────────────────────────────────────────────────────────────────────────╯

@router.post(
    "/ratings/{title_id}",
    status_code=204,
    summary="Set rating for a title (0–10)",
)
def set_rating(
    rating: RatingInput,
    title_id: str = Path(..., min_length=1),
    request: Request = None,
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Set or update a rating for a title.

    Validation
    ----------
    - `rating.rating` must be within 0–10 (schema validates).
    """
    # 1) Sanitize ID
    tid = sanitize_title_id(title_id)

    # 2) Persist
    repo = get_user_repository()
    try:
        repo.set_rating(str(user.get("id")), tid, rating.rating)
    except Exception as e:
        logger.exception("set_rating failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to set rating")

    _log_user_action(request, str(user.get("id")), "RATING_SET", title_id=tid, rating=rating.rating)
    return Response(status_code=204)


@router.delete(
    "/ratings/{title_id}",
    status_code=204,
    summary="Delete rating for a title",
)
def delete_rating(
    title_id: str = Path(..., min_length=1),
    request: Request = None,
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Delete an existing rating for a title.

    Notes
    -----
    - Idempotent: deleting a non-existing rating returns 204.
    """
    # 1) Sanitize ID
    tid = sanitize_title_id(title_id)

    # 2) Persist
    repo = get_user_repository()
    try:
        repo.delete_rating(str(user.get("id")), tid)
    except Exception as e:
        logger.exception("delete_rating failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to delete rating")

    _log_user_action(request, str(user.get("id")), "RATING_DELETE", title_id=tid)
    return Response(status_code=204)


# ╭───────────────────────────────────────────────────────────────────────────╮
# │ Reviews                                                                    │
# ╰───────────────────────────────────────────────────────────────────────────╯

@router.post(
    "/reviews",
    response_model=Review,
    response_model_exclude_none=True,
    status_code=201,
    summary="Create a review (optionally with rating)",
)
def create_review(
    body: ReviewInput,
    request: Request,
    response: Response,
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Create a review for a title.

    Notes
    -----
    - If a rating is included, the server persists both review and rating.
    - On success, returns 201 with the created review body and a `Location`
      header pointing to `/me/reviews?title_id=<id>` for convenience.
    """
    # 1) Sanitize ID
    tid = sanitize_title_id(body.title_id)

    # 2) Persist
    repo = get_user_repository()
    try:
        review = repo.create_review(str(user.get("id")), tid, body.content, body.rating)
    except Exception as e:
        logger.exception("create_review failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create review")

    # 3) Location header
    response.headers["Location"] = f"/me/reviews?title_id={tid}"

    _log_user_action(
        request,
        str(user.get("id")),
        "REVIEW_CREATE",
        title_id=tid,
        review_id=review.get("id") if isinstance(review, dict) else None,
        has_rating=body.rating is not None,
    )
    return json_no_store(Review(**review), status_code=201, response=response)


@router.get(
    "/reviews",
    response_model=PaginatedReviews,
    response_model_exclude_none=True,
    summary="List reviews (by title or current user)",
)
def list_reviews(
    request: Request,
    response: Response,
    title_id: Optional[str] = Query(None, description="Filter by title (optional)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    List reviews, either:
    - By `title_id` if provided, or
    - By the current user (if `title_id` omitted).

    Pagination
    ----------
    - `page` (1-based), `page_size` (≤100).
    - Response headers: `X-Total-Count` and RFC 5988 `Link`.
    """
    # 1) Determine scope
    tid = sanitize_title_id(title_id) if title_id else None
    user_id = None if tid else str(user.get("id"))

    # 2) Fetch page
    repo = get_user_repository()
    try:
        items, total = repo.list_reviews(
        title_id=tid,
        user_id=user_id,
        page=page,
        page_size=page_size,
    )
    except Exception as e:
        logger.exception("list_reviews failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch reviews")

    # 3) Shape payload
    payload = PaginatedReviews(
        items=[Review(**i) for i in items],
        page=page,
        page_size=page_size,
        total=total,
    )

    # 4) Headers + log + return
    _set_pagination_headers(request, response, page=page, page_size=page_size, total=total)
    _log_user_action(
        request,
        str(user.get("id")),
        "REVIEWS_LIST",
        by_title=bool(tid),
        title_id=tid,
        page=page,
        page_size=page_size,
    )
    return json_no_store(payload, response=response)


@router.delete(
    "/reviews/{review_id}",
    status_code=204,
    summary="Delete a review authored by the current user",
)
def delete_review(
    review_id: str = Path(..., min_length=1),
    request: Request = None,
    user=Depends(current_user_dep),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Delete a review authored by the current user.

    Responses
    ---------
    - 204 on success or if already deleted.
    - 404 if not found or not owned.
    """
    # 1) Attempt delete
    repo = get_user_repository()
    try:
        ok = repo.delete_review(str(user.get("id")), review_id)
    except Exception as e:
        logger.exception("delete_review failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to delete review")

    # 2) Neutral error if not found/not owned
    if not ok:
        raise HTTPException(status_code=404, detail="Review not found or not owned")

    _log_user_action(request, str(user.get("id")), "REVIEW_DELETE", review_id=review_id, deleted=ok)
    return Response(status_code=204)
