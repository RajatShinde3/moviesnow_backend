from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


class UserRepositoryProtocol:
    def get_profile(self, user_id: str) -> Dict[str, Any]:
        raise NotImplementedError

    def update_profile(self, user_id: str, patch: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def get_activity(self, user_id: str, page: int, page_size: int) -> Tuple[List[Dict[str, Any]], int]:
        raise NotImplementedError

    def get_sessions(self, user_id: str, current_session_id: Optional[str]) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def revoke_other_sessions(self, user_id: str, current_session_id: Optional[str]) -> int:
        raise NotImplementedError

    def revoke_all_sessions(self, user_id: str) -> int:
        raise NotImplementedError

    def get_watchlist(self, user_id: str) -> List[str]:
        raise NotImplementedError

    def add_watchlist(self, user_id: str, title_id: str) -> None:
        raise NotImplementedError

    def remove_watchlist(self, user_id: str, title_id: str) -> None:
        raise NotImplementedError

    def get_favorites(self, user_id: str) -> List[str]:
        raise NotImplementedError

    def add_favorite(self, user_id: str, title_id: str) -> None:
        raise NotImplementedError

    def remove_favorite(self, user_id: str, title_id: str) -> None:
        raise NotImplementedError

    def set_rating(self, user_id: str, title_id: str, rating: float) -> None:
        raise NotImplementedError

    def delete_rating(self, user_id: str, title_id: str) -> None:
        raise NotImplementedError

    def create_review(self, user_id: str, title_id: str, content: str, rating: Optional[float]) -> Dict[str, Any]:
        raise NotImplementedError

    def list_reviews(self, *, title_id: Optional[str], user_id: Optional[str], page: int, page_size: int) -> Tuple[List[Dict[str, Any]], int]:
        raise NotImplementedError

    def delete_review(self, user_id: str, review_id: str) -> bool:
        raise NotImplementedError


@dataclass
class _UserState:
    profile: Dict[str, Any] = field(default_factory=dict)
    activity: List[Dict[str, Any]] = field(default_factory=list)
    sessions: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # session_id -> session
    watchlist: List[str] = field(default_factory=list)
    favorites: List[str] = field(default_factory=list)
    ratings: Dict[str, float] = field(default_factory=dict)  # title_id -> rating
    reviews: Dict[str, Dict[str, Any]] = field(default_factory=dict)   # review_id -> review


class MemoryUserRepository(UserRepositoryProtocol):
    def __init__(self) -> None:
        self._users: Dict[str, _UserState] = {}

    def _now(self) -> int:
        return int(time.time())

    def _ensure(self, user_id: str) -> _UserState:
        if user_id not in self._users:
            self._users[user_id] = _UserState(profile={"id": user_id, "display_name": None, "avatar_url": None, "bio": None})
        return self._users[user_id]

    # Profile
    def get_profile(self, user_id: str) -> Dict[str, Any]:
        u = self._ensure(user_id)
        return dict(u.profile)

    def update_profile(self, user_id: str, patch: Dict[str, Any]) -> Dict[str, Any]:
        u = self._ensure(user_id)
        u.profile.update({k: v for k, v in patch.items() if v is not None})
        u.activity.insert(0, {"type": "profile.update", "at": self._now(), "patch": list(patch.keys())})
        return dict(u.profile)

    # Activity
    def get_activity(self, user_id: str, page: int, page_size: int) -> Tuple[List[Dict[str, Any]], int]:
        u = self._ensure(user_id)
        total = len(u.activity)
        start, end = (page - 1) * page_size, (page - 1) * page_size + page_size
        return list(u.activity[start:end]), total

    # Sessions
    def get_sessions(self, user_id: str, current_session_id: Optional[str]) -> List[Dict[str, Any]]:
        u = self._ensure(user_id)
        # ensure current session exists for visibility
        if current_session_id and current_session_id not in u.sessions:
            u.sessions[current_session_id] = {"id": current_session_id, "created_at": self._now(), "last_seen_at": self._now(), "current": True}
        res: List[Dict[str, Any]] = []
        for sid, s in u.sessions.items():
            res.append({
                "id": sid,
                "created_at": s.get("created_at", self._now()),
                "last_seen_at": s.get("last_seen_at", self._now()),
                "current": sid == current_session_id,
                "ip": s.get("ip"),
                "ua": s.get("ua"),
            })
        return res

    def revoke_other_sessions(self, user_id: str, current_session_id: Optional[str]) -> int:
        u = self._ensure(user_id)
        count = 0
        for sid in list(u.sessions.keys()):
            if sid != current_session_id:
                u.sessions.pop(sid, None)
                count += 1
        u.activity.insert(0, {"type": "session.revoke_others", "at": self._now(), "left": 1 if current_session_id else 0})
        return count

    def revoke_all_sessions(self, user_id: str) -> int:
        u = self._ensure(user_id)
        count = len(u.sessions)
        u.sessions.clear()
        u.activity.insert(0, {"type": "session.revoke_all", "at": self._now()})
        return count

    # Watchlist
    def get_watchlist(self, user_id: str) -> List[str]:
        u = self._ensure(user_id)
        return list(u.watchlist)

    def add_watchlist(self, user_id: str, title_id: str) -> None:
        u = self._ensure(user_id)
        if title_id not in u.watchlist:
            u.watchlist.insert(0, title_id)
            u.activity.insert(0, {"type": "watchlist.add", "title_id": title_id, "at": self._now()})

    def remove_watchlist(self, user_id: str, title_id: str) -> None:
        u = self._ensure(user_id)
        if title_id in u.watchlist:
            u.watchlist.remove(title_id)
            u.activity.insert(0, {"type": "watchlist.remove", "title_id": title_id, "at": self._now()})

    # Favorites
    def get_favorites(self, user_id: str) -> List[str]:
        u = self._ensure(user_id)
        return list(u.favorites)

    def add_favorite(self, user_id: str, title_id: str) -> None:
        u = self._ensure(user_id)
        if title_id not in u.favorites:
            u.favorites.insert(0, title_id)
            u.activity.insert(0, {"type": "favorite.add", "title_id": title_id, "at": self._now()})

    def remove_favorite(self, user_id: str, title_id: str) -> None:
        u = self._ensure(user_id)
        if title_id in u.favorites:
            u.favorites.remove(title_id)
            u.activity.insert(0, {"type": "favorite.remove", "title_id": title_id, "at": self._now()})

    # Ratings
    def set_rating(self, user_id: str, title_id: str, rating: float) -> None:
        u = self._ensure(user_id)
        u.ratings[title_id] = rating
        u.activity.insert(0, {"type": "rating.set", "title_id": title_id, "rating": rating, "at": self._now()})

    def delete_rating(self, user_id: str, title_id: str) -> None:
        u = self._ensure(user_id)
        if title_id in u.ratings:
            del u.ratings[title_id]
            u.activity.insert(0, {"type": "rating.delete", "title_id": title_id, "at": self._now()})

    # Reviews
    def create_review(self, user_id: str, title_id: str, content: str, rating: Optional[float]) -> Dict[str, Any]:
        u = self._ensure(user_id)
        rid = uuid.uuid4().hex
        review = {
            "id": rid,
            "user_id": user_id,
            "title_id": title_id,
            "content": content,
            "rating": rating,
            "created_at": self._now(),
        }
        u.reviews[rid] = review
        u.activity.insert(0, {"type": "review.create", "title_id": title_id, "review_id": rid, "at": self._now()})
        return dict(review)

    def list_reviews(self, *, title_id: Optional[str], user_id: Optional[str], page: int, page_size: int) -> Tuple[List[Dict[str, Any]], int]:
        # naive: iterate all users
        all_reviews: List[Dict[str, Any]] = []
        for uid, st in self._users.items():
            for r in st.reviews.values():
                if title_id and r.get("title_id") != title_id:
                    continue
                if user_id and r.get("user_id") != user_id:
                    continue
                all_reviews.append(r)
        all_reviews.sort(key=lambda r: r.get("created_at", 0), reverse=True)
        total = len(all_reviews)
        start, end = (page - 1) * page_size, (page - 1) * page_size + page_size
        return list(all_reviews[start:end]), total

    def delete_review(self, user_id: str, review_id: str) -> bool:
        for uid, st in self._users.items():
            if review_id in st.reviews:
                if st.reviews[review_id].get("user_id") != user_id:
                    return False
                del st.reviews[review_id]
                st.activity.insert(0, {"type": "review.delete", "review_id": review_id, "at": self._now()})
                return True
        return False


def _import_string(path: str):
    module_path, _, class_name = path.partition(":")
    if not module_path or not class_name:
        raise ValueError("USER_REPOSITORY_IMPL must be 'module.sub:ClassName'")
    module = __import__(module_path, fromlist=[class_name])
    return getattr(module, class_name)


def get_user_repository() -> UserRepositoryProtocol:
    impl_path = os.environ.get("USER_REPOSITORY_IMPL")
    if impl_path:
        cls = _import_string(impl_path)
        return cls()  # type: ignore
    return MemoryUserRepository()

