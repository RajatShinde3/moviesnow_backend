from __future__ import annotations

"""Titles discovery repository.

Provides an interface and a simple in-memory implementation for listing and
querying titles, stream variants, subtitles, credits, and related resources.
"""

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


# Protocol-like documentation for the expected interface.
# Implementations should return simple dicts that map cleanly to the public schemas.


class TitleRepositoryProtocol:
    def search_titles(
        self,
        *,
        q: Optional[str],
        filters: Dict[str, Any],
        sort: str,
        order: str,
        page: int,
        page_size: int,
    ) -> Tuple[List[Dict[str, Any]], int, Dict[str, Any]]:
        raise NotImplementedError

    def get_title(self, title_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    def get_stream_variants(self, title_id: str) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def get_subtitles(self, title_id: str) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def list_genres(self) -> List[str]:
        raise NotImplementedError

    def get_credits(self, title_id: str) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def get_similar(self, title_id: str) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def get_stream_resource_path(self, title_id: str) -> str:
        raise NotImplementedError

    def get_download_resource_path(self, title_id: str) -> str:
        raise NotImplementedError


@dataclass
class _MemoryTitle:
    id: str
    name: str
    year: Optional[int] = None
    rating: Optional[float] = None
    genres: Optional[List[str]] = None
    synopsis: Optional[str] = None
    runtime_minutes: Optional[int] = None
    released_at: Optional[int] = None
    poster_url: Optional[str] = None
    backdrop_url: Optional[str] = None
    tags: Optional[List[str]] = None
    credits: Optional[List[Dict[str, Any]]] = None
    subtitles: Optional[List[Dict[str, Any]]] = None


class MemoryTitleRepository(TitleRepositoryProtocol):
    """
    Simple in-memory repository, optionally backed by a JSON file.

    Env:
      - TITLES_DATA_PATH: Path to a JSON file. If provided, it should contain a list
        of title objects with optional keys: id, name, year, rating, genres, synopsis,
        runtime_minutes, released_at, poster_url, backdrop_url, tags, credits, subtitles.
    """

    def __init__(self, data_path: Optional[str] = None):
        self._titles: List[_MemoryTitle] = []
        if not data_path:
            data_path = os.environ.get("TITLES_DATA_PATH")
        if data_path and os.path.exists(data_path):
            try:
                with open(data_path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                for t in raw or []:
                    self._titles.append(_MemoryTitle(**t))
            except Exception:
                # Load failure -> keep empty (safe default)
                self._titles = []

    # Helpers
    def _iter(self) -> Iterable[_MemoryTitle]:
        return iter(self._titles)

    def _apply_filters(self, items: List[_MemoryTitle], filters: Dict[str, Any]) -> List[_MemoryTitle]:
        genres = set([g.lower() for g in (filters.get("genres") or [])])
        year_gte = filters.get("year_gte")
        year_lte = filters.get("year_lte")
        rating_gte = filters.get("rating_gte")
        rating_lte = filters.get("rating_lte")
        cast = set([c.lower() for c in (filters.get("cast") or [])])

        def ok(t: _MemoryTitle) -> bool:
            if genres:
                tgenres = set([g.lower() for g in (t.genres or [])])
                if not tgenres.intersection(genres):
                    return False
            if year_gte is not None and (t.year or 0) < year_gte:
                return False
            if year_lte is not None and (t.year or 0) > year_lte:
                return False
            if rating_gte is not None and (t.rating or 0.0) < rating_gte:
                return False
            if rating_lte is not None and (t.rating or 0.0) > rating_lte:
                return False
            if cast:
                names = set([str(c.get("name", "")).lower() for c in (t.credits or [])])
                if not names.intersection(cast):
                    return False
            return True

        return [t for t in items if ok(t)]

    def _search_text(self, items: List[_MemoryTitle], q: Optional[str]) -> List[_MemoryTitle]:
        if not q:
            return items
        qs = q.lower().strip()
        res: List[_MemoryTitle] = []
        for t in items:
            if (
                qs in (t.name or "").lower()
                or qs in (t.synopsis or "").lower()
                or qs in " ".join((t.tags or [])).lower()
            ):
                res.append(t)
        return res

    def _sort(self, items: List[_MemoryTitle], sort: str, order: str) -> List[_MemoryTitle]:
        reverse = (order or "desc").lower() != "asc"
        key = (sort or "popularity").lower()
        if key == "year":
            items.sort(key=lambda t: (t.year or 0), reverse=reverse)
        elif key == "rating":
            items.sort(key=lambda t: (t.rating or 0.0), reverse=reverse)
        elif key == "name":
            items.sort(key=lambda t: (t.name or ""), reverse=reverse)
        elif key == "released_at":
            items.sort(key=lambda t: (t.released_at or 0), reverse=reverse)
        else:  # popularity fallback: prefer rating then year
            items.sort(key=lambda t: ((t.rating or 0.0), (t.year or 0)), reverse=True)
            if not reverse:
                items.reverse()
        return items

    def _to_summary(self, t: _MemoryTitle) -> Dict[str, Any]:
        return {
            "id": t.id,
            "name": t.name,
            "year": t.year,
            "poster_url": t.poster_url,
            "genres": t.genres or [],
            "rating": t.rating,
        }

    # Interface
    def search_titles(
        self,
        *,
        q: Optional[str],
        filters: Dict[str, Any],
        sort: str,
        order: str,
        page: int,
        page_size: int,
    ) -> Tuple[List[Dict[str, Any]], int, Dict[str, Any]]:
        items = list(self._iter())
        items = self._apply_filters(items, filters)
        items = self._search_text(items, q)
        total = len(items)
        items = self._sort(items, sort, order)
        start = (page - 1) * page_size
        end = start + page_size
        page_items = items[start:end]
        summaries = [self._to_summary(t) for t in page_items]
        facets: Dict[str, Any] = {
            "genres": sorted({g for t in items for g in (t.genres or [])}),
        }
        return summaries, total, facets

    def get_title(self, title_id: str) -> Optional[Dict[str, Any]]:
        for t in self._iter():
            if t.id == title_id:
                return {
                    **self._to_summary(t),
                    "synopsis": t.synopsis,
                    "runtime_minutes": t.runtime_minutes,
                    "released_at": t.released_at,
                    "backdrop_url": t.backdrop_url,
                    "tags": t.tags or [],
                }
        return None

    def get_stream_variants(self, title_id: str) -> List[Dict[str, Any]]:
        # default variants; override in custom repo
        return [
            {"quality": "auto", "container": "m3u8", "codec": "h264"},
            {"quality": "480p", "bitrate_kbps": 1500, "container": "mp4", "codec": "h264"},
            {"quality": "720p", "bitrate_kbps": 3000, "container": "mp4", "codec": "h264"},
            {"quality": "1080p", "bitrate_kbps": 6000, "container": "mp4", "codec": "h265"},
        ]

    def get_subtitles(self, title_id: str) -> List[Dict[str, Any]]:
        for t in self._iter():
            if t.id == title_id:
                return list(t.subtitles or [])
        return []

    def list_genres(self) -> List[str]:
        return sorted({g for t in self._iter() for g in (t.genres or [])})

    def get_credits(self, title_id: str) -> List[Dict[str, Any]]:
        for t in self._iter():
            if t.id == title_id:
                return list(t.credits or [])
        return []

    def get_similar(self, title_id: str) -> List[Dict[str, Any]]:
        # naive: same top genre
        target: Optional[_MemoryTitle] = None
        for t in self._iter():
            if t.id == title_id:
                target = t
                break
        if not target:
            return []
        tgenre = (target.genres or [None])[0]
        cands = [t for t in self._iter() if t.id != title_id and tgenre and tgenre in (t.genres or [])]
        cands = cands[:12]
        return [self._to_summary(t) for t in cands]

    def get_stream_resource_path(self, title_id: str) -> str:
        return f"stream/{title_id}"

    def get_download_resource_path(self, title_id: str) -> str:
        return f"download/{title_id}"


def _import_string(path: str):
    module_path, _, class_name = path.partition(":")
    if not module_path or not class_name:
        raise ValueError("TITLES_REPOSITORY_IMPL must be 'module.sub:ClassName'")
    module = __import__(module_path, fromlist=[class_name])
    return getattr(module, class_name)


def get_titles_repository() -> TitleRepositoryProtocol:
    """
    Factory/dependency for the titles repository.
    Configure via env var `TITLES_REPOSITORY_IMPL` to point to a custom class.
    Defaults to MemoryTitleRepository.
    """
    impl_path = os.environ.get("TITLES_REPOSITORY_IMPL")
    if impl_path:
        cls = _import_string(impl_path)
        return cls()  # type: ignore
    return MemoryTitleRepository()


# Backwards-compatible alias if some code imports TitleRepository
class TitleRepository(MemoryTitleRepository):
    pass
