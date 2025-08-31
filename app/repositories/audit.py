from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


class AuditRepositoryProtocol:
    def add(self, *, source: str, action: str, actor: Optional[str], meta: Dict[str, Any]) -> None:
        raise NotImplementedError

    def list(self, *, page: int, page_size: int, source: Optional[str] = None, actor: Optional[str] = None) -> Tuple[List[Dict[str, Any]], int]:
        raise NotImplementedError


@dataclass
class _AuditEntry:
    at: int
    source: str
    action: str
    actor: Optional[str]
    meta: Dict[str, Any]


class MemoryAuditRepository(AuditRepositoryProtocol):
    def __init__(self, max_entries: int = 10000) -> None:
        self._entries: List[_AuditEntry] = []
        self._max = max_entries

    def add(self, *, source: str, action: str, actor: Optional[str], meta: Dict[str, Any]) -> None:
        e = _AuditEntry(at=int(time.time()), source=source, action=action, actor=actor, meta=meta)
        self._entries.append(e)
        if len(self._entries) > self._max:
            self._entries = self._entries[-self._max :]

    def list(self, *, page: int, page_size: int, source: Optional[str] = None, actor: Optional[str] = None) -> Tuple[List[Dict[str, Any]], int]:
        items = [
            {
                "at": e.at,
                "source": e.source,
                "action": e.action,
                "actor": e.actor,
                "meta": e.meta,
            }
            for e in self._entries
            if (not source or e.source == source) and (not actor or e.actor == actor)
        ]
        total = len(items)
        start, end = (page - 1) * page_size, (page - 1) * page_size + page_size
        return items[start:end], total


def _import_string(path: str):
    module_path, _, class_name = path.partition(":")
    if not module_path or not class_name:
        raise ValueError("AUDIT_REPOSITORY_IMPL must be 'module.sub:ClassName'")
    module = __import__(module_path, fromlist=[class_name])
    return getattr(module, class_name)


def get_audit_repository() -> AuditRepositoryProtocol:
    impl_path = os.environ.get("AUDIT_REPOSITORY_IMPL")
    if impl_path:
        cls = _import_string(impl_path)
        return cls()  # type: ignore
    return MemoryAuditRepository()

