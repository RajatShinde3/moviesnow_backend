# tests/test_lessons/test_patch_unlock_conditions.py

import uuid
import json
import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.db.models import Course, Lesson, LessonUnlockCondition
from app.schemas.enums import OrgRole, CourseVisibility

BASE = "/api/v1/lessons"


def _normalize_headers(h):
    return {"Authorization": h} if isinstance(h, str) else h


def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if hasattr(obj, k):
            setattr(obj, k, v)


async def _edges_for(db, course_id, target_id):
    rows = await db.execute(
        select(
            LessonUnlockCondition.source_lesson_id,
            LessonUnlockCondition.target_lesson_id,
            LessonUnlockCondition.soft_unlock,
        )
        .where(
            LessonUnlockCondition.course_id == course_id,
            LessonUnlockCondition.target_lesson_id == target_id,
        )
        .order_by(LessonUnlockCondition.source_lesson_id.asc())
    )
    return [(s, t, bool(soft)) for (s, t, soft) in rows.all()]

@pytest.mark.anyio
async def test_unlock_patch__200_replaces_edges_soft_flags_and_invalidates_cache(
    async_client: AsyncClient, db_session, org_user_with_token, monkeypatch
):
    # ── Arrange ─────────────────────────────────────────────────────────────
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(
        title="Flow",
        slug=f"flow-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PUBLIC,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)

    target = Lesson(title="Target", order=10, is_published=True, course_id=c.id, organization_id=org.id)
    a = Lesson(title="A", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    b = Lesson(title="B", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    x = Lesson(title="X", order=3, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (target, a, b, x):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(target); await db_session.refresh(a); await db_session.refresh(b); await db_session.refresh(x)

    # existing edge: x -> target (will be removed by patch)
    db_session.add(
        LessonUnlockCondition(source_lesson_id=x.id, target_lesson_id=target.id, course_id=c.id, soft_unlock=False)
    )
    await db_session.commit()

    # ── Monkeypatch the exact symbol the route calls ────────────────────────
    # Import the module object and patch its attribute so we capture the call.
    from app.api.v1.lessons import unlocks as unlocks_module

    called = {}
    async def _fake_invalidate(course_id, *args, **kwargs):
        called["course_id"] = course_id
        return 0

    monkeypatch.setattr(
        unlocks_module,
        "invalidate_unlock_related_caches",
        _fake_invalidate,
        raising=True,
    )

    # ── Act ─────────────────────────────────────────────────────────────────
    body = {
        "prerequisite_lesson_ids": [str(a.id), str(b.id)],
        "soft_unlock_flags": {str(b.id): True},
    }
    r = await async_client.patch(
        f"{BASE}/{target.id}/unlock-conditions",
        headers=headers,
        json=body,
    )

    # ── Assert ──────────────────────────────────────────────────────────────
    assert r.status_code == 200, r.text
    # Verify cache invalidation hook was invoked with the course id
    assert called.get("course_id") == c.id

    # Verify DB edges were fully replaced with correct soft flags (order-agnostic)
    es = await _edges_for(db_session, c.id, target.id)

    # Build a source_id -> soft_flag map and assert exact contents
    soft_by_src = {src: soft for (src, tgt, soft) in es}

    assert set(soft_by_src.keys()) == {a.id, b.id}, "should only have A and B as prerequisites (X->Target removed)"
    assert soft_by_src[a.id] is False
    assert soft_by_src[b.id] is True



@pytest.mark.anyio
async def test_unlock_patch__404_target_not_in_org(async_client: AsyncClient, db_session, org_user_with_token):
    """If the target lesson does not belong to caller's org, return 404."""
    caller, headers_a, org_a = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers_a = _normalize_headers(headers_a)

    _other, _headers_b, org_b = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c_b = Course(title="B", slug=f"b-{uuid.uuid4().hex[:8]}", organization_id=org_b.id, is_published=True)
    _set_if_has(c_b, created_by=caller.id)
    db_session.add(c_b); await db_session.commit(); await db_session.refresh(c_b)

    target_b = Lesson(title="Foreign", order=1, is_published=True, course_id=c_b.id, organization_id=org_b.id)
    _set_if_has(target_b, created_by=caller.id)
    db_session.add(target_b); await db_session.commit(); await db_session.refresh(target_b)

    r = await async_client.patch(
        f"{BASE}/{target_b.id}/unlock-conditions",
        headers=headers_a,
        json={"prerequisite_lesson_ids": []},
    )
    assert r.status_code == 404, r.text
    assert "not found" in r.text.lower() or "access denied" in r.text.lower()


@pytest.mark.anyio
async def test_unlock_patch__400_self_dependency(async_client: AsyncClient, db_session, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="C", slug=f"c-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="Target", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(target, created_by=user.id)
    db_session.add(target); await db_session.commit(); await db_session.refresh(target)

    r = await async_client.patch(
        f"{BASE}/{target.id}/unlock-conditions",
        headers=headers,
        json={"prerequisite_lesson_ids": [str(target.id)]},
    )
    assert r.status_code == 400, r.text
    assert "cannot depend on itself" in r.text


@pytest.mark.anyio
async def test_unlock_patch__400_invalid_prereqs_other_course(async_client: AsyncClient, db_session, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c1 = Course(title="C1", slug=f"c1-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    c2 = Course(title="C2", slug=f"c2-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c1, created_by=user.id); _set_if_has(c2, created_by=user.id)
    db_session.add_all([c1, c2]); await db_session.commit(); await db_session.refresh(c1); await db_session.refresh(c2)

    target = Lesson(title="Target", order=1, is_published=True, course_id=c1.id, organization_id=org.id)
    ok = Lesson(title="OK", order=2, is_published=True, course_id=c1.id, organization_id=org.id)
    bad = Lesson(title="BAD", order=3, is_published=True, course_id=c2.id, organization_id=org.id)  # other course
    for l in (target, ok, bad):
        _set_if_has(l, created_by=user.id); db_session.add(l)
    await db_session.commit()
    await db_session.refresh(target); await db_session.refresh(ok); await db_session.refresh(bad)

    r = await async_client.patch(
        f"{BASE}/{target.id}/unlock-conditions",
        headers=headers,
        json={"prerequisite_lesson_ids": [str(ok.id), str(bad.id)]},
    )
    assert r.status_code == 400, r.text
    assert "another course" in r.text.lower() or "invalid" in r.text.lower()


@pytest.mark.anyio
async def test_unlock_patch__400_cycle_detection(async_client: AsyncClient, db_session, org_user_with_token):
    """
    Existing graph: Target -> X -> Y
    Attempt to add Y as a prerequisite of Target (Y -> Target), which creates a cycle.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="G", slug=f"g-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="Target", order=10, is_published=True, course_id=c.id, organization_id=org.id)
    x = Lesson(title="X", order=11, is_published=True, course_id=c.id, organization_id=org.id)
    y = Lesson(title="Y", order=12, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (target, x, y):
        _set_if_has(l, created_by=user.id); db_session.add(l)
    await db_session.commit()
    await db_session.refresh(target); await db_session.refresh(x); await db_session.refresh(y)

    # Build existing forward path: target -> x -> y
    db_session.add_all([
        LessonUnlockCondition(source_lesson_id=target.id, target_lesson_id=x.id, course_id=c.id, soft_unlock=False),
        LessonUnlockCondition(source_lesson_id=x.id, target_lesson_id=y.id, course_id=c.id, soft_unlock=False),
    ])
    await db_session.commit()

    # Now attempt to set y as a prerequisite of target: (y -> target) → cycle
    r = await async_client.patch(
        f"{BASE}/{target.id}/unlock-conditions",
        headers=headers,
        json={"prerequisite_lesson_ids": [str(y.id)]},
    )
    assert r.status_code == 400, r.text
    assert "circular" in r.text.lower() or "cycle" in r.text.lower()


# ────────────────────────────────────────────────────────────────────────────
# Idempotency
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_unlock_patch__idempotent_replay_from_cache__skips_service(
    async_client: AsyncClient, db_session, org_user_with_token, monkeypatch
):
    """
    If Idempotency-Key is provided and a cached response exists, the route must
    return it WITHOUT invoking the update service.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="I", slug=f"i-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="Target", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    p = Lesson(title="P", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (target, p):
        _set_if_has(l, created_by=user.id); db_session.add(l)
    await db_session.commit()
    await db_session.refresh(target); await db_session.refresh(p)

    idem_key = "same-key"
    idemp_base = f"idemp:unlock_update:{org.id}:{target.id}:{idem_key}"
    idemp_resp_key = f"{idemp_base}:resp"

    cached_payload = {
        # minimal, but shaped like LessonRead; the route returns it then FastAPI validates it
        "id": str(target.id),
        "title": target.title,
        "order": target.order,
        "is_published": True,
        "course_id": str(c.id),
        "organization_id": str(org.id),
        "section_id": None,
        "created_at": None,
        "updated_at": None,
    }
    cached_raw = json.dumps(cached_payload, separators=(",", ":"), ensure_ascii=False)

    # Fake redis wrapper used by the route module
    class _Client:
        async def get(self, key):
            return cached_raw if key == idemp_resp_key else None
        async def set(self, *a, **kw): return True
        async def setex(self, *a, **kw): return True
        async def pexpire(self, *a, **kw): return True
    class _Wrapper:
        client = _Client()

    monkeypatch.setattr("app.api.v1.lessons.unlocks.redis_wrapper", _Wrapper(), raising=False)

    # Ensure service is NOT called when cache is hit
    async def _should_not_be_called(*a, **kw):
        raise AssertionError("update_lesson_unlock_conditions must not be called when idempotent cache is hit")
    monkeypatch.setattr(
        "app.api.v1.lessons.unlocks.update_lesson_unlock_conditions",
        _should_not_be_called,
        raising=True,
    )

    r = await async_client.patch(
        f"{BASE}/{target.id}/unlock-conditions",
        headers={**headers, "Idempotency-Key": idem_key},
        json={"prerequisite_lesson_ids": [str(p.id)]},
    )
    assert r.status_code == 200, r.text
    assert r.json()["id"] == str(target.id)


@pytest.mark.anyio
async def test_unlock_patch__idempotent_conflict_when_lock_present(
    async_client: AsyncClient, db_session, org_user_with_token, monkeypatch
):
    """
    If the idempotency lock already exists (SET NX fails), route returns 409.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="I2", slug=f"i2-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="Target", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    p = Lesson(title="P", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (target, p):
        _set_if_has(l, created_by=user.id); db_session.add(l)
    await db_session.commit()
    await db_session.refresh(target); await db_session.refresh(p)

    idem_key = "lock-key"
    idemp_base = f"idemp:unlock_update:{org.id}:{target.id}:{idem_key}"
    idemp_lock_key = f"{idemp_base}:lock"

    # Fake client: GET returns None; SET (lock) returns False to simulate existing lock
    class _Client:
        async def get(self, key): return None
        async def set(self, key, value, nx=False, px=None):
            if key == idemp_lock_key and nx:
                return False  # lock exists
            return True
        async def setex(self, *a, **kw): return True
        async def pexpire(self, *a, **kw): return True
    class _Wrapper:
        client = _Client()

    monkeypatch.setattr("app.api.v1.lessons.unlocks.redis_wrapper", _Wrapper(), raising=False)

    r = await async_client.patch(
        f"{BASE}/{target.id}/unlock-conditions",
        headers={**headers, "Idempotency-Key": idem_key},
        json={"prerequisite_lesson_ids": [str(p.id)]},
    )
    assert r.status_code == 409, r.text
    assert "duplicate request in progress" in r.text.lower()
