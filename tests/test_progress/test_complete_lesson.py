# tests/test_progress/test_complete_lesson.py

import uuid
import json
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.models import Course, Lesson, LessonProgress, Organization
from app.schemas.enums import OrgRole
from app.core.redis_client import redis_wrapper

BASE = "/api/v1/progress"


def _set_if_has(obj, **fields):
    """Set attributes only if they exist on the SQLAlchemy model."""
    for k, v in fields.items():
        if hasattr(obj, k):
            setattr(obj, k, v)


@pytest.mark.anyio
async def test_complete__404_when_lesson_missing(async_client: AsyncClient, org_user_with_token, monkeypatch):
    """
    404 if lesson doesn't exist. Patch access gate to 'allow' to isolate not-found.
    """
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    async def _allow(*a, **k): return True
    monkeypatch.setattr("app.api.v1.progress.progress.can_access_course", _allow, raising=True)

    missing = uuid.uuid4()
    r = await async_client.post(f"{BASE}/lesson/{missing}", headers=headers)
    assert r.status_code == 404, r.text


@pytest.mark.anyio
async def test_complete__403_when_course_in_other_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    403 when lesson exists but belongs to another organization.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Another org to create the foreign course
    org2 = Organization(
        name=f"Other-{uuid.uuid4().hex[:6]}",
        slug=f"other-{uuid.uuid4().hex[:8]}",
    )

    _set_if_has(org2, created_by=user.id)
    db_session.add(org2); await db_session.commit(); await db_session.refresh(org2)

    c = Course(
        title="Other Course",
        slug=f"other-{uuid.uuid4().hex[:8]}",
        organization_id=org2.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    l = Lesson(title="Foreign", order=1, is_published=True, course_id=c.id, organization_id=org2.id)
    _set_if_has(l, created_by=user.id)
    db_session.add(l); await db_session.commit(); await db_session.refresh(l)

    # Even if access helper returns True, org guard must block
    async def _allow(*a, **k): return True
    monkeypatch.setattr("app.api.v1.progress.progress.can_access_course", _allow, raising=True)

    r = await async_client.post(f"{BASE}/lesson/{l.id}", headers=headers)
    assert r.status_code == 403, r.text


# tests/test_progress/test_complete_lesson.py

@pytest.mark.anyio
async def test_complete__403_when_access_denied(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    403 if can_access_course denies enrollment/visibility.
    Includes print-debug to verify patches and runtime behavior.
    """
    print("\n[DEBUG] test_complete__403_when_access_denied: start")

    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    print(f"[DEBUG] user.id={user.id} org.id={org.id}")

    c = Course(
        title="NoAccess",
        slug=f"noacc-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)
    print(f"[DEBUG] course.id={c.id} slug={c.slug}")

    l = Lesson(title="L", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(l, created_by=user.id)
    db_session.add(l)
    await db_session.commit()
    await db_session.refresh(l)
    print(f"[DEBUG] lesson.id={l.id}")

    async def _deny(*a, **k):
        print("[DEBUG] can_access_course CALLED -> returning False")
        return False

    # 1) If the route imported the symbol directly
    try:
        monkeypatch.setattr("app.api.v1.progress.progress.can_access_course", _deny, raising=False)
        print("[DEBUG] patched app.api.v1.progress.progress.can_access_course")
    except Exception as e:
        print(f"[DEBUG] could not patch app.api.v1.progress.progress.can_access_course: {e!r}")

    # 2) If the route uses the service module symbol
    try:
        monkeypatch.setattr("app.services.courses.access_control.can_access_course", _deny, raising=False)
        print("[DEBUG] patched app.services.courses.access_control.can_access_course")
    except Exception as e:
        print(f"[DEBUG] could not patch app.services.courses.access_control.can_access_course: {e!r}")

    # 3) GUARANTEE: patch the function object's globals (covers aliases / bind-at-import)
    from app.api.v1.progress import progress as progress_mod
    fn = progress_mod.complete_lesson
    print(f"[DEBUG] complete_lesson fn={fn}")

    # Inspect globals for any alias pointing to the access_control module
    found_aliases = []
    for name, obj in list(fn.__globals__.items()):
        mod = getattr(obj, "__module__", "")
        if callable(obj) and mod.endswith("app.services.courses.access_control"):
            found_aliases.append(name)
            monkeypatch.setitem(fn.__globals__, name, _deny)
            print(f"[DEBUG] patched fn.__globals__ alias {name} (module {mod}) -> _deny")

    # Ensure canonical name is patched even if not present earlier
    monkeypatch.setitem(fn.__globals__, "can_access_course", _deny)
    print(f"[DEBUG] fn.__globals__['can_access_course'] is _deny: {fn.__globals__.get('can_access_course') is _deny}")
    print(f"[DEBUG] aliases found in fn.__globals__: {found_aliases}")

    # Call the endpoint
    r = await async_client.post(f"{BASE}/lesson/{l.id}", headers=headers)
    print(f"[DEBUG] response.status_code={r.status_code}")
    try:
        print(f"[DEBUG] response.json()={r.json()}")
    except Exception:
        print(f"[DEBUG] response.text={r.text}")

    assert r.status_code == 403, r.text
    print("[DEBUG] ASSERTION PASSED: got 403")






# --- replace this whole test ---
@pytest.mark.anyio
async def test_complete__200_creates_or_updates_progress_and_invalidates_cache(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    200 on success, returns LessonProgressRead payload, and invalidates unlock-related caches.
    Validates course_id via DB row (response may omit/alias it in some schemas).
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Happy",
        slug=f"happy-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    l = Lesson(title="Win", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(l, created_by=user.id)
    db_session.add(l); await db_session.commit(); await db_session.refresh(l)

    # access allowed
    async def _allow(*a, **k): return True
    monkeypatch.setattr("app.api.v1.progress.progress.can_access_course", _allow, raising=True)

    # track invalidation call
    called = {}
    async def _fake_invalidate(course_id, *args, **kwargs):
        called["course_id"] = course_id
        return 0
    monkeypatch.setattr("app.api.v1.progress.progress.invalidate_unlock_related_caches", _fake_invalidate, raising=True)

    # call
    r = await async_client.post(f"{BASE}/lesson/{l.id}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()

    # stable, schema-agnostic checks
    assert body["lesson_id"] == str(l.id)
    assert body.get("user_id") == str(user.id)

    # verify course_id via DB row to avoid schema differences in payload
    row = (
        await db_session.execute(
            select(LessonProgress).where(LessonProgress.lesson_id == l.id)
        )
    ).scalar_one_or_none()
    assert row is not None
    assert row.course_id == c.id

    # invalidation called with course id
    assert called.get("course_id") == c.id



# --- and replace this whole test too ---
@pytest.mark.anyio
async def test_complete__idempotent_replay_with_same_key(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    Two identical requests with the same Idempotency-Key should not create a new progress row.
    We compare stable fields and ensure the same progress id is returned; timestamps may differ.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Idem",
        slug=f"idem-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    l = Lesson(title="I", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(l, created_by=user.id)
    db_session.add(l); await db_session.commit(); await db_session.refresh(l)

    async def _allow(*a, **k): return True
    monkeypatch.setattr("app.api.v1.progress.progress.can_access_course", _allow, raising=True)

    idem = "same-key"

    r1 = await async_client.post(
        f"{BASE}/lesson/{l.id}",
        headers={**headers, "Idempotency-Key": idem},
    )
    assert r1.status_code == 200, r1.text
    body1 = r1.json()

    r2 = await async_client.post(
        f"{BASE}/lesson/{l.id}",
        headers={**headers, "Idempotency-Key": idem},
    )
    assert r2.status_code == 200, r2.text
    body2 = r2.json()

    # Stable fields must match
    for k in ("id", "lesson_id", "user_id"):
        assert body2.get(k) == body1.get(k)

    # If course_id is present in the payload, it must match.
    if "course_id" in body1 or "course_id" in body2:
        assert body2.get("course_id") == body1.get("course_id")

    # Timestamps may differ if the handler revalidates/completes again;
    # we only require the same progress row, not byte-identical JSON.



@pytest.mark.anyio
async def test_complete__409_when_idempotency_lock_present(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    If the idempotency lock already exists (SET NX fails), route returns 409.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Lock",
        slug=f"lock-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    l = Lesson(title="L", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(l, created_by=user.id)
    db_session.add(l); await db_session.commit(); await db_session.refresh(l)

    async def _allow(*a, **k): return True
    monkeypatch.setattr("app.api.v1.progress.progress.can_access_course", _allow, raising=True)

    idem_key = "lock-key"

    # Build the exact key the route will use:
    # idemp:lesson_complete:{org_id}:{lesson_id}:{actor_user_id}:{idempotency_key}:lock
    # We don't know actor_user_id here; patch redis client to simulate NX failure
    class _Client:
        async def get(self, key): return None
        async def set(self, key, value, nx=False, px=None):
            # when route tries to acquire the lock, pretend it's already held
            if nx and key.endswith(":lock"):
                return False
            return True
        async def setex(self, *a, **kw): return True
        async def pexpire(self, *a, **kw): return True

    class _Wrapper:
        client = _Client()

    # Patch where the route imports redis_wrapper
    monkeypatch.setattr("app.api.v1.progress.progress.redis_wrapper", _Wrapper(), raising=False)

    r = await async_client.post(
        f"{BASE}/lesson/{l.id}",
        headers={**headers, "Idempotency-Key": idem_key},
    )
    assert r.status_code == 409, r.text
