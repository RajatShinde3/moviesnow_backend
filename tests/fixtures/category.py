import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import Category
from uuid import uuid4, UUID
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional
from app.db.models.course import Course
from app.db.models import CourseCategoryAssociation


@pytest.fixture
def category_factory(db_session: AsyncSession):
    """
    Async factory fixture to create Category instances.

    Usage:
        category = await category_factory(name="Programming")
    """
    async def _create(name: str = None, slug: str = None) -> Category:
        name = name or f"Category {uuid4().hex[:6]}"
        slug = slug or name.lower().replace(" ", "-")
        now = datetime.now(timezone.utc)
        category = Category(
            id=uuid4(),
            name=name,
            slug=slug,
            created_at=now,
            updated_at=now,
        )
        db_session.add(category)
        await db_session.commit()
        await db_session.refresh(category)
        return category
    return _create



@pytest.fixture
def create_test_course(db_session: AsyncSession) -> Callable[..., Awaitable[Course]]:
    async def _create(**kwargs) -> Course:
        course = Course(
            id=uuid4(),
            title=kwargs.get("title", "Test Course"),
            slug=kwargs.get("slug", f"test-course-{uuid4().hex[:6]}"),
            description=kwargs.get("description", "Test Description"),
            visibility=kwargs.get("visibility", "public"),
            organization_id=kwargs["organization_id"],
            is_published=kwargs.get("is_published", True),
            created_by=kwargs["created_by"],
            updated_by=kwargs.get("updated_by", kwargs["created_by"]),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(course)
        await db_session.commit()
        await db_session.refresh(course)
        return course
    return _create

from slugify import slugify  # you can use python-slugify or any slug generator

@pytest.fixture
def create_test_category(db_session: AsyncSession) -> Callable[..., Awaitable[Category]]:
    async def _create(**kwargs) -> Category:
        name = kwargs.pop("name", "Test Category")
        slug = kwargs.pop("slug", slugify(name))

        category = Category(
            id=uuid4(),
            name=name,
            slug=slug,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            **kwargs,
        )
        db_session.add(category)
        await db_session.commit()
        await db_session.refresh(category)
        return category
    return _create




@pytest.fixture
def create_test_course_category_link(db_session: AsyncSession) -> Callable[..., Awaitable[CourseCategoryAssociation]]:
    async def _create(
        course: Course,
        category: Category,
        organization_id: UUID,
        created_by: UUID,
        updated_by: Optional[UUID] = None,
        name: str = "Test CourseCategory Link",
    ) -> CourseCategoryAssociation:
        link = CourseCategoryAssociation(
            id=uuid4(),
            course_id=course.id,
            category_id=category.id,
            organization_id=organization_id,
            created_by=created_by,
            updated_by=updated_by or created_by,
            name=name,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(link)
        await db_session.commit()
        await db_session.refresh(link)
        return link
    return _create
