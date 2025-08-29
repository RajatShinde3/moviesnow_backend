# check_db_connection.py
import sys
import os

# Add the project root (career-os/backend) to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

from tests.test_settings import settings


async def check_connection():
    engine = create_async_engine(settings.TEST_DATABASE_URL, echo=True)

    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        print("✅ Successfully connected to the test database.")
    except Exception as e:
        print(f"❌ Failed to connect to the test database:\n{e}")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(check_connection())
