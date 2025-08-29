# tests/test_settings.py

"""
🛠️ Test Settings:
Overrides environment-specific DB connection for isolated test database.
"""

from app.core.config import Settings

class TestSettings(Settings):
    @property
    def TEST_DATABASE_URL(self) -> str:
        """
        Returns a test-specific DB URL. Ensures isolation from production.
        Appends `_test` suffix to DB name if missing.
        """
        db_name = self.POSTGRES_DB
        if not db_name.endswith("_test"):
            db_name += "_test"
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD.get_secret_value()}"
            f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{db_name}"
        )

# 👇 Used in all test DB fixtures
settings = TestSettings()
