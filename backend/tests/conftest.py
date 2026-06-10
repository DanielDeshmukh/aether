import os
import pytest
from unittest.mock import MagicMock


@pytest.fixture(scope="session")
def test_db_url():
    """Get test database URL from environment or use a default."""
    return os.getenv("DATABASE_URL", os.getenv("TEST_DATABASE_URL", "postgresql://aether_test:test_password@localhost:5432/aether_test"))


@pytest.fixture(scope="session")
def mock_storage():
    """Create a mock storage instance for unit tests."""
    storage = MagicMock()
    storage.database_configured.return_value = False
    storage.configured.return_value = False
    return storage


@pytest.fixture(autouse=True)
def setup_test_env():
    """Set up test environment variables."""
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("AETHER_JWT_SECRET", "test-secret-key-for-testing-only")
    yield
    # Cleanup if needed