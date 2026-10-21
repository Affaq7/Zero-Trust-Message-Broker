import pytest
from fastapi.testclient import TestClient

from mocks.app import create_app
from mocks.config import MockSettings


@pytest.fixture
def mock_settings(tmp_path):
    return MockSettings(runtime_dir=tmp_path / "run time" / "mocks", log_dir=tmp_path / "logs")


@pytest.fixture
def mocks(mock_settings):
    return TestClient(create_app(mock_settings))


@pytest.fixture
def truth(mocks):
    """truth(**filters) -> ground-truth records from the running mock app."""
    def _truth(**params):
        return mocks.get("/ground-truth", params=params).json()["records"]
    return _truth
