"""Uvicorn entry point: uvicorn mocks.main:app --port 8090"""

from pathlib import Path

from dotenv import load_dotenv

from mocks.app import create_app
from mocks.config import load_mock_settings

load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)

app = create_app(load_mock_settings())
