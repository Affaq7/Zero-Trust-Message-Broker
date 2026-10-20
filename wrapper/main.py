"""Uvicorn entry point: uvicorn wrapper.main:app

Loads .env from the repo root (real environment variables win), then reads
the operator settings. A bad MODE or AGENT_NAME stops the server at startup.
"""

from pathlib import Path

from dotenv import load_dotenv

from wrapper.app import create_app
from wrapper.config import load_settings

load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)

app = create_app(load_settings())
