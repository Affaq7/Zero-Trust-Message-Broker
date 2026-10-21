"""Fixture web pages instead of the real internet.

pages.json maps a URL (scheme://host/path) to a local HTML file. Unknown
URLs are "not found"; nothing ever goes out to the network.
"""

import json
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "web"


class WebError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


@lru_cache(maxsize=1)
def pages() -> dict[str, str]:
    with open(FIXTURES / "pages.json", encoding="utf-8") as f:
        return {normalize(url): name for url, name in json.load(f).items()}


def normalize(url: str) -> str:
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise WebError(f"resource must be an http(s) URL, got {url!r}")
    path = parts.path.rstrip("/") or "/"
    return f"{parts.scheme}://{parts.netloc.lower()}{path}"


def fetch(url: str, max_chars: int) -> dict:
    key = normalize(url)
    name = pages().get(key)
    if name is None:
        raise WebError(f"page not found: {key}", status=404)
    html = (FIXTURES / name).read_text(encoding="utf-8")
    return {"url": key, "status": 200, "truncated": len(html) > max_chars,
            "content": html[:max_chars]}
