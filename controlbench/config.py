"""Environment-driven configuration (optionally seeded from a local .env file)."""

from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: str | os.PathLike = ".env") -> None:
    """Tiny .env reader; existing environment variables always win."""
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def claude_enabled() -> bool:
    return os.environ.get("CONTROLBENCH_ENABLE_CLAUDE", "0").lower() in ("1", "true", "yes")
