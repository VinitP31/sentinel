"""JSON writing that survives boto3 responses.

Boto3 returns datetime objects, which json.dump cannot serialize. Always use
write_json rather than calling json.dump directly.
"""

import json
from datetime import date, datetime
from pathlib import Path
from typing import Any


def _fallback(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "as_dict"):
        return value.as_dict()
    raise TypeError(f"Cannot serialize {type(value).__name__} to JSON")


def write_json(path: Path, data: Any) -> Path:
    """Write data as indented JSON, converting timestamps to ISO 8601."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, default=_fallback)
    return path


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)
