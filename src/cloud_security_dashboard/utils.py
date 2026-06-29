from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from zoneinfo import ZoneInfo


def now_utc() -> datetime:
    return datetime.now(UTC)


def to_utc(value: datetime, timezone_name: str) -> datetime:
    if value.tzinfo is not None:
        return value.astimezone(UTC)
    return value.replace(tzinfo=ZoneInfo(timezone_name)).astimezone(UTC)


def make_hash(*parts: object) -> str:
    joined = "||".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def safe_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None
