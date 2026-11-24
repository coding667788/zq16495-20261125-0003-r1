from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .errors import TimeFormatError


def parse_time(value: Any, field: str = "time") -> datetime:
    """Parse ISO-8601. Naive timestamps are interpreted as UTC.

    Datetime values are normalized as a convenience for cached intervals.
    ``Z`` is accepted on Python versions whose ``fromisoformat`` does not yet
    normalize it consistently in all patch releases.
    """
    if isinstance(value, datetime):
        parsed = value
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    if not isinstance(value, str) or not value.strip():
        raise TimeFormatError(f"{field} must be a non-empty ISO-8601 string")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise TimeFormatError(f"{field} is not valid ISO-8601: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_time(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def visible_at(record: dict[str, Any], known_at: datetime) -> bool:
    """Whether a record has been published by the reviewer's knowledge cut."""
    published = None
    for field in (
        "published_at",
        "publicized_at",
        "public_at",
        "announced_at",
        "disclosed_at",
        "published",
    ):
        if record.get(field) is not None:
            published = record[field]
            break
    if published is None:
        return True
    return parse_time(published, "published_at") <= known_at


def within_interval(
    instant: datetime,
    start: Any | None,
    end: Any | None,
    *,
    start_field: str = "start_at",
    end_field: str = "end_at",
    end_inclusive: bool = False,
) -> bool:
    """Interval check; temporal notice intervals default to half-open."""
    if start is not None and instant < parse_time(start, start_field):
        return False
    end_moment = parse_time(end, end_field) if end is not None else None
    if end_moment is not None:
        if end_inclusive:
            if instant > end_moment:
                return False
        elif instant >= end_moment:
            return False
    return True
