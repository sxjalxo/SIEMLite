#!/usr/bin/env python3
"""
Time Utilities
==============
Relative time parsing shared by every CLI verb, and the single conversion
point between timezone-aware sources (Windows Event Log emits UTC) and the
local naive datetimes the rest of the pipeline stores.
"""

import re
from datetime import datetime, timedelta

_RELATIVE = re.compile(r"^([0-9]+)([smhd])$")

_UNITS = {
    "s": "seconds",
    "m": "minutes",
    "h": "hours",
    "d": "days",
}


def parse_since(value, now=None):
    """Parse a relative offset ('30m', '24h', '7d') or an ISO timestamp.

    Returns a local naive datetime. Raises ValueError on anything else.
    """
    if now is None:
        now = datetime.now()

    if not value or not isinstance(value, str):
        raise ValueError("Empty time value. Use e.g. 24h, 30m, 7d, or 2026-09-01.")

    value = value.strip()

    match = _RELATIVE.match(value)
    if match:
        amount = int(match.group(1))
        unit = _UNITS[match.group(2)]
        try:
            return now - timedelta(**{unit: amount})
        except OverflowError:
            raise ValueError(
                "Time value {!r} is too large. Use a smaller offset like 24h, "
                "30m, 7d.".format(value)
            )

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(
            "Cannot parse time value {!r}. Use a relative offset like 24h, 30m, "
            "7d, or an ISO timestamp like 2026-09-01T08:30:00.".format(value)
        )
    try:
        return to_local_naive(parsed)
    except (OSError, OverflowError):
        raise ValueError(
            "Time value {!r} is out of range for local time conversion.".format(value)
        )


# ponytail: DST fall-back hour is ambiguous under the local-naive convention —
# two distinct UTC instants can map to the same wall clock. Accepted: the
# exposure is one hour a year. Upgrade path is storing UTC in `events` and
# converting at display time.
def to_local_naive(dt):
    """Convert an aware datetime to local time and drop tzinfo.

    Naive datetimes pass through unchanged.
    """
    if dt.tzinfo is None:
        return dt
    return dt.astimezone().replace(tzinfo=None)
