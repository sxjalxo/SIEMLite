#!/usr/bin/env python3
"""
Normalizer — Flat Event Schema
==============================
Every log source converts into a NormalizedEvent. Detection rules match
flat fields on this dataclass, never regexes over a raw message, so field
extraction happens exactly once, here.
"""

import hashlib
import json
from dataclasses import dataclass, field, fields
from datetime import datetime

from core.timeutil import to_local_naive


@dataclass
class NormalizedEvent:
    """A single security-relevant event, source-agnostic."""

    timestamp: datetime
    source_type: str
    host: str
    channel: str
    event_id: int
    record_id: int

    action: str = "OTHER"
    severity_hint: str = "INFO"

    user: str = "-"
    target_user: str = "-"
    source_ip: str = "-"
    dest_ip: str = "-"
    logon_type: int = 0

    process: str = "-"
    process_id: int = 0
    parent_process: str = "-"
    command_line: str = "-"

    object_name: str = "-"
    service_name: str = "-"

    detail: str = "-"
    raw: str = ""
    metadata: dict = field(default_factory=dict)

    @property
    def event_hash(self):
        """Stable identity for deduplication across repeated ingests.

        The line content is part of the key by default, because most sources
        reuse record_id as a file line number and line numbers repeat across
        files. A live Windows channel has a genuinely unique (host, channel,
        record_id) triple and opts out with metadata["stable_record_id"],
        because the same event rendered by pywin32 and by wevtutil can differ
        in whitespace and must not split into two rows.
        """
        parts = [self.host, self.channel, str(self.record_id)]
        if not self.metadata.get("stable_record_id"):
            parts.append(hashlib.sha256(self.raw.encode("utf-8")).hexdigest())
        return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()

    def to_row(self):
        """Flatten to a dict matching the `events` table columns."""
        row = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name == "timestamp":
                row[f.name] = value.isoformat(sep=" ")
            elif f.name == "metadata":
                row[f.name] = json.dumps(value, default=str)
            else:
                row[f.name] = value
        row["event_hash"] = self.event_hash
        return row

    @classmethod
    def from_row(cls, row):
        """Rebuild from a sqlite3.Row or dict produced by to_row()."""
        data = dict(row)
        data.pop("id", None)
        data.pop("event_hash", None)

        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            data["timestamp"] = to_local_naive(datetime.fromisoformat(timestamp))

        metadata = data.get("metadata")
        if isinstance(metadata, str):
            data["metadata"] = json.loads(metadata) if metadata else {}
        elif metadata is None:
            data["metadata"] = {}

        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


# Flat field names rules may match on. `raw` and `metadata` are excluded:
# raw is unstructured, metadata is source-specific and not schema-stable.
EVENT_FIELDS = tuple(
    f.name for f in fields(NormalizedEvent) if f.name not in ("raw", "metadata")
)
