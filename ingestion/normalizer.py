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
import re
import xml.etree.ElementTree as ET
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


EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Matches an Event start tag, end tag, or self-closing tag. `\b` keeps this from
# matching <EventData> or <EventID>, whose next character is a word character.
_EVENT_TAG = re.compile(r"<(/?)Event\b([^>]*?)(/?)>")

# Windows writes 7 fractional digits; fromisoformat on 3.8-3.10 accepts 3 or 6.
_FRACTION = re.compile(r"\.(\d{1,9})Z?$")


def split_events(xml_blob):
    """Split a concatenated wevtutil XML dump into individual event strings.

    Tracks nesting depth instead of matching the first </Event>, because some
    providers use <Event> as an element name inside their own payload, e.g.
    Resource-Exhaustion-Resolver 1015 emits <EventInfo><Event>4</Event>
    </EventInfo>, which a non-greedy match truncates mid-record. Slicing by
    position also keeps the exact original bytes, which `raw` depends on.

    Relies on the Event Log renderer escaping < and > inside Data values
    (checked against 6000 real events). Hand-supplied raw XML with literal
    < or > in a value would need a real streaming parser instead.

    Lossy on malformed input: if the blob contains an unterminated record,
    records after it are silently dropped, so callers handling non-renderer
    XML must not assume the result is complete.
    """
    records = []
    depth = 0
    start = None
    for match in _EVENT_TAG.finditer(xml_blob):
        closing, _attrs, self_closing = match.groups()
        if closing:
            if depth:
                depth -= 1
                if depth == 0 and start is not None:
                    records.append(xml_blob[start:match.end()])
                    start = None
        elif self_closing:
            if depth == 0:
                records.append(match.group(0))
        else:
            if depth == 0:
                start = match.start()
            depth += 1
    return records


def _parse_system_time(value):
    """Parse a SystemTime attribute into a local naive datetime."""
    original = value.strip()
    text = original
    match = _FRACTION.search(text)
    if match:
        digits = match.group(1)[:6].ljust(6, "0")
        text = text[: match.start()] + "." + digits
        if original.endswith("Z"):
            text += "+00:00"
    elif text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return to_local_naive(datetime.fromisoformat(text))


def _strip_ns(tag):
    """Drop an XML namespace prefix from a tag name."""
    return tag.split("}", 1)[-1] if "}" in tag else tag


def parse_event_xml(xml_text):
    """Parse one Windows Event XML record into a field dict.

    Handles both payload shapes: <EventData><Data Name='x'>v</Data> and
    <UserData><SomeElement><x>v</x>, which EventID 1102 among others uses.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError("Malformed event XML: {}".format(exc))

    if _strip_ns(root.tag) != "Event":
        raise ValueError(
            "Not a Windows Event record (root element is {!r})".format(
                _strip_ns(root.tag)
            )
        )

    system = root.find(EVENT_NS + "System")
    if system is None:
        system = root.find("System")
    if system is None:
        raise ValueError("Event XML has no <System> section")

    def sys_node(name):
        node = system.find(EVENT_NS + name)
        return node if node is not None else system.find(name)

    def sys_text(name, default=""):
        node = sys_node(name)
        return node.text.strip() if node is not None and node.text else default

    def required_text(name):
        # Windows always emits these. A silent default would corrupt the
        # dedup key (record_id, host) or the timeline (event time).
        value = sys_text(name)
        if not value:
            raise ValueError("Event XML has no {}".format(name))
        return value

    time_node = sys_node("TimeCreated")
    provider_node = sys_node("Provider")

    system_time = time_node.get("SystemTime") if time_node is not None else None
    if not system_time or not system_time.strip():
        raise ValueError("Event XML has no SystemTime")
    timestamp = _parse_system_time(system_time)

    data = {}
    for container_name in ("EventData", "UserData"):
        container = root.find(EVENT_NS + container_name)
        if container is None:
            container = root.find(container_name)
        if container is None:
            continue
        for element in container.iter():
            tag = _strip_ns(element.tag)
            if tag == container_name:
                continue
            text = (element.text or "").strip()
            if tag == "Data":
                name = element.get("Name")
                if name:
                    data[name] = text
            elif text:
                data[tag] = text

    return {
        "event_id": int(required_text("EventID")),
        "record_id": int(required_text("EventRecordID")),
        "channel": sys_text("Channel", "-"),
        "host": required_text("Computer"),
        "provider": provider_node.get("Name", "-") if provider_node is not None else "-",
        "level": int(sys_text("Level", "0") or 0),
        "timestamp": timestamp,
        "data": data,
    }
