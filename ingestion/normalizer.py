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


# ----------------------------------------------------------------------
# Windows EventID -> semantic action
# ----------------------------------------------------------------------

WINDOWS_ACTIONS = {
    4624: "LOGIN_OK",
    4625: "LOGIN_FAIL",
    4634: "LOGOFF",
    4672: "PRIVILEGE_ASSIGN",
    4688: "PROCESS_CREATE",
    4689: "PROCESS_EXIT",
    4720: "ACCOUNT_CREATE",
    4722: "ACCOUNT_ENABLE",
    4724: "PASSWORD_RESET",
    4728: "GROUP_ADD_GLOBAL",
    4732: "GROUP_ADD_LOCAL",
    4740: "ACCOUNT_LOCKOUT",
    4776: "NTLM_VALIDATE",
    4698: "TASK_CREATE",
    1102: "LOG_CLEARED",
    7045: "SERVICE_INSTALL",
    4104: "SCRIPTBLOCK",
    5140: "SHARE_ACCESS",
}

SYSMON_ACTIONS = {
    1: "PROCESS_CREATE",
    3: "NETWORK_CONNECT",
    11: "FILE_CREATE",
}

# Severity hints are parser-level only. Detection rules set real severity.
_SEVERITY_HINTS = {
    "LOGIN_FAIL": "LOW",
    "ACCOUNT_CREATE": "MEDIUM",
    "GROUP_ADD_GLOBAL": "MEDIUM",
    "GROUP_ADD_LOCAL": "MEDIUM",
    "PRIVILEGE_ASSIGN": "MEDIUM",
    "LOG_CLEARED": "HIGH",
    "SERVICE_INSTALL": "MEDIUM",
    "TASK_CREATE": "MEDIUM",
}

_LOCAL_ADDRESSES = {"-", "", "::1", "127.0.0.1", "0.0.0.0", "localhost"}

# metadata keys that are pipeline control flags. EventData names and values
# are attacker-influenced, so the catch-all must never write these; a clash
# is kept under an "eventdata_" prefix instead. A new flag is closed by
# adding its name here.
_RESERVED_METADATA_KEYS = frozenset({"stable_record_id"})

# data key -> flat field, applied per EventID. Keys absent from `data` are skipped.
_FIELD_MAPS = {
    4624: {"TargetUserName": "user", "IpAddress": "source_ip",
           "LogonType": "logon_type", "ProcessName": "process"},
    4625: {"TargetUserName": "target_user", "SubjectUserName": "user",
           "IpAddress": "source_ip", "LogonType": "logon_type"},
    4634: {"TargetUserName": "user", "LogonType": "logon_type"},
    4672: {"SubjectUserName": "user"},
    4688: {"SubjectUserName": "user", "NewProcessName": "process",
           "ParentProcessName": "parent_process", "CommandLine": "command_line"},
    4689: {"SubjectUserName": "user", "ProcessName": "process"},
    4720: {"SubjectUserName": "user", "TargetUserName": "target_user"},
    4722: {"SubjectUserName": "user", "TargetUserName": "target_user"},
    4724: {"SubjectUserName": "user", "TargetUserName": "target_user"},
    4728: {"SubjectUserName": "user", "MemberName": "target_user",
           "TargetUserName": "object_name"},
    4732: {"SubjectUserName": "user", "MemberName": "target_user",
           "TargetUserName": "object_name"},
    4740: {"TargetUserName": "target_user", "TargetDomainName": "object_name"},
    4776: {"TargetUserName": "target_user", "Workstation": "object_name"},
    4698: {"SubjectUserName": "user", "TaskName": "object_name"},
    1102: {"SubjectUserName": "user"},
    7045: {"AccountName": "user", "ServiceName": "service_name",
           "ImagePath": "process"},
    4104: {"ScriptBlockText": "command_line", "Path": "object_name"},
    5140: {"SubjectUserName": "user", "IpAddress": "source_ip",
           "ShareName": "object_name"},
}

_SYSMON_FIELD_MAPS = {
    1: {"User": "user", "Image": "process", "ParentImage": "parent_process",
        "CommandLine": "command_line"},
    3: {"User": "user", "Image": "process", "SourceIp": "source_ip",
        "DestinationIp": "dest_ip"},
    11: {"User": "user", "Image": "process", "TargetFilename": "object_name"},
}

# Fields that must end up as ints regardless of how the XML spelled them.
_INT_FIELDS = {"logon_type"}
_IP_FIELDS = ("source_ip", "dest_ip")

_DETAIL_ORDER = (
    "target_user", "user", "source_ip", "process", "command_line",
    "service_name", "object_name",
)


def _clean_ip(value):
    """Collapse loopback and placeholder addresses to a single 'local' token."""
    text = value.strip()
    return "local" if text.lower() in _LOCAL_ADDRESSES else text


def _to_int(value):
    """Parse an int that may be decimal or hex ('0x1a4')."""
    if value is None:
        return 0
    text = str(value).strip()
    if not text or text == "-":
        return 0
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return 0


def _is_sysmon(channel):
    return "sysmon" in (channel or "").lower()


def _channel_allowed(event_id, channel):
    """True if this Windows (non-Sysmon) EventID may be interpreted here.

    The mapping keys on EventID, and unprivileged code can write Application
    and often System, so a forged 1102 or 4720 there must not become a
    detection. An ID on any other channel is still kept, just not interpreted
    ("OTHER"). ForwardedEvents is allowed because Windows Event Forwarding is
    a legitimate collection path; its ACL matches Application's, the real
    barrier is that writing needs a registered publisher. Derived from
    WINDOWS_ACTIONS so a new Security ID needs no second table.
    """
    name = (channel or "").lower()
    if event_id == 7045:
        return name == "system"
    if event_id == 4104:
        return "powershell" in name
    return event_id in WINDOWS_ACTIONS and name in ("security", "forwardedevents")


def normalize_windows(parsed, raw=""):
    """Build a NormalizedEvent from the dict parse_event_xml() produced."""
    event_id = parsed["event_id"]
    channel = parsed["channel"]
    data = dict(parsed["data"])
    sysmon = _is_sysmon(channel)
    # Interpret as a Windows-native ID only on a channel that may carry it.
    win = not sysmon and _channel_allowed(event_id, channel)

    if sysmon:
        action = SYSMON_ACTIONS.get(event_id, "OTHER")
        field_map = _SYSMON_FIELD_MAPS.get(event_id, {})
    elif win:
        action = WINDOWS_ACTIONS.get(event_id, "OTHER")
        field_map = _FIELD_MAPS.get(event_id, {})
    else:
        action = "OTHER"
        field_map = {}

    flat = {}
    consumed = set()
    for key, target in field_map.items():
        # An empty IP is still a statement ("no remote peer"), so it maps to
        # "local" below instead of being skipped like other empty values.
        if key in data and (data[key] != "" or target in _IP_FIELDS):
            flat[target] = data[key]
            consumed.add(key)

    # 4624 records the same name on both sides of the action.
    if event_id == 4624 and win and "user" in flat:
        flat["target_user"] = flat["user"]

    if "source_ip" in flat:
        flat["source_ip"] = _clean_ip(flat["source_ip"])
    if "dest_ip" in flat:
        flat["dest_ip"] = _clean_ip(flat["dest_ip"])
    for name in _INT_FIELDS:
        if name in flat:
            flat[name] = _to_int(flat[name])

    if event_id == 4688 and win and "NewProcessId" in data:
        flat["process_id"] = _to_int(data["NewProcessId"])
        consumed.add("NewProcessId")
    if event_id == 1 and sysmon and "ProcessId" in data:
        flat["process_id"] = _to_int(data["ProcessId"])
        consumed.add("ProcessId")

    metadata = {"provider": parsed.get("provider", "-")}
    if event_id == 4625 and win:
        for key, name in (("Status", "status"), ("SubStatus", "sub_status"),
                          ("WorkstationName", "workstation")):
            if key in data:
                metadata[name] = data[key]
                consumed.add(key)
    if event_id == 4672 and win and "PrivilegeList" in data:
        metadata["privileges"] = data["PrivilegeList"].split()
        consumed.add("PrivilegeList")
    if event_id == 7045 and win and "StartType" in data:
        metadata["start_type"] = data["StartType"]
        consumed.add("StartType")
    if event_id == 4776 and win and "Status" in data:
        metadata["status"] = data["Status"]
        consumed.add("Status")
    if event_id == 3 and sysmon and "DestinationPort" in data:
        metadata["dest_port"] = data["DestinationPort"]
        consumed.add("DestinationPort")

    # Never drop information: whatever no mapping claimed goes to metadata.
    # Reserved control-flag names are kept, but under a prefix.
    for key, value in data.items():
        if key not in consumed and value:
            if key in _RESERVED_METADATA_KEYS:
                key = "eventdata_" + key
            metadata.setdefault(key, value)

    # Live channels have a unique (host, channel, record_id); see
    # NormalizedEvent.event_hash. Plain assignment, after the catch-all, so
    # nothing in the log content can pre-empt or alter it.
    metadata["stable_record_id"] = True

    event = NormalizedEvent(
        timestamp=parsed["timestamp"],
        source_type="windows",
        host=parsed["host"],
        channel=channel,
        event_id=event_id,
        record_id=parsed["record_id"],
        action=action,
        severity_hint=_SEVERITY_HINTS.get(action, "INFO"),
        raw=raw,
        metadata=metadata,
        **flat
    )
    event.detail = _build_detail(event)
    return event


def _one_line(text):
    """Replace non-printable characters (newlines, bidi overrides) with spaces."""
    return "".join(c if c.isprintable() else " " for c in text)


def _build_detail(event):
    """One readable line summarising the event, for timeline and CLI output."""
    parts = ["{} {}".format(event.event_id, event.action)]
    for name in _DETAIL_ORDER:
        value = getattr(event, name)
        if value and value not in ("-", 0, "local"):
            parts.append("{}={}".format(name, value))
    # raw keeps the original characters; detail is rendered as one timeline
    # row, so a newline or bidi override in a value must not survive.
    return _one_line(" ".join(parts))[:400]


def normalize_windows_xml(xml_text):
    """Parse and normalize one Windows Event XML record in a single call."""
    return normalize_windows(parse_event_xml(xml_text), raw=xml_text)


# Metadata keys the legacy LogEvent already carries that map onto flat fields.
_LEGACY_METADATA_FIELDS = {
    "command_line": "command_line",
    "process": "process",
    "new_account": "target_user",
}


def from_log_event(log_event, line_number=0):
    """Adapt a legacy LogEvent (Apache / SSH / Windows CSV) to NormalizedEvent.

    LogEvent has no channel, host or record id, so the source type stands in
    for the channel, metadata["computer"] gives the host, and line_number
    gives each row its record_id.

    line_number is an ordinal, not a physical file offset: the caller counts
    parsed events (e.g. enumerate(events, start=1)), so blank or unparsed
    lines do not advance it and log rotation shifts every value. It is a
    stable identity within one unchanged file only. It repeats across files,
    so this never sets metadata["stable_record_id"]: the raw digest in
    event_hash is what keeps two files' line 5 apart.

    The legacy parsers can leave None in fields, so this is a trust boundary:
    None falls back to the schema defaults. Only timestamp has no sensible
    default, so a None timestamp raises ValueError instead of failing
    obscurely later in to_row(). An aware timestamp outside what the OS can
    convert (e.g. Apache's %z accepts year 1 or pre-1970) also raises
    ValueError, so callers handle one exception type per record.

    Timestamps go through to_local_naive, the single conversion point:
    parse_apache emits tz-aware values, and a mixed aware/naive column breaks
    string-compared since= queries and ORDER BY timestamp.
    """
    if log_event.timestamp is None:
        raise ValueError(
            "LogEvent.timestamp is required, got None (line_number={})".format(
                line_number
            )
        )

    try:
        timestamp = to_local_naive(log_event.timestamp)
    except (OSError, OverflowError):
        raise ValueError(
            "LogEvent.timestamp {!r} is out of range for local time conversion "
            "(line_number={})".format(log_event.timestamp, line_number)
        )

    metadata = dict(log_event.metadata or {})
    # Control flags must come from this pipeline, never from parsed content.
    # Keep the clashing value under a prefix rather than dropping it.
    for key in _RESERVED_METADATA_KEYS & metadata.keys():
        metadata["legacy_" + key] = metadata.pop(key)

    source_type = log_event.source_type
    flat = {target: metadata[key] for key, target in _LEGACY_METADATA_FIELDS.items()
            if metadata.get(key)}
    action = log_event.action or "OTHER"

    return NormalizedEvent(
        timestamp=timestamp,
        source_type=source_type,
        host=metadata.get("computer") or metadata.get("host") or "-",
        channel="windows-csv" if source_type == "windows" else source_type,
        event_id=_to_int(metadata.get("event_id") or log_event.status_code),
        record_id=_to_int(line_number),
        action=action,
        severity_hint=_SEVERITY_HINTS.get(action, "INFO"),
        user=log_event.user or "-",
        source_ip=_clean_ip(log_event.source_ip or ""),
        detail=_one_line(log_event.detail or "-")[:400],
        raw=log_event.raw_line or "",
        metadata=metadata,
        **flat
    )
