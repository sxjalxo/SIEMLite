#!/usr/bin/env python3
"""
Windows Event Log Reader
========================
Yields raw Event XML from a channel. Two backends behind one interface:
pywin32 when installed, otherwise a `wevtutil` subprocess. Both produce
identical XML, so everything downstream is backend-agnostic.

The Security channel requires an elevated process. Denial is reported as a
clear instruction, never a traceback.
"""

import subprocess
from datetime import timezone

from ingestion.normalizer import parse_event_xml, split_events

try:
    import win32evtlog  # noqa: F401
    _HAS_PYWIN32 = True
except ImportError:
    _HAS_PYWIN32 = False


class EventLogAccessError(Exception):
    """The channel exists but could not be read."""


class ChannelNotFoundError(Exception):
    """The channel does not exist on this host."""


def backend_name():
    """Which reader will be used, for the startup notice."""
    return "pywin32" if _HAS_PYWIN32 else "wevtutil"


def build_query(since=None, after_record_id=0):
    """Build the XPath filter for a channel query.

    Plain XPath, with a bare '>'. Both wevtutil /q: and EvtQuery take it
    as-is; '&gt;' is only right inside an XML <Select> query, and wevtutil
    rejects it with exit 15001.
    """
    conditions = []

    if after_record_id:
        conditions.append("EventRecordID>{}".format(int(after_record_id)))

    if since is not None:
        aware = since if since.tzinfo else since.astimezone()
        stamp = aware.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        conditions.append("TimeCreated[@SystemTime>='{}']".format(stamp))

    if not conditions:
        return "*"
    return "*[System[{}]]".format(" and ".join(conditions))


def _check_channel_name(channel):
    """wevtutil treats a leading '/' as a switch: '/?' returns 0 records and no
    error, so a typo would look like an empty channel. Called by each backend,
    so direct calls and read_channel are all covered."""
    if channel.startswith(("/", "-")):
        raise ValueError(
            "Invalid channel name {!r}: must not start with '/' or '-'.".format(channel)
        )


def read_channel_wevtutil(channel, count=1000, since=None, after_record_id=0):
    """Read a channel via the wevtutil CLI. Returns raw XML, oldest first.

    Records that parse_event_xml rejects are not dropped and do not abort the
    read: they come back after the sorted ones, in stdout order. The tail is
    therefore NOT guaranteed oldest-first; callers must parse per record and
    handle ValueError (and count it) themselves.

    Failures are classified by exit code, never stderr text, which is localized.
    """
    _check_channel_name(channel)
    args = [
        "wevtutil", "qe", channel,
        "/f:xml",
        "/c:{}".format(int(count)),
        "/q:{}".format(build_query(since, after_record_id)),
    ]

    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            shell=False,
            encoding="utf-8",
            # Load-bearing: a few channels (Ntfs, Store, VHDMP) emit bytes that
            # are not valid UTF-8, which raises UnicodeDecodeError without this.
            errors="replace",
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        raise EventLogAccessError(
            "wevtutil timed out after 120s reading the '{}' channel.".format(channel)
        )
    except FileNotFoundError:
        raise EventLogAccessError(
            "wevtutil was not found on PATH. It ships with Windows; if this is "
            "not Windows, ingest from a file instead with --file."
        )

    if completed.returncode != 0:
        if completed.returncode == 5:
            raise EventLogAccessError(
                "Access denied reading the '{}' channel. This channel requires "
                "elevation. Re-run from an Administrator command prompt:\n"
                "    Right-click cmd.exe -> Run as administrator\n"
                "    python main.py ingest --channel {}".format(channel, channel)
            )
        if completed.returncode == 15007:
            raise ChannelNotFoundError(
                "The '{}' channel does not exist on this host. If this is an "
                "optional channel such as Sysmon, install the provider or omit "
                "it from --channel.".format(channel)
            )
        raise EventLogAccessError(
            "wevtutil failed reading '{}' (exit {}): {}".format(
                channel,
                completed.returncode,
                (completed.stderr or "").strip() or "no error output",
            )
        )

    # split_events is lossy on malformed input (an unterminated record drops
    # everything after it), so the result is not guaranteed complete.
    keyed, unparseable = [], []
    for xml_text in split_events(completed.stdout or ""):
        try:
            keyed.append((parse_event_xml(xml_text)["record_id"], xml_text))
        except ValueError:
            unparseable.append(xml_text)
    keyed.sort(key=lambda pair: pair[0])
    return [xml_text for _, xml_text in keyed] + unparseable


def read_channel_pywin32(channel, count=1000, since=None, after_record_id=0):
    """Read a channel via the native Event Log API."""
    _check_channel_name(channel)
    import win32evtlog
    import pywintypes

    query = build_query(since, after_record_id)
    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection

    try:
        handle = win32evtlog.EvtQuery(channel, flags, query, None)
    except pywintypes.error as exc:
        if exc.winerror == 5:
            raise EventLogAccessError(
                "Access denied reading the '{}' channel. This channel requires "
                "elevation. Re-run from an Administrator command prompt.".format(
                    channel
                )
            )
        if exc.winerror == 15007:
            raise ChannelNotFoundError(
                "The '{}' channel does not exist on this host.".format(channel)
            )
        raise EventLogAccessError(
            "Cannot open the '{}' channel: {}".format(channel, exc)
        )

    records = []
    remaining = int(count)
    try:
        while remaining > 0:
            batch = win32evtlog.EvtNext(handle, min(remaining, 100))
            if not batch:
                break
            for item in batch:
                records.append(
                    win32evtlog.EvtRender(item, win32evtlog.EvtRenderEventXml)
                )
            remaining -= len(batch)
    except pywintypes.error as exc:
        # Mid-stream: not reclassified as denied/not-found, just reported.
        raise EventLogAccessError(
            "Failed while reading the '{}' channel: {}".format(channel, exc)
        )

    return records


def read_channel(channel, count=1000, since=None, after_record_id=0,
                 prefer_pywin32=True):
    """Read raw Event XML from a channel using the best available backend."""
    if prefer_pywin32 and _HAS_PYWIN32:
        return read_channel_pywin32(channel, count, since, after_record_id)
    return read_channel_wevtutil(channel, count, since, after_record_id)
