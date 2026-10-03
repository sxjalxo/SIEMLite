#!/usr/bin/env python3
"""
siem ingest
===========
Read Windows channels or log files into the event store.
"""

import argparse
import json
import sqlite3
import sys
from contextlib import redirect_stdout

from core import store
from core.report import print_error, print_info, print_ok, print_section, print_warn
from core.timeutil import parse_since
from ingestion import windows_eventlog as wel
from ingestion.log_ingestor import ingest_file
from ingestion.normalizer import from_log_event, normalize_windows_xml

NAME = "ingest"

DEFAULT_CHANNELS = ["Security"]

# Rejected record_ids named in the text warning; the JSON result has them all.
MAX_IDS_SHOWN = 5


def _positive_int(text):
    """argparse type: an integer >= 1, else a usage error (exit 2)."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("{!r} is not a whole number".format(text))
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1, got {}".format(value))
    return value


def add_parser(subparsers):
    """Register the `ingest` subcommand."""
    parser = subparsers.add_parser(
        NAME, help="read Windows channels or log files into the event store"
    )
    # None, never "" or 0: later verbs' store filters must default to None
    # because core.store.query_events filters with `is not None` (see
    # cli/__init__.py). The default channel is applied in _split_channels.
    parser.add_argument(
        "--channel", action="append", default=None,
        help="channel to read; repeatable or comma-separated (default: Security)",
    )
    parser.add_argument(
        "--since", default="24h",
        help="how far back to read on a fresh run (default: 24h)",
    )
    parser.add_argument(
        "--count", type=_positive_int, default=5000,
        help="maximum records to read per channel (default: 5000)",
    )
    parser.add_argument(
        "--no-resume", action="store_true",
        help="ignore the saved bookmark and re-read from --since",
    )
    parser.add_argument(
        "--file", default=None,
        help="ingest an Apache, SSH or Windows CSV log file instead of a channel",
    )
    parser.set_defaults(func=run)
    return parser


def _split_channels(values):
    """Flatten repeated and comma-separated --channel values."""
    if not values:
        return list(DEFAULT_CHANNELS)
    channels = []
    for value in values:
        channels.extend(part.strip() for part in value.split(",") if part.strip())
    return channels or list(DEFAULT_CHANNELS)


def _store_events(conn, events):
    """Insert events; one poison event must not block the rest (ruling R18).

    store.insert_events rolls back a whole failing batch, so a permanently
    malformed event would otherwise stall its channel forever (the bookmark
    never advances). On IntegrityError, retry one event at a time so the good
    ones land. Returns (inserted, rejected), where rejected is the list of
    events the store refused.
    """
    before = store.count_events(conn)
    try:
        return store.insert_events(conn, events), []
    except sqlite3.IntegrityError:
        rejected = []
        for event in events:
            try:
                store.insert_events(conn, [event])
            except sqlite3.IntegrityError:
                rejected.append(event)
        # Counted from the table: batches that committed before the failure
        # are re-inserted as duplicates and would not show in a running sum.
        return store.count_events(conn) - before, rejected


def ingest_channel(conn, channel, count, since, resume=True):
    """Read one channel and store what it returns.

    Returns {"channel", "read", "inserted", "skipped", "last_record_id"}.
    "skipped" counts records that failed to parse plus events the store
    rejected; "rejected_record_ids" names the latter. "read" is what the
    reader returned, which is not guaranteed complete: split_events drops
    everything after an unterminated record (ruling R27).
    """
    after = store.get_bookmark(conn, channel) if resume else 0

    # build_query ANDs its conditions, so a since older than the gap since the
    # last run would hide records the bookmark still wants and the bookmark
    # would then advance past them. since is a fresh-run window only; resuming,
    # the bookmark alone defines it. --no-resume forces after=0, so it keeps since.
    raw_records = wel.read_channel(
        channel, count=count, since=None if after else since,
        after_record_id=after,
    )

    events = []
    skipped = 0
    for xml_text in raw_records:
        try:
            events.append(normalize_windows_xml(xml_text))
        except ValueError:
            # One malformed record must not lose the rest of the batch.
            skipped += 1

    inserted, rejected = _store_events(conn, events)
    skipped += len(rejected)

    # read_channel returns unparseable records at the tail, so the last list
    # item is not the newest. Only events that normalized count toward the
    # bookmark; a rejected one is skipped on purpose so it cannot stall us.
    last_record_id = max((e.record_id for e in events), default=after)
    if events:
        store.set_bookmark(conn, channel, last_record_id)

    return {
        "channel": channel,
        "read": len(raw_records),
        "inserted": inserted,
        "skipped": skipped,
        "last_record_id": last_record_id,
        "rejected_record_ids": sorted(e.record_id for e in rejected),
    }


def ingest_logfile(conn, path):
    """Ingest an Apache, SSH or Windows CSV file via the legacy parsers.

    Returns {"path", "read", "inserted", "skipped", "rejected_record_ids"}, plus
    "error" when the file is missing or its format is not recognised. A file
    event's record_id is its line ordinal.
    """
    log_events, stats = ingest_file(path)

    events = []
    skipped = stats.get("skipped", 0)
    for index, log_event in enumerate(log_events, start=1):
        try:
            events.append(from_log_event(log_event, line_number=index))
        except ValueError:
            skipped += 1

    inserted, rejected = _store_events(conn, events)

    result = {
        "path": path,
        "read": len(log_events),
        "inserted": inserted,
        "skipped": skipped + len(rejected),
        "rejected_record_ids": sorted(e.record_id for e in rejected),
    }
    if "error" in stats or stats.get("format") == "unknown":
        result["error"] = stats.get("error") or "Could not detect the log format."
    return result


def _rejected_note(ids):
    """'record_id 4, 9, +2 more' for the text warning; empty when none."""
    if not ids:
        return ""
    shown = ", ".join(str(i) for i in ids[:MAX_IDS_SHOWN])
    if len(ids) > MAX_IDS_SHOWN:
        shown += ", +{} more".format(len(ids) - MAX_IDS_SHOWN)
    return "; rejected record_id: {}".format(shown)


def _exit_code(results, denied, not_found):
    """0 clean, 1 no channel readable, 3 partial.

    3 means one thing on both halves of the verb: something that was asked
    for was not stored — a denied channel, or records that would not parse.
    Silently dropping records is the failure a SIEM can least afford to
    report as success, so it gets the same code as a denied channel rather
    than sharing 0 with a clean run.

    A missing channel is only a warning while another one worked (optional
    Sysmon), but when nothing was readable it is also a 1: a typo must not
    look like success. 2 is taken by argparse and dispatch's ValueError
    handler.
    """
    if not results and (denied or not_found):
        return 1
    if denied or any(r["skipped"] for r in results):
        return 3
    return 0


def _run_file(conn, args):
    # ingest_file prints its own errors to stdout; keep stdout JSON-only.
    if args.json:
        with redirect_stdout(sys.stderr):
            result = ingest_logfile(conn, args.file)
    else:
        result = ingest_logfile(conn, args.file)
    failed = "error" in result

    if args.json:
        print(json.dumps(
            {"results": [result], "total_inserted": result["inserted"]}, indent=2
        ))
    elif not failed:
        print_ok("{}: read {}, stored {}, skipped {}".format(
            result["path"], result["read"], result["inserted"], result["skipped"]
        ))
        if result["rejected_record_ids"]:
            print_warn("{}: store rejected some events{}".format(
                result["path"], _rejected_note(result["rejected_record_ids"])
            ))
    # ingest_file has already printed its own message for a failed file.
    if failed:
        return 1
    # Same meaning as on the channel path (see _exit_code): something asked
    # for was not stored. A file whose every row is unparseable must not
    # look clean.
    return 3 if result["skipped"] else 0


def run(args):
    """Execute ingestion. Returns a process exit code.

    Exit codes: 0 clean; 1 nothing completed (every channel denied or not
    found, or an unreadable file); 3 partial — some of what was asked for did
    not make it: a channel was denied, or a file had skipped rows. A denied
    Security channel is a coverage gap the operator must not miss, but
    unelevated it is permanent, so a partial run gets its own code instead of
    sharing 1 with "nothing worked". The other channels are still stored. A
    channel that does not exist is only a warning while another one completed
    (optional, e.g. Sysmon); if none did, it is a 1.
    """
    conn = store.connect(args.db)
    store.init_schema(conn)

    try:
        if args.file:
            return _run_file(conn, args)

        channels = _split_channels(args.channel)
        since = parse_since(args.since)

        results = []
        denied = []
        not_found = []

        for channel in channels:
            try:
                results.append(ingest_channel(
                    conn, channel, args.count, since, resume=not args.no_resume
                ))
            except wel.ChannelNotFoundError as exc:
                not_found.append({"channel": channel, "error": str(exc)})
            except wel.EventLogAccessError as exc:
                denied.append({"channel": channel, "error": str(exc)})

        total = sum(r["inserted"] for r in results)

        if args.json:
            print(json.dumps({
                "results": results,
                "total_inserted": total,
                "denied": denied,
                "not_found": not_found,
            }, indent=2))
            return _exit_code(results, denied, not_found)

        print_section("Ingestion — backend: {}".format(wel.backend_name()))
        for result in results:
            print_info("{:<45} read {:>6}  stored {:>6}  skipped {}".format(
                result["channel"], result["read"], result["inserted"],
                result["skipped"]
            ))
            if result["skipped"]:
                print_warn(
                    "{}: {} record(s) skipped (unparseable or rejected by "
                    "the store){}".format(
                        result["channel"], result["skipped"],
                        _rejected_note(result["rejected_record_ids"]),
                    )
                )
        for item in not_found:
            print_warn(item["error"])
        for item in denied:
            print_error(item["error"])
        print_ok("Stored {} new events".format(total))
        return _exit_code(results, denied, not_found)

    finally:
        conn.close()
