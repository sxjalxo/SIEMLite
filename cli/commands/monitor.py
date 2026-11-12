#!/usr/bin/env python3
"""
siem monitor
============
The loop the CLI already performs, on a timer: ingest the bookmarked channels,
detect, correlate. `--once` runs a single pass. Ctrl-C stops the loop and is
not a crash.

A pass detects over a WINDOW, not over the events it has just ingested (ruling
R126). `detect` has always read a window from the store, and a threshold rule
needs one: at the spec's five-second interval a five-minute burst arrives in
about sixty slices and no slice ever reaches the count, so every threshold rule
in the pack would be dead. `--window` therefore defaults to twice the widest
timeframe in the loaded pack with a ten-minute floor, and is printed on the
first pass. Derived rather than written down, because a literal default goes
stale the moment a rule declares a longer timeframe and the failure is silent.

Re-reading an overlapping window stores nothing twice: an alert's identity is
its exact event set, and correlate attaches a repeat to the same incident, so
the overlap inflates no incident count (ruling R97).

An unreadable channel warns ONCE per (channel, error text) per run, not every
interval (ruling R137); the pass still exits 3 every time. Channels are named
with `--channel` or `--channels`, repeatable and comma-separated, through
`ingest`'s own splitter (ruling R138).

`--no-alert` from spec section 12 is deliberately absent (ruling R127): there
is no delivery anywhere in cli/ for it to skip, and a flag that does nothing is
worse than one that complains. It arrives with delivery.

ponytail: threshold state lives in memory for the length of one pass only, so
a restart loses nothing the next pass does not re-derive from the store (ruling
R128). The surviving ceiling is the window: a threshold whose timeframe exceeds
the window would never fill, which is exactly why the window is derived from
the loaded rules and printed. Upgrade path, if a rule ever needs a window
larger than one pass can hold in memory: persist tracker state per (rule,
entity) and feed each pass only the events that are new to it.
"""

import argparse
import sys
import time
from contextlib import redirect_stdout
from datetime import timedelta

from cli.commands import detect as detect_command
from cli.commands.ingest import DEFAULT_CHANNELS, ingest_channel, split_channels
from cli.rulepack import DEFAULT_RULES_DIR
from core import store
from core.report import (fix_encoding, print_error, print_info, print_section,
                         print_warn)
from core.rule_engine.loader import load_rules
from core.timeutil import parse_duration, parse_since
from ingestion import windows_eventlog as wel

NAME = "monitor"

# The floor under the derived window, and so the reach of a fresh ingest.
MIN_WINDOW = timedelta(minutes=10)

# Records read per channel per pass, matching `ingest`'s own default.
PASS_COUNT = 5000


def add_parser(subparsers):
    """Register the `monitor` subcommand."""
    parser = subparsers.add_parser(
        NAME, help="run the ingest, detect and correlate loop on a timer")
    # Both spellings in one add_argument (dest is `channels`, the first long
    # option): `ingest` already takes --channel repeatably and comma-separated,
    # and two ingest-shaped verbs must not disagree on the flag (ruling R138).
    # None, not a literal: run() applies ingest's own DEFAULT_CHANNELS, so a
    # given-but-empty list stays distinguishable from no flag at all.
    parser.add_argument(
        "--channels", "--channel", action="append", default=None,
        help="channel to read each pass; repeatable or comma-separated "
             "(default: {})".format(", ".join(DEFAULT_CHANNELS)))
    parser.add_argument("--interval", type=int, default=5,
                        help="seconds between passes (default: 5)")
    parser.add_argument("--once", action="store_true",
                        help="run a single pass and exit")
    # None, never a literal duration: the window is derived from the pack.
    parser.add_argument(
        "--window", default=None,
        help="detection window per pass, e.g. 20m (default: twice the widest "
             "loaded rule timeframe, at least {})".format(MIN_WINDOW))
    parser.add_argument(
        "--rules-dir", default=DEFAULT_RULES_DIR,
        help="directory of rule files (default: {})".format(DEFAULT_RULES_DIR))
    parser.add_argument("--no-plugins", action="store_true",
                        help="skip the plugin rules")
    parser.set_defaults(func=run)
    return parser


def derive_window(rules):
    """max(widest declared timeframe x 2, MIN_WINDOW) -- ruling R126.

    getattr rather than attribute access: a plugin rule declares no timeframe.
    """
    widest = max((r.timeframe for r in rules if getattr(r, "timeframe", None)),
                 default=timedelta(0))
    return max(widest * 2, MIN_WINDOW)


def _window(args):
    """(window, how it was chosen). Raises ValueError on a bad --window.

    Rule-load errors are ignored here: every pass loads the pack again through
    `detect`, which reports them and exits 3. The pack is read once, at
    startup, so a timeframe edited mid-run changes the window on restart.
    """
    if args.window is not None:
        window = parse_duration(args.window)
        if window <= timedelta(0):
            raise ValueError(
                "--window must be longer than zero, got {!r}".format(args.window))
        return window, "from --window"
    rules, _errors = load_rules(args.rules_dir)
    # Not a rule count: detect counts plugins too, and two numbers that
    # disagree in the same output read as a bug.
    return derive_window(rules), "derived: widest rule timeframe x 2, floor {}".format(
        MIN_WINDOW)


def _ingest_pass(conn, channels, since):
    """Ingest every channel. Returns (results, failures, missing).

    One channel's failure must not stop the others or the loop, and not only
    the two errors `ingest` knows by name: a daemon survives whatever a reader
    throws. KeyboardInterrupt is not an Exception, so Ctrl-C still gets out.

    A channel that does not exist is kept apart from one that failed, because
    spec section 13 makes an absent optional channel (Sysmon) a warning. A
    daemon that exits 3 every pass because Sysmon is absent teaches its
    operator to ignore the exit code.
    """
    results, failures, missing = [], [], []
    for channel in channels:
        try:
            results.append(ingest_channel(conn, channel, PASS_COUNT, since))
        except wel.ChannelNotFoundError as exc:
            missing.append((channel, str(exc)))
        except Exception as exc:
            # (channel, text), not a formatted line: both lists are latched on
            # the pair (rulings R137, R139).
            failures.append((channel, str(exc)))
    return results, failures, missing


def _pass(args, detect_args, channels, stream, latched):
    """One pass. Returns 0 clean, 3 partial, 1 nothing could run.

    `latched` is {channel: error text} from the previous pass, and it holds
    this pass's absent AND failed channels on return. Only the repeated TEXT
    is latched (rulings R137, R139): unelevated, the default run printed a
    four-line elevation block every five seconds forever, and a host that
    names Sysmon -- which four shipped rules target -- got the absent-channel
    warning every interval forever. Both bury every other line. The EXIT CODE
    is never latched -- the coverage gap is still real on every pass and a
    failure must never exit 0 (ruling R51). Keyed on (channel, text) rather
    than on the channel, so a channel that becomes readable, or that fails a
    different way, warns again.
    """
    conn = store.connect(args.db)
    try:
        store.init_schema(conn)
        # detect_args.since is the window as a relative string, so a fresh
        # channel (no bookmark yet) reaches back exactly as far as detection
        # will look. Resuming, the bookmark alone defines the read.
        results, failures, missing = _ingest_pass(
            conn, channels, parse_since(detect_args.since))
    finally:
        conn.close()

    with redirect_stdout(stream):
        for result in results:
            print_info("{:<20} read {:>5}  stored {:>5}  skipped {}".format(
                result["channel"], result["read"], result["inserted"],
                result["skipped"]))
        for channel, text in missing:
            if latched.get(channel) != text:
                print_warn("{}: {}".format(channel, text))
        for channel, text in failures:
            if latched.get(channel) != text:
                print_error("{}: {}".format(channel, text))
    # Replace rather than accumulate: a channel that did not fail this pass
    # drops out, so its next failure prints again. ONE dict for both lists
    # (ruling R139): one keying rule, one place to clear. Measured, not
    # assumed -- a second dict for `missing` would behave identically on every
    # realistic input, because an absent channel's text and a denied one's
    # never match; the two differ only when the SAME text arrives as both
    # kinds, where the shared dict suppresses the repeat and two dicts would
    # print it. Suppressing an identical repeat is what the latch is for.
    latched.clear()
    latched.update(missing)
    latched.update(failures)

    # detect prints its own output and routes its own JSON; do not wrap it.
    try:
        code = detect_command.run(detect_args)
    except Exception as exc:
        with redirect_stdout(stream):
            print_error("Detection failed: {}: {}".format(type(exc).__name__, exc))
        return 3
    if code == 1:
        return 1
    # Ruling R51: something asked for was not stored.
    if failures or any(r["skipped"] for r in results):
        return 3
    # Every named channel absent is not a quiet host, it is a typo.
    if missing and not results:
        return 3
    return code


def run(args):
    """Run the loop. Returns a process exit code.

    Exit codes: 0 every pass was clean, Ctrl-C included -- stopping a daemon
    is how it is stopped, not a failure; 3 a pass was partial: a channel could
    not be read, records were skipped, or detection raised; 1 nothing could
    run, which no later pass would fix (an empty rule pack), so the loop stops
    there rather than printing the same error every interval. 2 (a bad
    --window, --interval or --channels) comes from dispatch.

    Ctrl-C after a partial pass still exits 3: the interrupt itself is clean,
    but a channel that was never read is a coverage gap, and a failure must
    never exit 0.
    """
    fix_encoding()
    if args.interval < 1:
        raise ValueError(
            "--interval must be at least 1 second, got {}".format(args.interval))
    if args.channels is None:
        channels = list(DEFAULT_CHANNELS)
    else:
        channels = split_channels(args.channels)
        if not channels:
            raise ValueError(
                "--channel/--channels needs at least one channel name, got "
                "{!r}".format(args.channels))

    window, chosen = _window(args)
    # A relative string, re-read against `now` on every pass, so the window
    # rolls. detect reads nothing else off this namespace.
    detect_args = argparse.Namespace(
        db=args.db, json=args.json,
        since="{}s".format(int(window.total_seconds())), until=None, rule=None,
        rules_dir=args.rules_dir, no_plugins=args.no_plugins,
        no_correlate=False)

    # Text goes to stderr under --json so stdout stays JSON-only.
    stream = sys.stderr if args.json else sys.stdout
    worst = 0
    passes = 0
    # Per run, never module state: a fresh daemon must re-warn (ruling R137).
    latched = {}
    try:
        while True:
            passes += 1
            with redirect_stdout(stream):
                if passes == 1:
                    print_section("Monitor - channels {}, every {}s".format(
                        ", ".join(channels), args.interval))
                    print_info("Window : {} ({}s), {}".format(
                        window, int(window.total_seconds()), chosen))
                print_info("Pass {}".format(passes))
            code = _pass(args, detect_args, channels, stream, latched)
            if code == 1:
                return 1
            worst = max(worst, code)
            if args.once:
                return worst
            time.sleep(args.interval)
    except KeyboardInterrupt:
        with redirect_stdout(stream):
            print_info("Stopped after {} pass(es).".format(passes))
        return worst
