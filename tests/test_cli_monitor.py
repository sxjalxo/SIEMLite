"""`siem monitor` -- the ingest -> detect -> correlate loop on a timer.

No test here sleeps and none reads the real Windows Event Log: every one
patches `windows_eventlog.read_channel` and `time.sleep`. A loop test gives
sleep a terminating side effect rather than returning None forever, so a
mutation that ignores `--once` fails an assertion instead of hanging.

Event timestamps are anchored to `now`. The XML fixtures carry fixed 2026-05-09
dates (ruling R98) and no window of minutes will ever contain them, so
`restamped` moves each one and asserts that it really moved -- a test input
that silently missed would look exactly like a test that passed.
"""

import argparse
import json
import re
from datetime import datetime, timedelta, timezone
from unittest import mock

import cli
from cli.commands import detect as detect_command
from cli.commands import ingest as ingest_command
from cli.commands import monitor as monitor_command
from cli.rulepack import DEFAULT_RULES_DIR
from core import store
from ingestion import windows_eventlog as wel
from tests.fixtures import events_xml
from tests.helpers_rules import rule_from_yaml
from tests.test_cli_rules import SINGLE_EVENT, RulesCase
from tests.test_rule_loader_yaml import VALID

# VALID is a threshold rule: five 4625s in 5m grouped by source_ip and
# target_user. WIDE and NARROW only move the timeframe, which is all the
# derived window reads.
WIDE = VALID.replace("timeframe: 5m", "timeframe: 30m")
NARROW = VALID.replace("timeframe: 5m", "timeframe: 2m")

_STAMP = re.compile(r"SystemTime='[^']+'")
_RECORD = re.compile(r"<EventRecordID>[0-9]+</EventRecordID>")


def restamped(xml, record_id, seconds_ago):
    """One XML record re-stamped `seconds_ago` before now, with a new id."""
    stamp = (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
             ).strftime("SystemTime='%Y-%m-%dT%H:%M:%S.0000000Z'")
    text, moved = _STAMP.subn(stamp, xml)
    assert moved == 1, "the fixture's SystemTime attribute moved"
    text, renumbered = _RECORD.subn(
        "<EventRecordID>{}</EventRecordID>".format(record_id), text)
    assert renumbered == 1, "the fixture's EventRecordID element moved"
    return text


def logons(count, record_id, newest_seconds_ago):
    """`count` failed logons, one second apart, newest `newest_seconds_ago`."""
    return [restamped(events_xml.FAILED_LOGON_4625, record_id + i,
                      newest_seconds_ago + count - 1 - i)
            for i in range(count)]


def log_cleared(seconds_ago, record_id=999):
    return restamped(events_xml.LOG_CLEARED_1102, record_id, seconds_ago)


class MonitorCase(RulesCase):
    """The CLI harness plus the packs the loop is run against."""

    def setUp(self):
        super().setUp()
        self.reads = []
        self.single = self.make_pack(rule=SINGLE_EVENT)   # one 1102 fires it
        self.burst = self.make_pack(rule=VALID)           # five 4625s in 5m
        self.wide = self.make_pack(rule=WIDE)             # 30m timeframe

    def monitor(self, *extra, **kwargs):
        pack = kwargs.pop("pack", None)
        json_mode = kwargs.pop("json_mode", False)
        assert not kwargs, kwargs
        argv = (["--json"] if json_mode else []) + [
            "monitor", "--rules-dir", pack or self.single] + list(extra)
        return self.run_cli_split(argv)

    def reading(self, *batches):
        """Patch the reader: one batch per call, then nothing."""
        queue = [list(b) for b in batches]

        def read_channel(channel, count=None, since=None, after_record_id=0):
            self.reads.append({"channel": channel, "since": since,
                               "after_record_id": after_record_id})
            return queue.pop(0) if queue else []

        return mock.patch.object(wel, "read_channel", side_effect=read_channel)

    def stopping(self, *before_stop):
        """Patch sleep: `before_stop` results, then Ctrl-C ends the loop.

        Never None forever: a mutation that ignores --once must fail an
        assertion, not spin.
        """
        return mock.patch("time.sleep",
                          side_effect=list(before_stop) + [KeyboardInterrupt])

    def alerts(self):
        return store.query_alerts(self.conn, limit=None)

    def rule_ids(self):
        return sorted(a["rule_id"] for a in self.alerts())


class TestMonitorParser(MonitorCase):
    def test_defaults(self):
        args = cli.build_parser().parse_args(["monitor"])
        # None, not "Security": --channels appends, and the default channel is
        # applied in run() from ingest's own constant (ruling R138).
        self.assertIsNone(args.channels)
        self.assertEqual(5, args.interval)
        self.assertFalse(args.once)
        # None, not a literal: the window is derived from the loaded rules.
        self.assertIsNone(args.window)
        self.assertEqual(DEFAULT_RULES_DIR, args.rules_dir)

    def test_a_bad_window_is_a_usage_error(self):
        code, out, _ = self.monitor("--once", "--window", "yesterday")
        self.assertEqual(2, code)

    def test_an_interval_below_one_second_is_a_usage_error(self):
        # A zero interval is a busy loop, not a daemon.
        code, out, _ = self.monitor("--interval", "0")
        self.assertEqual(2, code)
        self.assertIn("--interval", out)

    def test_an_empty_channel_list_is_a_usage_error(self):
        code, out, _ = self.monitor("--once", "--channels", " , ")
        self.assertEqual(2, code)
        self.assertIn("--channels", out)

    def test_no_alert_is_not_a_flag(self):
        # Ruling R127: there is no delivery to skip, and a flag that does
        # nothing is worse than one that complains.
        with self.assertRaises(SystemExit) as caught:
            self.monitor("--once", "--no-alert")
        self.assertEqual(2, caught.exception.code)


class TestChannelFlags(MonitorCase):
    """Ruling R138: --channel AND --channels, repeatable AND comma-separated.

    Asserted on the channels the reader was actually called with, not on the
    namespace, so a flag that parses but never reaches the loop fails.
    """

    def channels_read(self, *extra):
        with self.reading(), self.stopping():
            code, _, _ = self.monitor("--once", *extra)
        self.assertEqual(0, code)
        return [r["channel"] for r in self.reads]

    def test_channels_takes_a_comma_separated_list(self):
        self.assertEqual(["Security", "System"],
                         self.channels_read("--channels", "Security,System"))

    def test_channel_is_repeatable(self):
        self.assertEqual(
            ["Security", "System"],
            self.channels_read("--channel", "Security", "--channel", "System"))

    def test_channel_also_comma_splits(self):
        self.assertEqual(["Security", "System"],
                         self.channels_read("--channel", "Security,System"))

    def test_neither_flag_reads_ingests_default_channels(self):
        # Pinned against ingest's constant rather than the literal "Security":
        # the two verbs' defaults must not drift apart.
        self.assertEqual(list(ingest_command.DEFAULT_CHANNELS),
                         self.channels_read())

    def test_the_two_spellings_mix(self):
        self.assertEqual(
            ["Security", "System", "Setup"],
            self.channels_read("--channels", "Security,System", "--channel", "Setup"))

    def test_both_option_strings_are_declared_not_merely_abbreviated(self):
        # The one observable difference the alias makes: argparse would
        # prefix-match --channel to --channels on its own, so every behaviour
        # test below passes without it -- but then --channel is undocumented
        # in --help and a later option starting with "--channel" would make
        # the abbreviation ambiguous and break scripts silently.
        holder = argparse.ArgumentParser().add_subparsers()
        action = next(a for a in monitor_command.add_parser(holder)._actions
                      if a.dest == "channels")
        self.assertEqual(["--channels", "--channel"], action.option_strings)

    def test_monitor_reuses_ingests_splitter_rather_than_a_second_one(self):
        # Ruling R138, and Phase 4's I2: one public splitter, no private
        # cross-module import and no copy.
        self.assertIs(ingest_command.split_channels, monitor_command.split_channels)


class TestDerivedWindow(MonitorCase):
    def test_the_window_doubles_the_widest_rule_timeframe(self):
        self.assertEqual(timedelta(minutes=60),
                         monitor_command.derive_window([rule_from_yaml(WIDE)]))

    def test_the_widest_timeframe_wins_whichever_order_they_load_in(self):
        wide, narrow = rule_from_yaml(WIDE), rule_from_yaml(NARROW)
        self.assertEqual(timedelta(minutes=60), monitor_command.derive_window([wide, narrow]))
        self.assertEqual(timedelta(minutes=60), monitor_command.derive_window([narrow, wide]))

    def test_a_timeframe_whose_double_is_under_the_floor_gets_the_floor(self):
        self.assertEqual(timedelta(minutes=10),
                         monitor_command.derive_window([rule_from_yaml(NARROW)]))

    def test_a_pack_with_no_threshold_rule_gets_the_floor(self):
        self.assertEqual(timedelta(minutes=10),
                         monitor_command.derive_window([rule_from_yaml(SINGLE_EVENT)]))

    def test_an_empty_pack_still_yields_the_floor(self):
        # detect reports the empty pack; derive_window must not raise first.
        self.assertEqual(timedelta(minutes=10), monitor_command.derive_window([]))

    def test_the_derived_window_is_printed_on_the_first_pass(self):
        with self.reading(), self.stopping():
            code, out, _ = self.monitor("--once", pack=self.wide)
        self.assertEqual(0, code)
        self.assertIn("1:00:00", out)
        self.assertIn("3600s", out)

    def test_the_window_is_printed_once_not_on_every_pass(self):
        with self.reading(), self.stopping(None, None):
            code, out, _ = self.monitor()
        self.assertEqual(0, code)
        self.assertEqual(1, out.count("Window"))
        self.assertEqual(3, out.count("Pass "))

    def test_an_explicit_window_overrides_the_derived_one(self):
        # The same stored event, read by two different windows: the 20-minute
        # -old 1102 is outside the derived 10m window and inside --window 45m.
        with self.reading([log_cleared(20 * 60)]), self.stopping():
            code, _, _ = self.monitor("--once")
        self.assertEqual(0, code)
        self.assertEqual([], self.alerts())
        with self.reading(), self.stopping():
            code, out, _ = self.monitor("--once", "--window", "45m")
        self.assertEqual(0, code)
        self.assertEqual(["win-log-cleared"], self.rule_ids())
        self.assertIn("0:45:00", out)


class TestOnePass(MonitorCase):
    def test_once_runs_exactly_one_pass_and_never_sleeps(self):
        with self.reading(), self.stopping() as sleeper:
            code, _, _ = self.monitor("--once")
        self.assertEqual(0, code)
        sleeper.assert_not_called()
        self.assertEqual(1, len(self.reads))

    def test_a_pass_ingests_then_detects_then_correlates_in_that_order(self):
        order = []

        def tracked(name, func):
            def wrapper(*a, **k):
                order.append(name)
                return func(*a, **k)
            return wrapper

        with self.reading([log_cleared(60)]), self.stopping(), \
                mock.patch.object(monitor_command, "ingest_channel",
                                  tracked("ingest", monitor_command.ingest_channel)), \
                mock.patch.object(detect_command, "run_rules",
                                  tracked("detect", detect_command.run_rules)), \
                mock.patch.object(detect_command, "correlate",
                                  tracked("correlate", detect_command.correlate)):
            code, _, _ = self.monitor("--once")
        self.assertEqual(0, code)
        self.assertEqual(["ingest", "detect", "correlate"], order)

    def test_a_pass_stores_what_it_read_and_alerts_on_it(self):
        with self.reading([log_cleared(60)]), self.stopping():
            code, out, _ = self.monitor("--once")
        self.assertEqual(0, code)
        self.assertEqual(1, store.count_events(self.conn))
        self.assertEqual(["win-log-cleared"], self.rule_ids())

    def test_a_pass_that_finds_nothing_is_not_an_error(self):
        with self.reading(), self.stopping():
            code, out, _ = self.monitor("--once")
        self.assertEqual(0, code)
        self.assertEqual([], self.alerts())

    def test_every_named_channel_is_read(self):
        with self.reading(), self.stopping():
            code, _, _ = self.monitor("--once", "--channels", "Security, System")
        self.assertEqual(0, code)
        self.assertEqual(["Security", "System"], [r["channel"] for r in self.reads])

    def test_the_bookmark_advances_so_the_next_pass_reads_only_new_records(self):
        with self.reading(logons(2, 500, 20)), self.stopping(None):
            code, _, _ = self.monitor()
        self.assertEqual(0, code)
        self.assertEqual(0, self.reads[0]["after_record_id"])
        self.assertEqual(501, self.reads[1]["after_record_id"])

    def test_a_pass_with_skipped_records_exits_3(self):
        # Something that was asked for was not stored (ruling R51).
        with self.reading(["<Event>not xml"]), self.stopping():
            code, out, _ = self.monitor("--once")
        self.assertEqual(3, code)


class TestFailuresDoNotStopTheLoop(MonitorCase):
    def denying(self, channel="Security", batch=()):
        """Reader that raises for `channel` and returns `batch` otherwise."""
        def read_channel(ch, count=None, since=None, after_record_id=0):
            self.reads.append({"channel": ch, "since": since,
                               "after_record_id": after_record_id})
            if ch == channel:
                raise wel.EventLogAccessError(
                    "Access denied reading Security: run elevated")
            return list(batch)
        return mock.patch.object(wel, "read_channel", side_effect=read_channel)

    def test_an_ingest_failure_on_one_channel_does_not_stop_the_others(self):
        with self.denying(batch=[log_cleared(60)]), self.stopping():
            code, out, _ = self.monitor("--once", "--channels", "Security,System")
        self.assertEqual(3, code)
        self.assertIn("Access denied", out)
        self.assertEqual(["Security", "System"], [r["channel"] for r in self.reads])
        self.assertEqual(1, store.count_events(self.conn))
        self.assertEqual(["win-log-cleared"], self.rule_ids())

    def test_an_ingest_failure_does_not_stop_the_loop(self):
        with self.denying(), self.stopping(None):
            code, _, _ = self.monitor()
        self.assertEqual(3, code)
        self.assertEqual(2, len(self.reads))

    def test_an_unexpected_reader_error_is_contained_too(self):
        # A daemon must survive anything one channel throws, not just the two
        # errors `ingest` knows by name.
        def read_channel(ch, count=None, since=None, after_record_id=0):
            self.reads.append(ch)
            raise RuntimeError("reader exploded")
        with mock.patch.object(wel, "read_channel", side_effect=read_channel), \
                self.stopping(None):
            code, out, _ = self.monitor()
        self.assertEqual(3, code)
        self.assertIn("reader exploded", out)
        self.assertEqual(2, len(self.reads))

    def test_a_missing_optional_channel_is_a_warning_not_a_failure(self):
        # Spec section 13: an optional channel that does not exist on this
        # host (Sysmon) is a warning. A daemon that exits 3 on every pass
        # because Sysmon is absent teaches its operator to ignore exit codes.
        def read_channel(ch, count=None, since=None, after_record_id=0):
            self.reads.append(ch)
            if ch == "Security":
                return [log_cleared(60)]
            raise wel.ChannelNotFoundError(
                "The '{}' channel does not exist on this host".format(ch))
        with mock.patch.object(wel, "read_channel", side_effect=read_channel), \
                self.stopping():
            code, out, _ = self.monitor(
                "--once", "--channels", "Security,Microsoft-Windows-Sysmon/Operational")
        self.assertEqual(0, code)
        self.assertIn("does not exist", out)
        self.assertEqual(["win-log-cleared"], self.rule_ids())

    def test_every_named_channel_missing_is_not_a_clean_run(self):
        # A typo in --channels must not look like a quiet host.
        def read_channel(ch, count=None, since=None, after_record_id=0):
            self.reads.append(ch)
            raise wel.ChannelNotFoundError("no such channel")
        with mock.patch.object(wel, "read_channel", side_effect=read_channel), \
                self.stopping():
            code, _, _ = self.monitor("--once", "--channels", "Securtiy")
        self.assertEqual(3, code)

    def test_a_detection_failure_is_reported_and_the_loop_continues(self):
        with self.reading(), self.stopping(None), \
                mock.patch.object(detect_command, "run_rules",
                                  side_effect=RuntimeError("engine exploded")):
            code, out, _ = self.monitor()
        self.assertEqual(3, code)
        self.assertIn("engine exploded", out)
        self.assertEqual(2, len(self.reads))

    def test_an_unloadable_pack_stops_the_loop_rather_than_spinning(self):
        # detect returns 1 for "nothing could run", which no later pass fixes.
        empty = self.make_pack()
        with self.reading(), self.stopping(None):
            code, out, _ = self.monitor(pack=empty)
        self.assertEqual(1, code)
        self.assertEqual(1, len(self.reads))


class TestUnreadableChannelWarnsOnce(MonitorCase):
    """Ruling R137: the repeated TEXT is latched, never the exit code.

    Unelevated, the default run printed this four-line block every five
    seconds forever, which buries every other line the daemon writes.
    """

    DENIED = ("Access denied reading the 'Security' channel. This channel "
              "requires elevation. Re-run from an Administrator command "
              "prompt:\n    Right-click cmd.exe -> Run as administrator\n"
              "    python main.py ingest --channel Security")
    OTHER = "Access denied reading the 'Security' channel: the handle is closed"

    def failing(self, *messages):
        """Reader raising messages[i] on pass i+1; "" is a clean read."""
        queue = list(messages)

        def read_channel(ch, count=None, since=None, after_record_id=0):
            self.reads.append(ch)
            message = queue.pop(0) if queue else ""
            if message:
                raise wel.EventLogAccessError(message)
            return []

        return mock.patch.object(wel, "read_channel", side_effect=read_channel)

    def run_passes(self, *messages, **kwargs):
        """One pass per message. Returns (per-pass codes, output, final code).

        The per-pass codes are what discriminate a latch on the text from a
        latch that also swallowed the exit code: the second one still prints
        once, and a test that only counted the text would call it a pass.
        """
        channels = kwargs.pop("channels", ())
        passes = kwargs.pop("passes", len(messages))
        assert not kwargs, kwargs
        codes = []
        real = monitor_command._pass

        def spy(*a, **k):
            code = real(*a, **k)
            codes.append(code)
            return code

        with self.failing(*messages), self.stopping(*([None] * (passes - 1))), \
                mock.patch.object(monitor_command, "_pass", spy):
            final, out, _ = self.monitor(*channels)
        return codes, out, final

    def test_the_same_failure_warns_once_and_every_pass_still_exits_3(self):
        codes, out, final = self.run_passes(self.DENIED, self.DENIED, self.DENIED)
        self.assertEqual([3, 3, 3], codes, "the coverage gap is real every pass")
        self.assertEqual(3, final)
        self.assertEqual(3, out.count("Pass "))
        self.assertEqual(1, out.count("Access denied"))
        self.assertEqual(1, out.count("Run as administrator"))

    def test_a_channel_that_recovers_and_fails_again_warns_again(self):
        codes, out, _ = self.run_passes(self.DENIED, "", self.DENIED)
        self.assertEqual([3, 0, 3], codes)
        self.assertEqual(2, out.count("Access denied"))

    def test_the_same_channel_failing_a_different_way_warns_again(self):
        # Discriminates a latch keyed on the channel alone, which would print
        # the first message and swallow a different one.
        codes, out, _ = self.run_passes(self.DENIED, self.OTHER, self.OTHER)
        self.assertEqual([3, 3, 3], codes)
        self.assertEqual(1, out.count("Run as administrator"))
        self.assertEqual(1, out.count("the handle is closed"))

    def test_two_channels_failing_the_same_way_each_warn(self):
        # Discriminates a latch keyed on the text alone.
        codes, out, _ = self.run_passes(
            self.OTHER, self.OTHER, self.OTHER, self.OTHER,
            passes=2, channels=("--channels", "Security,System"))
        self.assertEqual([3, 3], codes)
        self.assertEqual(["Security", "System"] * 2, self.reads)
        self.assertEqual(2, out.count("the handle is closed"))

    def test_the_latch_is_per_run_so_a_second_run_warns_again(self):
        for _ in range(2):
            codes, out, _ = self.run_passes(self.DENIED, self.DENIED)
            self.assertEqual([3, 3], codes)
            self.assertEqual(1, out.count("Access denied"))


class TestAbsentChannelWarnsOnce(MonitorCase):
    """Ruling R139: the ABSENT-channel warning latches like the denied one.

    The pack ships four Sysmon rules, so naming Sysmon in --channel is an
    expected configuration; on a host without the provider it warned every
    interval forever. Latched in the SAME dict as the denied path, so a
    channel that is absent on one pass and denied on the next is a changed
    condition and prints again.
    """

    SYSMON = "Microsoft-Windows-Sysmon/Operational"
    ABSENT = ("The '{}' channel does not exist on this host. If this is an "
              "optional channel such as Sysmon, install the provider or omit "
              "it from --channel.".format(SYSMON))
    DENIED = ("Access denied reading the '{}' channel. This channel requires "
              "elevation.".format(SYSMON))

    def raising(self, *errors):
        """Reader raising errors[i] on read i+1; None is a clean read."""
        queue = list(errors)

        def read_channel(ch, count=None, since=None, after_record_id=0):
            self.reads.append(ch)
            exc = queue.pop(0) if queue else None
            if exc is not None:
                raise exc
            return []

        return mock.patch.object(wel, "read_channel", side_effect=read_channel)

    def run_passes(self, *errors, **kwargs):
        """One read per error. Returns (per-pass codes, output, final code).

        The per-pass codes are what discriminate a latch on the text from a
        latch that also swallowed the exit code (ruling R51): the second one
        still prints once, and a test that only counted the text would call
        it a pass.
        """
        channels = kwargs.pop("channels", (self.SYSMON,))
        passes = kwargs.pop("passes", len(errors))
        assert not kwargs, kwargs
        codes = []
        real = monitor_command._pass

        def spy(*a, **k):
            code = real(*a, **k)
            codes.append(code)
            return code

        with self.raising(*errors), self.stopping(*([None] * (passes - 1))), \
                mock.patch.object(monitor_command, "_pass", spy):
            final, out, _ = self.monitor("--channels", ",".join(channels))
        return codes, out, final

    def absent(self, text=None):
        return wel.ChannelNotFoundError(text or self.ABSENT)

    def denied(self):
        return wel.EventLogAccessError(self.DENIED)

    def test_the_same_absent_channel_warns_once_and_every_pass_still_exits_3(self):
        codes, out, final = self.run_passes(
            self.absent(), self.absent(), self.absent())
        self.assertEqual([3, 3, 3], codes, "the coverage gap is real every pass")
        self.assertEqual(3, final)
        self.assertEqual(3, out.count("Pass "))
        self.assertEqual(1, out.count("does not exist"))
        self.assertEqual(1, out.count("install the provider"))

    def test_absent_then_denied_on_the_same_channel_warns_twice(self):
        # The changed condition. A latch keyed on the channel alone would
        # print the first text and swallow the second.
        codes, out, _ = self.run_passes(self.absent(), self.denied())
        self.assertEqual([3, 3], codes)
        self.assertEqual(1, out.count("does not exist"))
        self.assertEqual(1, out.count("requires elevation"))

    def test_denied_then_absent_on_the_same_channel_warns_twice(self):
        # The mirror of the case above, and the one that discriminates a latch
        # keyed on the channel alone: the denied path writes the channel into
        # the shared dict, so a channel-keyed latch would swallow the absent
        # text that follows it.
        codes, out, _ = self.run_passes(self.denied(), self.absent())
        self.assertEqual([3, 3], codes)
        self.assertEqual(1, out.count("requires elevation"))
        self.assertEqual(1, out.count("does not exist"))

    def test_a_channel_that_appears_and_goes_absent_again_warns_again(self):
        codes, out, _ = self.run_passes(self.absent(), None, self.absent())
        self.assertEqual([3, 0, 3], codes)
        self.assertEqual(2, out.count("does not exist"))

    def test_two_channels_absent_with_the_same_text_each_warn(self):
        # Discriminates a latch keyed on the text alone.
        same = "no such channel"
        codes, out, _ = self.run_passes(
            self.absent(same), self.absent(same),
            self.absent(same), self.absent(same),
            passes=2, channels=(self.SYSMON, "Microsoft-Windows-DNS/Nowhere"))
        self.assertEqual([3, 3], codes)
        self.assertEqual(2, out.count(same))

    def test_the_latch_is_per_run_so_a_second_run_warns_again(self):
        for _ in range(2):
            codes, out, _ = self.run_passes(self.absent(), self.absent())
            self.assertEqual([3, 3], codes)
            self.assertEqual(1, out.count("does not exist"))


class TestInterval(MonitorCase):
    def test_the_interval_is_honoured_between_passes(self):
        with self.reading(), self.stopping(None) as sleeper:
            code, _, _ = self.monitor("--interval", "7")
        self.assertEqual(0, code)
        self.assertEqual([mock.call(7), mock.call(7)], sleeper.call_args_list)


class TestKeyboardInterrupt(MonitorCase):
    def test_keyboard_interrupt_exits_0_cleanly_without_a_traceback(self):
        with self.reading(), self.stopping():
            code, out, err = self.monitor()
        self.assertEqual(0, code)
        self.assertNotIn("Traceback", out + err)
        self.assertIn("Stopped", out)

    def test_keyboard_interrupt_during_a_pass_is_also_clean(self):
        with self.reading(), mock.patch.object(
                monitor_command, "ingest_channel", side_effect=KeyboardInterrupt):
            code, out, err = self.monitor()
        self.assertEqual(0, code)
        self.assertNotIn("Traceback", out + err)

    def test_keyboard_interrupt_after_a_partial_pass_still_exits_3(self):
        # Ctrl-C is not a crash, but a channel that was never read is still a
        # coverage gap: the worst code of the passes that ran wins.
        def read_channel(ch, count=None, since=None, after_record_id=0):
            self.reads.append(ch)
            raise wel.EventLogAccessError("Access denied reading Security")
        with mock.patch.object(wel, "read_channel", side_effect=read_channel), \
                self.stopping():
            code, _, _ = self.monitor()
        self.assertEqual(3, code)


class TestRollingWindow(MonitorCase):
    """Ruling R126. A pass detects over a window, not over what it ingested."""

    def test_a_threshold_fires_when_its_events_arrive_across_two_passes(self):
        # Five 4625s make the rule; three arrive on one pass and two on the
        # next. A pass that detected over only the events it had just ingested
        # would see 3 and then 2 and never reach the count -- which is every
        # threshold rule in the shipped pack at the spec's 5-second interval.
        with self.reading(logons(3, 500, 25)), self.stopping():
            code, _, _ = self.monitor("--once", pack=self.burst)
        self.assertEqual(0, code)
        self.assertEqual([], self.alerts(), "three of five must not fire")

        with self.reading(logons(2, 600, 5)), self.stopping():
            code, _, _ = self.monitor("--once", pack=self.burst)
        self.assertEqual(0, code)
        self.assertEqual(5, store.count_events(self.conn))
        self.assertEqual(["win-bruteforce-4625"], self.rule_ids())

    def test_an_overlapping_window_does_not_inflate_the_incident_count(self):
        # Ruling R97: an alert's identity is its exact event set, so re-reading
        # the same window stores no second alert and opens no second incident.
        with self.reading(logons(5, 500, 10)), self.stopping(None, None):
            code, _, _ = self.monitor(pack=self.burst)
        self.assertEqual(0, code)
        self.assertEqual(3, len(self.reads))
        self.assertEqual(["win-bruteforce-4625"], self.rule_ids())
        self.assertEqual(1, len(store.query_incidents(self.conn, limit=None)))


class TestEntryPoint(MonitorCase):
    def test_fix_encoding_runs_before_anything_prints(self):
        order = []
        with self.reading(), self.stopping(), \
                mock.patch.object(monitor_command, "fix_encoding",
                                  lambda: order.append("fix_encoding")), \
                mock.patch.object(monitor_command, "print_section",
                                  lambda *a, **k: order.append("print")):
            code, _, _ = self.monitor("--once")
        self.assertEqual(0, code)
        self.assertEqual(["fix_encoding", "print"], order)


class TestJson(MonitorCase):
    def test_json_is_parseable_on_stdout_with_the_text_on_stderr(self):
        with self.reading([log_cleared(60)]), self.stopping():
            code, out, err = self.monitor("--once", json_mode=True)
        self.assertEqual(0, code)
        payload = json.loads(out)
        self.assertEqual(1, payload["alerts_new"])
        self.assertIn("Pass 1", err)
        self.assertNotIn("Pass 1", out)
