import subprocess
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from ingestion import windows_eventlog as wel
from ingestion.normalizer import normalize_windows_xml, parse_event_xml
from tests.fixtures import events_xml


class TestBuildQuery(unittest.TestCase):
    def test_unfiltered(self):
        self.assertEqual("*", wel.build_query())

    def test_after_record_id(self):
        query = wel.build_query(after_record_id=143105)
        self.assertEqual("*[System[EventRecordID>143105]]", query)

    def test_non_numeric_after_record_id_raises_instead_of_being_interpolated(self):
        # int() is the injection guard: without it this builds the valid query
        # *[System[EventRecordID>1]] or *[System[EventID=4624]].
        with self.assertRaises(ValueError):
            wel.build_query(after_record_id="1]] or *[System[EventID=4624")

    def test_query_is_plain_xpath_not_xml_escaped(self):
        # wevtutil /q and EvtQuery take bare XPath; '&gt;' is exit 15001.
        query = wel.build_query(
            since=datetime(2026, 9, 29, 12, 0, 0), after_record_id=10
        )
        self.assertNotIn("&", query)

    def test_aware_since_is_converted_to_exact_utc_stamp(self):
        # Aware input makes the expectation host-independent. Dropping the
        # UTC conversion would emit 12:00 and shift --since by 5.5 hours.
        ist = timezone(timedelta(hours=5, minutes=30))
        query = wel.build_query(since=datetime(2026, 9, 29, 12, 0, 0, tzinfo=ist))
        self.assertEqual(
            "*[System[TimeCreated[@SystemTime>='2026-09-29T06:30:00.000Z']]]", query
        )

    def test_naive_since_is_treated_as_local_time(self):
        naive = datetime(2026, 9, 29, 12, 0, 0)
        # Independent route to the UTC stamp: time.mktime/gmtime, not datetime.
        expected = time.strftime(
            "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.mktime(naive.timetuple()))
        )
        self.assertEqual(
            "*[System[TimeCreated[@SystemTime>='{}']]]".format(expected),
            wel.build_query(since=naive),
        )

    def test_both_filters_combine(self):
        query = wel.build_query(
            since=datetime(2026, 9, 29, 12, 0, 0), after_record_id=10
        )
        self.assertIn(" and ", query)
        self.assertIn("EventRecordID>10", query)


class TestReadChannelWevtutil(unittest.TestCase):
    def _run(self, stdout="", stderr="", returncode=0):
        return mock.Mock(stdout=stdout, stderr=stderr, returncode=returncode)

    def test_parses_multiple_events(self):
        with mock.patch("subprocess.run",
                        return_value=self._run(events_xml.TWO_EVENTS_CONCATENATED)):
            result = wel.read_channel_wevtutil("System")
        self.assertEqual(2, len(result))

    def test_returns_oldest_first(self):
        with mock.patch("subprocess.run",
                        return_value=self._run(events_xml.TWO_EVENTS_CONCATENATED)):
            result = wel.read_channel_wevtutil("System")
        ids = [parse_event_xml(x)["record_id"] for x in result]
        self.assertEqual(sorted(ids), ids)
        self.assertEqual([500, 143105], ids)

    def test_unparseable_record_does_not_abort_the_channel(self):
        # Valid record and one with no EventRecordID: parse_event_xml raises
        # ValueError for the second. The good record must still come back.
        no_record_id = events_xml.SERVICE_7040.replace(
            "<EventRecordID>143105</EventRecordID>", ""
        )
        blob = no_record_id + events_xml.FAILED_LOGON_4625
        with mock.patch("subprocess.run", return_value=self._run(blob)):
            result = wel.read_channel_wevtutil("System")
        self.assertIn(events_xml.FAILED_LOGON_4625, result)

    def test_unparseable_record_is_passed_on_for_the_caller_to_count(self):
        no_record_id = events_xml.SERVICE_7040.replace(
            "<EventRecordID>143105</EventRecordID>", ""
        )
        blob = events_xml.FAILED_LOGON_4625 + no_record_id
        with mock.patch("subprocess.run", return_value=self._run(blob)):
            result = wel.read_channel_wevtutil("System")
        # Good record first, bad one last, nothing silently lost.
        self.assertEqual([events_xml.FAILED_LOGON_4625, no_record_id], result)

    def test_non_utf8_output_does_not_raise(self):
        # Three real channels on the dev host (Ntfs, Store, VHDMP) emit bytes
        # such as 0xb5 that are not valid UTF-8. subprocess.run is redirected
        # to a child that writes such bytes, with the code's own decoding
        # kwargs, so errors="replace" is what keeps this from raising.
        payload = events_xml.SERVICE_7040.replace(
            "IsolationSession", "Isolation\x00", 1
        ).encode("utf-8").replace(b"\x00", b"\xb5")
        real_run = subprocess.run

        def child_run(args, **kwargs):
            code = "import sys; sys.stdout.buffer.write({!r})".format(payload)
            return real_run([sys.executable, "-c", code], **kwargs)

        with mock.patch("subprocess.run", side_effect=child_run):
            result = wel.read_channel_wevtutil("Microsoft-Windows-Ntfs/Operational")
        self.assertEqual(1, len(result))
        self.assertIn("�", result[0])

    def test_exit_5_raises_elevation_error_whatever_the_locale(self):
        # Classified by exit code: German stderr must not lose the instruction.
        with mock.patch("subprocess.run",
                        return_value=self._run(stderr="Zugriff verweigert.",
                                               returncode=5)):
            with self.assertRaises(wel.EventLogAccessError) as ctx:
                wel.read_channel_wevtutil("Security")
        message = str(ctx.exception)
        self.assertIn("Security", message)
        self.assertIn("Administrator", message)

    def test_exit_15007_raises_channel_not_found_whatever_the_locale(self):
        with mock.patch(
            "subprocess.run",
            return_value=self._run(
                stderr="Der angegebene Kanal wurde nicht gefunden.",
                returncode=15007,
            ),
        ):
            with self.assertRaises(wel.ChannelNotFoundError):
                wel.read_channel_wevtutil("Microsoft-Windows-Sysmon/Operational")

    def test_other_exit_code_is_generic_error_with_stderr(self):
        with mock.patch("subprocess.run",
                        return_value=self._run(stderr="Invalid option c.",
                                               returncode=87)):
            with self.assertRaises(wel.EventLogAccessError) as ctx:
                wel.read_channel_wevtutil("System")
        message = str(ctx.exception)
        self.assertIn("System", message)
        self.assertIn("87", message)
        self.assertIn("Invalid option c.", message)
        self.assertNotIn("Administrator", message)

    def test_nonzero_exit_with_empty_stderr_says_no_error_output(self):
        with mock.patch("subprocess.run",
                        return_value=self._run(stderr="   ", returncode=87)):
            with self.assertRaises(wel.EventLogAccessError) as ctx:
                wel.read_channel_wevtutil("System")
        self.assertIn("no error output", str(ctx.exception))

    def test_timeout_is_set_and_reported_as_access_error(self):
        with mock.patch("subprocess.run", return_value=self._run("")) as runner:
            wel.read_channel_wevtutil("System")
        self.assertEqual(120, runner.call_args[1]["timeout"])
        with mock.patch("subprocess.run",
                        side_effect=subprocess.TimeoutExpired("wevtutil", 120)):
            with self.assertRaises(wel.EventLogAccessError) as ctx:
                wel.read_channel_wevtutil("Application")
        self.assertIn("Application", str(ctx.exception))

    def test_empty_output_returns_empty_list(self):
        with mock.patch("subprocess.run", return_value=self._run("")):
            self.assertEqual([], wel.read_channel_wevtutil("System"))

    def test_command_is_an_argument_list_not_a_shell_string(self):
        with mock.patch("subprocess.run", return_value=self._run("")) as runner:
            wel.read_channel_wevtutil("System", count=5)
        args, kwargs = runner.call_args
        self.assertIsInstance(args[0], list)
        self.assertEqual("wevtutil", args[0][0])
        self.assertFalse(kwargs.get("shell", False))

    def test_count_is_passed_through(self):
        with mock.patch("subprocess.run", return_value=self._run("")) as runner:
            wel.read_channel_wevtutil("System", count=17)
        self.assertIn("/c:17", runner.call_args[0][0])

    def test_query_reaches_wevtutil_as_plain_xpath(self):
        with mock.patch("subprocess.run", return_value=self._run("")) as runner:
            wel.read_channel_wevtutil("System", after_record_id=7)
        self.assertIn("/q:*[System[EventRecordID>7]]", runner.call_args[0][0])

    def test_direct_call_rejects_switch_like_channel_names(self):
        # '/?' returns 0 records and no error from the real tool, so a direct
        # call must not reach it.
        for name in ("/?", "/c:1", "-?", "-x"):
            with mock.patch("subprocess.run") as runner:
                with self.assertRaises(ValueError) as ctx:
                    wel.read_channel_wevtutil(name)
            self.assertIn(name, str(ctx.exception))
            self.assertIn("must not start with", str(ctx.exception))
            runner.assert_not_called()

    def test_missing_wevtutil_binary_is_reported(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError()):
            with self.assertRaises(wel.EventLogAccessError):
                wel.read_channel_wevtutil("System")


class TestBackendSelection(unittest.TestCase):
    def test_falls_back_to_wevtutil_when_pywin32_absent(self):
        with mock.patch.object(wel, "_HAS_PYWIN32", False):
            with mock.patch.object(wel, "read_channel_wevtutil",
                                   return_value=["x"]) as fallback:
                result = wel.read_channel("System")
        self.assertEqual(["x"], result)
        fallback.assert_called_once()

    def test_backend_name_reflects_availability(self):
        with mock.patch.object(wel, "_HAS_PYWIN32", False):
            self.assertEqual("wevtutil", wel.backend_name())
        with mock.patch.object(wel, "_HAS_PYWIN32", True):
            self.assertEqual("pywin32", wel.backend_name())

    def test_prefer_pywin32_false_forces_wevtutil(self):
        with mock.patch.object(wel, "_HAS_PYWIN32", True):
            with mock.patch.object(wel, "read_channel_wevtutil",
                                   return_value=["x"]) as fallback:
                wel.read_channel("System", prefer_pywin32=False)
        fallback.assert_called_once()

    def test_pywin32_receives_all_four_arguments(self):
        since = datetime(2026, 9, 29, 12, 0, 0)
        with mock.patch.object(wel, "_HAS_PYWIN32", True):
            with mock.patch.object(wel, "read_channel_pywin32",
                                   return_value=["y"]) as native:
                self.assertEqual(["y"], wel.read_channel("System", 3, since, 9))
        self.assertEqual(("System", 3, since, 9), native.call_args[0])

    def test_wevtutil_receives_all_four_arguments(self):
        # A dropped after_record_id would make the bookmark silently decorative.
        since = datetime(2026, 9, 29, 12, 0, 0)
        with mock.patch.object(wel, "_HAS_PYWIN32", False):
            with mock.patch.object(wel, "read_channel_wevtutil",
                                   return_value=[]) as fallback:
                wel.read_channel("System", 3, since, 9)
        self.assertEqual(("System", 3, since, 9), fallback.call_args[0])

    def test_switch_like_channel_names_are_rejected(self):
        # The guard lives in the backend, so read_channel inherits it; the
        # subprocess is patched (not the backend) to prove nothing is run.
        for name in ("/?", "/c:1", "-?", "-x"):
            with mock.patch("subprocess.run") as runner:
                with self.assertRaises(ValueError) as ctx:
                    wel.read_channel(name)
            self.assertIn(name, str(ctx.exception))
            runner.assert_not_called()


class TestReadChannelPywin32Mocked(unittest.TestCase):
    """Mock-only: pywin32 is not installed on the dev host, so this checks the
    shape of the calls, not the real native API."""

    def _fake_modules(self):
        win32evtlog = mock.MagicMock()
        win32evtlog.EvtQueryChannelPath = 1
        win32evtlog.EvtQueryForwardDirection = 2
        win32evtlog.EvtRenderEventXml = 4

        class PyWinError(Exception):
            def __init__(self, winerror):
                super().__init__(winerror)
                self.winerror = winerror

        pywintypes = mock.MagicMock()
        pywintypes.error = PyWinError
        return win32evtlog, pywintypes, PyWinError

    def _patched(self, win32evtlog, pywintypes):
        return mock.patch.dict(
            sys.modules, {"win32evtlog": win32evtlog, "pywintypes": pywintypes}
        )

    def test_renders_events_in_batches(self):
        win32evtlog, pywintypes, _ = self._fake_modules()
        win32evtlog.EvtNext.side_effect = [["a", "b"], []]
        win32evtlog.EvtRender.side_effect = lambda item, flag: "<" + item + ">"
        with self._patched(win32evtlog, pywintypes):
            result = wel.read_channel_pywin32("System", count=5)
        self.assertEqual(["<a>", "<b>"], result)

    def test_events_are_rendered_as_xml(self):
        win32evtlog, pywintypes, _ = self._fake_modules()
        win32evtlog.EvtNext.side_effect = [["a"], []]
        with self._patched(win32evtlog, pywintypes):
            wel.read_channel_pywin32("System")
        win32evtlog.EvtRender.assert_called_once_with("a", 4)  # EvtRenderEventXml

    def test_other_open_failure_is_generic_error_not_elevation(self):
        win32evtlog, pywintypes, PyWinError = self._fake_modules()
        win32evtlog.EvtQuery.side_effect = PyWinError(1234)
        with self._patched(win32evtlog, pywintypes):
            with self.assertRaises(wel.EventLogAccessError) as ctx:
                wel.read_channel_pywin32("System")
        message = str(ctx.exception)
        self.assertIn("Cannot open the 'System' channel", message)
        self.assertIn("1234", message)
        self.assertNotIn("Administrator", message)

    def test_evtnext_failing_mid_stream_is_a_clean_error(self):
        win32evtlog, pywintypes, PyWinError = self._fake_modules()
        win32evtlog.EvtNext.side_effect = [["a"], PyWinError(1450)]
        win32evtlog.EvtRender.return_value = "<e/>"
        with self._patched(win32evtlog, pywintypes):
            with self.assertRaises(wel.EventLogAccessError) as ctx:
                wel.read_channel_pywin32("System", count=5)
        self.assertIn("System", str(ctx.exception))
        self.assertIn("1450", str(ctx.exception))

    def test_evtrender_failing_mid_stream_is_a_clean_error(self):
        win32evtlog, pywintypes, PyWinError = self._fake_modules()
        win32evtlog.EvtNext.side_effect = [["a", "b"], []]
        win32evtlog.EvtRender.side_effect = ["<e/>", PyWinError(1450)]
        with self._patched(win32evtlog, pywintypes):
            with self.assertRaises(wel.EventLogAccessError) as ctx:
                wel.read_channel_pywin32("System", count=5)
        self.assertIn("System", str(ctx.exception))
        self.assertIn("1450", str(ctx.exception))

    def test_batches_are_at_most_100_and_total_honours_count(self):
        win32evtlog, pywintypes, _ = self._fake_modules()
        win32evtlog.EvtNext.side_effect = [["x"] * 100, ["x"] * 50, ["x"] * 50]
        win32evtlog.EvtRender.return_value = "<e/>"
        with self._patched(win32evtlog, pywintypes):
            result = wel.read_channel_pywin32("System", count=150)
        self.assertEqual(150, len(result))
        sizes = [call[0][1] for call in win32evtlog.EvtNext.call_args_list]
        self.assertEqual([100, 50], sizes)

    def test_query_uses_forward_direction_channel_path_and_plain_xpath(self):
        win32evtlog, pywintypes, _ = self._fake_modules()
        win32evtlog.EvtNext.return_value = []
        with self._patched(win32evtlog, pywintypes):
            wel.read_channel_pywin32("System", after_record_id=9)
        channel, flags, query, session = win32evtlog.EvtQuery.call_args[0]
        self.assertEqual("System", channel)
        self.assertEqual(1 | 2, flags)  # EvtQueryChannelPath | ...ForwardDirection
        self.assertEqual("*[System[EventRecordID>9]]", query)

    def test_direct_call_rejects_switch_like_channel_names(self):
        win32evtlog, pywintypes, _ = self._fake_modules()
        # Empty batch, so a missing guard fails the assertions instead of
        # spinning: len() of a bare MagicMock is 0, so `remaining` never drops.
        win32evtlog.EvtNext.return_value = []
        with self._patched(win32evtlog, pywintypes):
            for name in ("/?", "-?"):
                with self.assertRaises(ValueError) as ctx:
                    wel.read_channel_pywin32(name)
                self.assertIn(name, str(ctx.exception))
        win32evtlog.EvtQuery.assert_not_called()

    def test_access_denied_raises_elevation_error(self):
        win32evtlog, pywintypes, PyWinError = self._fake_modules()
        win32evtlog.EvtQuery.side_effect = PyWinError(5)
        with self._patched(win32evtlog, pywintypes):
            with self.assertRaises(wel.EventLogAccessError) as ctx:
                wel.read_channel_pywin32("Security")
        self.assertIn("Security", str(ctx.exception))
        self.assertIn("Administrator", str(ctx.exception))

    def test_missing_channel_raises_named_error(self):
        win32evtlog, pywintypes, PyWinError = self._fake_modules()
        win32evtlog.EvtQuery.side_effect = PyWinError(15007)
        with self._patched(win32evtlog, pywintypes):
            with self.assertRaises(wel.ChannelNotFoundError):
                wel.read_channel_pywin32("Nope/Operational")


def _raw_wevtutil(channel, query="*"):
    """Run the real tool, bypassing the module under test."""
    return subprocess.run(
        ["wevtutil", "qe", channel, "/f:xml", "/c:1", "/q:" + query],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )


class TestLiveRead(unittest.TestCase):
    """Touches the real System channel, which is readable without elevation."""

    def _read(self, **kwargs):
        # No skip here: a query syntax error (exit 15001) also surfaces as
        # EventLogAccessError, and that must fail the test, not skip it.
        return wel.read_channel_wevtutil("System", count=1, **kwargs)

    def test_reads_a_real_event(self):
        try:
            result = wel.read_channel("System", count=1)
        except wel.EventLogAccessError as exc:
            self.skipTest("Event Log unavailable: {}".format(exc))
        self.assertTrue(len(result) <= 1)
        if result:
            event = normalize_windows_xml(result[0])
            self.assertEqual("System", event.channel)
            self.assertGreater(event.record_id, 0)

    def test_generated_query_is_accepted_by_real_wevtutil(self):
        # Proves build_query output reaches wevtutil in a form it accepts, for
        # each filter alone and combined. A syntax error would raise (exit 15001).
        for kwargs in (
            {"after_record_id": 1},
            {"since": datetime(2020, 1, 1)},
            {"since": datetime(2020, 1, 1), "after_record_id": 1},
        ):
            result = self._read(**kwargs)
            self.assertEqual(1, len(result), kwargs)
            self.assertGreater(parse_event_xml(result[0])["record_id"], 1)

    def test_filter_actually_filters(self):
        result = self._read(since=datetime(2999, 1, 1))
        self.assertEqual([], result)

    def test_record_id_above_newest_returns_nothing(self):
        # Plain '>' reaches the tool and genuinely filters, not just parses.
        self.assertEqual(1, len(self._read(after_record_id=1)))
        self.assertEqual([], self._read(after_record_id=10 ** 9))


class TestLiveErrors(unittest.TestCase):
    def test_security_without_elevation_is_a_clean_error(self):
        raw = _raw_wevtutil("Security")
        if raw.returncode == 0:
            self.skipTest("process is elevated; Security channel is readable")
        self.assertEqual(5, raw.returncode)
        self.assertIn("Access is denied.", raw.stderr)
        with self.assertRaises(wel.EventLogAccessError) as ctx:
            wel.read_channel_wevtutil("Security", count=1)
        self.assertIn("Security", str(ctx.exception))
        self.assertIn("Administrator", str(ctx.exception))

    def test_unknown_channel_is_channel_not_found(self):
        raw = _raw_wevtutil("No-Such-Provider/Operational")
        self.assertEqual(15007, raw.returncode)
        with self.assertRaises(wel.ChannelNotFoundError):
            wel.read_channel_wevtutil("No-Such-Provider/Operational", count=1)


if __name__ == "__main__":
    unittest.main()
