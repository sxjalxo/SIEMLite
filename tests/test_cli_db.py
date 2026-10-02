import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import cli
import main
from core import database, store
from ingestion.normalizer import NormalizedEvent


def make_event(record_id, timestamp, channel="Security"):
    return NormalizedEvent(
        timestamp=timestamp, source_type="windows", host="H",
        channel=channel, event_id=4625, record_id=record_id,
    )


class TestParser(unittest.TestCase):
    def test_registers_db_subcommand(self):
        args = cli.build_parser().parse_args(["db", "init"])
        self.assertEqual("db", args.command)
        self.assertEqual("init", args.action)

    def test_command_names_reads_module_constants(self):
        self.assertEqual({"db"}, cli.command_names())

    def test_command_names_is_derived_from_registered_modules(self):
        stub = SimpleNamespace(NAME="stub")
        with mock.patch.object(cli, "COMMAND_MODULES", [stub]):
            self.assertEqual({"stub"}, cli.command_names())
            self.assertTrue(cli.is_subcommand(["stub"]))

    def test_no_command_prints_help_and_returns_2(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.dispatch([])
        self.assertEqual(2, code)
        self.assertIn("usage:", buffer.getvalue())

    def test_is_subcommand_recognises_db(self):
        self.assertTrue(cli.is_subcommand(["db", "init"]))

    def test_is_subcommand_skips_leading_global_flags(self):
        self.assertTrue(cli.is_subcommand(["--db", "x.db", "db", "stats"]))
        self.assertTrue(cli.is_subcommand(["--db=x.db", "--json", "db", "stats"]))

    def test_is_subcommand_rejects_legacy_flag_with_command_name_value(self):
        self.assertFalse(cli.is_subcommand(["--analyze", "db"]))

    def test_is_subcommand_rejects_legacy_flags(self):
        self.assertFalse(cli.is_subcommand(["--scan", "https://example.com"]))
        self.assertFalse(cli.is_subcommand(["--analyze", "access.log"]))

    def test_is_subcommand_on_empty_argv(self):
        self.assertFalse(cli.is_subcommand([]))


class TestDbCommand(unittest.TestCase):
    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)

    def tearDown(self):
        # WAL mode leaves -wal/-shm sidecars next to the temp database.
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(self.db_path + suffix)
            except OSError:
                pass

    def run_cli(self, argv):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.dispatch(["--db", self.db_path] + argv)
        return code, buffer.getvalue()

    def seed(self, *events):
        conn = store.connect(self.db_path)
        store.init_schema(conn)
        store.insert_events(conn, list(events))
        conn.close()

    def surviving_record_ids(self):
        conn = store.connect(self.db_path)
        ids = [r["record_id"] for r in conn.execute(
            "SELECT record_id FROM events ORDER BY record_id")]
        conn.close()
        return ids

    def test_db_init_creates_tables(self):
        code, _ = self.run_cli(["db", "init"])
        self.assertEqual(0, code)
        conn = store.connect(self.db_path)
        names = {
            r["name"]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        conn.close()
        self.assertIn("events", names)
        self.assertIn("incidents", names)

    def test_db_init_reports_the_store_path(self):
        code, output = self.run_cli(["db", "init"])
        self.assertEqual(0, code)
        self.assertIn(self.db_path, output)

        code, output = self.run_cli(["--json", "db", "init"])
        self.assertEqual({"status": "ok", "db": self.db_path}, json.loads(output))

    def test_db_init_is_idempotent(self):
        self.run_cli(["db", "init"])
        code, _ = self.run_cli(["db", "init"])
        self.assertEqual(0, code)

    def test_db_stats_on_empty_store(self):
        self.run_cli(["db", "init"])
        code, output = self.run_cli(["db", "stats"])
        self.assertEqual(0, code)
        self.assertIn("Total events : 0", output)

    def test_db_stats_json_is_parseable(self):
        self.run_cli(["db", "init"])
        code, output = self.run_cli(["--json", "db", "stats"])
        self.assertEqual(0, code)
        self.assertEqual(0, json.loads(output)["total"])

    def test_db_purge_removes_old_and_keeps_recent_by_record_id(self):
        now = datetime.now()
        self.seed(make_event(1, now - timedelta(days=60)),
                  make_event(2, now - timedelta(days=1)))

        code, _ = self.run_cli(["db", "purge", "--older-than", "30d"])
        self.assertEqual(0, code)
        self.assertEqual([2], self.surviving_record_ids())

    def test_db_purge_cutoff_is_exact_within_the_same_day(self):
        # Same calendar day as the cutoff, either side of it by clock time. A
        # cutoff bound as 'T'-separated text would sort after both stored
        # (space-separated) timestamps and wrongly delete the later one.
        self.seed(make_event(1, datetime(2026, 9, 15, 8, 0, 0)),
                  make_event(2, datetime(2026, 9, 15, 15, 0, 0)))

        code, output = self.run_cli(["db", "purge", "--older-than", "2026-09-15T12:00:00"])
        self.assertEqual(0, code)
        self.assertIn("Removed 1 events", output)
        self.assertEqual([2], self.surviving_record_ids())

    def test_db_purge_json_reports_removed_and_cutoff(self):
        self.seed(make_event(1, datetime(2026, 9, 14, 8, 0, 0)),
                  make_event(2, datetime(2026, 9, 15, 8, 0, 0)),
                  make_event(3, datetime(2026, 9, 16, 8, 0, 0)))

        code, output = self.run_cli(["--json", "db", "purge", "--older-than", "2026-09-15T12:00:00"])
        self.assertEqual(0, code)
        self.assertEqual({"removed": 2, "cutoff": "2026-09-15T12:00:00"}, json.loads(output))

    def test_db_stats_counts_real_events(self):
        self.seed(make_event(1, datetime(2026, 9, 29, 10, 0, 1)),
                  make_event(2, datetime(2026, 9, 29, 10, 0, 2)),
                  make_event(3, datetime(2026, 9, 29, 10, 0, 3), channel="System"))

        code, output = self.run_cli(["--json", "db", "stats"])
        self.assertEqual(0, code)
        summary = json.loads(output)
        self.assertEqual(3, summary["total"])
        self.assertEqual({"Security": 2, "System": 1}, summary["by_channel"])
        self.assertEqual({"4625": 3}, {str(k): v for k, v in summary["by_event_id"].items()})

    def test_db_stats_text_lists_channels_and_event_ids(self):
        self.seed(make_event(1, datetime(2026, 9, 29, 10, 0, 1)),
                  make_event(2, datetime(2026, 9, 29, 10, 0, 2)),
                  make_event(3, datetime(2026, 9, 29, 10, 0, 3), channel="System"))

        code, output = self.run_cli(["db", "stats"])
        self.assertEqual(0, code)
        self.assertRegex(output, r"Security\s+2\b")
        self.assertRegex(output, r"System\s+1\b")
        self.assertRegex(output, r"4625\s+3\b")

    def test_empty_db_path_is_rejected_and_default_never_opened(self):
        for argv in (["--db=", "db", "purge"], ["--db", "", "db", "purge"],
                     ["--db", "   ", "db", "purge"]):
            with self.subTest(argv=argv), mock.patch.object(store, "connect") as connect:
                buffer = io.StringIO()
                with redirect_stdout(buffer):
                    code = cli.dispatch(argv)
                self.assertEqual(2, code)
                self.assertIn("--db", buffer.getvalue())
                connect.assert_not_called()

    def test_bad_time_value_is_clean_usage_error(self):
        code, output = self.run_cli(["db", "purge", "--older-than", "bogus"])
        self.assertEqual(2, code)
        self.assertIn("Cannot parse time value", output)
        self.assertNotIn("Traceback", output)

    def test_main_py_routes_subcommand_after_global_flags(self):
        main_py = Path(__file__).resolve().parent.parent / "main.py"
        result = subprocess.run(
            [sys.executable, str(main_py), "--db", self.db_path, "db", "init"],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("Event store ready", result.stdout)

    def test_unknown_action_is_usage_error(self):
        with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
            cli.build_parser().parse_args(["db", "frobnicate"])


class TestLegacyWiring(unittest.TestCase):
    def test_init_database_also_builds_pipeline_tables(self):
        handle, path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        try:
            with mock.patch.object(database, "DB_PATH", Path(path)):
                with redirect_stdout(io.StringIO()):
                    self.assertTrue(database.init_database())
                    self.assertTrue(database.init_database())  # idempotent
            conn = store.connect(path)
            names = {
                r["name"]
                for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            conn.close()
            self.assertIn("events", names)
            self.assertIn("logs", names)
        finally:
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.unlink(path + suffix)
                except OSError:
                    pass

    def test_main_py_imports_print_error(self):
        # The --output failure path calls print_error; it must be importable there.
        self.assertTrue(callable(main.print_error))


class TestMainOutputExitCode(unittest.TestCase):
    """`--output` must exit non-zero when the report was not written."""

    def run_main(self, output_path):
        argv = ["main.py", "--analyze", "ignored.log", "--output", output_path]
        buffer = io.StringIO()
        # Stubs keep the run off the real database and off the filesystem.
        with mock.patch.object(sys, "argv", argv),                 mock.patch.object(main, "fix_encoding"),                 mock.patch.object(main, "banner"),                 mock.patch.object(main, "init_database"),                 mock.patch.object(main, "analyze_log", return_value=([], {})),                 mock.patch.object(main, "generate_report"),                 redirect_stdout(buffer):
            try:
                main.main()
                code = 0
            except SystemExit as exc:
                code = exc.code
        return code, buffer.getvalue()

    def test_failed_save_prints_message_and_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, output = self.run_main(os.path.join(tmp, "missing", "report.json"))
        self.assertNotEqual(0, code)
        self.assertIn("Failed to save JSON report", output)

    def test_successful_save_still_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            code, output = self.run_main(path)
            self.assertTrue(os.path.exists(path))
        self.assertEqual(0, code)
        self.assertIn("JSON report saved", output)


if __name__ == "__main__":
    unittest.main()
