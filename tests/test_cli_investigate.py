import json
import re
import unittest
from datetime import timedelta
from unittest import mock

from cli.commands import investigate as investigate_command
from core import store
from tests import helpers_rules
from tests.helpers_rules import T0, sample_alert
from tests.test_cli_alerts import ANSI, ROW
from tests.test_cli_ingest import IngestTestCase
from tests.test_cli_incidents import defanged, hostile, sections

NODE = re.compile(r"^\s+(ip|user|host) (.*) events=(\d+)$")
MORE = re.compile(r"^\s+\[~\] \+(\d+) more (\w+)\(s\) not shown")


def rows(out, title):
    """The rows of the section whose title starts with `title`, as columns:
    time, then four more. Events: id, action, host, fields. Alerts: severity,
    rule, entity, evidence."""
    body = next((v for k, v in sections(out).items() if k.startswith(title)), [])
    return [re.split(r"\s{2,}", line.strip(), maxsplit=4) for line in body if ROW.match(line)]


def nodes(out):
    """The pivot tree as (kind, value, events) in print order."""
    body = sections(out).get("Related", [])
    return [(m.group(1), m.group(2), int(m.group(3)))
            for m in map(NODE.match, body) if m]


def mores(out):
    return [(int(m.group(1)), m.group(2)) for m in
            map(MORE.match, sections(out).get("Related", [])) if m]


class InvestigateCase(IngestTestCase):
    def setUp(self):
        super().setUp()
        self.next_record = 0

    def add(self, minutes=0, **fields):
        """Store one event `minutes` after T0 and return it. record_id is
        counted: event_hash is (host, channel, record_id, raw), so two events
        that differ only in a field would otherwise be one row."""
        self.next_record += 1
        fields.setdefault("record_id", self.next_record)
        event = helpers_rules.event(timestamp=T0 + timedelta(minutes=minutes), **fields)
        store.insert_events(self.conn, [event])
        return event

    def alert(self, minutes=0, **fields):
        store.insert_alerts(self.conn, [sample_alert(
            timestamp=T0 + timedelta(minutes=minutes), **fields)])

    def legacy_alert(self, entity_value="1.2.3.4"):
        """A row as the legacy scanner writes it, but with an entity filled in
        so the entity filter alone would let it through: only the missing
        rule_id says it is not a rule-engine row. UTC, so 5.5h off."""
        self.conn.execute(
            "INSERT INTO alerts (timestamp, category, severity, detail, source, "
            "entity_type, entity_value) VALUES (?, 'SQLi', 'HIGH', 'legacy', "
            "'scanner', 'ip', ?)", ("2026-10-03 06:30:00", entity_value))
        self.conn.commit()


class TestInvestigate(InvestigateCase):
    def test_ip_lists_that_entitys_events_and_alerts_chronologically(self):
        # Inserted out of order, so only the query's ordering can sort them.
        self.add(minutes=2, source_ip="1.2.3.4", event_id=4625, host="PC-02")
        self.add(minutes=0, source_ip="1.2.3.4", event_id=4624, host="PC-01")
        self.add(minutes=1, source_ip="1.2.3.4", event_id=4672, host="PC-03")
        self.add(minutes=1, source_ip="9.9.9.9", event_id=1102, host="OTHER")
        self.alert(minutes=3, rule_id="late", entity_value="1.2.3.4")
        self.alert(minutes=1, rule_id="early", entity_value="1.2.3.4")
        self.alert(minutes=2, rule_id="elsewhere", entity_value="9.9.9.9")
        code, out = self.run_cli(["investigate", "--ip", "1.2.3.4"])
        self.assertEqual(0, code)
        events = rows(out, "Events")
        self.assertEqual(["4624", "4672", "4625"], [r[1] for r in events])
        self.assertEqual(["2026-10-03 12:00:00", "2026-10-03 12:01:00",
                          "2026-10-03 12:02:00"], [r[0] for r in events])
        self.assertEqual(["early", "late"], [r[2] for r in rows(out, "Alerts")])

    def test_user_matches_either_side_of_an_action(self):
        # query_events(user=) deliberately matches `user` OR `target_user`: an
        # analyst asking about an account wants what it did and what was done
        # to it. Pin that, so narrowing it is a visible change.
        self.add(minutes=0, user="alice", event_id=4720)
        self.add(minutes=1, target_user="alice", event_id=4625)
        self.add(minutes=2, user="bob", target_user="carol", event_id=4688)
        code, out = self.run_cli(["investigate", "--user", "alice"])
        self.assertEqual(0, code)
        self.assertEqual(["4720", "4625"], [r[1] for r in rows(out, "Events")])

    def test_host_lists_that_hosts_events_and_alerts(self):
        self.add(host="PC-01", event_id=4624)
        self.add(host="PC-02", event_id=4625)
        self.alert(rule_id="on-host", entity_type="host", entity_value="PC-01")
        code, out = self.run_cli(["investigate", "--host", "PC-01"])
        self.assertEqual(0, code)
        self.assertEqual(["4624"], [r[1] for r in rows(out, "Events")])
        self.assertEqual(["on-host"], [r[2] for r in rows(out, "Alerts")])

    def test_an_alert_for_another_kind_of_entity_with_the_same_text_is_not_listed(self):
        # ip 1.2.3.4 and user 1.2.3.4 are different entities (the correlator
        # and find_open_incident already say so).
        self.alert(rule_id="the-ip", entity_type="ip", entity_value="1.2.3.4")
        self.alert(rule_id="a-user-so-named", entity_type="user", entity_value="1.2.3.4")
        _, out = self.run_cli(["investigate", "--ip", "1.2.3.4"])
        self.assertEqual(["the-ip"], [r[2] for r in rows(out, "Alerts")])

    def test_exactly_one_of_ip_user_host_is_required(self):
        # A verb that silently picks one is worse than one that refuses.
        for argv in ([], ["--ip", "1.2.3.4", "--user", "alice"],
                     ["--ip", "1.2.3.4", "--user", "alice", "--host", "PC-01"],
                     ["--user", "alice", "--host", "PC-01"]):
            with self.subTest(argv=argv):
                code, out = self.run_cli(["investigate"] + argv)
                self.assertEqual(2, code)
                self.assertIn("give exactly one of --ip, --user, --host", out)
                self.assertEqual([], rows(out, "Events"))

    def test_an_empty_entity_is_a_usage_error_not_an_empty_answer(self):
        # "" would reach the store as "match nothing" and exit 0 as "no history".
        for blank in ("", "   "):
            with self.subTest(blank=blank):
                code, out = self.run_cli(["investigate", "--ip", blank])
                self.assertEqual(2, code)
                self.assertIn("--ip needs a value", out)

    def test_bad_numbers_and_times_are_usage_errors(self):
        for argv in (["--limit", "0"], ["--cap", "0"], ["--since", "yesterday-ish"],
                     ["--until", "x"]):
            with self.subTest(argv=argv):
                code, _, _ = self.run_cli_split(["investigate", "--ip", "1.2.3.4"] + argv)
                self.assertEqual(2, code)

    def test_an_entity_with_no_history_exits_0_and_says_so(self):
        # "No results" is an answer, not a failure.
        code, out, err = self.run_cli_split(["investigate", "--ip", "9.9.9.9"])
        self.assertEqual(0, code)
        self.assertIn("No events or alerts for ip 9.9.9.9", ANSI.sub("", out))
        code, out, _ = self.run_cli_split(["investigate", "--ip", "9.9.9.9", "--related"])
        self.assertEqual(0, code)
        self.assertEqual([], nodes(out))

    def test_since_and_until_bound_events_and_alerts(self):
        for minute in (0, 10, 20):
            self.add(minutes=minute, source_ip="1.2.3.4", event_id=4000 + minute)
            self.alert(minutes=minute, rule_id="r{}".format(minute), entity_value="1.2.3.4",
                       event_hashes=(str(minute),))
        _, out = self.run_cli(["investigate", "--ip", "1.2.3.4",
                               "--since", "2026-10-03 12:05:00",
                               "--until", "2026-10-03 12:15:00"])
        self.assertEqual(["4010"], [r[1] for r in rows(out, "Events")])
        self.assertEqual(["r10"], [r[2] for r in rows(out, "Alerts")])

    def test_related_is_one_hop_and_stops(self):
        # ip -> user -> host -> ip2 -> user2. user2 is a fourth step away.
        self.add(minutes=0, source_ip="1.1.1.1", target_user="alice", host="H1")
        self.add(minutes=1, user="alice", host="H1", source_ip="1.1.1.1")
        self.add(minutes=2, source_ip="2.2.2.2", target_user="user2", host="H1")
        self.add(minutes=3, source_ip="2.2.2.2", target_user="user2", host="H9")
        code, out = self.run_cli(["investigate", "--ip", "1.1.1.1", "--related"])
        self.assertEqual(0, code)
        self.assertEqual([("user", "alice"), ("host", "H1"), ("ip", "2.2.2.2")],
                         [(k, v) for k, v, _ in nodes(out)])
        self.assertNotIn("user2", "\n".join(sections(out)["Related"]))

    def test_related_starts_from_the_kind_of_entity_given(self):
        # user -> host -> ip -> user, the same ring entered at another point.
        self.add(minutes=0, user="alice", host="H1", source_ip="1.1.1.1")
        self.add(minutes=1, user="bob", host="H1", source_ip="1.1.1.1")
        code, out = self.run_cli(["investigate", "--user", "alice", "--related"])
        self.assertEqual(0, code)
        self.assertEqual([("host", "H1"), ("ip", "1.1.1.1"), ("user", "bob")],
                         [(k, v) for k, v, _ in nodes(out)])

    def test_the_tree_never_lists_the_entity_it_started_from(self):
        self.add(source_ip="1.1.1.1", target_user="alice", host="H1")
        _, out = self.run_cli(["investigate", "--ip", "1.1.1.1", "--related"])
        self.assertNotIn("1.1.1.1", [v for _, v, _ in nodes(out)])

    def test_a_missing_value_is_not_a_node(self):
        # "-" is Windows' "not recorded"; it is the default for user, source_ip.
        self.add(source_ip="1.1.1.1", user="-", target_user="-", host="H1")
        _, out = self.run_cli(["investigate", "--ip", "1.1.1.1", "--related"])
        self.assertEqual([], nodes(out))

    def test_every_pivot_level_is_capped(self):
        # 200 users on one IP: ten are shown, the rest counted.
        for i in range(200):
            self.add(source_ip="1.1.1.1", target_user="u{:03d}".format(i), host="H1")
        code, out = self.run_cli(["investigate", "--ip", "1.1.1.1", "--related"])
        self.assertEqual(0, code)
        self.assertEqual(10, sum(1 for k, _, _ in nodes(out) if k == "user"))
        self.assertEqual([(190, "user")], mores(out))
        _, out = self.run_cli(["investigate", "--ip", "1.1.1.1", "--related", "--cap", "3"])
        self.assertEqual([(197, "user")], mores(out))

    def test_the_cap_holds_at_every_level_not_just_the_first(self):
        # --cap 3. Level 1: 6 users. Level 2: the kept u0-u2 are on H plus 5
        # private hosts each (16 hosts); u3-u5 have 5 private hosts too, which
        # only a pivot from ALL the users, not the kept ones, would count.
        # Level 3: H has 7 other ips, and hu54 (never kept) has one more. A
        # different overflow at each level, so a cap dropped from any one of
        # them shows, and so does a level that pivots from what was not shown.
        for i in range(6):
            self.add(source_ip="1.1.1.1", target_user="u{}".format(i), host="H")
            for j in range(5):
                self.add(target_user="u{}".format(i), host="hu{}{}".format(i, j))
        for k in range(7):
            self.add(source_ip="9.9.9.{}".format(k), host="H")
        self.add(source_ip="8.8.8.8", host="hu54")
        code, out = self.run_cli(["investigate", "--ip", "1.1.1.1", "--related", "--cap", "3"])
        self.assertEqual(0, code)
        shown = [k for k, _, _ in nodes(out)]
        self.assertEqual({"user": 3, "host": 3, "ip": 3},
                         {k: shown.count(k) for k in ("user", "host", "ip")})
        self.assertEqual([(3, "user"), (13, "host"), (4, "ip")], mores(out))

    def test_the_busiest_nodes_are_the_ones_kept(self):
        # Cap 1 of three users: carol has the most events, not the lowest name.
        self.add(source_ip="1.1.1.1", target_user="alice")
        self.add(source_ip="1.1.1.1", target_user="bob")
        for _ in range(3):
            self.add(source_ip="1.1.1.1", target_user="carol")
        _, out = self.run_cli(["investigate", "--ip", "1.1.1.1", "--related", "--cap", "1"])
        self.assertEqual([("user", "carol", 3)], [n for n in nodes(out) if n[0] == "user"])

    def test_a_scan_that_hit_its_limit_says_so(self):
        for _ in range(5):
            self.add(source_ip="1.1.1.1", target_user="alice")
        with mock.patch.object(investigate_command, "PIVOT_SCAN", 3):
            _, out = self.run_cli(["investigate", "--ip", "1.1.1.1", "--related"])
            _, jout, _ = self.run_cli_split(["--json", "investigate", "--ip", "1.1.1.1",
                                             "--related"])
        self.assertIn("newest 3 events", ANSI.sub("", out))
        self.assertTrue(json.loads(jout)["related"]["truncated"])
        # And the counts obey the scan limit. The read asks for PIVOT_SCAN + 1
        # to tell "exactly PIVOT_SCAN" from "more", so without the slice that
        # cuts the extra row back off, alice would count 4 of 5.
        self.assertEqual([("user", "alice", 3)], [n for n in nodes(out) if n[0] == "user"])
        self.assertEqual(3, json.loads(jout)["related"]["levels"][0]["nodes"][0]["events"])

    def test_a_node_two_parents_reach_hangs_under_the_first(self):
        # alice has two events and bob one, so the level is kept in the order
        # alice, bob and alice is the FIRST parent to reach HOSTX. Attributing
        # it to the last parent instead (a plain assignment rather than
        # setdefault) hangs HOSTX under bob and prints it in another place.
        self.add(source_ip="1.1.1.1", user="alice", host="HOSTX")
        self.add(source_ip="1.1.1.1", user="alice", host="HOSTX")
        self.add(source_ip="1.1.1.1", user="bob", host="HOSTX")
        code, out = self.run_cli(["investigate", "--ip", "1.1.1.1", "--related"])
        self.assertEqual(0, code)
        self.assertEqual([("user", "alice", 2), ("host", "HOSTX", 3), ("user", "bob", 1)],
                         nodes(out), "HOSTX is printed under alice, before bob")
        _, jout, _ = self.run_cli_split(["--json", "investigate", "--ip", "1.1.1.1",
                                         "--related"])
        self.assertEqual([{"value": "HOSTX", "parent": "alice", "events": 3}],
                         json.loads(jout)["related"]["levels"][1]["nodes"])

    def test_related_honours_since_and_until(self):
        self.add(minutes=0, source_ip="1.1.1.1", target_user="early")
        self.add(minutes=10, source_ip="1.1.1.1", target_user="inside")
        self.add(minutes=20, source_ip="1.1.1.1", target_user="late")
        _, out = self.run_cli(["investigate", "--ip", "1.1.1.1", "--related",
                               "--since", "2026-10-03 12:05:00",
                               "--until", "2026-10-03 12:15:00"])
        self.assertEqual(["inside"], [v for k, v, _ in nodes(out) if k == "user"])

    def test_every_pivot_read_is_bounded(self):
        # PIVOT_SCAN is the promise that a busy host cannot make the pivot read
        # without end; each entity's read must carry a limit. The listing's own
        # read (limit=None, counted exactly) is the one unbounded call.
        self.add(source_ip="1.1.1.1", target_user="alice", host="H1")
        with mock.patch.object(store, "query_events", wraps=store.query_events) as spy:
            self.run_cli(["investigate", "--ip", "1.1.1.1", "--related"])
        limits = [c.kwargs.get("limit") for c in spy.call_args_list]
        self.assertEqual(1, limits.count(None))
        self.assertGreater(len(limits), 1)

    def test_a_scan_that_did_not_hit_its_limit_says_nothing(self):
        # Exactly PIVOT_SCAN events is a full read, not a cut one.
        for _ in range(3):
            self.add(source_ip="1.1.1.1", target_user="alice")
        with mock.patch.object(investigate_command, "PIVOT_SCAN", 3):
            _, out = self.run_cli(["investigate", "--ip", "1.1.1.1", "--related"])
        self.assertEqual([("user", "alice", 3)], [n for n in nodes(out) if n[0] == "user"])
        self.assertNotIn("newest", out)

    def test_the_listing_is_capped_and_says_how_many_it_hid(self):
        for i in range(60):
            self.add(minutes=i, source_ip="1.1.1.1")
        _, out = self.run_cli(["investigate", "--ip", "1.1.1.1"])
        self.assertEqual(50, len(rows(out, "Events")))
        self.assertIn("Events (showing first 50 of 60)", ANSI.sub("", out))
        _, out = self.run_cli(["investigate", "--ip", "1.1.1.1", "--limit", "5"])
        self.assertEqual(5, len(rows(out, "Events")))

    def test_legacy_alert_rows_are_not_mixed_in(self):
        self.alert(rule_id="real", entity_value="1.2.3.4")
        self.legacy_alert("1.2.3.4")
        code, out = self.run_cli(["investigate", "--ip", "1.2.3.4"])
        self.assertEqual(0, code)
        self.assertEqual(["real"], [r[2] for r in rows(out, "Alerts")])
        _, jout, _ = self.run_cli_split(["--json", "investigate", "--ip", "1.2.3.4"])
        payload = json.loads(jout)
        self.assertEqual(1, payload["counts"]["alerts"])
        self.assertEqual(["real"], [a["rule_id"] for a in payload["alerts"]])

    def test_json_is_parseable_and_carries_counts(self):
        self.add(minutes=1, source_ip="1.2.3.4", target_user="alice", host="H1")
        self.add(minutes=0, source_ip="1.2.3.4", target_user="bob", host="H1")
        self.alert(rule_id="r1", entity_value="1.2.3.4")
        code, out, err = self.run_cli_split(
            ["--json", "investigate", "--ip", "1.2.3.4", "--related"])
        self.assertEqual(0, code)
        self.assertEqual("", err)
        payload = json.loads(out)
        self.assertEqual({"type": "ip", "value": "1.2.3.4"}, payload["entity"])
        self.assertEqual({"events": 2, "alerts": 1}, payload["counts"])
        self.assertEqual(["bob", "alice"], [e["target_user"] for e in payload["events"]])
        self.assertEqual(["r1"], [a["rule_id"] for a in payload["alerts"]])
        level = payload["related"]["levels"][0]
        self.assertEqual(("user", 2, 2), (level["type"], level["total"], len(level["nodes"])))
        self.assertEqual({"value": "alice", "parent": "1.2.3.4", "events": 1},
                         level["nodes"][0])

    def test_json_without_related_has_no_related_key(self):
        _, out, _ = self.run_cli_split(["--json", "investigate", "--ip", "1.2.3.4"])
        self.assertNotIn("related", json.loads(out))

    def test_json_is_not_capped_by_default(self):
        for i in range(60):
            self.add(minutes=i, source_ip="1.1.1.1")
        _, out, _ = self.run_cli_split(["--json", "investigate", "--ip", "1.1.1.1"])
        payload = json.loads(out)
        self.assertEqual((60, 60), (payload["counts"]["events"], len(payload["events"])))
        _, out, _ = self.run_cli_split(["--json", "investigate", "--ip", "1.1.1.1",
                                        "--limit", "5"])
        payload = json.loads(out)
        self.assertEqual((60, 5), (payload["counts"]["events"], len(payload["events"])))


class TestInvestigateMarkup(InvestigateCase):
    """Ruling R30/R96: stored text never goes through rich markup and a control
    character cannot reach the terminal or forge a row."""

    def test_markup_in_a_field_is_not_interpreted(self):
        # rich swallows "[red]" and leaves a bare FORGED, so assert the literal.
        self.add(source_ip="1.1.1.1", host="[red]FORGED[/red]",
                 target_user="[red]FORGED[/red]", action="[red]FORGED[/red]")
        _, out = self.run_cli(["investigate", "--ip", "1.1.1.1", "--related"])
        row = rows(out, "Events")[0]
        self.assertEqual(["[red]FORGED[/red]", "[red]FORGED[/red]"], [row[2], row[3]])
        self.assertIn("[red]FORGED[/red]", row[4])
        self.assertIn(("user", "[red]FORGED[/red]", 1), nodes(out))
        self.assertIn(("host", "[red]FORGED[/red]", 1), nodes(out))

    def test_the_entity_argument_is_echoed_defanged(self):
        code, out = self.run_cli(
            ["investigate", "--user", "[red]FORGED[/red]\x1b[2J\nx", "--related"])
        self.assertEqual(0, code)
        self.assertNotIn("\x1b[2J", out)
        self.assertIn("[red]FORGED[/red]?[2J?x", ANSI.sub("", out))


class TestEveryColumnIsDefanged(InvestigateCase):
    """One hostile value in every column `investigate` prints, each with its
    own tag: removing plain() from one column fails that column's assertion
    and no other's. Raw SQL, the stronger position: the store's writers would
    coerce some of these."""

    def setUp(self):
        super().setUp()
        self.add(source_ip="1.1.1.1", target_user="alice", host="H1")
        self.add(source_ip="2.2.2.2", host="H1")
        self.alert(rule_id="r", entity_value="1.1.1.1")
        self.conn.execute(
            "UPDATE events SET event_id=?, action=?, user=? WHERE record_id=1",
            (hostile("EID"), hostile("ACT"), hostile("WHO")))
        self.conn.execute(
            "UPDATE events SET host=?, target_user=?, source_ip=? WHERE record_id=1",
            (hostile("HOST"), hostile("TGT"), "1.1.1.1"))
        self.conn.execute(
            "UPDATE events SET host=?, source_ip=? WHERE record_id=2",
            (hostile("HOST"), hostile("IP2")))
        self.conn.execute(
            "UPDATE alerts SET severity=?, rule_id=?, evidence=?",
            (hostile("ASEV"), hostile("RULE"), json.dumps([{"service_name": hostile("EVID")}])))
        self.conn.commit()

    def check(self, out, tags):
        self.assertNotIn("\x1b[2J", out)
        plain_out = ANSI.sub("", out)
        for tag in tags:
            self.assertIn(defanged(tag), plain_out, tag)
        self.assertEqual([], [l for l in plain_out.splitlines()
                              if l.strip().startswith("forged")],
                         "a newline in a column started a line of its own")

    def test_every_column_of_the_listing(self):
        code, out = self.run_cli(["investigate", "--ip", "1.1.1.1"])
        self.assertEqual(0, code)
        self.check(out, ("EID", "ACT", "HOST", "WHO", "TGT", "ASEV", "RULE", "EVID"))

    def test_every_node_of_the_tree(self):
        code, out = self.run_cli(["investigate", "--ip", "1.1.1.1", "--related"])
        self.assertEqual(0, code)
        self.check(out, ("WHO", "TGT", "HOST", "IP2"))
        # Each tag as a node of its own, not merely somewhere in the output.
        shown = {v for _, v, _ in nodes(out)}
        for tag in ("WHO", "TGT", "HOST", "IP2"):
            self.assertIn(defanged(tag), shown)


if __name__ == "__main__":
    unittest.main()
