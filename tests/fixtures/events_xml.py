"""Synthetic Windows Event XML shaped like `wevtutil qe <channel> /f:xml`."""

SERVICE_7040 = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System><Provider Name='Service Control Manager' "
    "Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' "
    "EventSourceName='Service Control Manager'/>"
    "<EventID Qualifiers='16384'>7040</EventID><Version>0</Version>"
    "<Level>4</Level><Task>0</Task><Opcode>0</Opcode>"
    "<Keywords>0x8080000000000000</Keywords>"
    "<TimeCreated SystemTime='2026-09-29T17:43:30.7880600Z'/>"
    "<EventRecordID>143105</EventRecordID><Correlation/>"
    "<Execution ProcessID='1964' ThreadID='20476'/>"
    "<Channel>System</Channel><Computer>LAPTOP-A4BLML0Q</Computer>"
    "<Security UserID='S-1-5-18'/></System>"
    "<EventData><Data Name='param1'>IsolationSession</Data>"
    "<Data Name='param2'>auto start</Data>"
    "<Data Name='param3'>demand start</Data>"
    "<Data Name='param4'>IsolationSession</Data></EventData></Event>"
)

FAILED_LOGON_4625 = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System><Provider Name='Microsoft-Windows-Security-Auditing' "
    "Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>"
    "<EventID>4625</EventID><Version>0</Version><Level>0</Level>"
    "<Task>12544</Task><Opcode>0</Opcode>"
    "<Keywords>0x8010000000000000</Keywords>"
    "<TimeCreated SystemTime='2026-05-09T10:00:01.1234567Z'/>"
    "<EventRecordID>500</EventRecordID><Correlation/>"
    "<Execution ProcessID='728' ThreadID='4084'/>"
    "<Channel>Security</Channel><Computer>WORKSTATION1</Computer>"
    "<Security/></System>"
    "<EventData>"
    "<Data Name='SubjectUserName'>-</Data>"
    "<Data Name='TargetUserName'>administrator</Data>"
    "<Data Name='TargetDomainName'>WORKSTATION1</Data>"
    "<Data Name='Status'>0xc000006d</Data>"
    "<Data Name='SubStatus'>0xc000006a</Data>"
    "<Data Name='LogonType'>3</Data>"
    "<Data Name='IpAddress'>203.0.113.50</Data>"
    "<Data Name='IpPort'>49871</Data>"
    "<Data Name='WorkstationName'>KALI</Data>"
    "<Data Name='ProcessName'>-</Data>"
    "</EventData></Event>"
)

PROCESS_4688 = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
    "<EventID>4688</EventID><Level>0</Level>"
    "<TimeCreated SystemTime='2026-05-09T10:05:30.000000Z'/>"
    "<EventRecordID>612</EventRecordID>"
    "<Channel>Security</Channel><Computer>WORKSTATION1</Computer>"
    "</System>"
    "<EventData>"
    "<Data Name='SubjectUserName'>backdoor_user</Data>"
    "<Data Name='NewProcessId'>0x1a4</Data>"
    "<Data Name='NewProcessName'>C:\\Windows\\System32\\WindowsPowerShell"
    "\\v1.0\\powershell.exe</Data>"
    "<Data Name='ParentProcessName'>C:\\Windows\\System32\\cmd.exe</Data>"
    "<Data Name='CommandLine'>powershell -enc SQBFAFgA</Data>"
    "</EventData></Event>"
)

SYSMON_NETWORK_3 = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System><Provider Name='Microsoft-Windows-Sysmon' "
    "Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/>"
    "<EventID>3</EventID><Version>5</Version><Level>4</Level>"
    "<TimeCreated SystemTime='2026-05-09T10:07:00.000000Z'/>"
    "<EventRecordID>9001</EventRecordID>"
    "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
    "<Computer>WORKSTATION1</Computer></System>"
    "<EventData>"
    "<Data Name='ProcessId'>4120</Data>"
    "<Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data>"
    "<Data Name='User'>WORKSTATION1\\bob</Data>"
    "<Data Name='Protocol'>tcp</Data>"
    "<Data Name='SourceIp'>10.0.0.5</Data>"
    "<Data Name='SourcePort'>49900</Data>"
    "<Data Name='DestinationIp'>203.0.113.9</Data>"
    "<Data Name='DestinationPort'>4444</Data>"
    "</EventData></Event>"
)

LOG_CLEARED_1102 = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System><Provider Name='Microsoft-Windows-Eventlog'/>"
    "<EventID>1102</EventID><Level>4</Level>"
    "<TimeCreated SystemTime='2026-05-09T11:00:00.000000Z'/>"
    "<EventRecordID>999</EventRecordID>"
    "<Channel>Security</Channel><Computer>WORKSTATION1</Computer>"
    "</System>"
    "<UserData>"
    "<LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/"
    "windows/eventlog'>"
    "<SubjectUserName>administrator</SubjectUserName>"
    "<SubjectDomainName>WORKSTATION1</SubjectDomainName>"
    "</LogFileCleared>"
    "</UserData></Event>"
)

# Same structure as FAILED_LOGON_4625 but with no xmlns on the root, as a
# future .evtx reader may emit.
NO_NAMESPACE_4625 = FAILED_LOGON_4625.replace(
    " xmlns='http://schemas.microsoft.com/win/2004/08/events/event'", ""
)

TWO_EVENTS_CONCATENATED = SERVICE_7040 + FAILED_LOGON_4625

# Resource-Exhaustion-Resolver 1015 uses <Event> as an element NAME inside its
# payload, which a non-greedy </Event> match cuts short.
NESTED_EVENT_ELEMENT_1015 = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System><Provider Name='Microsoft-Windows-Resource-Exhaustion-Resolver'/>"
    "<EventID>1015</EventID><Level>4</Level>"
    "<TimeCreated SystemTime='2026-05-09T12:00:00.000000Z'/>"
    "<EventRecordID>77</EventRecordID>"
    "<Channel>Microsoft-Windows-Resource-Exhaustion-Resolver/Operational"
    "</Channel><Computer>WORKSTATION1</Computer>"
    "</System>"
    "<UserData>"
    "<ResolverInfo xmlns='http://manifests.microsoft.com/win/2004/08/"
    "windows/resolver'>"
    "<EventInfo><Event>4</Event></EventInfo>"
    "</ResolverInfo>"
    "</UserData></Event>"
)

# A literal newline inside a Data value, as real command lines and messages
# carry. Protects split_events against any single-line-only matching.
MULTILINE_DATA = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System><Provider Name='Application Error'/>"
    "<EventID>1000</EventID><Level>2</Level>"
    "<TimeCreated SystemTime='2026-05-09T13:00:00.000000Z'/>"
    "<EventRecordID>88</EventRecordID>"
    "<Channel>Application</Channel><Computer>WORKSTATION1</Computer>"
    "</System>"
    "<EventData>"
    "<Data Name='Message'>line one\nline two\nline three</Data>"
    "</EventData></Event>"
)
