#!/usr/bin/env python3
"""
siem mitre
==========
Where an incident sits on the kill chain (`--incident N`), and which
techniques the incidents in a range used (`--matrix`).

Read-only. Tactic names come from `tactic_name()` over `TACTIC_NAMES`, not from
`MITRE_MAPPINGS`: that dict is keyed by alert category and has duplicate keys,
so a tactic may be missing from it.
"""

import json
import re
from collections import Counter

from cli.render import clip, incident_dict, no_incident, plain, print_table, tactic_ids
from core import store
from core.report import print_info, print_section
from core.timeutil import parse_since
from modules.mitre_mapping import tactic_name

NAME = "mitre"

# The ATT&CK matrix's order, which is the order an attack runs in, and NOT
# TACTIC_NAMES' (by id): it starts at Reconnaissance (TA0043) as spec section 9
# shows, Command and Control (TA0011) comes before Exfiltration (TA0010), and
# Impact (TA0040) is last. Ruling R103 added the three ids that were missing.
KILL_CHAIN = ("TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
              "TA0006", "TA0007", "TA0008", "TA0009", "TA0011", "TA0010", "TA0040")

SEPARATOR = " · "
# The strip's own syntax, neutralised in a stage name so stored text cannot
# forge a stage: brackets mark a hit chain stage, braces an off-chain extra.
SYNTAX = re.compile(r"[\[\]{}·]")
# Ruling R110: 76, which leaves room for the two-space indent the strip is
# printed under inside an 80-column terminal.
WIDTH = 76


def add_parser(subparsers):
    """Register the `mitre` subcommand."""
    parser = subparsers.add_parser(NAME, help="kill-chain coverage and technique counts")
    # Store filters (see cli/__init__.py): None, never 0 or "".
    parser.add_argument("--incident", type=int, default=None,
                        help="the kill chain with this incident's tactics marked")
    parser.add_argument("--matrix", action="store_true",
                        help="technique counts across all incidents in the range")
    parser.add_argument("--since", default=None,
                        help="matrix only: incidents seen at or after this time: "
                             "30m, 24h, 7d or an ISO time (default: all)")
    parser.set_defaults(func=run)
    return parser


def stages(ids):
    """The kill chain as [{"tactic", "name", "hit", "extra"}], in chain order.

    A tactic the chain does not know is not dropped: it follows the chain,
    marked, under its own id (tactic_name returns an unknown id unchanged),
    in the order the incident lists them, and `extra` is True so it cannot be
    read as a chain stage. A stored tactic value of "Execution" would otherwise
    print a second, identical [Execution].
    """
    hit = set(ids)
    extras = [t for t in dict.fromkeys(ids) if t not in KILL_CHAIN]
    return [{"tactic": t, "name": tactic_name(t), "hit": t in hit,
             "extra": t in extras} for t in KILL_CHAIN + tuple(extras)]


def strip_lines(stage_list, width=WIDTH):
    """The strip as lines of at most `width`: stages joined by " . ", a hit
    chain stage in [brackets], an off-chain extra in {braces}.

    Wrapped at the SEPARATOR only, so no stage name is ever split (ruling
    R110): the 14 stages are 235 characters, and a mid-name break destroys the
    left-to-right scan the strip exists for. `SEPARATOR.join(...)` of the
    result is the whole strip back; a stage wider than `width` takes a line of
    its own rather than being broken.

    An extra's name is stored text of any length (an unknown tactic id), and a
    stage has to fit a line, so it is clipped; brackets, braces and the
    separator are what the strip is made of, so they are neutralised too: a
    tactic of "x] . [Discovery" must not read as a second, marked stage.
    """
    lines = []
    for stage in stage_list:
        text = ("{{{}}}" if stage["extra"] else "[{}]" if stage["hit"] else "{}").format(
            clip(SYNTAX.sub("?", plain(stage["name"]))))
        if lines and len(lines[-1]) + len(SEPARATOR) + len(text) <= width:
            lines[-1] += SEPARATOR + text
        else:
            lines.append(text)
    return lines


def matrix(conn, since):
    """Technique counts over the incidents last seen at or after `since`.

    Returns {"incidents": n, "techniques": [{"technique", "tactic",
    "tactic_name", "incidents", "alerts"}]}, busiest first. One row per
    (technique, tactic): a technique can sit under two tactics. `incidents`
    counts distinct incidents and `alerts` their member alerts, so a rule firing
    fifty times is one incident's worth. An alert in no incident is not counted.
    """
    incidents = {r["id"] for r in store.query_incidents(conn, since=since, limit=None)}
    alerts, seen = Counter(), {}
    for a in store.query_alerts(conn, limit=None):
        if a["incident_id"] in incidents:
            key = (a["mitre_technique_id"], a["mitre_tactic_id"])
            alerts[key] += 1
            seen.setdefault(key, set()).add(a["incident_id"])
    rows = [{"technique": t or "-", "tactic": k, "tactic_name": tactic_name(k) if k else None,
             "incidents": len(seen[(t, k)]), "alerts": n} for (t, k), n in alerts.items()]
    rows.sort(key=lambda r: (-r["incidents"], -r["alerts"], r["technique"], str(r["tactic"])))
    return {"incidents": len(incidents), "techniques": rows}


def run(args):
    """Print the strip or the matrix. Returns a process exit code: 0, or 1 for
    an incident that does not exist. A bad argument is 2, from dispatch."""
    if (args.incident is None) == (not args.matrix):
        raise ValueError("give exactly one of --incident, --matrix")
    if args.incident is not None and args.since is not None:
        raise ValueError("--since goes with --matrix only")
    since = None if args.since is None else parse_since(args.since)

    conn = store.connect(args.db)
    try:
        store.init_schema(conn)
        if args.matrix:
            result = matrix(conn, since)
        else:
            found = store.query_incidents(conn, incident_id=args.incident)
            if not found:
                return no_incident(args, args.incident)
            incident = found[0]
    finally:
        conn.close()

    if args.matrix:
        return _print_matrix(args, result)
    chain = stages(tactic_ids(incident))
    if args.json:
        print(json.dumps({"incident": incident_dict(incident), "stages": chain},
                         indent=2, default=str))
        return 0
    print_section("Kill chain for incident {}".format(incident["id"]))
    print_info("{} {}: {}".format(plain(incident["entity_type"]),
                                  plain(incident["entity_value"]),
                                  plain(incident["title"] or "-")))
    for line in strip_lines(chain):
        print("  " + line)
    return 0


def _print_matrix(args, result):
    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0
    if not result["incidents"]:
        print_info("0 incidents in range")
        return 0
    print_section("Technique matrix ({} incident(s))".format(result["incidents"]))
    if not result["techniques"]:
        print_info("No technique recorded on any alert of those incidents")
        return 0
    print_table(("TECHNIQUE", "TACTIC", "INCIDENTS", "ALERTS"), [
        (plain(r["technique"]), plain(r["tactic_name"] or "-"), str(r["incidents"]),
         str(r["alerts"])) for r in result["techniques"]])
    return 0
