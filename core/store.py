#!/usr/bin/env python3
"""
Event Store
===========
SQLite is the pipeline spine. Ingestion writes normalized events here;
detection, correlation, investigation and timeline all read back from here.
Storing events is not optional — investigation and timeline are pure queries
over history — so the store is the design centre rather than a side effect.
"""

import sqlite3
from pathlib import Path

from core.timeutil import to_local_naive
from ingestion.normalizer import NormalizedEvent

DEFAULT_DB_PATH = Path("db/siem_lite.db")

EVENT_COLUMNS = (
    "timestamp", "source_type", "host", "channel", "event_id", "record_id",
    "action", "severity_hint", "user", "target_user", "source_ip", "dest_ip",
    "dest_port", "logon_type", "status", "workstation", "process", "process_id",
    "parent_process", "command_line", "object_name", "service_name", "detail",
    "raw", "metadata", "event_hash",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      DATETIME NOT NULL,
    source_type    TEXT NOT NULL,
    host           TEXT NOT NULL,
    channel        TEXT NOT NULL,
    event_id       INTEGER NOT NULL,
    record_id      INTEGER NOT NULL,
    action         TEXT NOT NULL,
    severity_hint  TEXT,
    user           TEXT,
    target_user    TEXT,
    source_ip      TEXT,
    dest_ip        TEXT,
    dest_port      INTEGER DEFAULT 0,
    logon_type     INTEGER,
    status         TEXT DEFAULT '-',
    workstation    TEXT DEFAULT '-',
    process        TEXT,
    process_id     INTEGER,
    parent_process TEXT,
    command_line   TEXT,
    object_name    TEXT,
    service_name   TEXT,
    detail         TEXT,
    raw            TEXT,
    metadata       TEXT,
    event_hash     TEXT NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_user      ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_target    ON events(target_user);
CREATE INDEX IF NOT EXISTS idx_events_host      ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_event_id  ON events(event_id);
CREATE INDEX IF NOT EXISTS idx_events_channel   ON events(channel);

CREATE TABLE IF NOT EXISTS incidents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    opened_at     DATETIME NOT NULL,
    last_seen     DATETIME NOT NULL,
    entity_type   TEXT NOT NULL,
    entity_value  TEXT NOT NULL,
    severity      TEXT NOT NULL,
    score         INTEGER DEFAULT 0,
    tactics       TEXT DEFAULT '[]',
    status        TEXT DEFAULT 'OPEN',
    title         TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_entity ON incidents(entity_value, status);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

CREATE TABLE IF NOT EXISTS bookmarks (
    channel        TEXT PRIMARY KEY,
    last_record_id INTEGER NOT NULL DEFAULT 0,
    last_run       DATETIME
);

CREATE TABLE IF NOT EXISTS response_actions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  INTEGER NOT NULL,
    playbook_id  TEXT NOT NULL,
    action_name  TEXT NOT NULL,
    command      TEXT NOT NULL,
    undo_command TEXT,
    executed_at  DATETIME,
    exit_code    INTEGER,
    operator     TEXT
);

CREATE INDEX IF NOT EXISTS idx_response_incident ON response_actions(incident_id);

-- `alerts` predates this store but is owned here, because core.database's
-- init_database() is only reached from the legacy --scan/--analyze path: a
-- store created by `siem db init` or `--db demo.db` would otherwise have no
-- table to write an alert to. core.database calls init_schema, so defining it
-- once here covers both entry points.
CREATE TABLE IF NOT EXISTS alerts (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp            DATETIME DEFAULT CURRENT_TIMESTAMP,
    category             TEXT NOT NULL,
    severity             TEXT NOT NULL,
    detail               TEXT NOT NULL,
    evidence             TEXT,
    source               TEXT NOT NULL,
    related_ip           TEXT,
    related_url          TEXT,
    resolved             BOOLEAN DEFAULT 0,
    mitre_technique_id   TEXT,
    mitre_technique_name TEXT,
    mitre_tactic         TEXT,
    mitre_tactic_id      TEXT,
    mitre_url            TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_category  ON alerts(category);
CREATE INDEX IF NOT EXISTS idx_alerts_source    ON alerts(source);
"""

# Columns added to the `alerts` table above. SQLite has no
# "ADD COLUMN IF NOT EXISTS", so each is checked against PRAGMA table_info first.
ALERT_COLUMNS = (
    ("rule_id", "TEXT"),
    ("rule_title", "TEXT"),
    ("entity_type", "TEXT"),
    ("entity_value", "TEXT"),
    ("event_ids", "TEXT"),
    ("incident_id", "INTEGER"),
    ("status", "TEXT DEFAULT 'NEW'"),
)


# Columns added to `events` after Plan 1 shipped it. Same mechanism as above.
# The constant DEFAULT backfills pre-existing rows to the dataclass defaults
# ("-" / 0), so a rule can never read None; SCHEMA repeats it so a fresh table
# matches a migrated one.
# No `if present:` guard: `events` is always in SCHEMA, so table_info is never
# empty here.
EVENT_MIGRATION_COLUMNS = (
    ("status", "TEXT DEFAULT '-'"),
    ("workstation", "TEXT DEFAULT '-'"),
    ("dest_port", "INTEGER DEFAULT 0"),
)


def connect(db_path=None):
    """Open a WAL-mode connection with row access by column name."""
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_schema(conn):
    """Create the pipeline tables. Safe to run repeatedly."""
    conn.executescript(SCHEMA)

    for table, columns in (("events", EVENT_MIGRATION_COLUMNS),
                           ("alerts", ALERT_COLUMNS)):
        present = {r["name"] for r in conn.execute(
            "PRAGMA table_info({})".format(table))}
        for name, decl in columns:
            if name not in present:
                conn.execute("ALTER TABLE {} ADD COLUMN {} {}".format(
                    table, name, decl))
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id)"
    )
    conn.commit()


# ON CONFLICT(event_hash) ignores only duplicates; any other constraint
# violation (e.g. NOT NULL) raises sqlite3.IntegrityError instead of vanishing.
_INSERT_SQL = (
    "INSERT INTO events ({}) VALUES ({}) ON CONFLICT(event_hash) DO NOTHING".format(
        ", ".join('"{}"'.format(c) for c in EVENT_COLUMNS),
        ", ".join("?" for _ in EVENT_COLUMNS),
    )
)


def insert_events(conn, events, batch_size=500):
    """Insert normalized events, skipping any already stored.

    Returns the number of rows actually written. Duplicates (same event_hash)
    are skipped silently.

    Transaction semantics (sqlite3's `with conn:` does not nest):
    - Each batch is its own transaction. Committing a batch also commits any
      uncommitted work the caller already had open on this connection.
    - If a batch raises, that batch is rolled back, and so are the good events
      sharing it with a bad one. sqlite3.IntegrityError (constraint violation)
      is the common case; any exception during the flush behaves the same.
      Earlier batches stay committed.
    - The caller's uncommitted work is lost only if the failure comes before
      any batch has committed. Once one has, that work was committed with it.
    - The inserted count is lost when it raises.
    - Re-running is idempotent (dedup) and resolves transient failures. But a
      malformed event raises on every attempt and takes its whole batch down
      with it, so fix or quarantine it rather than retrying.

    There is no `commit` flag. A caller that advances a bookmark after a
    successful insert can safely re-run. A caller needing atomicity across
    insert and bookmark should add the flag then.
    """
    batch_size = max(1, int(batch_size))
    inserted = 0
    batch = []

    for event in events:
        row = event.to_row()
        batch.append(tuple(row[c] for c in EVENT_COLUMNS))
        if len(batch) >= batch_size:
            inserted += _flush(conn, batch)
            batch = []

    if batch:
        inserted += _flush(conn, batch)

    return inserted


def _flush(conn, batch):
    """Write one batch in a single transaction; return rows inserted."""
    with conn:
        return conn.executemany(_INSERT_SQL, batch).rowcount


def count_events(conn):
    """Total events stored."""
    return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def stats(conn):
    """Summary counts for `siem db stats`.

    `by_event_id` is the top 25 only, so its values may sum to less than `total`.
    """
    total = count_events(conn)

    by_channel = {
        r["channel"]: r["n"]
        for r in conn.execute(
            "SELECT channel, COUNT(*) AS n FROM events GROUP BY channel "
            "ORDER BY n DESC"
        )
    }
    by_event_id = {
        r["event_id"]: r["n"]
        for r in conn.execute(
            "SELECT event_id, COUNT(*) AS n FROM events GROUP BY event_id "
            "ORDER BY n DESC LIMIT 25"
        )
    }

    span = conn.execute(
        "SELECT MIN(timestamp) AS earliest, MAX(timestamp) AS latest FROM events"
    ).fetchone()

    return {
        "total": total,
        "by_channel": by_channel,
        "by_event_id": by_event_id,
        "earliest": span["earliest"],
        "latest": span["latest"],
    }


# `order` is the one query input that goes into the SQL text, so it is mapped
# through this allow-list; anything unrecognised raises.
_ORDER = {"asc": "ASC", "desc": "DESC"}


def query_events(conn, since=None, until=None, source_ip=None, user=None,
                 host=None, event_id=None, channel=None, action=None,
                 limit=1000, order="asc"):
    """Fetch stored events matching the given filters.

    `user` deliberately matches either side of an action — an analyst asking
    about an account wants both the logons it performed and the logons
    attempted against it.

    `since`/`until` go through to_local_naive, the same single conversion point
    the write side uses. Stored timestamps are local naive and SQLite compares
    them as text, so an aware bound stringified with its '+HH:MM' suffix would
    be compared character by character and quietly select the wrong rows.

    `limit` defaults to 1000 to protect interactive output. `limit=None` emits
    no LIMIT clause: a batch reader that must see a whole window has to pass it
    explicitly or it silently works on the newest 1000 rows only. A negative
    limit reaches SQLite as-is, where -1 also means no limit.
    """
    clauses = []
    params = []

    if since is not None:
        clauses.append("timestamp >= ?")
        params.append(to_local_naive(since).isoformat(sep=" "))
    if until is not None:
        clauses.append("timestamp <= ?")
        params.append(to_local_naive(until).isoformat(sep=" "))
    if user is not None:
        clauses.append('("user" = ? OR target_user = ?)')
        params.extend([user, user])
    # `is not None`, not truthiness: event_id=0 marks a malformed record and
    # must match only those, not everything.
    for col, val in (("source_ip", source_ip), ("host", host),
                     ("event_id", event_id), ("channel", channel),
                     ("action", action)):
        if val is not None:
            clauses.append(col + " = ?")
            params.append(val)

    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    try:
        direction = _ORDER[str(order).lower()]
    except KeyError:
        raise ValueError("order must be 'asc' or 'desc', got {!r}".format(order))

    sql = "SELECT * FROM events{} ORDER BY timestamp {}, id {}".format(
        where, direction, direction
    )
    if limit is not None:
        sql += " LIMIT ?"
        params.append(int(limit))

    return [NormalizedEvent.from_row(r) for r in conn.execute(sql, params)]


def get_bookmark(conn, channel):
    """Last consumed EventRecordID for a channel, 0 if never read."""
    row = conn.execute(
        "SELECT last_record_id FROM bookmarks WHERE channel = ?", (channel,)
    ).fetchone()
    return row["last_record_id"] if row else 0


def set_bookmark(conn, channel, record_id):
    """Record the resume point for a channel."""
    with conn:
        conn.execute(
            "INSERT INTO bookmarks (channel, last_record_id, last_run) "
            "VALUES (?, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(channel) DO UPDATE SET "
            "last_record_id = excluded.last_record_id, "
            "last_run = excluded.last_run",
            (channel, int(record_id)),
        )
