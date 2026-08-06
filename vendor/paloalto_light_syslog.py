#!/usr/bin/env python3
"""Lightweight PAN-OS allow-log collector.

The collector receives PAN-OS traffic syslog over UDP, keeps only allow traffic,
aggregates flows in SQLite, and exposes a small HTTP API for health, stats, and
CSV export.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import signal
import socketserver
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, urlparse


LOGGER = logging.getLogger("paloalto-light-syslog")

PANOS_TRAFFIC_INDEX = {
    "receive_time": 1,
    "serial": 2,
    "type": 3,
    "subtype": 4,
    "src": 7,
    "dst": 8,
    "rule": 11,
    "src_user": 12,
    "dst_user": 13,
    "app": 14,
    "src_zone": 16,
    "dst_zone": 17,
    "repeat": 23,
    "dport": 25,
    "proto": 29,
    "action": 30,
    "bytes": 31,
    "url_category": 47,
}

CSV_START_RE = re.compile(
    r"(?:^|\s)(\d+,\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2},.*)$"
)

EXPORT_FIELDS = [
    "first_seen",
    "last_seen",
    "repeat",
    "bytes",
    "serial",
    "src",
    "dst",
    "src_zone",
    "dst_zone",
    "src_user",
    "app",
    "proto",
    "dport",
    "action",
    "rule",
    "url_category",
]


def env_int(name: str, default: int) -> int:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        LOGGER.warning("Invalid integer for %s=%r, using %s", name, value, default)
        return default


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def sqlite_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def panos_time(value: str) -> str:
    value = value.strip()
    if not value:
        return sqlite_time(now_utc())
    try:
        parsed = datetime.strptime(value, "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return sqlite_time(parsed)
    except ValueError:
        return value


def clean(value: str, default: str = "") -> str:
    value = (value or "").strip().strip('"').strip("'")
    if not value or value.lower() in {"n/a", "none", "null", "(empty)"}:
        return default
    return value


def parse_int(value: str, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def field(fields: list[str], name: str, default: str = "") -> str:
    index = PANOS_TRAFFIC_INDEX[name]
    if index >= len(fields):
        return default
    return clean(fields[index], default)


@dataclass(frozen=True)
class Flow:
    receive_time: str
    serial: str
    src: str
    dst: str
    src_zone: str
    dst_zone: str
    src_user: str
    app: str
    proto: str
    dport: str
    action: str
    rule: str
    url_category: str
    repeat: int
    bytes_total: int


def extract_panos_csv(line: str) -> str | None:
    line = line.strip()
    if not line:
        return None
    match = CSV_START_RE.search(line)
    if match:
        return match.group(1)
    return None


def parse_panos_syslog(line: str) -> Flow | None:
    payload = extract_panos_csv(line)
    if payload is None:
        return None
    try:
        fields = next(csv.reader([payload]))
    except csv.Error:
        LOGGER.debug("Dropped malformed CSV payload")
        return None
    if len(fields) <= PANOS_TRAFFIC_INDEX["action"]:
        return None
    if field(fields, "type").upper() != "TRAFFIC":
        return None
    action = field(fields, "action").lower()
    if action != "allow":
        return None

    src = field(fields, "src")
    dst = field(fields, "dst")
    src_zone = field(fields, "src_zone", "any")
    dst_zone = field(fields, "dst_zone", "any")
    app = field(fields, "app", "any")
    proto = field(fields, "proto", "tcp").lower()
    dport = field(fields, "dport", "application-default")
    if not src or not dst:
        return None

    return Flow(
        receive_time=panos_time(field(fields, "receive_time")),
        serial=field(fields, "serial"),
        src=src,
        dst=dst,
        src_zone=src_zone,
        dst_zone=dst_zone,
        src_user=field(fields, "src_user"),
        app=app,
        proto=proto,
        dport=dport,
        action=action,
        rule=field(fields, "rule"),
        url_category=field(fields, "url_category"),
        repeat=max(parse_int(field(fields, "repeat"), 1), 1),
        bytes_total=parse_int(field(fields, "bytes"), 0),
    )


class FlowStore:
    def __init__(self, db_path: Path, retention_days: int) -> None:
        self.db_path = db_path
        self.retention_days = retention_days
        self.lock = threading.Lock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connect().close()
        self.init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def init_schema(self) -> None:
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY,
                    serial TEXT NOT NULL DEFAULT '',
                    src TEXT NOT NULL,
                    dst TEXT NOT NULL,
                    src_zone TEXT NOT NULL,
                    dst_zone TEXT NOT NULL,
                    src_user TEXT NOT NULL DEFAULT '',
                    app TEXT NOT NULL,
                    proto TEXT NOT NULL,
                    dport TEXT NOT NULL,
                    action TEXT NOT NULL DEFAULT 'allow',
                    rule TEXT NOT NULL DEFAULT '',
                    url_category TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    repeat INTEGER NOT NULL DEFAULT 0,
                    bytes INTEGER NOT NULL DEFAULT 0,
                    UNIQUE (
                        serial, src, dst, src_zone, dst_zone, src_user,
                        app, proto, dport, action, rule, url_category
                    )
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(last_seen)")

    def add_flow(self, flow: Flow) -> None:
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO flows (
                    serial, src, dst, src_zone, dst_zone, src_user, app, proto,
                    dport, action, rule, url_category, first_seen, last_seen,
                    repeat, bytes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (
                    serial, src, dst, src_zone, dst_zone, src_user,
                    app, proto, dport, action, rule, url_category
                )
                DO UPDATE SET
                    first_seen = MIN(first_seen, excluded.first_seen),
                    last_seen = MAX(last_seen, excluded.last_seen),
                    repeat = repeat + excluded.repeat,
                    bytes = bytes + excluded.bytes
                """,
                (
                    flow.serial,
                    flow.src,
                    flow.dst,
                    flow.src_zone,
                    flow.dst_zone,
                    flow.src_user,
                    flow.app,
                    flow.proto,
                    flow.dport,
                    flow.action,
                    flow.rule,
                    flow.url_category,
                    flow.receive_time,
                    flow.receive_time,
                    flow.repeat,
                    flow.bytes_total,
                ),
            )

    def cleanup(self) -> int:
        if self.retention_days <= 0:
            return 0
        cutoff = sqlite_time(now_utc() - timedelta(days=self.retention_days))
        with self.lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM flows WHERE last_seen < ?", (cutoff,))
            return cursor.rowcount

    def purge(self, serial: str) -> int:
        """Remove all aggregated flows for one firewall serial."""
        if not serial.strip():
            raise ValueError("serial is required")
        with self.lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM flows WHERE serial = ?", (serial.strip(),))
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            return cursor.rowcount

    def stats(self) -> dict[str, object]:
        with self.lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS flow_count,
                    COALESCE(SUM(repeat), 0) AS total_sessions,
                    COALESCE(SUM(bytes), 0) AS total_bytes,
                    MIN(first_seen) AS first_seen,
                    MAX(last_seen) AS last_seen
                FROM flows
                """
            ).fetchone()
        return {
            "status": "ok",
            "db_path": str(self.db_path),
            "retention_days": self.retention_days,
            "flow_count": row["flow_count"],
            "total_sessions": row["total_sessions"],
            "total_bytes": row["total_bytes"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
        }

    def export_rows(
        self,
        since: str | None = None,
        until: str | None = None,
        min_sessions: int = 1,
    ) -> Iterable[sqlite3.Row]:
        where = ["repeat >= ?"]
        params: list[object] = [min_sessions]
        if since:
            where.append("last_seen >= ?")
            params.append(since)
        if until:
            where.append("first_seen <= ?")
            params.append(until)
        sql = f"""
            SELECT {", ".join(EXPORT_FIELDS)}
            FROM flows
            WHERE {" AND ".join(where)}
            ORDER BY src_zone, dst_zone, app, proto, dport, src, dst
        """
        with self.lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return rows

    def export_csv(self, since: str | None = None, until: str | None = None, min_sessions: int = 1) -> str:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=EXPORT_FIELDS, lineterminator="\n")
        writer.writeheader()
        for row in self.export_rows(since=since, until=until, min_sessions=min_sessions):
            writer.writerow({field_name: row[field_name] for field_name in EXPORT_FIELDS})
        return output.getvalue()


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    store: FlowStore

    def handle(self) -> None:
        data = self.request[0]
        try:
            line = data.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            return
        flow = parse_panos_syslog(line)
        if flow is None:
            return
        self.store.add_flow(flow)


def make_http_handler(store: FlowStore) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "PaloAltoLightSyslog/1.0"

        def log_message(self, fmt: str, *args: object) -> None:
            LOGGER.info("http %s - %s", self.address_string(), fmt % args)

        def write_json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
            body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/health":
                self.write_json(HTTPStatus.OK, {"status": "ok"})
                return
            if parsed.path == "/stats":
                self.write_json(HTTPStatus.OK, store.stats())
                return
            if parsed.path == "/export.csv":
                query = parse_qs(parsed.query)
                min_sessions = parse_int(query.get("min_sessions", ["1"])[0], 1)
                body = store.export_csv(
                    since=query.get("since", [None])[0],
                    until=query.get("until", [None])[0],
                    min_sessions=max(min_sessions, 1),
                ).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", "attachment; filename=paloalto-allow-flows.csv")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.write_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    return Handler


class CleanupThread(threading.Thread):
    def __init__(self, store: FlowStore, interval_seconds: int) -> None:
        super().__init__(daemon=True)
        self.store = store
        self.interval_seconds = interval_seconds
        self.stop_event = threading.Event()

    def run(self) -> None:
        while not self.stop_event.wait(self.interval_seconds):
            deleted = self.store.cleanup()
            if deleted:
                LOGGER.info("retention cleanup removed %s flows", deleted)

    def stop(self) -> None:
        self.stop_event.set()


def main() -> int:
    logging.basicConfig(
        level=os.getenv("PLS_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    syslog_host = os.getenv("PLS_SYSLOG_HOST", "0.0.0.0")
    syslog_port = env_int("PLS_SYSLOG_PORT", 5514)
    http_host = os.getenv("PLS_HTTP_HOST", "0.0.0.0")
    http_port = env_int("PLS_HTTP_PORT", 8080)
    db_path = Path(os.getenv("PLS_DB_PATH", "/data/flows.sqlite3"))
    retention_days = env_int("PLS_RETENTION_DAYS", 30)
    cleanup_interval = env_int("PLS_CLEANUP_INTERVAL_SECONDS", 300)

    store = FlowStore(db_path, retention_days)
    store.cleanup()

    SyslogUDPHandler.store = store
    udp_server = socketserver.ThreadingUDPServer((syslog_host, syslog_port), SyslogUDPHandler)
    http_server = ThreadingHTTPServer((http_host, http_port), make_http_handler(store))
    cleanup_thread = CleanupThread(store, cleanup_interval)

    shutdown = threading.Event()

    def handle_signal(signum: int, _frame: object) -> None:
        LOGGER.info("received signal %s, shutting down", signum)
        shutdown.set()
        udp_server.shutdown()
        http_server.shutdown()
        cleanup_thread.stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    threads = [
        threading.Thread(target=udp_server.serve_forever, daemon=True),
        threading.Thread(target=http_server.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    cleanup_thread.start()
    LOGGER.info("listening syslog udp=%s:%s http=%s:%s db=%s", syslog_host, syslog_port, http_host, http_port, db_path)

    while not shutdown.wait(1):
        pass

    udp_server.server_close()
    http_server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
