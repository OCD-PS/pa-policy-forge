from __future__ import annotations

from contextlib import contextmanager
from io import BytesIO
import json
import sqlite3

from cryptography.fernet import Fernet
from flask import Flask
from PIL import Image

from app.bug_reports import MAX_TOTAL_REPORTS, create_bug_reports_blueprint, prune_bug_reports


def make_png() -> bytes:
    image = Image.new("RGB", (1, 1), color="orange")
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def test_prune_keeps_only_the_newest_100_reports(tmp_path):
    database_path = tmp_path / "reports.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "CREATE TABLE bug_reports (id INTEGER PRIMARY KEY, created_at TEXT, screenshot_blob BLOB)"
        )
        connection.executemany(
            "INSERT INTO bug_reports(id,created_at,screenshot_blob) VALUES(?,?,?)",
            ((report_id, f"2026-10-01 00:00:{report_id:02}", b"png") for report_id in range(1, 106)),
        )

    @contextmanager
    def db():
        connection = sqlite3.connect(database_path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    with db() as connection:
        assert prune_bug_reports(connection) == 5
        remaining = [row[0] for row in connection.execute("SELECT id FROM bug_reports ORDER BY id")]

    assert len(remaining) == MAX_TOTAL_REPORTS
    assert remaining == list(range(6, 106))


def test_new_submission_replaces_oldest_report_at_limit(tmp_path):
    database_path = tmp_path / "reports.sqlite3"
    fernet = Fernet(Fernet.generate_key())
    screenshot = fernet.encrypt(make_png())
    private_data = fernet.encrypt(json.dumps({"email": "old@example.test", "description": "old", "page_path": "/"}).encode())
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "CREATE TABLE bug_reports (id INTEGER PRIMARY KEY, reporter_user_id INTEGER NOT NULL, "
            "secret_blob BLOB NOT NULL, screenshot_blob BLOB, status TEXT NOT NULL, "
            "created_at TEXT NOT NULL, updated_at TEXT NOT NULL, notified_at TEXT NOT NULL DEFAULT '')"
        )
        connection.executemany(
            "INSERT INTO bug_reports(id,reporter_user_id,secret_blob,screenshot_blob,status,created_at,updated_at) "
            "VALUES(?,?,?,?,'new',?,?)",
            (
                (report_id, report_id, private_data, screenshot, f"2026-10-28 10:{report_id // 60:02}:{report_id % 60:02}", "2026-10-28 10:00:00")
                for report_id in range(1, MAX_TOTAL_REPORTS + 1)
            ),
        )

    @contextmanager
    def db():
        connection = sqlite3.connect(database_path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    audits = []
    app = Flask(__name__)
    app.secret_key = "test-only-session-key"
    app.register_blueprint(
        create_bug_reports_blueprint(
            db,
            fernet,
            lambda: "2026-10-28 15:00:00",
            lambda action, detail="", username=None: audits.append((action, detail)),
        )
    )
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = 1001

    response = client.post(
        "/bug-reports",
        data={
            "email": "reporter@example.test",
            "description": "new test report",
            "page_path": "/test",
            "screenshot": (BytesIO(make_png()), "report.png"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 201
    assert response.json["id"] == MAX_TOTAL_REPORTS + 1
    with db() as connection:
        ids = [row[0] for row in connection.execute("SELECT id FROM bug_reports ORDER BY id")]
    assert len(ids) == MAX_TOTAL_REPORTS
    assert ids == list(range(2, MAX_TOTAL_REPORTS + 2))
    assert ("bug-report-submitted", "report_id=101 pruned=1") in audits
