"""Private bug intake, SMTP settings, and status notifications."""

from __future__ import annotations

from email.message import EmailMessage
from email.utils import parseaddr
from io import BytesIO
import json
import os
import re
import smtplib
import ssl

from flask import (
    Blueprint, Response, abort, current_app, flash, redirect, render_template,
    request, session, url_for,
)
from PIL import Image, UnidentifiedImageError

MAX_SCREENSHOT_BYTES = 2 * 1024 * 1024
MAX_TOTAL_REPORTS = 1000
MAX_SCREENSHOT_STORAGE_BYTES = 256 * 1024 * 1024
SMTP_TIMEOUT_SECONDS = 12
SMTP_PORTS = {25, 465, 587, 2525}
VALID_STATUSES = {"new", "triaged", "in_progress", "fixed_deployed", "closed"}
EMAIL_RE = re.compile(r"^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$")
SMTP_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def create_bug_reports_blueprint(db, fernet, now, audit):
    bp = Blueprint("bug_reports", __name__)
    allowed_smtp_hosts = {
        host.strip().casefold()
        for host in os.getenv("PPF_SMTP_ALLOWED_HOSTS", "").split(",")
        if host.strip()
    }

    def smtp_host_allowed(host):
        return str(host or "").strip().casefold() in allowed_smtp_hosts

    def admin_required():
        user_id = session.get("user_id")
        if not user_id:
            abort(401)
        with db() as conn:
            row = conn.execute("SELECT is_admin FROM users WHERE id=?", (user_id,)).fetchone()
        if not row or not row["is_admin"]:
            abort(403)

    def valid_email(value: str) -> bool:
        value = str(value or "").strip()
        parsed_name, parsed_address = parseaddr(value)
        return not parsed_name and parsed_address == value and bool(EMAIL_RE.fullmatch(value)) and len(value) <= 254

    def mail_configuration():
        with db() as conn:
            row = conn.execute(
                "SELECT settings_json,secret_blob FROM system_settings WHERE setting_key='bug_reporting'"
            ).fetchone()
        settings = json.loads(row["settings_json"] or "{}") if row else {}
        secrets = json.loads(fernet.decrypt(row["secret_blob"]).decode()) if row and row["secret_blob"] else {}
        return settings, secrets

    def send_mail(settings, secrets, message):
        host = str(settings.get("host") or "").strip()
        port = int(settings.get("port") or 0)
        mode = settings.get("encryption")
        if (
            not SMTP_HOST_RE.fullmatch(host) or not _valid_smtp_host_labels(host)
            or not smtp_host_allowed(host) or port not in SMTP_PORTS
            or mode not in {"starttls", "tls"}
        ):
            raise ValueError("Mailrelay is niet volledig ingesteld.")
        context = ssl.create_default_context()
        if mode == "tls":
            with smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT_SECONDS, context=context) as smtp:
                smtp.ehlo()
                if settings.get("username"):
                    smtp.login(settings["username"], secrets.get("password", ""))
                smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT_SECONDS) as smtp:
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
                if settings.get("username"):
                    smtp.login(settings["username"], secrets.get("password", ""))
                smtp.send_message(message)

    def notification_message(settings, recipient, subject, text):
        sender = str(settings.get("sender") or "").strip()
        if not valid_email(sender) or not valid_email(recipient):
            raise ValueError("Afzender of ontvanger is ongeldig.")
        message = EmailMessage()
        message["From"] = sender
        message["To"] = recipient
        message["Subject"] = subject
        message.set_content(text)
        return message

    def _valid_smtp_host_labels(host):
        return all(
            label and len(label) <= 63 and not label.startswith("-") and not label.endswith("-")
            for label in host.split(".")
        )

    @bp.get("/admin")
    def admin():
        admin_required()
        settings, secret_values = mail_configuration()
        settings.setdefault("port", 587)
        settings.setdefault("encryption", "starttls")
        settings.setdefault("sender", "steven@vispoel.com")
        settings["password_configured"] = bool(secret_values.get("password"))
        settings["host_allowed"] = smtp_host_allowed(settings.get("host"))
        with db() as conn:
            reports = conn.execute(
                "SELECT id,secret_blob,(screenshot_blob IS NOT NULL) AS has_screenshot,"
                "status,created_at,updated_at,notified_at "
                "FROM bug_reports ORDER BY id DESC LIMIT 200"
            ).fetchall()
        report_views = []
        for report in reports:
            data = json.loads(fernet.decrypt(report["secret_blob"]).decode())
            report_views.append({
                "id": report["id"], "reporter_email": data["email"],
                "description": data["description"], "page_path": data["page_path"],
                "status": report["status"], "created_at": report["created_at"],
                "updated_at": report["updated_at"], "notified_at": report["notified_at"],
                "has_screenshot": bool(report["has_screenshot"]),
            })
        return render_template("admin.html", mail=settings, reports=report_views)

    @bp.post("/admin/mail")
    def save_mail_settings():
        admin_required()
        host = request.form.get("host", "").strip()
        username = request.form.get("username", "").strip()
        sender = request.form.get("sender", "").strip()
        recipient = request.form.get("test_recipient", "").strip()
        encryption = request.form.get("encryption", "")
        try:
            port = int(request.form.get("port", ""))
        except ValueError:
            port = 0
        password = request.form.get("password", "")
        if (
            not host or len(host) > 253 or any(char in host for char in "\r\n/\\")
            or port not in SMTP_PORTS or encryption not in {"starttls", "tls"}
            or not valid_email(sender) or not valid_email(recipient)
            or len(username) > 254 or len(password) > 2048
        ):
            flash("Controleer host, poort, TLS-keuze en e-mailadressen.", "error")
            return redirect(url_for("bug_reports.admin"))
        settings = {
            "host": host, "port": port, "encryption": encryption,
            "username": username, "sender": sender, "test_recipient": recipient,
        }
        with db() as conn:
            existing = conn.execute(
                "SELECT secret_blob FROM system_settings WHERE setting_key='bug_reporting'"
            ).fetchone()
            old_secrets = json.loads(fernet.decrypt(existing["secret_blob"]).decode()) if existing and existing["secret_blob"] else {}
            if request.form.get("clear_password") == "yes":
                old_secrets.pop("password", None)
            if password:
                old_secrets["password"] = password
            blob = fernet.encrypt(json.dumps(old_secrets).encode()) if old_secrets else b""
            conn.execute(
                "INSERT INTO system_settings(setting_key,settings_json,secret_blob,updated_at) VALUES('bug_reporting',?,?,?) "
                "ON CONFLICT(setting_key) DO UPDATE SET settings_json=excluded.settings_json,secret_blob=excluded.secret_blob,updated_at=excluded.updated_at",
                (json.dumps(settings), blob, now()),
            )
        audit("bug-report-mail-settings-saved", f"host={host} port={port} encryption={encryption}")
        flash("Mailrelay-instellingen opgeslagen.", "success")
        return redirect(url_for("bug_reports.admin"))

    @bp.post("/admin/mail/test")
    def test_mail():
        admin_required()
        settings, secrets = mail_configuration()
        recipient = settings.get("test_recipient", "")
        try:
            message = notification_message(
                settings, recipient, "PA Policy Forge mailrelaytest",
                "De ingestelde mailrelay kan berichten afleveren bij het vaste testadres.",
            )
            send_mail(settings, secrets, message)
        except Exception as exc:
            current_app.logger.warning("Bug-report mail test failed (%s)", type(exc).__name__)
            flash("Testmail mislukt. Controleer relay, poort, TLS en aanmeldgegevens.", "error")
        else:
            flash("Testmail verzonden naar het ingestelde testadres.", "success")
            audit("bug-report-mail-test-sent", "fixed test recipient")
        return redirect(url_for("bug_reports.admin"))

    @bp.post("/bug-reports")
    def submit():
        if not session.get("user_id"):
            abort(401)
        # Keep multipart parsing on this route close to the screenshot limit.
        request.max_content_length = MAX_SCREENSHOT_BYTES + 64 * 1024
        reporter_email = request.form.get("email", "").strip()
        description = request.form.get("description", "").strip()
        page_path = request.form.get("page_path", "").strip()
        upload = request.files.get("screenshot")
        screenshot = upload.read(MAX_SCREENSHOT_BYTES + 1) if upload else b""
        if not valid_email(reporter_email) or not description or len(description) > 5000:
            return {"error": "Vul een geldig e-mailadres en een beschrijving in."}, 400
        if not screenshot:
            return {"error": "De screenshot ontbreekt. Probeer de melding opnieuw te openen."}, 400
        if not page_path.startswith("/") or "?" in page_path or "#" in page_path or len(page_path) > 500:
            page_path = "/"
        if len(screenshot) > MAX_SCREENSHOT_BYTES:
            return {"error": "De screenshot is groter dan 2 MB."}, 413
        if screenshot and not (screenshot.startswith(b"\x89PNG\r\n\x1a\n") and len(screenshot) >= 24):
            return {"error": "De screenshot moet een geldige PNG zijn."}, 400
        if screenshot:
            try:
                with Image.open(BytesIO(screenshot)) as image:
                    width, height = image.size
                    if image.format != "PNG" or image.n_frames != 1:
                        return {"error": "Voeg een statische PNG-screenshot toe."}, 400
                    if not width or not height or width > 2400 or height > 1600 or width * height > 3_840_000:
                        return {"error": "De screenshotafmetingen zijn ongeldig."}, 400
                    image.verify()
                # verify() checks structure; load() also fully decodes pixel data.
                with Image.open(BytesIO(screenshot)) as image:
                    image.load()
            except (Image.DecompressionBombError, UnidentifiedImageError, OSError, ValueError):
                return {"error": "De screenshotafmetingen zijn ongeldig."}, 400
        timestamp = now()
        private_data = fernet.encrypt(json.dumps({
            "email": reporter_email, "description": description, "page_path": page_path,
            "user_agent": request.user_agent.string[:500],
        }).encode())
        encrypted_screenshot = fernet.encrypt(screenshot)
        with db() as conn:
            # Serialize quota checks and inserts so concurrent uploads cannot pass
            # the global storage limit at the same time.
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM bug_reports WHERE created_at<strftime('%Y-%m-%d %H:%M:%S','now','-180 days')")
            recent = conn.execute(
                "SELECT COUNT(*) FROM bug_reports WHERE reporter_user_id=? AND created_at>=strftime('%Y-%m-%d %H:%M:%S','now','-1 hour')",
                (session["user_id"],),
            ).fetchone()[0]
            if recent >= 5:
                return {"error": "Er zijn te veel meldingen verstuurd. Probeer het later opnieuw."}, 429
            usage = conn.execute(
                "SELECT COUNT(*),COALESCE(SUM(length(screenshot_blob)),0) FROM bug_reports"
            ).fetchone()
            if usage[0] >= MAX_TOTAL_REPORTS or usage[1] + len(encrypted_screenshot) > MAX_SCREENSHOT_STORAGE_BYTES:
                return {"error": "De meldingenwachtrij heeft haar opslaglimiet bereikt. Probeer later opnieuw."}, 507
            cursor = conn.execute(
                "INSERT INTO bug_reports(reporter_user_id,secret_blob,screenshot_blob,status,created_at,updated_at) "
                "VALUES(?,?,?,'new',?,?)",
                (session["user_id"], private_data, encrypted_screenshot, timestamp, timestamp),
            )
            report_id = int(cursor.lastrowid)
        audit("bug-report-submitted", f"report_id={report_id}")
        return {"id": report_id, "message": "Bedankt. Je melding staat veilig in de reviewwachtrij."}, 201

    @bp.post("/admin/bug-reports/<int:report_id>/delete")
    def delete_report(report_id):
        admin_required()
        with db() as conn:
            cursor = conn.execute(
                "DELETE FROM bug_reports WHERE id=? AND status='closed'", (report_id,)
            )
            if cursor.rowcount != 1:
                abort(404)
        audit("bug-report-deleted", f"report_id={report_id}")
        flash("Gesloten melding verwijderd.", "success")
        return redirect(url_for("bug_reports.admin") + "#reports")

    @bp.get("/admin/bug-reports/<int:report_id>/screenshot")
    def screenshot(report_id):
        admin_required()
        with db() as conn:
            row = conn.execute("SELECT screenshot_blob FROM bug_reports WHERE id=?", (report_id,)).fetchone()
        if not row or not row["screenshot_blob"]:
            abort(404)
        response = Response(fernet.decrypt(row["screenshot_blob"]), mimetype="image/png")
        response.headers["Content-Disposition"] = "inline; filename=bug-report.png"
        response.headers["Cache-Control"] = "private, no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @bp.post("/admin/bug-reports/<int:report_id>/status")
    def update_status(report_id):
        admin_required()
        status = request.form.get("status", "")
        if status not in VALID_STATUSES:
            abort(400)
        timestamp = now()
        with db() as conn:
            report = conn.execute("SELECT * FROM bug_reports WHERE id=?", (report_id,)).fetchone()
            if not report:
                abort(404)
            conn.execute("UPDATE bug_reports SET status=?,updated_at=? WHERE id=?", (status, timestamp, report_id))
        if status == "fixed_deployed" and not report["notified_at"]:
            report_data = json.loads(fernet.decrypt(report["secret_blob"]).decode())
            settings, secrets = mail_configuration()
            try:
                message = notification_message(
                    settings, report_data["email"],
                    f"PA Policy Forge: melding #{report_id} mogelijk opgelost",
                    "We hebben een mogelijke oplossing voor je melding uitgerold.\n\n"
                    "Wil je het gemelde scenario opnieuw testen? Is het probleem niet opgelost, meld het dan opnieuw via de bugknop in Policy Forge.",
                )
                send_mail(settings, secrets, message)
            except Exception as exc:
                current_app.logger.warning("Bug-report resolution mail failed (%s)", type(exc).__name__)
                flash("Status bijgewerkt, maar de e-mail kon niet worden verzonden.", "error")
            else:
                with db() as conn:
                    conn.execute("UPDATE bug_reports SET notified_at=?,updated_at=? WHERE id=?", (timestamp, timestamp, report_id))
                flash("Status bijgewerkt en tester geïnformeerd.", "success")
        else:
            flash("Status bijgewerkt.", "success")
        audit("bug-report-status-updated", f"report_id={report_id} status={status}")
        return redirect(url_for("bug_reports.admin") + "#reports")

    return bp
