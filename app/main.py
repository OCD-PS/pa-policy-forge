from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import socketserver
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timezone
from functools import wraps

from cryptography.fernet import Fernet
from flask import Flask, Response, flash, has_request_context, redirect, render_template, request, send_file, session, url_for

from vendor.paloalto_light_syslog import FlowStore, parse_panos_syslog

BASE = Path(__file__).resolve().parent.parent
DATA = Path(os.getenv("PPF_DATA_DIR", "/data"))
APP_DB = DATA / "forge.sqlite3"
FLOW_DB = DATA / "flows.sqlite3"
RUNS = DATA / "runs"
SECRETS = DATA / "secrets"
MAX_BYTES = int(float(os.getenv("PPF_MAX_GIB", "50")) * 1024**3)

app = Flask(__name__)
DATA.mkdir(parents=True, exist_ok=True)
RUNS.mkdir(parents=True, exist_ok=True)
SECRETS.mkdir(parents=True, exist_ok=True)


def secret_file(name: str, generator) -> bytes:
    path = SECRETS / name
    if not path.exists():
        path.write_bytes(generator())
        path.chmod(0o600)
    return path.read_bytes().strip()


app.secret_key = secret_file("session.key", lambda: secrets.token_bytes(64))
fernet = Fernet(secret_file("encryption.key", Fernet.generate_key))
flow_store = FlowStore(FLOW_DB, retention_days=0)


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(APP_DB, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def password_hash(value: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(value.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024)
    return salt.hex() + ":" + digest.hex()


def password_ok(value: str, stored: str) -> bool:
    try:
        salt_hex, expected = stored.split(":", 1)
        actual = password_hash(value, bytes.fromhex(salt_hex)).split(":", 1)[1]
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def init_db() -> None:
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS profiles (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          serial TEXT NOT NULL DEFAULT '', source_ip TEXT NOT NULL DEFAULT '',
          target_type TEXT NOT NULL DEFAULT 'scm', settings_json TEXT NOT NULL DEFAULT '{}',
          secret_blob BLOB NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sources (
          serial TEXT NOT NULL, source_ip TEXT NOT NULL, first_seen TEXT NOT NULL,
          last_seen TEXT NOT NULL, messages INTEGER NOT NULL DEFAULT 1,
          PRIMARY KEY(serial, source_ip)
        );
        CREATE TABLE IF NOT EXISTS runs (
          id INTEGER PRIMARY KEY, profile_id INTEGER NOT NULL, mode TEXT NOT NULL,
          status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT,
          rule_count INTEGER NOT NULL DEFAULT 0, run_dir TEXT NOT NULL,
          output TEXT NOT NULL DEFAULT '', FOREIGN KEY(profile_id) REFERENCES profiles(id)
        );
        CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, username TEXT NOT NULL,
          action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT ''
        );
        """)
        if not conn.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
            conn.execute("INSERT INTO users(username,password_hash,must_change) VALUES(?,?,1)",
                         ("admin", password_hash(os.getenv("PPF_BOOTSTRAP_PASSWORD", "OCD1234!"))))


init_db()


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def audit(action: str, detail: str = "") -> None:
    with db() as conn:
        conn.execute("INSERT INTO audit(created_at,username,action,detail) VALUES(?,?,?,?)",
                     (now(), session.get("username", "system") if has_request_context() else "system", action, detail[:1000]))


def csrf() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf


@app.before_request
def protect_csrf():
    if request.method == "POST" and not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "-")):
        return "Invalid CSRF token", 400


def login_required(fn):
    @wraps(fn)
    def inner(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        if session.get("must_change") and request.endpoint not in {"change_password", "logout", "static"}:
            return redirect(url_for("change_password"))
        return fn(*args, **kwargs)
    return inner


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "pa-policy-forge"}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (request.form.get("username", ""),)).fetchone()
        if user and password_ok(request.form.get("password", ""), user["password_hash"]):
            session.clear(); session["user_id"] = user["id"]; session["username"] = user["username"]; session["must_change"] = bool(user["must_change"]); csrf()
            audit("login")
            return redirect(url_for("change_password" if user["must_change"] else "index"))
        flash("Ongeldige gebruikersnaam of wachtwoord.", "error")
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        value = request.form.get("password", "")
        if len(value) < 12 or value == "OCD1234!":
            flash("Gebruik minimaal 12 tekens en niet het standaardwachtwoord.", "error")
        elif value != request.form.get("confirm"):
            flash("De wachtwoorden komen niet overeen.", "error")
        else:
            with db() as conn:
                conn.execute("UPDATE users SET password_hash=?,must_change=0 WHERE id=?", (password_hash(value), session["user_id"]))
            session["must_change"] = False; audit("password-changed"); flash("Wachtwoord gewijzigd.", "success")
            return redirect(url_for("index"))
    return render_template("change_password.html")


def stats() -> dict:
    result = flow_store.stats()
    with db() as conn:
        result["profiles"] = conn.execute("SELECT COUNT(*) FROM profiles").fetchone()[0]
        result["sources"] = conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
        result["runs"] = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    used = sum(p.stat().st_size for p in DATA.rglob("*") if p.is_file())
    result.update(storage_used=used, storage_limit=MAX_BYTES, storage_pct=round(used / MAX_BYTES * 100, 2))
    return result


def profile_settings(profile) -> dict:
    try:
        return json.loads(profile["settings_json"] or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}


def profile_serials(profile) -> list[str]:
    settings = profile_settings(profile)
    return list(dict.fromkeys(
        value.strip()
        for value in (profile["serial"], settings.get("passive_serial", ""))
        if value and value.strip()
    ))


@app.get("/")
@login_required
def index():
    with db() as conn:
        profile_rows = conn.execute("SELECT * FROM profiles ORDER BY name").fetchall()
        sources = conn.execute("SELECT * FROM sources ORDER BY last_seen DESC LIMIT 100").fetchall()
        runs = conn.execute("SELECT runs.*,profiles.name profile_name FROM runs JOIN profiles ON profiles.id=runs.profile_id ORDER BY runs.id DESC LIMIT 50").fetchall()
        audits = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 20").fetchall()
    profiles = []
    with flow_store._connect() as conn:
        counts = {row["serial"]: row["count"] for row in conn.execute("SELECT serial,COUNT(*) count FROM flows GROUP BY serial")}
        for row in profile_rows:
            profile = dict(row)
            settings = profile_settings(row)
            profile.update(settings)
            profile["passive_serial"] = settings.get("passive_serial", "")
            profile["passive_source_ip"] = settings.get("passive_source_ip", "")
            profile["zones_text"] = "\n".join(f"{zone} = {role}" for zone, role in settings.get("zones", {}).items())
            profile["scm_scope_type"] = "snippet" if settings.get("snippet") else "device" if settings.get("device") else "folder"
            profile["flow_count"] = sum(counts.get(serial, 0) for serial in profile_serials(row))
            profiles.append(profile)
        editing_id = request.args.get("edit_profile", type=int)
        editing_profile = next((profile for profile in profiles if profile["id"] == editing_id), None)
        selected_id = request.args.get("flow_profile", type=int)
        selected_flow_profile = next((profile for profile in profiles if profile["id"] == selected_id), None)
        if selected_flow_profile is None and len(profiles) == 1:
            selected_flow_profile = profiles[0]
        flows = []
        if selected_flow_profile:
            serials = [selected_flow_profile["serial"], selected_flow_profile["passive_serial"]]
            serials = [serial for serial in dict.fromkeys(serials) if serial]
            if serials:
                placeholders = ",".join("?" for _ in serials)
                flows = conn.execute(f"SELECT * FROM flows WHERE serial IN ({placeholders}) ORDER BY last_seen DESC LIMIT 100", serials).fetchall()
    return render_template("app.html", profiles=profiles, editing_profile=editing_profile, selected_flow_profile=selected_flow_profile, sources=sources, runs=runs, flows=flows, audits=audits, stats=stats())


def parse_zones(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        if not line.strip(): continue
        if "=" not in line: raise ValueError(f"Ongeldige zoneregel: {line}")
        zone, role = [x.strip() for x in line.split("=", 1)]
        if role not in {"client", "server", "internet", "other"}: raise ValueError(f"Ongeldige rol voor {zone}")
        result[zone] = role
    if not result: raise ValueError("Voeg minstens één zone toe")
    return result


@app.post("/profiles/save")
@login_required
def profile_save():
    try:
        profile_id = int(request.form.get("id") or 0)
        active_serial = request.form.get("serial", "").strip()
        passive_serial = request.form.get("passive_serial", "").strip()
        if passive_serial and passive_serial == active_serial:
            raise ValueError("Passieve serial moet verschillen van de actieve serial")
        settings = {
            "zones": parse_zones(request.form.get("zones", "")),
            "min_sessions": max(1, int(request.form.get("min_sessions", "3"))),
            "disabled": request.form.get("disabled") == "on",
            "tags": [x.strip() for x in request.form.get("tags", "AI builder").split(",") if x.strip()],
            "global_ping": request.form.get("global_ping") == "on",
            "global_dns": request.form.get("global_dns") == "on",
            "endpoint": request.form.get("endpoint", "").strip(),
            "vsys": request.form.get("vsys", "vsys1").strip(),
            "device_group": request.form.get("device_group", "").strip(),
            "rulebase": request.form.get("rulebase", "pre"),
            "folder": request.form.get("folder", "").strip(),
            "snippet": request.form.get("snippet", "").strip(),
            "device": request.form.get("device", "").strip(),
            "object_folder": request.form.get("object_folder", "").strip(),
            "log_profile": request.form.get("log_profile", "").strip(),
            "passive_serial": passive_serial,
            "passive_source_ip": request.form.get("passive_source_ip", "").strip(),
        }
        supplied = {k: request.form.get(k, "") for k in ("username", "password", "client_id", "client_secret", "tsg_id")}
        if request.form["target_type"] in {"panorama", "panos"} and not settings["endpoint"]:
            raise ValueError("Endpoint is verplicht voor Panorama en standalone PAN-OS")
        if request.form["target_type"] == "panorama" and not settings["device_group"]:
            raise ValueError("Device group is verplicht voor Panorama")
        if request.form["target_type"] == "scm" and sum(bool(settings[k]) for k in ("folder", "snippet", "device")) != 1:
            raise ValueError("Selecteer exact één SCM-scope: folder, snippet of device")
        with db() as conn:
            existing = conn.execute("SELECT secret_blob FROM profiles WHERE id=?", (profile_id,)).fetchone() if profile_id else None
            old = json.loads(fernet.decrypt(existing["secret_blob"]).decode()) if existing and existing["secret_blob"] else {}
            credential_updates = {k: v for k, v in supplied.items() if v}
            merged = {**old, **credential_updates}
            if existing and not credential_updates:
                blob = existing["secret_blob"]
            else:
                blob = fernet.encrypt(json.dumps(merged).encode()) if merged else b""
            values = (request.form["name"].strip(), request.form.get("enabled") == "on", active_serial, request.form.get("source_ip", "").strip(), request.form["target_type"], json.dumps(settings), blob, now())
            if profile_id:
                conn.execute("UPDATE profiles SET name=?,enabled=?,serial=?,source_ip=?,target_type=?,settings_json=?,secret_blob=?,updated_at=? WHERE id=?", (*values, profile_id))
            else:
                conn.execute("INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", (*values, now()))
        audit("profile-saved", request.form["name"]); flash("Firewallprofiel opgeslagen.", "success")
    except Exception as exc:
        flash(f"Profiel niet opgeslagen: {exc}", "error")
    return redirect(url_for("index") + "#profiles")


@app.post("/profiles/<int:profile_id>/delete")
@login_required
def profile_delete(profile_id):
    with db() as conn:
        row = conn.execute("SELECT name FROM profiles WHERE id=?", (profile_id,)).fetchone()
        if row: conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,)); audit("profile-deleted", row["name"])
    flash("Profiel verwijderd.", "success")
    return redirect(url_for("index") + "#profiles")


@app.post("/profiles/<int:profile_id>/purge-flows")
@login_required
def profile_purge_flows(profile_id):
    with db() as conn:
        profile = conn.execute("SELECT name,serial,settings_json FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile:
        return "Not found", 404
    if not profile["serial"]:
        flash("Flows niet verwijderd: het profiel heeft geen firewallserial.", "error")
        return redirect(url_for("index") + "#profiles")
    serials = profile_serials(profile)
    deleted = flow_store.purge_serials(serials)
    audit("flows-purged", f"profile={profile['name']} serials={','.join(serials)} flows={deleted}")
    flash(f"Schone lei aangemaakt: {deleted} geaggregeerde flows verwijderd voor {profile['name']}.", "success")
    return redirect(url_for("index") + "#flows")


def toml_string(value) -> str:
    return json.dumps(str(value))


def write_config(profile, run_dir: Path, push: bool) -> dict:
    s = json.loads(profile["settings_json"]); secret = json.loads(fernet.decrypt(profile["secret_blob"]).decode()) if profile["secret_blob"] else {}
    target = profile["target_type"]
    lines = [
        "[deployment]", f"panorama = {'true' if target == 'panorama' else 'false'}", f"scm = {'true' if target == 'scm' else 'false'}", "",
        "[builder]", 'logs = ["flows.csv"]', 'xml_output = "policy.xml"', 'review_csv = "review.csv"', 'ptr_cache_file = "ptr-cache.json"',
        f"disabled = {'true' if s.get('disabled') else 'false'}", "tags = [" + ",".join(toml_string(x) for x in s.get("tags", [])) + "]",
        f"global_ping_traceroute = {'true' if s.get('global_ping', True) else 'false'}", 'global_ping_traceroute_apps = ["ping","traceroute"]',
        f"global_dns = {'true' if s.get('global_dns', True) else 'false'}", 'global_dns_apps = ["dns-base"]', 'global_dns_internal_resolvers = []', 'global_dns_external_resolvers = ["1.1.1.1","9.9.9.9"]',
        f"min_sessions = {s.get('min_sessions', 3)}", "limit = 0", "group_threshold = 10", "source_any_threshold = 5", f"workers = {max(1, (os.cpu_count() or 1) - 2)}", 'include_actions = ["allow"]', f"log_setting = {toml_string(s.get('log_profile',''))}", "",
        "[panorama]", f"panorama_template = {toml_string(s.get('device_group',''))}", f"panorama_rulebase = {toml_string(s.get('rulebase','pre'))}", f"panorama_log_setting = {toml_string(s.get('log_profile',''))}", "",
        "[panos]", f"panos_vsys = {toml_string(s.get('vsys','vsys1'))}", f"panos_log_setting = {toml_string(s.get('log_profile',''))}", f"panos_endpoint = {toml_string(s.get('endpoint',''))}", 'panos_username = ""', 'panos_password = ""', f"panos_auto_push = {'true' if push else 'false'}", "",
        "[scm]", 'scm_client_id = ""', 'scm_client_secret = ""', 'scm_tsg_id = ""', 'scm_token_url = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"', 'scm_api_base = "https://api.strata.paloaltonetworks.com/config/security/v1"', f"scm_folder = {toml_string(s.get('folder',''))}", f"scm_snippet = {toml_string(s.get('snippet',''))}", f"scm_device = {toml_string(s.get('device',''))}", f"scm_object_folder = {toml_string(s.get('object_folder') or s.get('folder',''))}", f"scm_rulebase = {toml_string(s.get('rulebase','pre'))}", f"scm_log_forwarding_profile = {toml_string(s.get('log_profile',''))}", "",
        "[profile_groups]", 'client = "best-practice"', 'server = "best-practice"', 'internet = "best-practice"', 'other = "best-practice"', "", "[zone_roles]",
    ]
    lines += [f"{toml_string(k)} = {toml_string(v)}" for k, v in s["zones"].items()]
    (run_dir / "bdnd_panos_zone_roles.toml").write_text("\n".join(lines) + "\n")
    return secret


def export_profile_flows(profile, path: Path) -> int:
    fields = ["first_seen","last_seen","repeat","bytes","serial","src","dst","src_zone","dst_zone","src_user","app","proto","dport","action","rule","url_category"]
    where = ["action='allow'"]; params = []
    serials = profile_serials(profile)
    if serials:
        where.append("serial IN (" + ",".join("?" for _ in serials) + ")")
        params.extend(serials)
    elif profile["source_ip"]:
        raise ValueError("Koppel dit profiel aan een firewallserial; bron-IP is alleen voor herkenning")
    else: raise ValueError("Koppel eerst een firewallserial aan dit profiel")
    with flow_store._connect() as conn:
        rows = conn.execute(f"SELECT {','.join(fields)} FROM flows WHERE {' AND '.join(where)} ORDER BY last_seen", params).fetchall()
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields); writer.writeheader(); writer.writerows(dict(r) for r in rows)
    return len(rows)


@app.post("/profiles/<int:profile_id>/build")
@login_required
def build(profile_id):
    push = request.form.get("mode") == "push"
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile: return "Not found", 404
    run_dir = RUNS / (datetime.now().strftime("%Y%m%d-%H%M%S") + f"-{profile_id}-{secrets.token_hex(3)}"); run_dir.mkdir(mode=0o700)
    with db() as conn:
        cur = conn.execute("INSERT INTO runs(profile_id,mode,status,started_at,run_dir) VALUES(?,?,?,?,?)", (profile_id,"push" if push else "preview","running",now(),str(run_dir))); run_id = cur.lastrowid
    try:
        count = export_profile_flows(profile, run_dir / "flows.csv")
        if not count: raise ValueError("Geen geaggregeerde flows voor deze firewall")
        shutil.copy(BASE / "vendor/bdnd_panos_policy_builder.py", run_dir)
        shutil.copy(BASE / "vendor/bdnd_bpa_policy_builder.py", run_dir)
        run_secret = write_config(profile, run_dir, push)
        run_env = {**os.environ,
            "PPF_PANOS_USERNAME": run_secret.get("username", ""), "PPF_PANOS_PASSWORD": run_secret.get("password", ""),
            "PPF_SCM_CLIENT_ID": run_secret.get("client_id", ""), "PPF_SCM_CLIENT_SECRET": run_secret.get("client_secret", ""),
            "PPF_SCM_TSG_ID": run_secret.get("tsg_id", "")}
        result = subprocess.run(["python3", "bdnd_panos_policy_builder.py"], cwd=run_dir, env=run_env, capture_output=True, text=True, timeout=1800)
        run_secret = {}; run_env = {}
        output = (result.stdout + "\n" + result.stderr)[-12000:]
        if result.returncode: raise RuntimeError(output)
        with (run_dir / "review.csv").open(newline="") as fh: rules = sum(1 for _ in csv.DictReader(fh))
        with db() as conn: conn.execute("UPDATE runs SET status='complete',finished_at=?,rule_count=?,output=? WHERE id=?", (now(),rules,output,run_id))
        audit("candidate-written" if push else "policy-preview", f"profile={profile['name']} run={run_id} rules={rules}")
        flash(("Candidateconfiguratie geschreven; geen commit/deployment uitgevoerd." if push else "Policy-preview gegenereerd.") + f" {rules} regels.", "success")
    except Exception as exc:
        with db() as conn: conn.execute("UPDATE runs SET status='failed',finished_at=?,output=? WHERE id=?", (now(),str(exc)[-12000:],run_id))
        audit("build-failed", f"profile={profile['name']} run={run_id}"); flash(f"Run mislukt: {exc}", "error")
    return redirect(url_for("run_detail", run_id=run_id))


def quota_loop():
    while True:
        time.sleep(3600)
        try:
            used = sum(p.stat().st_size for p in DATA.rglob("*") if p.is_file())
            if used <= MAX_BYTES:
                continue
            with flow_store.lock, flow_store._connect() as conn:
                while used > int(MAX_BYTES * .9):
                    count = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
                    batch = max(10000, count // 10)
                    deleted = conn.execute("DELETE FROM flows WHERE id IN (SELECT id FROM flows ORDER BY last_seen ASC LIMIT ?)", (batch,)).rowcount
                    if not deleted: break
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    conn.execute("VACUUM")
                    used = sum(p.stat().st_size for p in DATA.rglob("*") if p.is_file())
            audit("storage-quota-cleanup", f"usage={used} limit={MAX_BYTES}")
        except Exception:
            app.logger.exception("storage quota cleanup failed")


@app.get("/runs/<int:run_id>")
@login_required
def run_detail(run_id):
    with db() as conn: run = conn.execute("SELECT runs.*,profiles.name profile_name FROM runs JOIN profiles ON profiles.id=runs.profile_id WHERE runs.id=?", (run_id,)).fetchone()
    if not run: return "Not found", 404
    review=[]; path=Path(run["run_dir"])/"review.csv"
    if path.exists():
        with path.open(newline="") as fh: review=list(csv.DictReader(fh))
    return render_template("run.html", run=run, review=review)


@app.get("/runs/<int:run_id>/<kind>")
@login_required
def run_download(run_id, kind):
    with db() as conn: run=conn.execute("SELECT * FROM runs WHERE id=?",(run_id,)).fetchone()
    if not run: return "Not found",404
    names={"csv":"review.csv","xml":"policy.xml"}; name=names.get(kind)
    if not name: return "Not found",404
    path=Path(run["run_dir"])/name
    return send_file(path, as_attachment=True, download_name=f"pa-policy-forge-run-{run_id}-{name}")


def udp_loop():
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            flow=parse_panos_syslog(self.request[0].decode("utf-8",errors="replace"))
            if not flow: return
            flow_store.add_flow(flow); source=self.client_address[0]; timestamp=now()
            with db() as conn:
                conn.execute("INSERT INTO sources(serial,source_ip,first_seen,last_seen,messages) VALUES(?,?,?,?,1) ON CONFLICT(serial,source_ip) DO UPDATE SET last_seen=excluded.last_seen,messages=messages+1", (flow.serial,source,timestamp,timestamp))
    server=socketserver.ThreadingUDPServer(("0.0.0.0", int(os.getenv("PPF_SYSLOG_PORT","514"))),Handler); server.daemon_threads=True; server.serve_forever()


threading.Thread(target=udp_loop,daemon=True,name="syslog-udp").start()
threading.Thread(target=quota_loop,daemon=True,name="storage-quota").start()

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=8080)
