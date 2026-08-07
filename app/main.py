from __future__ import annotations

import csv
import hashlib
import html
import hmac
import io
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socketserver
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import lru_cache, wraps

from cryptography.fernet import Fernet
from defusedxml import ElementTree as SafeET
from flask import Flask, Response, flash, has_request_context, redirect, render_template, request, send_file, session, url_for

from vendor.paloalto_light_syslog import FlowStore, parse_panos_syslog
from app.policy_bulk import POLICY_LIST_FIELDS, apply_bulk_operations, apply_single_replacements
from app.offline_config import (
    OBJECT_NODES, POLICY_NODES, OfflineConfigError, available_scopes, available_templates,
    configuration_inventory, normalized_config_xml, parse_snapshot,
    policy_fingerprint as offline_policy_fingerprint, render_set_commands,
    replace_policy_in_snapshot, safe_workspace_path, scoped_objects,
    scoped_policies, snapshot_sha256, referenced_template,
)

BASE = Path(__file__).resolve().parent.parent
DATA = Path(os.getenv("PPF_DATA_DIR", "/data"))
APP_DB = DATA / "forge.sqlite3"
FLOW_DB = DATA / "flows.sqlite3"
RUNS = DATA / "runs"
SECRETS = DATA / "secrets"
POLICY_DRAFTS = DATA / "policy-drafts"
OBJECT_DRAFTS = DATA / "object-drafts"
OBJECT_CACHE = DATA / "object-cache"
MAX_BYTES = int(float(os.getenv("PPF_MAX_GIB", "50")) * 1024**3)
PREPARE_INTERVAL = max(300, int(os.getenv("PPF_PREPARE_INTERVAL", "1800")))
PREPARE_INITIAL_DELAY = max(30, int(os.getenv("PPF_PREPARE_INITIAL_DELAY", "60")))
PREPARE_MAX_AGE = PREPARE_INTERVAL + 300
LOGIN_WINDOW_SECONDS = 900
LOGIN_MAX_FAILURES = 10
BLOCKED_PASSWORD_SHA256 = {
    "421d2f00ccdd4ccccf0455cdd0557d5af23dc70b06c83b94cf210ba9d4f3bf58",
    "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
}

app = Flask(__name__)
DATA.mkdir(parents=True, exist_ok=True)
RUNS.mkdir(parents=True, exist_ok=True)
SECRETS.mkdir(parents=True, exist_ok=True)
POLICY_DRAFTS.mkdir(parents=True, exist_ok=True)
OBJECT_DRAFTS.mkdir(parents=True, exist_ok=True)
OBJECT_CACHE.mkdir(parents=True, exist_ok=True)
CONFIG_WORKSPACES = DATA / "config-workspaces"
CONFIG_WORKSPACES.mkdir(parents=True, exist_ok=True)

SCM_POLICY_TYPES = {
    "security": ("security", "security-rules", "Security"),
    "nat": ("network", "nat-rules", "NAT"),
    "qos": ("network", "qos-policy-rules", "QoS"),
    "pbf": ("network", "pbf-rules", "Policy Based Forwarding"),
    "decryption": ("security", "decryption-rules", "Decryption"),
    "tunnel-inspection": ("security", "tunnel-inspection-rules", "Tunnel Inspection"),
    "application-override": ("security", "app-override-rules", "Application Override"),
    "authentication": ("identity", "authentication-rules", "Authentication"),
    "dos": ("network", "dos-rules", "DoS Protection"),
    "sdwan": ("network", "sdwan-rules", "SD-WAN"),
}
SCM_UNAVAILABLE_POLICY_TYPES = {"tunnel-inspection", "dos", "sdwan"}
TARGET_TYPES = {"scm", "panorama", "panos"}
PANOS_POLICY_NODES = {
    "security": "security", "nat": "nat", "qos": "qos", "pbf": "pbf",
    "decryption": "decryption", "application-override": "application-override",
    "authentication": "authentication", "tunnel-inspection": "tunnel-inspect",
    "dos": "dos", "sdwan": "sdwan",
}

SCM_OBJECT_TYPES = {
    "addresses": {"label": "Addresses", "creatable": True},
    "address-groups": {"label": "Address Groups", "creatable": True},
    "applications": {"label": "Applications", "creatable": False},
    "application-groups": {"label": "Application Groups", "creatable": True},
    "application-filters": {"label": "Application Filters", "creatable": False},
    "services": {"label": "Services", "creatable": True},
    "service-groups": {"label": "Service Groups", "creatable": True},
    "tags": {"label": "Tags", "creatable": True},
    "zones": {"label": "Zones", "creatable": True, "network": True},
}
_catalog_refreshing: set[tuple[int, str]] = set()
_catalog_refresh_lock = threading.Lock()
_catalog_errors: dict[tuple[int, str], str] = {}
_panos_key_cache: dict[int, tuple[str, str, str, float]] = {}
_panos_key_cache_lock = threading.Lock()
PANOS_KEY_CACHE_SECONDS = 900


def secret_file(name: str, generator) -> bytes:
    path = SECRETS / name
    if not path.exists():
        path.write_bytes(generator())
        path.chmod(0o600)
    return path.read_bytes().strip()


app.secret_key = secret_file("session.key", lambda: secrets.token_bytes(64))
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=int(os.getenv("PPF_MAX_CONFIG_UPLOAD_BYTES", str(100 * 1024 * 1024))),
    MAX_FORM_MEMORY_SIZE=512 * 1024,
    MAX_FORM_PARTS=200,
)
trusted_hosts = [value.strip() for value in os.getenv("PPF_TRUSTED_HOSTS", "").split(",") if value.strip()]
if trusted_hosts: app.config["TRUSTED_HOSTS"] = trusted_hosts
fernet = Fernet(secret_file("encryption.key", Fernet.generate_key))
flow_store = FlowStore(FLOW_DB, retention_days=0)
_login_failures: dict[tuple[str, str], deque[float]] = defaultdict(deque)
_login_failures_lock = threading.Lock()
_syslog_source_policy: dict[str, set[str] | None] = {}
_syslog_source_policy_lock = threading.Lock()
sys.path.insert(0, str(BASE / "vendor"))
from vendor import bdnd_panos_policy_builder as policy_api


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


def password_is_blocked(value: str) -> bool:
    return hashlib.sha256(value.encode()).hexdigest() in BLOCKED_PASSWORD_SHA256


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
        CREATE TABLE IF NOT EXISTS config_workspaces (
          id INTEGER PRIMARY KEY, profile_id INTEGER NOT NULL, name TEXT NOT NULL,
          source TEXT NOT NULL, original_name TEXT NOT NULL, config_path TEXT NOT NULL,
          sha256 TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          FOREIGN KEY(profile_id) REFERENCES profiles(id)
        );
        """)
        if not conn.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
            bootstrap_password = os.getenv("PPF_BOOTSTRAP_PASSWORD", "admin") or "admin"
            if bootstrap_password != "admin" and (len(bootstrap_password) < 12 or password_is_blocked(bootstrap_password)):
                raise RuntimeError("Set PPF_BOOTSTRAP_PASSWORD to admin or a unique value of at least 12 characters")
            conn.execute("INSERT INTO users(username,password_hash,must_change) VALUES(?,?,0)",
                         ("admin", password_hash(bootstrap_password)))


init_db()
_dummy_password_hash = password_hash(secrets.token_urlsafe(32))


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


@app.after_request
def security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
        "form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'"
    )
    if request.endpoint != "static": response.headers["Cache-Control"] = "no-store"
    return response


def login_rate_limited(client: str, username: str, record_failure: bool = False) -> bool:
    keys = ((client, "*"), (client, username.casefold()))
    cutoff = time.monotonic() - LOGIN_WINDOW_SECONDS
    with _login_failures_lock:
        blocked = False
        for key in keys:
            failures = _login_failures[key]
            while failures and failures[0] < cutoff: failures.popleft()
            if record_failure: failures.append(time.monotonic())
            blocked = blocked or len(failures) >= LOGIN_MAX_FAILURES
            if not failures: _login_failures.pop(key, None)
        return blocked


def clear_login_failures(client: str, username: str) -> None:
    with _login_failures_lock:
        _login_failures.pop((client, "*"), None)
        _login_failures.pop((client, username.casefold()), None)


def login_required(fn):
    @wraps(fn)
    def inner(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return inner


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "pa-policy-forge"}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        client = request.remote_addr or "unknown"
        if login_rate_limited(client, username):
            flash("Te veel mislukte pogingen. Probeer later opnieuw.", "error")
            return render_template("login.html"), 429
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        password_valid = password_ok(request.form.get("password", ""), user["password_hash"] if user else _dummy_password_hash)
        if user and password_valid:
            clear_login_failures(client, username)
            session.clear(); session.permanent = True; session["user_id"] = user["id"]; session["username"] = user["username"]; session["must_change"] = False; csrf()
            audit("login")
            return redirect(url_for("index"))
        login_rate_limited(client, username, record_failure=True)
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
        if len(value) < 12 or password_is_blocked(value):
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


def refresh_syslog_source_policy() -> None:
    configured_serials: set[str] = set()
    allowed_sources: dict[str, set[str]] = defaultdict(set)
    with db() as conn: profiles = conn.execute("SELECT serial,source_ip,settings_json FROM profiles").fetchall()
    for profile in profiles:
        settings = profile_settings(profile)
        pairs = ((profile["serial"], profile["source_ip"]), (settings.get("passive_serial", ""), settings.get("passive_source_ip", "")))
        for serial, source_ip in pairs:
            serial = str(serial or "").strip(); source_ip = str(source_ip or "").strip()
            if not serial: continue
            configured_serials.add(serial)
            if source_ip: allowed_sources[serial].add(source_ip)
    policy = {serial: (allowed_sources[serial] or None) for serial in configured_serials}
    with _syslog_source_policy_lock:
        _syslog_source_policy.clear(); _syslog_source_policy.update(policy)


def syslog_source_allowed(serial: str, source_ip: str) -> bool:
    with _syslog_source_policy_lock:
        if serial not in _syslog_source_policy: return True
        allowed = _syslog_source_policy[serial]
        return allowed is None or source_ip in allowed


def validate_panos_endpoint(value: str) -> str:
    endpoint = value.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ValueError("PAN-OS/Panorama endpoint moet een HTTPS-origin zonder pad, credentials, query of fragment zijn")
    try: parsed.port
    except ValueError as exc: raise ValueError("Ongeldige PAN-OS/Panorama endpointpoort") from exc
    return endpoint


def optional_ip_address(value: str) -> str:
    value = value.strip()
    if not value: return ""
    try: return str(ipaddress.ip_address(value))
    except ValueError as exc: raise ValueError(f"Ongeldig herkennings-IP: {value}") from exc


def scm_client(profile):
    settings = profile_settings(profile)
    secret = json.loads(fernet.decrypt(profile["secret_blob"]).decode()) if profile["secret_blob"] else {}
    scm = policy_api.SCMConfig(
        secret.get("client_id", ""), secret.get("client_secret", ""), secret.get("tsg_id", ""),
        "https://auth.apps.paloaltonetworks.com/oauth2/access_token",
        "https://api.strata.paloaltonetworks.com/config/security/v1",
        settings.get("folder", ""), settings.get("object_folder") or settings.get("folder", ""),
        settings.get("snippet", ""), settings.get("device", ""), settings.get("rulebase", "pre"), settings.get("log_profile", ""),
    )
    token = policy_api.get_scm_token(scm)
    endpoint = policy_api.scm_api_root(scm.scm_api_base) + "/config/security/v1/security-rules"
    container = policy_api.scm_container(folder=scm.scm_folder, snippet=scm.scm_snippet, device=scm.scm_device)
    return scm, token, endpoint, container


def normalize_scm_policy(rule: dict) -> dict:
    normalized = {
        "id": str(rule.get("id", "")), "name": str(rule.get("name", "")),
        "action": str(rule.get("action", "allow")), "disabled": bool(rule.get("disabled", False)),
        "log_setting": str(rule.get("log_setting", "") or ""),
        "profile_group": ", ".join((rule.get("profile_setting") or {}).get("group", [])),
        "description": str(rule.get("description", "") or ""),
        "source_user": list(rule.get("source_user", []) or ["any"]),
        "destination_user": list(rule.get("destination_user", []) or ["any"]),
        "category": list(rule.get("category", []) or ["any"]),
        "source_hip": list(rule.get("source_hip", []) or ["any"]),
        "destination_hip": list(rule.get("destination_hip", []) or ["any"]),
        "negate_source": bool(rule.get("negate_source", False)),
        "negate_destination": bool(rule.get("negate_destination", False)),
        "schedule": str(rule.get("schedule", "") or ""),
        "log_start": rule.get("log_start"), "log_end": rule.get("log_end"),
        "rule_type": str(rule.get("rule_type", "universal") or "universal"),
    }
    for field in POLICY_LIST_FIELDS:
        value = rule.get(field, []) or []
        normalized[field] = [str(item) for item in (value if isinstance(value, list) else [value])]
    return normalized


def normalize_policy(rule: dict, policy_kind: str) -> dict:
    """Expose one stable UI model while retaining the complete target payload."""
    if policy_kind == "security":
        normalized = normalize_scm_policy(rule)
    else:
        normalized = {
            "id": str(rule.get("id", "")), "name": str(rule.get("name", "")),
            "action": str(rule.get("action", "") or ""), "disabled": bool(rule.get("disabled", False)),
            "description": str(rule.get("description", "") or ""),
            "log_setting": str(rule.get("log_setting", "") or ""),
            "profile_group": "", "source_user": list(rule.get("source_user", []) or ["any"]),
            "destination_user": list(rule.get("destination_user", []) or ["any"]),
            "source_hip": list(rule.get("source_hip", []) or ["any"]),
            "destination_hip": list(rule.get("destination_hip", []) or ["any"]),
            "category": list(rule.get("category", []) or ["any"]),
            "negate_source": bool(rule.get("negate_source", False)),
            "negate_destination": bool(rule.get("negate_destination", False)),
            "schedule": str(rule.get("schedule", "") or ""), "log_start": rule.get("log_start"),
            "log_end": rule.get("log_end"), "rule_type": str(rule.get("rule_type", "") or ""),
        }
        for field in POLICY_LIST_FIELDS:
            value = rule.get(field, []) or []
            normalized[field] = [str(item) for item in (value if isinstance(value, list) else [value])]
    normalized["_raw"] = rule
    normalized["_policy_kind"] = policy_kind
    return normalized


def xml_value(node: ET.Element):
    children = list(node)
    if not children:
        return node.text or ""
    if all(child.tag == "member" for child in children):
        return [child.text or "" for child in children]
    result = {}
    for child in children:
        value = xml_value(child)
        if child.tag in result:
            result[child.tag] = result[child.tag] if isinstance(result[child.tag], list) else [result[child.tag]]
            result[child.tag].append(value)
        else:
            result[child.tag] = value
    return result


def xml_entry_to_policy(entry: ET.Element, policy_kind: str) -> dict:
    raw = {child.tag.replace("-", "_"): xml_value(child) for child in entry}
    raw.update({"id": entry.attrib.get("uuid") or entry.attrib.get("name", ""), "name": entry.attrib.get("name", "")})
    for key in ("disabled", "negate_source", "negate_destination", "log_start", "log_end"):
        if key in raw: raw[key] = str(raw[key]).lower() == "yes"
    normalized = normalize_policy(raw, policy_kind)
    normalized["_xml"] = ET.tostring(entry, encoding="unicode")
    return normalized


def panos_profile_context(profile):
    settings = json.loads(profile["settings_json"] or "{}")
    secret = json.loads(fernet.decrypt(profile["secret_blob"]).decode()) if profile["secret_blob"] else {}
    endpoint = validate_panos_endpoint(settings.get("endpoint", ""))
    if not endpoint: raise ValueError("PAN-OS/Panorama endpoint ontbreekt")
    profile_id = int(profile["id"]) if "id" in profile.keys() else 0
    profile_version = str(profile["updated_at"]) if "updated_at" in profile.keys() else ""
    ctx = ssl._create_unverified_context()
    if profile_id:
        with _panos_key_cache_lock:
            cached = _panos_key_cache.get(profile_id)
            if cached and cached[0] == profile_version and cached[1] == endpoint and cached[3] > time.time():
                return settings, endpoint, cached[2], ctx
    key_root = policy_api.require_success(panos_api_post(endpoint, {"type": "keygen", "user": secret.get("username", ""), "password": secret.get("password", "")}, ctx), "keygen")
    key = key_root.findtext(".//key")
    if not key: raise RuntimeError("API key generation gaf geen sleutel terug")
    if profile_id:
        with _panos_key_cache_lock:
            _panos_key_cache[profile_id] = (profile_version, endpoint, key, time.time() + PANOS_KEY_CACHE_SECONDS)
    return settings, endpoint, key, ctx


def invalidate_profile_caches(profile_id: int) -> None:
    for cache_path in OBJECT_CACHE.glob(f"{profile_id}-*.json"):
        try: cache_path.unlink()
        except FileNotFoundError: pass
    with _catalog_refresh_lock:
        for key in [key for key in _catalog_errors if key[0] == profile_id]:
            _catalog_errors.pop(key, None)
    with _panos_key_cache_lock:
        _panos_key_cache.pop(profile_id, None)


def panos_api_post(endpoint: str, params: dict, ctx: ssl.SSLContext) -> str:
    request_params = dict(params)
    api_key = request_params.pop("key", "")
    request_body = urllib.parse.urlencode(request_params).encode()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if api_key: headers["X-PAN-KEY"] = api_key
    api_request = urllib.request.Request(endpoint.rstrip("/") + "/api/", data=request_body, headers=headers, method="POST")
    with urllib.request.urlopen(api_request, context=ctx, timeout=120) as response:
        return response.read().decode("utf-8", errors="replace")


def panos_policy_xpath(profile, policy_kind: str) -> str:
    settings = json.loads(profile["settings_json"] or "{}")
    node = PANOS_POLICY_NODES[policy_kind]
    device = policy_api.xpath_literal("localhost.localdomain")
    if profile["target_type"] == "panorama":
        group = policy_api.xpath_literal(settings.get("device_group", ""))
        position = settings.get("rulebase", "pre")
        return f"/config/devices/entry[@name={device}]/device-group/entry[@name={group}]/{position}-rulebase/{node}/rules"
    vsys = policy_api.xpath_literal(settings.get("vsys", "vsys1"))
    return f"/config/devices/entry[@name={device}]/vsys/entry[@name={vsys}]/rulebase/{node}/rules"


def fetch_panos_policies(profile, policy_kind: str) -> list[dict]:
    _, endpoint, key, ctx = panos_profile_context(profile)
    root = policy_api.require_success(policy_api.api_get(endpoint, {"type": "config", "action": "get", "xpath": panos_policy_xpath(profile, policy_kind), "key": key}, ctx), f"fetch {policy_kind} rules")
    return [xml_entry_to_policy(entry, policy_kind) for entry in root.findall(".//entry")]


def fetch_security_policies(profile) -> list[dict]:
    if profile["target_type"] != "scm": return fetch_panos_policies(profile, "security")
    scm, token, endpoint, container = scm_client(profile)
    return [normalize_policy(rule, "security") for rule in policy_api.scm_fetch_rules(endpoint, token, container, scm.scm_rulebase)]


def fetch_scm_policy_type(profile, policy_kind: str) -> list[dict]:
    if policy_kind not in SCM_POLICY_TYPES: raise ValueError("Onbekend policytype")
    if profile["target_type"] != "scm": return fetch_panos_policies(profile, policy_kind)
    if policy_kind in SCM_UNAVAILABLE_POLICY_TYPES: return []
    if policy_kind == "security": return fetch_security_policies(profile)
    service, endpoint_name, _ = SCM_POLICY_TYPES[policy_kind]
    scm, token, _, container = scm_client(profile)
    endpoint = policy_api.scm_api_root(scm.scm_api_base) + f"/config/{service}/v1/{endpoint_name}"
    return [normalize_policy(rule, policy_kind) for rule in policy_api.scm_fetch_all(endpoint, token, {**container, "position": scm.scm_rulebase})]


def fetch_scm_objects(profile, object_type: str) -> list[dict]:
    if object_type not in SCM_OBJECT_TYPES:
        raise ValueError("Onbekend objecttype")
    if profile["target_type"] != "scm": return fetch_panos_objects(profile, object_type)
    scm, token, _, _ = scm_client(profile)
    service = "network" if object_type == "zones" else "objects"
    root = policy_api.scm_api_root(scm.scm_api_base) + f"/config/{service}/v1"
    container = policy_api.scm_container(folder=scm.scm_folder if object_type == "zones" else scm.scm_object_folder, snippet=scm.scm_snippet, device=scm.scm_device)
    return policy_api.scm_fetch_all(f"{root}/{object_type}", token, container)


def managed_view(object_type: str) -> str:
    return "network" if object_type == "zones" else "objects"


PANOS_OBJECT_NODES = {"addresses": "address", "address-groups": "address-group", "applications": "application", "application-groups": "application-group", "application-filters": "application-filter", "services": "service", "service-groups": "service-group", "tags": "tag", "zones": "zone"}


def panos_object_bases(profile, object_type: str) -> list[str]:
    settings = json.loads(profile["settings_json"] or "{}")
    if object_type == "applications": return ["/config/predefined"]
    device = policy_api.xpath_literal("localhost.localdomain")
    if object_type == "zones" and profile["target_type"] == "panorama":
        vsys = policy_api.xpath_literal(settings.get("vsys", "vsys1"))
        _, endpoint, key, ctx = panos_profile_context(profile)
        group = policy_api.xpath_literal(settings.get("device_group", ""))
        group_xpath = f"/config/devices/entry[@name={device}]/device-group/entry[@name={group}]"
        root = policy_api.require_success(policy_api.api_get(endpoint, {"type": "config", "action": "get", "xpath": group_xpath, "key": key}, ctx), "fetch device-group reference templates")
        references = []
        for path in (".//reference-templates/member", ".//reference-template/member", ".//reference-template-stack/member"):
            references.extend(node.text.strip() for node in root.findall(path) if node.text and node.text.strip())
        references = list(dict.fromkeys(references))
        bases = []
        for reference in references:
            literal = policy_api.xpath_literal(reference)
            stack_xpath = f"/config/devices/entry[@name={device}]/template-stack/entry[@name={literal}]"
            stack_root = policy_api.require_success(policy_api.api_get(endpoint, {"type": "config", "action": "get", "xpath": stack_xpath, "key": key}, ctx), f"inspect reference template {reference}")
            kind = "template-stack" if stack_root.find(".//entry") is not None else "template"
            bases.append(f"/config/devices/entry[@name={device}]/{kind}/entry[@name={literal}]/config/devices/entry[@name={device}]/vsys/entry[@name={vsys}]")
        return bases
    if profile["target_type"] == "panorama":
        group = policy_api.xpath_literal(settings.get("device_group", ""))
        return ["/config/shared", f"/config/devices/entry[@name={device}]/device-group/entry[@name={group}]"]
    vsys = policy_api.xpath_literal(settings.get("vsys", "vsys1"))
    return [f"/config/devices/entry[@name={device}]/vsys/entry[@name={vsys}]"]


def xml_object_to_dict(entry: ET.Element, object_type: str, base: str) -> dict:
    item = {"id": entry.attrib.get("uuid") or entry.attrib.get("name", ""), "name": entry.attrib.get("name", ""), "_xml": ET.tostring(entry, encoding="unicode"), "_scope_xpath": base}
    children = {child.tag.replace("-", "_"): xml_value(child) for child in entry}
    item.update(children)
    if object_type == "address-groups" and isinstance(item.get("dynamic"), dict): item["dynamic"] = item["dynamic"].get("filter", "")
    return item


def fetch_panos_objects(profile, object_type: str) -> list[dict]:
    _, endpoint, key, ctx = panos_profile_context(profile)
    node = PANOS_OBJECT_NODES[object_type]
    collected = []
    for base in panos_object_bases(profile, object_type):
        response = policy_api.require_success(policy_api.api_get(endpoint, {"type": "config", "action": "get", "xpath": f"{base}/{node}", "key": key}, ctx), f"fetch {object_type}")
        collected.extend(xml_object_to_dict(entry, object_type, base) for entry in response.findall(".//entry"))
    return collected


def refresh_catalog_async(profile, kind: str, cache_path: Path) -> None:
    key = (int(profile["id"]), kind)
    with _catalog_refresh_lock:
        if key in _catalog_refreshing: return
        _catalog_refreshing.add(key)
    def refresh():
        try:
            fresh = fetch_scm_objects(profile, kind)
            temporary = cache_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(fresh)); temporary.chmod(0o600); temporary.replace(cache_path)
            with _catalog_refresh_lock: _catalog_errors.pop(key, None)
        except Exception as exc:
            with _catalog_refresh_lock: _catalog_errors[key] = f"{type(exc).__name__}: ophalen mislukt"
            app.logger.exception("catalog refresh failed for profile=%s kind=%s", profile["id"], kind)
        finally:
            with _catalog_refresh_lock: _catalog_refreshing.discard(key)
    threading.Thread(target=refresh, name=f"catalog-{profile['id']}-{kind}", daemon=True).start()


def fetch_object_catalog(profile, object_type: str) -> list[dict]:
    related = {"addresses": ("tags",), "services": ("tags",), "address-groups": ("addresses", "address-groups", "tags"), "service-groups": ("services", "service-groups", "tags"), "application-groups": ("applications", "application-groups", "tags"), "zones": ("zones",), "policy-picker": ("zones", "addresses", "address-groups", "applications", "application-groups", "application-filters", "services", "service-groups", "tags")}.get(object_type, ())
    catalog = []
    for kind in related:
        cache_path = OBJECT_CACHE / f"{profile['id']}-{kind}.json"
        cached = None
        if cache_path.exists():
            try: cached = json.loads(cache_path.read_text())
            except (OSError, json.JSONDecodeError): cached = None
        stale = not cache_path.exists() or time.time() - cache_path.stat().st_mtime >= 1800
        if kind == "applications" and stale:
            refresh_catalog_async(profile, kind, cache_path)
        elif cached is None or stale:
            try:
                cached = fetch_scm_objects(profile, kind)
                cache_path.write_text(json.dumps(cached)); cache_path.chmod(0o600)
            except Exception:
                if cached is None and object_type != "policy-picker": raise
        cached = cached or []
        catalog.extend({"name": item.get("name", ""), "kind": kind} for item in cached if item.get("name"))
    return sorted(catalog, key=lambda item: (item["name"].lower(), item["kind"]))


@app.get("/profiles/<int:profile_id>/catalog/applications")
@login_required
def application_catalog(profile_id):
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile: return {"ready": False, "items": []}, 404
    cache_path = OBJECT_CACHE / f"{profile_id}-applications.json"
    items = []
    if cache_path.exists():
        try: items = json.loads(cache_path.read_text())
        except (OSError, json.JSONDecodeError): items = []
    stale = not cache_path.exists() or time.time() - cache_path.stat().st_mtime >= 1800
    if stale: refresh_catalog_async(profile, "applications", cache_path)
    with _catalog_refresh_lock:
        refreshing = (profile_id, "applications") in _catalog_refreshing
        error = _catalog_errors.get((profile_id, "applications"), "")
    return {"ready": bool(items), "refreshing": refreshing, "error": error, "items": [{"name": item.get("name", ""), "kind": "applications"} for item in items if item.get("name")]}


def scm_object_payload(object_type: str, form, container: dict) -> dict:
    name = form.get("name", "").strip()
    if not name:
        raise ValueError("Naam is verplicht")
    payload = {"name": name, **container}
    description = form.get("description", "").strip()
    if description: payload["description"] = description
    tags = split_values(form.get("tags", ""))
    if tags and object_type != "tags": payload["tag"] = tags
    if object_type == "addresses":
        value_type = form.get("value_type", "ip_netmask")
        if value_type not in {"ip_netmask", "ip_range", "ip_wildcard", "fqdn"}:
            raise ValueError("Ongeldig adrestype")
        value = form.get("value", "").strip()
        if not value:
            raise ValueError("Adreswaarde is verplicht")
        payload[value_type] = value
    elif object_type == "address-groups":
        if form.get("group_type", "static") == "dynamic":
            match = form.get("dynamic", "").strip()
            if not match: raise ValueError("Dynamic match criteria is verplicht")
            payload["dynamic"] = {"filter": match}
        else:
            members = split_values(form.get("members", ""))
            if not members: raise ValueError("Voeg minstens één member toe")
            payload["static"] = members
    elif object_type in {"application-groups", "service-groups"}:
        members = split_values(form.get("members", ""))
        if not members: raise ValueError("Voeg minstens één member toe")
        payload["members"] = members
    elif object_type == "services":
        protocol = form.get("protocol", "tcp").lower()
        if protocol not in {"tcp", "udp"}:
            raise ValueError("Protocol moet TCP of UDP zijn")
        port = form.get("port", "").strip()
        if not port:
            raise ValueError("Poort is verplicht")
        protocol_payload = {"port": port}
        source_port = form.get("source_port", "").strip()
        if source_port: protocol_payload["source_port"] = source_port
        if form.get("override") == "on":
            protocol_payload["override"] = True
            for form_key, payload_key in (("timeout", "timeout"), ("halfclose_timeout", "halfclose_timeout"), ("timewait_timeout", "timewait_timeout")):
                value = form.get(form_key, "").strip()
                if value: protocol_payload[payload_key] = int(value)
        payload["protocol"] = {protocol: protocol_payload}
    elif object_type == "tags":
        color = form.get("color", "").strip()
        comments = form.get("comments", "").strip() or description
        if color: payload["color"] = color
        if comments: payload["comments"] = comments
    elif object_type == "zones":
        zone_type = form.get("zone_type", "layer3")
        if zone_type not in {"layer3", "layer2", "virtual_wire", "tap", "tunnel"}: raise ValueError("Ongeldig zonetype")
        interfaces = split_values(form.get("interfaces", ""))
        payload["network"] = {zone_type: interfaces}
        payload["enable_user_identification"] = form.get("enable_user_identification") == "on"
        for form_key, payload_key in (("zone_protection_profile", "zone_protection_profile"), ("log_setting", "log_setting")):
            value = form.get(form_key, "").strip()
            if value: payload[payload_key] = value
    else:
        raise ValueError("Dit objecttype is momenteel alleen-lezen")
    return payload


def object_fingerprint(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def object_payload_xml(payload: dict) -> str:
    entry = ET.Element("entry", {"name": payload["name"]})
    for key, value in payload.items():
        if key in {"name", "folder", "snippet", "device"} or value in (None, "", []): continue
        tag = key.replace("_", "-")
        node = ET.SubElement(entry, tag)
        if isinstance(value, list):
            for member in value: ET.SubElement(node, "member").text = str(member)
        elif isinstance(value, dict):
            for child_key, child_value in value.items():
                child = ET.SubElement(node, child_key.replace("_", "-"))
                if isinstance(child_value, dict):
                    for detail_key, detail_value in child_value.items(): ET.SubElement(child, detail_key.replace("_", "-")).text = "yes" if detail_value is True else str(detail_value)
                elif isinstance(child_value, list):
                    for member in child_value: ET.SubElement(child, "member").text = str(member)
                else: child.text = str(child_value)
        else: node.text = "yes" if value is True else "no" if value is False else str(value)
    return ET.tostring(entry, encoding="unicode")


def write_panos_object_draft(profile, draft: dict) -> None:
    _, endpoint, key, ctx = panos_profile_context(profile)
    object_type = draft["object_type"]; node = PANOS_OBJECT_NODES[object_type]; operation = draft["operation"]
    if operation == "create":
        bases = panos_object_bases(profile, object_type) if profile["target_type"] != "panorama" or object_type == "zones" else []
        if object_type == "zones" and not bases: raise ValueError("De Device Group heeft geen Reference Template; de zonenaam blijft freeform en er is geen template-candidate om te wijzigen")
        base = "/config/shared" if profile["target_type"] == "panorama" and object_type != "zones" else bases[0]
        params = {"type": "config", "action": "set", "xpath": f"{base}/{node}", "element": object_payload_xml(draft["payload"]), "key": key}
        policy_api.require_success(panos_api_post(endpoint, params, ctx), f"create {object_type}")
    elif operation == "update":
        before = draft["before"]; base = before.get("_scope_xpath") or ("/config/shared" if profile["target_type"] == "panorama" and object_type != "zones" else panos_object_bases(profile, object_type)[0])
        xpath = f"{base}/{node}/entry[@name={policy_api.xpath_literal(before['name'])}]"
        params = {"type": "config", "action": "edit", "xpath": xpath, "element": object_payload_xml(draft["payload"]), "key": key}
        policy_api.require_success(panos_api_post(endpoint, params, ctx), f"update {object_type}")
    else:
        for wrapped in draft["objects"]:
            item = wrapped["value"]; base = item.get("_scope_xpath") or ("/config/shared" if profile["target_type"] == "panorama" and object_type != "zones" else panos_object_bases(profile, object_type)[0])
            xpath = f"{base}/{node}/entry[@name={policy_api.xpath_literal(item['name'])}]"
            policy_api.require_success(panos_api_post(endpoint, {"type": "config", "action": "delete", "xpath": xpath, "key": key}, ctx), f"delete {object_type}")


def validate_object_payload(payload: dict, object_type: str, existing: list[dict], own_id: str = "") -> None:
    others = [item for item in existing if str(item.get("id", "")) != own_id]
    same_name = next((item for item in others if item.get("name") == payload["name"]), None)
    if same_name:
        raise ValueError(f"Object {payload['name']} bestaat al; gebruik het bestaande object.")
    comparable_keys = {
        "addresses": ("ip_netmask", "ip_range", "ip_wildcard", "fqdn"),
        "address-groups": ("static", "dynamic"), "application-groups": ("members",),
        "services": ("protocol",), "service-groups": ("members",), "tags": ("color",), "zones": ("network",),
    }[object_type]
    wanted = {key: payload.get(key) for key in comparable_keys if payload.get(key) is not None}
    equivalent = next((item for item in others if {key: item.get(key) for key in comparable_keys if item.get(key) is not None} == wanted), None)
    if equivalent:
        raise ValueError(f"Een equivalent object bestaat al als {equivalent['name']}; gebruik dat bestaande object.")


def policy_fingerprint(policy: dict) -> str:
    return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def split_values(value: str) -> list[str]:
    return list(dict.fromkeys(item.strip() for item in value.replace("\n", ",").split(",") if item.strip()))


def validate_policy_zones(policy: dict, zone_names: set[str]) -> None:
    missing = sorted({value for field in ("from", "to") for value in policy.get(field, []) if value != "any" and value not in zone_names})
    if missing: raise ValueError("Onbekende zone(s): " + ", ".join(missing) + ". Maak ze eerst aan onder Network > Zones.")


def scm_policy_payload(policy: dict, container: dict) -> dict:
    payload = {
        "name": policy["name"], "from": policy["from"], "to": policy["to"],
        "source": policy["source"], "destination": policy["destination"],
        "source_user": policy["source_user"], "destination_user": policy["destination_user"], "category": policy["category"],
        "application": policy["application"], "service": policy["service"],
        "action": policy["action"], "disabled": policy["disabled"],
        "negate_source": policy["negate_source"], "negate_destination": policy["negate_destination"],
        **container,
    }
    for field in ("description", "log_setting", "schedule"):
        if policy.get(field): payload[field] = policy[field]
    for field in ("source_hip", "destination_hip", "tag"):
        if policy.get(field): payload[field] = policy[field]
    for field in ("log_start", "log_end"):
        if policy.get(field) is not None: payload[field] = policy[field]
    if policy.get("profile_group"): payload["profile_setting"] = {"group": split_values(policy["profile_group"])}
    return payload


def target_policy_payload(policy: dict, container: dict, policy_kind: str) -> dict:
    if policy_kind == "security": return scm_policy_payload(policy, container)
    payload = json.loads(json.dumps(policy.get("_raw") or {}))
    for internal in ("id", "_xml", "_raw", "_policy_kind"): payload.pop(internal, None)
    payload["name"] = policy["name"]
    for field in POLICY_LIST_FIELDS:
        if field in policy and (field in payload or policy.get(field) not in ([], ["any"])):
            payload[field] = policy[field]
    for field in ("action", "disabled", "description", "log_setting", "schedule", "negate_source", "negate_destination", "log_start", "log_end"):
        if field in policy and (field in payload or policy.get(field) not in (None, "")): payload[field] = policy[field]
    payload.update(container)
    return payload


def update_xml_policy(policy: dict) -> str:
    entry = SafeET.fromstring(policy["_xml"])
    list_fields = set(POLICY_LIST_FIELDS)
    for field in list_fields:
        if field not in policy: continue
        tag = field.replace("_", "-")
        node = entry.find(f"./{tag}")
        if node is None and policy[field] in ([], ["any"]): continue
        if node is None: node = ET.SubElement(entry, tag)
        node.clear()
        for value in policy[field]: ET.SubElement(node, "member").text = str(value)
    for field in ("action", "description", "log_setting", "schedule"):
        if field not in policy: continue
        tag = field.replace("_", "-")
        node = entry.find(f"./{tag}")
        if node is None and not policy[field]: continue
        if node is None: node = ET.SubElement(entry, tag)
        node.text = str(policy[field])
    for field in ("disabled", "negate_source", "negate_destination", "log_start", "log_end"):
        if field not in policy or policy[field] is None: continue
        tag = field.replace("_", "-")
        node = entry.find(f"./{tag}")
        if node is None: node = ET.SubElement(entry, tag)
        node.text = "yes" if policy[field] else "no"
    return ET.tostring(entry, encoding="unicode")


def write_target_policy(profile, policy_kind: str, policy: dict) -> None:
    if profile["target_type"] == "scm":
        scm, token, _, container = scm_client(profile)
        service, endpoint_name, _ = SCM_POLICY_TYPES[policy_kind]
        endpoint = policy_api.scm_api_root(scm.scm_api_base) + f"/config/{service}/v1/{endpoint_name}"
        policy_api.scm_http_request("PUT", f"{endpoint}/{policy['id']}", token, payload=target_policy_payload(policy, container, policy_kind), params={"position": scm.scm_rulebase})
        return
    _, endpoint, key, ctx = panos_profile_context(profile)
    xpath = f"{panos_policy_xpath(profile, policy_kind)}/entry[@name={policy_api.xpath_literal(policy['name'])}]"
    policy_api.require_success(panos_api_post(endpoint, {"type": "config", "action": "edit", "xpath": xpath, "element": update_xml_policy(policy), "key": key}, ctx), f"edit {policy_kind} rule {policy['name']}")


def workspace_row(workspace_id: int):
    with db() as conn:
        return conn.execute(
            "SELECT config_workspaces.*,profiles.name profile_name,profiles.target_type,profiles.settings_json,profiles.secret_blob,profiles.updated_at profile_updated_at "
            "FROM config_workspaces JOIN profiles ON profiles.id=config_workspaces.profile_id WHERE config_workspaces.id=?",
            (workspace_id,),
        ).fetchone()


def store_config_workspace(profile, name: str, original_name: str, xml_bytes: bytes, source: str) -> int:
    expected = "panorama" if profile["target_type"] == "panorama" else "panos"
    root, snapshot = parse_snapshot(xml_bytes, expected_kind=expected)
    normalized = normalized_config_xml(root)
    workspace_token = secrets.token_hex(16)
    path = CONFIG_WORKSPACES / f"{workspace_token}.xml"
    path.write_bytes(normalized)
    path.chmod(0o600)
    timestamp = now()
    try:
        with db() as conn:
            cursor = conn.execute(
                "INSERT INTO config_workspaces(profile_id,name,source,original_name,config_path,sha256,metadata_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (profile["id"], name[:120], source, original_name[:255], str(path), snapshot_sha256(normalized), json.dumps(snapshot.as_dict()), timestamp, timestamp),
            )
            workspace_id = int(cursor.lastrowid)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    audit("config-workspace-created", f"workspace={workspace_id} profile={profile['name']} source={source} kind={snapshot.kind}")
    return workspace_id


def workspace_config_path(workspace) -> Path:
    path = safe_workspace_path(CONFIG_WORKSPACES, workspace["config_path"])
    if not path.is_file():
        raise FileNotFoundError("Workspace XML ontbreekt")
    return path


@lru_cache(maxsize=4)
def cached_workspace_config(stored_path: str, sha256: str):
    path = safe_workspace_path(CONFIG_WORKSPACES, stored_path)
    if not path.is_file():
        raise FileNotFoundError("Workspace XML ontbreekt")
    xml_bytes = path.read_bytes()
    if snapshot_sha256(xml_bytes) != sha256:
        raise OfflineConfigError("Workspace XML komt niet meer overeen met de opgeslagen checksum")
    root, snapshot = parse_snapshot(xml_bytes)
    return xml_bytes, root, snapshot


def active_config_workspace_id(profile) -> int:
    try:
        return int(profile_settings(profile).get("config_workspace_id") or 0)
    except (TypeError, ValueError):
        return 0


def set_active_config_workspace(profile_id: int, workspace_id: int | None) -> None:
    with db() as conn:
        profile = conn.execute("SELECT settings_json FROM profiles WHERE id=?", (profile_id,)).fetchone()
        if not profile:
            raise OfflineConfigError("Het firewallprofiel bestaat niet meer")
        settings = json.loads(profile["settings_json"] or "{}")
        if workspace_id:
            owned = conn.execute(
                "SELECT 1 FROM config_workspaces WHERE id=? AND profile_id=?",
                (workspace_id, profile_id),
            ).fetchone()
            if not owned:
                raise OfflineConfigError("De gekozen configuratie hoort niet bij dit profiel")
            settings["config_workspace_id"] = int(workspace_id)
        else:
            settings.pop("config_workspace_id", None)
        conn.execute("UPDATE profiles SET settings_json=? WHERE id=?", (json.dumps(settings), profile_id))


@app.post("/config-workspaces/<int:workspace_id>/select")
@login_required
def config_workspace_select(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    try:
        set_active_config_workspace(workspace["profile_id"], workspace_id)
        audit("config-workspace-selected", f"workspace={workspace_id} profile={workspace['profile_name']}")
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id))
    except Exception as exc:
        flash(f"Configuratie niet geselecteerd: {exc}", "error")
        return redirect(url_for("index", policy_profile=workspace["profile_id"], policy_source="choose") + "#policy-management")


OFFLINE_POLICY_FIELDS = (
    "from", "to", "source", "destination", "source_user", "category",
    "application", "service", "tag",
)
WORKSPACE_POLICY_NAV = {
    "Security": "security", "NAT": "nat", "QoS": "qos",
    "Policy Based Forwarding": "pbf", "Decryption": "decryption",
    "Tunnel Inspection": "tunnel-inspection", "Application Override": "application-override",
    "Authentication": "authentication", "DoS Protection": "dos", "SD-WAN": "sdwan",
}
WORKSPACE_OBJECT_NAV = {
    "Addresses": "addresses", "Address Groups": "address-groups", "Regions": "regions",
    "Dynamic User Groups": "dynamic-user-groups",
    "Applications": "applications", "Application Groups": "application-groups",
    "Application Filters": "application-filters", "Services": "services",
    "Service Groups": "service-groups", "Tags": "tags",
    "HIP Objects": "hip-objects", "HIP Profiles": "hip-profiles",
    "External Dynamic Lists": "external-dynamic-lists",
    "Custom URL Categories": "custom-url-categories",
    "↳ Antivirus": "antivirus", "↳ Anti-Spyware": "anti-spyware",
    "↳ Vulnerability Protection": "vulnerability-protection",
    "↳ URL Filtering": "url-filtering", "↳ File Blocking": "file-blocking",
    "↳ WildFire Analysis": "wildfire-analysis", "↳ DoS Protection": "dos-protection",
    "Security Profile Groups": "security-profile-groups", "Log Forwarding": "log-forwarding",
    "Authentication": "authentication",
}
WORKSPACE_NETWORK_NAV = {
    "Interfaces": "interfaces", "Zones": "zones", "VLANs": "vlans", "Virtual Wires": "virtual-wires",
    "Virtual Routers": "virtual-routers",
    "Logical Routers": "logical-routers", "IPSec Tunnels": "ipsec-tunnels",
    "Routing Profiles": "routing-profiles", "GRE Tunnels": "gre-tunnels",
    "GlobalProtect Portals": "globalprotect-portals",
    "GlobalProtect Gateways": "globalprotect-gateways", "DHCP": "dhcp", "DNS Proxy": "dns-proxy",
    "QoS": "qos", "LLDP": "lldp", "Network Profiles": "network-profiles",
}
WORKSPACE_DEVICE_NAV = {
    "Setup": "setup", "Administrators": "administrators", "Admin Roles": "admin-roles",
    "Authentication Profile": "authentication-profile", "Authentication Sequence": "authentication-sequence",
    "Certificates": "certificates", "Certificate Management": "certificate-management",
    "Local User Database": "local-user-database",
    "Server Profiles": "server-profiles", "Log Settings": "log-settings",
    "High Availability": "high-availability", "User Identification": "user-identification",
    "VM Information Sources": "vm-information-sources", "Licenses": "licenses",
    "Dynamic Updates": "dynamic-updates", "Software": "software",
}


@app.get("/config-workspaces/<int:workspace_id>/edit")
@login_required
def config_workspace_editor(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    try:
        xml_bytes, parsed_root, snapshot = cached_workspace_config(workspace["config_path"], workspace["sha256"])
        scopes = available_scopes(snapshot)
        if not scopes:
            raise OfflineConfigError("Geen device group of VSYS gevonden")
        workspace_contexts = dict(session.get("workspace_contexts") or {})
        saved_context = dict(workspace_contexts.get(str(workspace_id)) or {})
        requested_scope = request.args.get("scope", "").strip()
        if requested_scope and requested_scope not in scopes:
            raise OfflineConfigError("De gekozen scope bestaat niet")
        scope = requested_scope or saved_context.get("scope", "")
        if scope not in scopes:
            scope = scopes[0]
        workspace_view = request.args.get("workspace_view", "policies")
        if workspace_view not in {"policies", "objects", "network", "device"}:
            workspace_view = "policies"
        policy_kind = request.args.get("policy_kind", "security")
        if policy_kind not in POLICY_NODES:
            policy_kind = "security"
        rulebase = request.args.get("rulebase", "pre" if snapshot.kind == "panorama" else "standard")
        if snapshot.kind == "panorama" and rulebase not in {"pre", "post"}:
            rulebase = "pre"
        object_type = request.args.get("object_type", "addresses")
        if object_type not in OBJECT_NODES:
            object_type = "addresses"
        config_section = request.args.get("config_section", "").strip()
        templates = available_templates(snapshot)
        requested_template = request.args.get("template", "").strip()
        preferred_template = referenced_template(snapshot, scope)
        template = requested_template or saved_context.get("template", "") or preferred_template or (templates[0] if templates else "")
        if template and template not in templates:
            template = preferred_template or (templates[0] if templates else "")
        workspace_contexts[str(workspace_id)] = {"scope": scope, "template": template}
        session["workspace_contexts"] = dict(list(workspace_contexts.items())[-20:])
        policies = objects = []
        alternate_policy_count = 0
        inventory = {"network": [], "device": []}
        if workspace_view == "policies":
            _, policies = scoped_policies(xml_bytes, scope, policy_kind, rulebase, parsed=(parsed_root, snapshot))
            if snapshot.kind == "panorama":
                other_rulebase = "post" if rulebase == "pre" else "pre"
                _, alternate_policies = scoped_policies(xml_bytes, scope, policy_kind, other_rulebase, parsed=(parsed_root, snapshot))
                alternate_policy_count = len(alternate_policies)
        elif workspace_view == "objects":
            _, objects = scoped_objects(xml_bytes, scope, object_type, parsed=(parsed_root, snapshot))
        else:
            inventory = configuration_inventory(xml_bytes, scope, template, parsed=(parsed_root, snapshot))
            for item in inventory["network"]:
                item["slug"] = WORKSPACE_NETWORK_NAV.get(item["name"], "")
            for item in inventory["device"]:
                item["slug"] = WORKSPACE_DEVICE_NAV.get(item["name"], "")
        edit_name = request.args.get("edit_policy", "")
        edit_policy = next((item for item in policies if item["name"] == edit_name and item["editable"]), None)
        return render_template(
            "workspace_editor.html", workspace=workspace, snapshot=snapshot,
            scopes=scopes, scope=scope, templates=templates, template=template,
            preferred_template=preferred_template, workspace_view=workspace_view,
            policy_kind=policy_kind, policy_nodes=POLICY_NODES,
            rulebase=rulebase, policies=policies, edit_policy=edit_policy,
            alternate_policy_count=alternate_policy_count,
            object_type=object_type, object_nodes=OBJECT_NODES, objects=objects,
            config_section=config_section,
            inventory=inventory, offline_policy_fields=OFFLINE_POLICY_FIELDS,
            workspace_policy_nav=WORKSPACE_POLICY_NAV, workspace_object_nav=WORKSPACE_OBJECT_NAV,
            workspace_network_nav=WORKSPACE_NETWORK_NAV, workspace_device_nav=WORKSPACE_DEVICE_NAV,
        )
    except Exception as exc:
        flash(f"Workspace niet geopend: {exc}", "error")
        return redirect(url_for("index", policy_profile=workspace["profile_id"]) + "#policy-management")


@app.post("/config-workspaces/<int:workspace_id>/policies/preview")
@login_required
def config_workspace_policy_preview(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    try:
        xml_bytes, parsed_root, parsed_snapshot = cached_workspace_config(workspace["config_path"], workspace["sha256"])
        scope = request.form.get("scope", "")
        kind = request.form.get("policy_kind", "security")
        rulebase = request.form.get("rulebase", "pre")
        name = request.form.get("policy_name", "")
        _, policies = scoped_policies(xml_bytes, scope, kind, rulebase, parsed=(parsed_root, parsed_snapshot))
        before = next((item for item in policies if item["name"] == name and item["editable"]), None)
        if before is None:
            raise OfflineConfigError("Alleen een policy uit de geselecteerde scope kan hier worden gewijzigd")
        updated = copy.deepcopy(before)
        for field in OFFLINE_POLICY_FIELDS:
            updated[field] = split_values(request.form.get(field, ""))
        updated["action"] = request.form.get("action", "").strip()
        updated["description"] = request.form.get("description", "").strip()
        updated["log_setting"] = request.form.get("log_setting", "").strip()
        updated["schedule"] = request.form.get("schedule", "").strip()
        updated["disabled"] = request.form.get("disabled") == "yes"
        replacement_xml = update_xml_policy(updated)
        if replacement_xml == before["_xml"]:
            raise OfflineConfigError("Er zijn geen wijzigingen om te bewaren")
        draft_id = secrets.token_urlsafe(24)
        draft = {
            "workspace_id": workspace_id, "scope": scope, "kind": kind,
            "rulebase": rulebase, "policy_name": name,
            "fingerprint": offline_policy_fingerprint(before),
            "before": before, "after": updated,
            "replacement_xml": replacement_xml, "created_at": now(),
        }
        draft_path = POLICY_DRAFTS / f"offline-{draft_id}.json"
        draft_path.write_text(json.dumps(draft))
        draft_path.chmod(0o600)
        return render_template("workspace_policy_preview.html", workspace=workspace, draft_id=draft_id, draft=draft)
    except Exception as exc:
        flash(f"Wijziging niet voorbereid: {exc}", "error")
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id))


@app.post("/config-workspaces/policy-drafts/<draft_id>/apply")
@login_required
def config_workspace_policy_apply(draft_id):
    if not draft_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in draft_id):
        return "Not found", 404
    draft_path = POLICY_DRAFTS / f"offline-{draft_id}.json"
    if not draft_path.is_file():
        return "Not found", 404
    try:
        draft = json.loads(draft_path.read_text())
        workspace = workspace_row(int(draft["workspace_id"]))
        if not workspace:
            raise OfflineConfigError("De bronworkspace bestaat niet meer")
        new_xml = replace_policy_in_snapshot(
            workspace_config_path(workspace).read_bytes(), draft["scope"], draft["kind"],
            draft["rulebase"], draft["policy_name"], draft["fingerprint"], draft["replacement_xml"],
        )
        with db() as conn:
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)).fetchone()
        if not profile:
            raise OfflineConfigError("Het firewallprofiel bestaat niet meer")
        new_id = store_config_workspace(
            profile, f"{workspace['name']} · edit {now()}", workspace["original_name"], new_xml, "edit",
        )
        set_active_config_workspace(workspace["profile_id"], new_id)
        audit("config-workspace-policy-edited", f"source={workspace['id']} workspace={new_id} scope={draft['scope']} policy={draft['policy_name']}")
        draft_path.unlink(missing_ok=True)
        flash("Policy gewijzigd in een nieuwe workspaceversie; de bronsnapshot bleef onaangeroerd.", "success")
        return redirect(url_for("config_workspace_editor", workspace_id=new_id, scope=draft["scope"], policy_kind=draft["kind"], rulebase=draft["rulebase"]))
    except Exception as exc:
        flash(f"Wijziging niet bewaard: {exc}", "error")
        workspace_id = json.loads(draft_path.read_text()).get("workspace_id") if draft_path.is_file() else None
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id)) if workspace_id else redirect(url_for("index"))


@app.post("/profiles/<int:profile_id>/config-workspaces/upload")
@login_required
def config_workspace_upload(profile_id):
    with db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile or profile["target_type"] not in {"panorama", "panos"}:
        return "Not found", 404
    uploaded = request.files.get("config_file")
    if not uploaded or not uploaded.filename:
        flash("Kies eerst een volledige XML-configuratie.", "error")
        return redirect(url_for("index", policy_profile=profile_id) + "#policy-management")
    try:
        data = uploaded.read()
        workspace_id = store_config_workspace(
            profile,
            request.form.get("name", "").strip() or Path(uploaded.filename).stem,
            Path(uploaded.filename).name,
            data,
            "upload",
        )
        set_active_config_workspace(profile_id, workspace_id)
        flash("Volledige configuratie veilig geïmporteerd; het oorspronkelijke XML blijft behouden.", "success")
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id))
    except Exception as exc:
        flash(f"Configuratie niet geïmporteerd: {exc}", "error")
        return redirect(url_for("index", policy_profile=profile_id) + "#policy-management")


@app.post("/profiles/<int:profile_id>/config-workspaces/pull")
@login_required
def config_workspace_pull(profile_id):
    with db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile or profile["target_type"] not in {"panorama", "panos"}:
        return "Not found", 404
    try:
        _, endpoint, key, ctx = panos_profile_context(profile)
        root = policy_api.require_success(
            panos_api_post(endpoint, {"type": "config", "action": "get", "xpath": "/config", "key": key}, ctx),
            "volledige candidateconfiguratie ophalen",
        )
        config = root.find("./result/config")
        if config is None:
            raise RuntimeError("API-antwoord bevat geen volledige configuratie")
        xml_bytes = normalized_config_xml(config)
        workspace_id = store_config_workspace(
            profile,
            request.form.get("name", "").strip() or f"{profile['name']} candidate {now()}",
            "api-candidate.xml",
            xml_bytes,
            "api",
        )
        set_active_config_workspace(profile_id, workspace_id)
        flash("Volledige candidateconfiguratie via API opgehaald.", "success")
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id))
    except Exception as exc:
        flash(f"Volledige configuratie niet opgehaald: {exc}", "error")
        return redirect(url_for("index", policy_profile=profile_id) + "#policy-management")


@app.get("/config-workspaces/<int:workspace_id>/export/<kind>")
@login_required
def config_workspace_export(workspace_id, kind):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    path = workspace_config_path(workspace)
    safe_name = "".join(char if char.isalnum() or char in "-_." else "-" for char in workspace["name"]).strip("-.") or f"workspace-{workspace_id}"
    if kind == "xml":
        return send_file(path, as_attachment=True, download_name=f"{safe_name}.xml", mimetype="application/xml")
    if kind == "set":
        return Response(render_set_commands(path.read_bytes()), mimetype="text/plain", headers={"Content-Disposition": f'attachment; filename="{safe_name}.set.txt"'})
    return "Not found", 404


@app.get("/config-workspaces/<int:workspace_id>/push-preview")
@login_required
def config_workspace_push_preview(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    metadata = json.loads(workspace["metadata_json"] or "{}")
    return render_template("workspace_push.html", workspace=workspace, metadata=metadata)


@app.post("/config-workspaces/<int:workspace_id>/push")
@login_required
def config_workspace_push(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    if request.form.get("confirm_name", "") != workspace["name"]:
        flash("API-load gestopt: de workspacenaam kwam niet overeen.", "error")
        return redirect(url_for("config_workspace_push_preview", workspace_id=workspace_id))
    try:
        with db() as conn:
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)).fetchone()
        if not profile or profile["target_type"] not in {"panorama", "panos"}:
            raise RuntimeError("Dit target ondersteunt geen volledige PAN-OS XML-load")
        path = workspace_config_path(workspace)
        expected = "panorama" if profile["target_type"] == "panorama" else "panos"
        parse_snapshot(path.read_bytes(), expected_kind=expected)
        _, endpoint, key, ctx = panos_profile_context(profile)
        imported_name = f"ppf-workspace-{workspace_id}-{secrets.token_hex(4)}.xml"
        import_path = path.with_name(imported_name)
        shutil.copyfile(path, import_path)
        import_path.chmod(0o600)
        try:
            policy_api.require_success(
                policy_api.api_post_multipart(endpoint, {"type": "import", "category": "configuration", "key": key}, import_path, ctx),
                "volledige configuratie uploaden",
            )
            load_command = f"<load><config><from>{html.escape(imported_name, quote=False)}</from></config></load>"
            policy_api.require_success(
                panos_api_post(endpoint, {"type": "op", "cmd": load_command, "key": key}, ctx),
                "volledige configuratie naar candidate laden",
            )
        finally:
            import_path.unlink(missing_ok=True)
        audit("config-workspace-loaded", f"workspace={workspace_id} profile={profile['name']} sha256={workspace['sha256']}")
        flash("Volledige XML-configuratie via API naar de candidate geladen; er is niet gecommit.", "success")
    except Exception as exc:
        flash(f"Volledige XML niet geladen: {exc}", "error")
    return redirect(url_for("index", policy_profile=workspace["profile_id"]) + "#policy-management")


@app.post("/config-workspaces/<int:workspace_id>/delete")
@login_required
def config_workspace_delete(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    try:
        with db() as conn:
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)).fetchone()
        was_active = bool(profile and active_config_workspace_id(profile) == workspace_id)
        workspace_config_path(workspace).unlink(missing_ok=True)
        with db() as conn:
            conn.execute("DELETE FROM config_workspaces WHERE id=?", (workspace_id,))
        if was_active:
            set_active_config_workspace(workspace["profile_id"], None)
        audit("config-workspace-deleted", f"workspace={workspace_id} profile={workspace['profile_name']}")
        flash("Offline configuratieworkspace verwijderd.", "success")
    except Exception as exc:
        flash(f"Workspace niet verwijderd: {exc}", "error")
    return redirect(url_for("index", policy_profile=workspace["profile_id"]) + "#policy-management")


@app.get("/")
@login_required
def index():
    with db() as conn:
        profile_rows = conn.execute("SELECT * FROM profiles ORDER BY name").fetchall()
        sources = conn.execute("SELECT * FROM sources ORDER BY last_seen DESC LIMIT 100").fetchall()
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
        run_profile_id = request.args.get("run_profile", type=int)
        selected_run_profile = next((profile for profile in profiles if profile["id"] == run_profile_id), None)
        runs = []
        if selected_run_profile:
            with db() as run_conn:
                runs = run_conn.execute(
                    "SELECT runs.*,profiles.name profile_name FROM runs "
                    "JOIN profiles ON profiles.id=runs.profile_id "
                    "WHERE runs.profile_id=? AND runs.mode!='prepared' "
                    "AND (runs.status!='complete' OR runs.id IN ("
                    "SELECT id FROM runs WHERE profile_id=? AND mode!='prepared' AND status='complete' ORDER BY id DESC LIMIT 5"
                    ")) ORDER BY runs.id DESC",
                    (selected_run_profile["id"], selected_run_profile["id"]),
                ).fetchall()
        editing_id = request.args.get("edit_profile", type=int)
        editing_profile = next((profile for profile in profiles if profile["id"] == editing_id), None)
        selected_id = request.args.get("flow_profile", type=int)
        selected_flow_profile = next((profile for profile in profiles if profile["id"] == selected_id), None)
        flows = []
        if selected_flow_profile:
            serials = [selected_flow_profile["serial"], selected_flow_profile["passive_serial"]]
            serials = [serial for serial in dict.fromkeys(serials) if serial]
            if serials:
                placeholders = ",".join("?" for _ in serials)
                flows = conn.execute(f"SELECT * FROM flows WHERE serial IN ({placeholders}) ORDER BY last_seen DESC LIMIT 100", serials).fetchall()
    policy_profile = None; policies = []; policy_error = ""; policy_objects = []; object_catalog = []; policy_catalog = []; policy_workspaces = []
    policy_source = request.args.get("policy_source", "").strip()
    policy_view = request.args.get("policy_view", "policies")
    if policy_view not in {"policies", "objects", "network"}: policy_view = "policies"
    policy_kind = request.args.get("policy_kind", "security")
    object_type = request.args.get("object_type", "addresses")
    if object_type not in SCM_OBJECT_TYPES: object_type = "addresses"
    if policy_kind not in SCM_POLICY_TYPES: policy_kind = "security"
    policy_profile_id = request.args.get("policy_profile", type=int)
    if policy_profile_id:
        policy_profile = next((profile for profile in profiles if profile["id"] == policy_profile_id), None)
        if policy_profile:
            if policy_profile["target_type"] in {"panorama", "panos"}:
                with db() as conn:
                    policy_workspaces = conn.execute(
                        "SELECT * FROM config_workspaces WHERE profile_id=? ORDER BY id DESC",
                        (policy_profile["id"],),
                    ).fetchall()
                active_id = active_config_workspace_id(policy_profile)
                active_workspace = next((item for item in policy_workspaces if item["id"] == active_id), None)
                if policy_source != "choose" and active_workspace:
                    return redirect(url_for("config_workspace_editor", workspace_id=active_workspace["id"]))
                policy_source = "choose"
            else:
                policy_source = "live"
            if policy_source == "live":
                try:
                    if policy_view in {"objects", "network"}:
                        if policy_view == "network": object_type = "zones"
                        policy_objects = fetch_scm_objects(policy_profile, object_type)
                        object_catalog = fetch_object_catalog(policy_profile, object_type)
                    else:
                        policies = fetch_scm_policy_type(policy_profile, policy_kind)
                        policy_catalog = fetch_object_catalog(policy_profile, "policy-picker")
                except Exception as exc: policy_error = str(exc)
    return render_template("app.html", profiles=profiles, editing_profile=editing_profile, selected_flow_profile=selected_flow_profile, selected_run_profile=selected_run_profile, policy_profile=policy_profile, policy_source=policy_source, policy_workspaces=policy_workspaces, policies=policies, policy_objects=policy_objects, object_catalog=object_catalog, policy_catalog=policy_catalog, policy_view=policy_view, policy_kind=policy_kind, policy_types=SCM_POLICY_TYPES, unsupported_policy_types=SCM_UNAVAILABLE_POLICY_TYPES, object_type=object_type, object_types=SCM_OBJECT_TYPES, policy_error=policy_error, sources=sources, runs=runs, flows=flows, audits=audits, stats=stats())


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
        preserved_workspace_id = 0
        if profile_id:
            with db() as conn:
                existing_profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
            if existing_profile:
                preserved_workspace_id = active_config_workspace_id(existing_profile)
        target_type = request.form.get("target_type", "")
        if target_type not in TARGET_TYPES: raise ValueError("Onbekend targettype")
        rulebase = request.form.get("rulebase", "pre")
        if rulebase not in {"pre", "post"}: raise ValueError("Rulebase moet pre of post zijn")
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
            "endpoint": validate_panos_endpoint(request.form.get("endpoint", "")) if request.form.get("target_type") in {"panorama", "panos"} else "",
            "vsys": request.form.get("vsys", "vsys1").strip(),
            "device_group": request.form.get("device_group", "").strip(),
            "rulebase": rulebase,
            "folder": request.form.get("folder", "").strip(),
            "snippet": request.form.get("snippet", "").strip(),
            "device": request.form.get("device", "").strip(),
            "object_folder": request.form.get("object_folder", "").strip(),
            "log_profile": request.form.get("log_profile", "").strip(),
            "passive_serial": passive_serial,
            "passive_source_ip": optional_ip_address(request.form.get("passive_source_ip", "")),
        }
        if preserved_workspace_id:
            settings["config_workspace_id"] = preserved_workspace_id
        supplied = {k: request.form.get(k, "") for k in ("username", "password", "client_id", "client_secret", "tsg_id")}
        if target_type in {"panorama", "panos"} and not settings["endpoint"]:
            raise ValueError("Endpoint is verplicht voor Panorama en standalone PAN-OS")
        if target_type == "panorama" and not settings["device_group"]:
            raise ValueError("Device group is verplicht voor Panorama")
        if target_type == "scm" and sum(bool(settings[k]) for k in ("folder", "snippet", "device")) != 1:
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
            values = (request.form["name"].strip(), request.form.get("enabled") == "on", active_serial, optional_ip_address(request.form.get("source_ip", "")), target_type, json.dumps(settings), blob, now())
            if profile_id:
                conn.execute("UPDATE profiles SET name=?,enabled=?,serial=?,source_ip=?,target_type=?,settings_json=?,secret_blob=?,updated_at=? WHERE id=?", (*values, profile_id))
            else:
                cursor = conn.execute("INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", (*values, now()))
                profile_id = int(cursor.lastrowid)
        invalidate_profile_caches(profile_id)
        refresh_syslog_source_policy()
        audit("profile-saved", request.form["name"]); flash("Firewallprofiel opgeslagen.", "success")
    except Exception as exc:
        flash(f"Profiel niet opgeslagen: {exc}", "error")
    return redirect(url_for("index") + "#profiles")


@app.post("/profiles/<int:profile_id>/delete")
@login_required
def profile_delete(profile_id):
    try:
        with db() as conn:
            row = conn.execute("SELECT name FROM profiles WHERE id=?", (profile_id,)).fetchone()
            if not row: return "Not found", 404
            run_count = conn.execute("SELECT COUNT(*) FROM runs WHERE profile_id=?", (profile_id,)).fetchone()[0]
            if run_count: raise ValueError(f"Verwijder eerst de {run_count} policy run(s) van dit profiel")
            conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))
            deleted_name = row["name"]
        invalidate_profile_caches(profile_id)
        refresh_syslog_source_policy()
        audit("profile-deleted", deleted_name)
        flash("Profiel verwijderd.", "success")
    except Exception as exc:
        flash(f"Profiel niet verwijderd: {exc}", "error")
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


def write_config(profile, run_dir: Path, push: bool, disabled_override: bool | None = None) -> dict:
    s = json.loads(profile["settings_json"]); secret = json.loads(fernet.decrypt(profile["secret_blob"]).decode()) if profile["secret_blob"] else {}
    target = profile["target_type"]
    if target not in TARGET_TYPES: raise ValueError("Onbekend targettype")
    if target in {"panorama", "panos"}: s["endpoint"] = validate_panos_endpoint(s.get("endpoint", ""))
    generated_disabled = s.get("disabled") if disabled_override is None else disabled_override
    lines = [
        "[deployment]", f"panorama = {'true' if target == 'panorama' else 'false'}", f"scm = {'true' if target == 'scm' else 'false'}", "",
        "[builder]", 'logs = ["flows.csv"]', 'xml_output = "policy.xml"', 'review_csv = "review.csv"', 'ptr_cache_file = "ptr-cache.json"',
        f"disabled = {'true' if generated_disabled else 'false'}", "tags = [" + ",".join(toml_string(x) for x in s.get("tags", [])) + "]",
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


def spreadsheet_safe(value: str) -> str:
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r")):
        return "'" + text
    return text


@app.post("/policies/<int:profile_id>/preview")
@login_required
def policy_bulk_preview(profile_id):
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile: return "Not found", 404
    selected_ids = set(request.form.getlist("policy_id"))
    policy_kind = request.form.get("policy_kind", "security")
    if policy_kind not in SCM_POLICY_TYPES or (profile["target_type"] == "scm" and policy_kind in SCM_UNAVAILABLE_POLICY_TYPES): return "Not found", 404
    if not selected_ids:
        flash("Selecteer minstens één policy.", "error")
        return redirect(url_for("index", policy_profile=profile_id, policy_kind=policy_kind) + "#policy-management")
    operations = {}
    for field in POLICY_LIST_FIELDS:
        operations[field] = {"add": split_values(request.form.get(f"{field}_add", "")), "remove": split_values(request.form.get(f"{field}_remove", ""))}
    for field in ("action", "log_setting", "profile_group"):
        operations[field] = request.form.get(field) or None
    operations["description_append"] = request.form.get("description_append", "").strip()
    disabled = request.form.get("disabled", "")
    operations["disabled"] = disabled == "true" if disabled in {"true", "false"} else None
    try:
        current = fetch_scm_policy_type(profile, policy_kind)
        selected = [policy for policy in current if policy["id"] in selected_ids]
        if len(selected) != len(selected_ids): raise ValueError("Niet alle geselecteerde policies bestaan nog. Vernieuw de rulebase.")
        changes = []; zones_changed = profile["target_type"] != "panorama" and any(operations[field]["add"] or operations[field]["remove"] for field in ("from", "to")); zone_names = {item.get("name", "") for item in fetch_scm_objects(profile, "zones")} if zones_changed else set()
        for policy in selected:
            updated = apply_bulk_operations(policy, operations)
            if zones_changed: validate_policy_zones(updated, zone_names)
            if updated != policy:
                changes.append({"before": policy, "after": updated, "fingerprint": policy_fingerprint(policy)})
        if not changes: raise ValueError("De gekozen bulkbewerking veroorzaakt geen wijzigingen.")
        draft_id = secrets.token_urlsafe(18)
        draft = {"profile_id": profile_id, "policy_kind": policy_kind, "created_at": now(), "changes": changes}
        path = POLICY_DRAFTS / f"{draft_id}.json"; path.write_text(json.dumps(draft)); path.chmod(0o600)
        audit("policy-bulk-preview", f"profile={profile['name']} rules={len(changes)}")
        return render_template("policy_preview.html", profile=profile, changes=changes, draft_id=draft_id, policy_kind=policy_kind, policy_label=SCM_POLICY_TYPES[policy_kind][2])
    except Exception as exc:
        flash(f"Bulk-preview mislukt: {exc}", "error")
        return redirect(url_for("index", policy_profile=profile_id, policy_kind=policy_kind) + "#policy-management")


@app.post("/policies/<int:profile_id>/single-preview")
@login_required
def policy_single_preview(profile_id):
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile: return "Not found", 404
    policy_kind = request.form.get("policy_kind", "security")
    if policy_kind not in SCM_POLICY_TYPES or (profile["target_type"] == "scm" and policy_kind in SCM_UNAVAILABLE_POLICY_TYPES): return "Not found", 404
    policy_id = request.form.get("policy_id", "").strip()
    try:
        current = fetch_scm_policy_type(profile, policy_kind)
        policy = next((item for item in current if item["id"] == policy_id), None)
        if not policy: raise ValueError("De policy bestaat niet meer. Vernieuw de rulebase.")
        replacements = {}
        for field in POLICY_LIST_FIELDS:
            if request.form.get(f"{field}_present") == "1":
                values = split_values(request.form.get(field, ""))
                replacements[field] = values or ([] if field == "tag" else ["any"])
        for field in ("action", "log_setting", "profile_group", "schedule"):
            if request.form.get(f"{field}_present") == "1": replacements[field] = request.form.get(field, "").strip()
        if request.form.get("description_present") == "1": replacements["description"] = request.form.get("description", "").strip()
        if request.form.get("disabled_present") == "1": replacements["disabled"] = request.form.get("disabled") == "true"
        updated = apply_single_replacements(policy, replacements)
        if profile["target_type"] != "panorama" and (updated.get("from") != policy.get("from") or updated.get("to") != policy.get("to")):
            validate_policy_zones(updated, {item.get("name", "") for item in fetch_scm_objects(profile, "zones")})
        if updated == policy: raise ValueError("De policy bevat geen wijzigingen.")
        draft_id = secrets.token_urlsafe(18)
        changes = [{"before": policy, "after": updated, "fingerprint": policy_fingerprint(policy)}]
        draft = {"profile_id": profile_id, "policy_kind": policy_kind, "created_at": now(), "changes": changes}
        path = POLICY_DRAFTS / f"{draft_id}.json"; path.write_text(json.dumps(draft)); path.chmod(0o600)
        audit("policy-single-preview", f"profile={profile['name']} rule={policy['name']}")
        return render_template("policy_preview.html", profile=profile, changes=changes, draft_id=draft_id, policy_kind=policy_kind, policy_label=SCM_POLICY_TYPES[policy_kind][2])
    except Exception as exc:
        flash(f"Policy-preview mislukt: {exc}", "error")
        return redirect(url_for("index", policy_profile=profile_id, policy_kind=policy_kind) + "#policy-management")


@app.post("/objects/<int:profile_id>/<object_type>/preview")
@login_required
def object_preview(profile_id, object_type):
    if object_type not in SCM_OBJECT_TYPES or not SCM_OBJECT_TYPES[object_type]["creatable"]: return "Not found", 404
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile: return "Not found", 404
    try:
        container = {}
        if profile["target_type"] == "scm":
            scm, _, _, _ = scm_client(profile)
            container = policy_api.scm_container(folder=scm.scm_folder if object_type == "zones" else scm.scm_object_folder, snippet=scm.scm_snippet, device=scm.scm_device)
        payload = scm_object_payload(object_type, request.form, container)
        existing = fetch_scm_objects(profile, object_type)
        object_id = request.form.get("object_id", "").strip()
        before = next((item for item in existing if str(item.get("id", "")) == object_id), None) if object_id else None
        if object_id and not before: raise ValueError("Het object bestaat niet meer. Vernieuw de lijst.")
        validate_object_payload(payload, object_type, existing, object_id)
        draft_id = secrets.token_urlsafe(18)
        draft = {"profile_id": profile_id, "created_at": now(), "object_type": object_type, "operation": "update" if before else "create", "payload": payload, "before": before, "fingerprint": object_fingerprint(before) if before else "", "scope_xpath": before.get("_scope_xpath", "") if before else ""}
        path = OBJECT_DRAFTS / f"{draft_id}.json"; path.write_text(json.dumps(draft)); path.chmod(0o600)
        audit("object-preview", f"profile={profile['name']} operation={draft['operation']} type={object_type} name={payload['name']}")
        return render_template("object_preview.html", profile=profile, object_type=object_type, object_label=SCM_OBJECT_TYPES[object_type]["label"], payload=payload, before=before, operation=draft["operation"], draft_id=draft_id)
    except Exception as exc:
        flash(f"Object-preview mislukt: {exc}", "error")
        return redirect(url_for("index", policy_profile=profile_id, policy_view=managed_view(object_type), object_type=object_type) + "#policy-management")


@app.post("/objects/<int:profile_id>/<object_type>/delete-preview")
@login_required
def object_delete_preview(profile_id, object_type):
    if object_type not in SCM_OBJECT_TYPES or not SCM_OBJECT_TYPES[object_type]["creatable"]: return "Not found", 404
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile: return "Not found", 404
    try:
        selected_ids = set(request.form.getlist("object_id"))
        if not selected_ids: raise ValueError("Selecteer minstens één object")
        current = fetch_scm_objects(profile, object_type)
        selected = [item for item in current if str(item.get("id", "")) in selected_ids]
        if len(selected) != len(selected_ids): raise ValueError("Niet alle geselecteerde objecten bestaan nog. Vernieuw de lijst.")
        draft_id = secrets.token_urlsafe(18)
        draft = {"profile_id": profile_id, "created_at": now(), "object_type": object_type, "operation": "delete", "objects": [{"value": item, "fingerprint": object_fingerprint(item)} for item in selected]}
        path = OBJECT_DRAFTS / f"{draft_id}.json"; path.write_text(json.dumps(draft)); path.chmod(0o600)
        audit("object-delete-preview", f"profile={profile['name']} type={object_type} count={len(selected)}")
        return render_template("object_preview.html", profile=profile, object_type=object_type, object_label=SCM_OBJECT_TYPES[object_type]["label"], delete_objects=selected, operation="delete", draft_id=draft_id)
    except Exception as exc:
        flash(f"Delete-preview mislukt: {exc}", "error")
        return redirect(url_for("index", policy_profile=profile_id, policy_view=managed_view(object_type), object_type=object_type) + "#policy-management")


@app.post("/objects/drafts/<draft_id>/push")
@login_required
def object_push(draft_id):
    if not draft_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in draft_id): return "Not found", 404
    path = OBJECT_DRAFTS / f"{draft_id}.json"
    if not path.exists(): return "Not found", 404
    draft = json.loads(path.read_text())
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (draft["profile_id"],)).fetchone()
    if not profile: return "Not found", 404
    try:
        object_type = draft["object_type"]
        current = fetch_scm_objects(profile, object_type)
        operation = draft.get("operation", "create")
        if operation == "create":
            validate_object_payload(draft["payload"], object_type, current)
        elif operation == "update":
            before = draft["before"]; live = next((item for item in current if str(item.get("id", "")) == str(before.get("id", ""))), None)
            if not live or object_fingerprint(live) != draft["fingerprint"]: raise RuntimeError(f"Object {before['name']} is intussen gewijzigd; Push gestopt.")
            validate_object_payload(draft["payload"], object_type, current, str(before["id"]))
        elif operation == "delete":
            for entry in draft["objects"]:
                before = entry["value"]; live = next((item for item in current if str(item.get("id", "")) == str(before.get("id", ""))), None)
                if not live or object_fingerprint(live) != entry["fingerprint"]: raise RuntimeError(f"Object {before['name']} is intussen gewijzigd; Delete gestopt.")
        else: raise RuntimeError("Onbekende objectbewerking")
        if profile["target_type"] == "scm":
            scm, token, _, _ = scm_client(profile)
            service = "network" if object_type == "zones" else "objects"
            root = policy_api.scm_api_root(scm.scm_api_base) + f"/config/{service}/v1"
            container = policy_api.scm_container(folder=scm.scm_folder if object_type == "zones" else scm.scm_object_folder, snippet=scm.scm_snippet, device=scm.scm_device)
            if operation == "create": policy_api.scm_http_request("POST", f"{root}/{object_type}", token, payload=draft["payload"])
            elif operation == "update": policy_api.scm_http_request("PUT", f"{root}/{object_type}/{draft['before']['id']}", token, payload=draft["payload"])
            else:
                for entry in draft["objects"]: policy_api.scm_http_request("DELETE", f"{root}/{object_type}/{entry['value']['id']}", token, params=container)
        else:
            write_panos_object_draft(profile, draft)
        path.unlink()
        count = len(draft.get("objects", [])) or 1
        audit("object-candidate", f"profile={profile['name']} operation={operation} type={object_type} count={count}")
        flash(f"Objectbewerking ({operation}) geschreven naar {profile['target_type'].upper()} candidate.", "success")
    except Exception as exc:
        flash(f"Object-Push gestopt: {exc}", "error")
    return redirect(url_for("index", policy_profile=profile["id"], policy_view=managed_view(draft["object_type"]), object_type=draft["object_type"]) + "#policy-management")


@app.post("/policies/drafts/<draft_id>/push")
@login_required
def policy_bulk_push(draft_id):
    if not draft_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in draft_id): return "Not found", 404
    path = POLICY_DRAFTS / f"{draft_id}.json"
    if not path.exists(): return "Not found", 404
    draft = json.loads(path.read_text())
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (draft["profile_id"],)).fetchone()
    if not profile: return "Not found", 404
    try:
        policy_kind = draft.get("policy_kind", "security")
        current = {policy["id"]: policy for policy in fetch_scm_policy_type(profile, policy_kind)}
        for change in draft["changes"]:
            live = current.get(change["before"]["id"])
            if not live or policy_fingerprint(live) != change["fingerprint"]:
                raise RuntimeError(f"Policy {change['before']['name']} is intussen gewijzigd; Push gestopt.")
        for change in draft["changes"]:
            write_target_policy(profile, policy_kind, change["after"])
        path.unlink()
        audit("policy-bulk-candidate", f"profile={profile['name']} rules={len(draft['changes'])}")
        flash(f"{len(draft['changes'])} {SCM_POLICY_TYPES[policy_kind][2]} policies bijgewerkt in {profile['target_type'].upper()} candidate.", "success")
        return redirect(url_for("index", policy_profile=profile["id"], policy_kind=policy_kind) + "#policy-management")
    except Exception as exc:
        flash(f"Bulk-Push gestopt: {exc}", "error")
        return redirect(url_for("index", policy_profile=profile["id"], policy_kind=draft.get("policy_kind", "security")) + "#policy-management")


def build_fingerprint(profile, include_flows: bool = True) -> str:
    serials = profile_serials(profile)
    flow_state = []
    if include_flows and serials:
        placeholders = ",".join("?" for _ in serials)
        with flow_store._connect() as conn:
            flow_state = list(conn.execute(
                f"SELECT serial,COUNT(*) count,MAX(last_seen) last_seen,SUM(repeat) sessions,SUM(bytes) bytes FROM flows WHERE action='allow' AND serial IN ({placeholders}) GROUP BY serial ORDER BY serial",
                serials,
            ))
    builder_settings = json.loads(profile["settings_json"] or "{}")
    builder_settings.pop("config_workspace_id", None)
    state = {
        "profile": {
            **{key: profile[key] for key in ("id", "enabled", "serial", "source_ip", "target_type", "updated_at")},
            "settings_json": json.dumps(builder_settings, sort_keys=True, separators=(",", ":")),
        },
        "secret": hashlib.sha256(bytes(profile["secret_blob"] or b"")).hexdigest(),
        "builder": hashlib.sha256((BASE / "vendor/bdnd_panos_policy_builder.py").read_bytes()).hexdigest(),
    }
    if include_flows: state["flows"] = [dict(row) for row in flow_state]
    return hashlib.sha256(json.dumps(state, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def remove_run_artifacts(run) -> None:
    runs_root = RUNS.resolve()
    run_path = Path(run["run_dir"]).resolve()
    try:
        run_path.relative_to(runs_root)
    except ValueError as exc:
        raise RuntimeError(f"Refused to delete run outside runs root: {run_path}") from exc
    if run_path == runs_root:
        raise RuntimeError("Refused to delete runs root")
    if run_path.exists():
        if not run_path.is_dir():
            raise RuntimeError(f"Run artifact path is not a directory: {run_path}")
        shutil.rmtree(run_path)


def prune_successful_run_history(profile_id: int, keep: int = 5) -> int:
    with db() as conn:
        old_runs = conn.execute(
            "SELECT * FROM runs WHERE profile_id=? AND mode!='prepared' AND status='complete' "
            "ORDER BY id DESC LIMIT -1 OFFSET ?",
            (profile_id, keep),
        ).fetchall()
    removed = 0
    for old_run in old_runs:
        remove_run_artifacts(old_run)
        with db() as conn:
            conn.execute("DELETE FROM runs WHERE id=? AND status='complete'", (old_run["id"],))
        removed += 1
    return removed


def execute_run(profile, mode: str, disabled_override: bool | None = None, prepared=None) -> int:
    push = mode == "push"
    run_dir = RUNS / (datetime.now().strftime("%Y%m%d-%H%M%S") + f"-{profile['id']}-{secrets.token_hex(3)}")
    run_dir.mkdir(mode=0o700)
    with db() as conn:
        cur = conn.execute("INSERT INTO runs(profile_id,mode,status,started_at,run_dir) VALUES(?,?,?,?,?)", (profile["id"], mode, "running", now(), str(run_dir)))
        run_id = cur.lastrowid
    try:
        profile_fingerprint = build_fingerprint(profile, include_flows=False)
        flow_fingerprint = build_fingerprint(profile, include_flows=True)
        if prepared:
            shutil.copy(Path(prepared["run_dir"]) / "flows.csv", run_dir / "flows.csv")
            shutil.copy(Path(prepared["run_dir"]) / "policy.xml", run_dir / "policy.xml")
            shutil.copy(Path(prepared["run_dir"]) / "review.csv", run_dir / "review.csv")
            ptr_cache = Path(prepared["run_dir"]) / "ptr-cache.json"
            if ptr_cache.exists(): shutil.copy(ptr_cache, run_dir / "ptr-cache.json")
            count = 1
        else:
            count = export_profile_flows(profile, run_dir / "flows.csv")
        if not count: raise ValueError("Geen geaggregeerde flows voor deze firewall")
        shutil.copy(BASE / "vendor/bdnd_panos_policy_builder.py", run_dir)
        shutil.copy(BASE / "vendor/bdnd_bpa_policy_builder.py", run_dir)
        run_secret = write_config(profile, run_dir, push, disabled_override)
        run_env = {**os.environ,
            "PPF_PANOS_USERNAME": run_secret.get("username", ""), "PPF_PANOS_PASSWORD": run_secret.get("password", ""),
            "PPF_SCM_CLIENT_ID": run_secret.get("client_id", ""), "PPF_SCM_CLIENT_SECRET": run_secret.get("client_secret", ""),
            "PPF_SCM_TSG_ID": run_secret.get("tsg_id", ""),
            "PPF_SCM_DEPLOY_DEVICES": ",".join(profile_serials(profile)) if push and profile["target_type"] == "scm" else ""}
        if prepared: run_env["PPF_PUSH_PREBUILT"] = "1"
        result = subprocess.run([sys.executable, "bdnd_panos_policy_builder.py"], cwd=run_dir, env=run_env, capture_output=True, text=True, timeout=1800)
        run_secret = {}; run_env = {}
        output = (result.stdout + "\n" + result.stderr)[-12000:]
        if result.returncode: raise RuntimeError(output)
        with (run_dir / "review.csv").open(newline="") as fh: rules = sum(1 for _ in csv.DictReader(fh))
        (run_dir / "fingerprint").write_text(json.dumps({
            "profile": profile_fingerprint,
            "flows": flow_fingerprint,
            "prepared_at": int(time.time()),
        }))
        with db() as conn: conn.execute("UPDATE runs SET status='complete',finished_at=?,rule_count=?,output=? WHERE id=?", (now(), rules, output, run_id))
        if mode != "prepared":
            try:
                removed = prune_successful_run_history(profile["id"])
                if removed:
                    audit("policy-run-retention", f"profile={profile['name']} removed={removed} kept=5")
            except Exception:
                app.logger.exception("policy-run retention cleanup failed for profile %s", profile["id"])
        audit("policy-prepared" if mode == "prepared" else "candidate-written" if push else "policy-preview", f"profile={profile['name']} run={run_id} rules={rules} reused={bool(prepared)} disabled={disabled_override if push else 'profile-default'}")
        return run_id
    except Exception as exc:
        with db() as conn: conn.execute("UPDATE runs SET status='failed',finished_at=?,output=? WHERE id=?", (now(), str(exc)[-12000:], run_id))
        audit("build-failed", f"profile={profile['name']} run={run_id} mode={mode}")
        if mode != "prepared": raise
        return run_id


def fresh_prepared_run(profile):
    profile_fingerprint = build_fingerprint(profile, include_flows=False)
    with db() as conn:
        candidates = conn.execute("SELECT * FROM runs WHERE profile_id=? AND mode='prepared' AND status='complete' ORDER BY id DESC LIMIT 3", (profile["id"],)).fetchall()
    for candidate in candidates:
        marker = Path(candidate["run_dir"]) / "fingerprint"
        if marker.exists():
            try:
                metadata = json.loads(marker.read_text())
                if metadata["profile"] == profile_fingerprint and time.time() - int(metadata["prepared_at"]) <= PREPARE_MAX_AGE:
                    return candidate
            except (KeyError, ValueError, TypeError, json.JSONDecodeError):
                continue
    return None


@app.post("/profiles/<int:profile_id>/build")
@login_required
def build(profile_id):
    push = request.form.get("mode") == "push"
    disabled_override = None
    if push and request.form.get("disabled_override") in {"true", "false"}:
        disabled_override = request.form["disabled_override"] == "true"
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile: return "Not found", 404
    try:
        prepared = fresh_prepared_run(profile) if push else None
        run_id = execute_run(profile, "push" if push else "preview", disabled_override, prepared)
        with db() as conn: completed = conn.execute("SELECT rule_count FROM runs WHERE id=?", (run_id,)).fetchone()
        suffix = " Voorbereide berekening hergebruikt." if prepared else ""
        flash(("Candidateconfiguratie geschreven; geen commit/deployment uitgevoerd." if push else "Policy-preview gegenereerd.") + f" {completed['rule_count']} regels.{suffix}", "success")
    except Exception as exc:
        flash(f"Run mislukt: {exc}", "error")
        with db() as conn: failed = conn.execute("SELECT id FROM runs WHERE profile_id=? ORDER BY id DESC LIMIT 1", (profile_id,)).fetchone()
        run_id = failed["id"] if failed else 0
    return redirect(url_for("run_detail", run_id=run_id))


def prepare_loop():
    time.sleep(PREPARE_INITIAL_DELAY)
    while True:
        try:
            with db() as conn: profiles = conn.execute("SELECT * FROM profiles WHERE enabled=1 ORDER BY id").fetchall()
            for profile in profiles:
                if not profile_serials(profile):
                    continue
                if fresh_prepared_run(profile): continue
                execute_run(profile, "prepared")
                with db() as conn:
                    old = conn.execute("SELECT * FROM runs WHERE profile_id=? AND mode='prepared' ORDER BY id DESC LIMIT -1 OFFSET 1", (profile["id"],)).fetchall()
                for run in old:
                    path = Path(run["run_dir"])
                    if path.exists() and path.is_dir(): shutil.rmtree(path)
                    with db() as conn: conn.execute("DELETE FROM runs WHERE id=?", (run["id"],))
        except Exception:
            app.logger.exception("scheduled policy preparation failed")
        time.sleep(PREPARE_INTERVAL)


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


@app.post("/runs/<int:run_id>/delete")
@login_required
def run_delete(run_id):
    with db() as conn:
        run = conn.execute(
            "SELECT runs.*,profiles.name profile_name FROM runs JOIN profiles ON profiles.id=runs.profile_id WHERE runs.id=?",
            (run_id,),
        ).fetchone()
    if not run:
        return "Not found", 404
    if run["status"] == "running":
        flash("Een actieve policy-run kan niet worden verwijderd.", "error")
        return redirect(url_for("index", run_profile=run["profile_id"]) + "#runs")

    runs_root = RUNS.resolve()
    run_path = Path(run["run_dir"]).resolve()
    try:
        run_path.relative_to(runs_root)
    except ValueError:
        app.logger.error("Refused to delete run outside runs root: %s", run_path)
        flash("Run niet verwijderd: ongeldig artifactpad.", "error")
        return redirect(url_for("index", run_profile=run["profile_id"]) + "#runs")
    if run_path == runs_root:
        flash("Run niet verwijderd: ongeldig artifactpad.", "error")
        return redirect(url_for("index", run_profile=run["profile_id"]) + "#runs")
    if run_path.exists():
        if not run_path.is_dir():
            flash("Run niet verwijderd: artifactpad is geen map.", "error")
            return redirect(url_for("index", run_profile=run["profile_id"]) + "#runs")
        shutil.rmtree(run_path)
    with db() as conn:
        conn.execute("DELETE FROM runs WHERE id=?", (run_id,))
    audit("policy-run-deleted", f"run={run_id} profile={run['profile_name']}")
    flash(f"Policy-run #{run_id} en bijhorende artifacts verwijderd.", "success")
    return redirect(url_for("index", run_profile=run["profile_id"]) + "#runs")


@app.get("/runs/<int:run_id>/<kind>")
@login_required
def run_download(run_id, kind):
    with db() as conn: run=conn.execute("SELECT * FROM runs WHERE id=?",(run_id,)).fetchone()
    if not run: return "Not found",404
    names={"csv":"review.csv","xml":"policy.xml"}; name=names.get(kind)
    if not name: return "Not found",404
    path=Path(run["run_dir"])/name
    if kind == "csv":
        if not path.exists(): return "Not found", 404
        output = io.StringIO()
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            writer = csv.DictWriter(output, fieldnames=reader.fieldnames or [], lineterminator="\n")
            writer.writeheader()
            for row in reader: writer.writerow({key: spreadsheet_safe(value) for key, value in row.items()})
        return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f'attachment; filename="pa-policy-forge-run-{run_id}-{name}"'})
    return send_file(path, as_attachment=True, download_name=f"pa-policy-forge-run-{run_id}-{name}")


def udp_loop():
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            flow=parse_panos_syslog(self.request[0].decode("utf-8",errors="replace"))
            if not flow: return
            source=self.client_address[0]
            if not syslog_source_allowed(flow.serial, source): return
            flow_store.add_flow(flow); timestamp=now()
            with db() as conn:
                conn.execute("INSERT INTO sources(serial,source_ip,first_seen,last_seen,messages) VALUES(?,?,?,?,1) ON CONFLICT(serial,source_ip) DO UPDATE SET last_seen=excluded.last_seen,messages=messages+1", (flow.serial,source,timestamp,timestamp))
    server=socketserver.ThreadingUDPServer(("0.0.0.0", int(os.getenv("PPF_SYSLOG_PORT","514"))),Handler); server.daemon_threads=True; server.serve_forever()


refresh_syslog_source_policy()
threading.Thread(target=udp_loop,daemon=True,name="syslog-udp").start()
threading.Thread(target=quota_loop,daemon=True,name="storage-quota").start()
threading.Thread(target=prepare_loop,daemon=True,name="policy-prepare").start()

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=8080)
