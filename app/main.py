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
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from functools import wraps

from cryptography.fernet import Fernet
from flask import Flask, Response, flash, has_request_context, redirect, render_template, request, send_file, session, url_for

from vendor.paloalto_light_syslog import FlowStore, parse_panos_syslog
from app.policy_bulk import POLICY_LIST_FIELDS, apply_bulk_operations, apply_single_replacements

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

app = Flask(__name__)
DATA.mkdir(parents=True, exist_ok=True)
RUNS.mkdir(parents=True, exist_ok=True)
SECRETS.mkdir(parents=True, exist_ok=True)
POLICY_DRAFTS.mkdir(parents=True, exist_ok=True)
OBJECT_DRAFTS.mkdir(parents=True, exist_ok=True)
OBJECT_CACHE.mkdir(parents=True, exist_ok=True)

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


def secret_file(name: str, generator) -> bytes:
    path = SECRETS / name
    if not path.exists():
        path.write_bytes(generator())
        path.chmod(0o600)
    return path.read_bytes().strip()


app.secret_key = secret_file("session.key", lambda: secrets.token_bytes(64))
fernet = Fernet(secret_file("encryption.key", Fernet.generate_key))
flow_store = FlowStore(FLOW_DB, retention_days=0)
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
    endpoint = settings.get("endpoint", "").rstrip("/")
    if not endpoint: raise ValueError("PAN-OS/Panorama endpoint ontbreekt")
    ctx = ssl._create_unverified_context()
    key_root = policy_api.require_success(policy_api.api_get(endpoint, {"type": "keygen", "user": secret.get("username", ""), "password": secret.get("password", "")}, ctx), "keygen")
    key = key_root.findtext(".//key")
    if not key: raise RuntimeError("API key generation gaf geen sleutel terug")
    return settings, endpoint, key, ctx


def panos_api_post(endpoint: str, params: dict, ctx: ssl.SSLContext) -> str:
    request_body = urllib.parse.urlencode(params).encode()
    api_request = urllib.request.Request(endpoint.rstrip("/") + "/api/", data=request_body, headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
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
            key = (int(profile["id"]), kind)
            with _catalog_refresh_lock:
                if key not in _catalog_refreshing:
                    _catalog_refreshing.add(key)
                    def refresh_catalog(profile=profile, kind=kind, cache_path=cache_path, key=key):
                        try:
                            fresh = fetch_scm_objects(profile, kind)
                            cache_path.write_text(json.dumps(fresh)); cache_path.chmod(0o600)
                        finally:
                            with _catalog_refresh_lock: _catalog_refreshing.discard(key)
                    threading.Thread(target=refresh_catalog, name=f"catalog-{profile['id']}-{kind}", daemon=True).start()
        elif cached is None or stale:
            try:
                cached = fetch_scm_objects(profile, kind)
                cache_path.write_text(json.dumps(cached)); cache_path.chmod(0o600)
            except Exception:
                if cached is None and object_type != "policy-picker": raise
        cached = cached or []
        catalog.extend({"name": item.get("name", ""), "kind": kind} for item in cached if item.get("name"))
    return sorted(catalog, key=lambda item: (item["name"].lower(), item["kind"]))


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
    entry = ET.fromstring(policy["_xml"])
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
        flows = []
        if selected_flow_profile:
            serials = [selected_flow_profile["serial"], selected_flow_profile["passive_serial"]]
            serials = [serial for serial in dict.fromkeys(serials) if serial]
            if serials:
                placeholders = ",".join("?" for _ in serials)
                flows = conn.execute(f"SELECT * FROM flows WHERE serial IN ({placeholders}) ORDER BY last_seen DESC LIMIT 100", serials).fetchall()
    policy_profile = None; policies = []; policy_error = ""; policy_objects = []; object_catalog = []; policy_catalog = []
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
            try:
                if policy_view in {"objects", "network"}:
                    if policy_view == "network": object_type = "zones"
                    policy_objects = fetch_scm_objects(policy_profile, object_type)
                    object_catalog = fetch_object_catalog(policy_profile, object_type)
                else:
                    policies = fetch_scm_policy_type(policy_profile, policy_kind)
                    policy_catalog = fetch_object_catalog(policy_profile, "policy-picker")
            except Exception as exc: policy_error = str(exc)
    return render_template("app.html", profiles=profiles, editing_profile=editing_profile, selected_flow_profile=selected_flow_profile, policy_profile=policy_profile, policies=policies, policy_objects=policy_objects, object_catalog=object_catalog, policy_catalog=policy_catalog, policy_view=policy_view, policy_kind=policy_kind, policy_types=SCM_POLICY_TYPES, unsupported_policy_types=SCM_UNAVAILABLE_POLICY_TYPES, object_type=object_type, object_types=SCM_OBJECT_TYPES, policy_error=policy_error, sources=sources, runs=runs, flows=flows, audits=audits, stats=stats())


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


def write_config(profile, run_dir: Path, push: bool, disabled_override: bool | None = None) -> dict:
    s = json.loads(profile["settings_json"]); secret = json.loads(fernet.decrypt(profile["secret_blob"]).decode()) if profile["secret_blob"] else {}
    target = profile["target_type"]
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
    state = {
        "profile": {key: profile[key] for key in ("id", "enabled", "serial", "source_ip", "target_type", "settings_json", "updated_at")},
        "secret": hashlib.sha256(bytes(profile["secret_blob"] or b"")).hexdigest(),
        "builder": hashlib.sha256((BASE / "vendor/bdnd_panos_policy_builder.py").read_bytes()).hexdigest(),
    }
    if include_flows: state["flows"] = [dict(row) for row in flow_state]
    return hashlib.sha256(json.dumps(state, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


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
            "PPF_SCM_TSG_ID": run_secret.get("tsg_id", "")}
        if prepared: run_env["PPF_PUSH_PREBUILT"] = "1"
        result = subprocess.run(["python3", "bdnd_panos_policy_builder.py"], cwd=run_dir, env=run_env, capture_output=True, text=True, timeout=1800)
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
        return redirect(url_for("index") + "#runs")

    runs_root = RUNS.resolve()
    run_path = Path(run["run_dir"]).resolve()
    try:
        run_path.relative_to(runs_root)
    except ValueError:
        app.logger.error("Refused to delete run outside runs root: %s", run_path)
        flash("Run niet verwijderd: ongeldig artifactpad.", "error")
        return redirect(url_for("index") + "#runs")
    if run_path == runs_root:
        flash("Run niet verwijderd: ongeldig artifactpad.", "error")
        return redirect(url_for("index") + "#runs")
    if run_path.exists():
        if not run_path.is_dir():
            flash("Run niet verwijderd: artifactpad is geen map.", "error")
            return redirect(url_for("index") + "#runs")
        shutil.rmtree(run_path)
    with db() as conn:
        conn.execute("DELETE FROM runs WHERE id=?", (run_id,))
    audit("policy-run-deleted", f"run={run_id} profile={run['profile_name']}")
    flash(f"Policy-run #{run_id} en bijhorende artifacts verwijderd.", "success")
    return redirect(url_for("index") + "#runs")


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
threading.Thread(target=prepare_loop,daemon=True,name="policy-prepare").start()

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=8080)
