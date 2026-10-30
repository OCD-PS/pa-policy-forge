from __future__ import annotations

import csv
import copy
from dataclasses import dataclass
from difflib import SequenceMatcher
import hashlib
import html
import hmac
import io
import ipaddress
import json
import math
import os
import re
from pathlib import Path
import secrets
import shutil
import signal
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
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from functools import lru_cache, wraps

from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from defusedxml import ElementTree as SafeET
from flask import Flask, Response, flash, has_request_context, redirect, render_template, request, send_file, session, url_for

from app.bug_reports import create_bug_reports_blueprint, prune_bug_reports
from app.certificates import (
    CERTIFICATE_MAX_BYTES,
    PRIVATE_KEY_MAX_BYTES,
    CertificateError,
    certificate_summary,
    configured_fqdn,
    install_certificate,
    read_upload,
)
from vendor.panos_tls import create_panos_ssl_context, inspect_panos_certificate
from vendor.paloalto_light_syslog import FlowStore, env_int, parse_panos_syslog
from vendor.syslog_stream import tcp_server, udp_server
from app.policy_bulk import POLICY_LIST_FIELDS, apply_bulk_operations, apply_single_replacements
from app.workspace_access import (
    initialize_workspace_access, inherit_workspace_access, link_workspace_project,
    workspace_allowed,
)
from app.migration import (
    MIGRATION_FILTER_FIELDS, MIGRATION_FILTER_OPERATORS, MIGRATION_KIND_LABELS, MIGRATION_MAPPING_ACTIONS,
    MIGRATION_TOPOLOGY_KINDS, Address, AddressGroup, MigrationError, MigrationModel, PARSERS, Policy, Service, ServiceGroup,
    apply_family_mappings, apply_merge_rules, apply_topology_mappings, apply_transform_rules, auto_map_nat_topology, merge_inventory,
    merge_model_into_panos_xml, migration_api_plan, migration_base_xml, migration_best_practices,
    migration_discovery, migration_filter_inventory, migration_health_dashboard, migration_zone_names, migration_topology_targets,
    migration_interface_zone_memberships,
    clean_name, item_selector, merge_member_names, migration_analysis, migration_item_semantic, migration_review_findings,
    migration_search, model_collections, panos_candidate_analysis, panos_fragment, parse_vendor, raw_item_payload,
    reconcile_model, scm_items, restore_migration_source_topology,
)
from app.offline_config import (
    OBJECT_NODES, POLICY_NODES, PANOS_LOCATION_SECTIONS, PANOS_SCOPE_MOVE_OBJECT_TYPES, REFERENCE_CHECK_OBJECT_TYPES, MERGEABLE_OBJECT_TYPES, UNUSED_OBJECT_TYPES, OfflineConfigError, available_scopes, available_templates,
    apply_configuration_changes, apply_object_changes, configuration_inventory,
    create_basic_network_entry, configuration_create_templates, create_configuration_entry,
    configuration_records as scoped_configuration_records,
    merge_config_xml, normalized_config_xml, parse_snapshot,
    object_create_record, policy_create_record,
    object_fingerprint as offline_object_fingerprint,
    policy_fingerprint as offline_policy_fingerprint, render_set_commands,
    panos_ui_decorate_record, scoped_object_names, scoped_object_page, scoped_server_profiles,
    object_reference_index, object_reference_indexes,
    _merge_object_signature, _reference_scope, _resolve_scoped_object_entry,
    _is_panos_path_monitor_address_reference,
    _typed_object_reference_nodes,
    duplicate_object_groups, duplicate_object_groups_across_panos_scopes,
    merge_duplicate_object_groups, merge_duplicate_object_groups_to_shared,
    move_panos_scope_entries,
    replace_policy_in_snapshot, replace_policies_in_snapshot, insert_policy_in_snapshot,
    delete_policies_from_snapshot, move_policies_in_snapshot,
    safe_workspace_path, scoped_objects,
    scoped_policies, snapshot_sha256, referenced_template,
    unresolved_object_reference_index, unresolved_object_reference_indexes,
)

BASE = Path(__file__).resolve().parent.parent
BEST_PRACTICE_BASE = BASE / "app" / "bases" / "ocd-bpa-v11.xml"
DATA = Path(os.getenv("PPF_DATA_DIR", "/data"))
CERT_DIR = Path(os.getenv("PPF_CERT_DIR", "/certs"))
APPLIANCE_CONFIG = Path(os.getenv("PPF_APPLIANCE_CONFIG", str(DATA / "appliance.json")))
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
CANDIDATE_PREVIEW_CACHE_TTL_SECONDS = 10
CANDIDATE_PREVIEW_CACHE_MAX_ENTRIES = 2
CANDIDATE_PREVIEW_CACHE_MAX_BYTES = 16 * 1024 * 1024
_candidate_preview_cache: dict[tuple[int, str], tuple[float, bytes]] = {}
_candidate_preview_cache_generation = 0
_candidate_preview_cache_lock = threading.Lock()
LOGIN_MAX_FAILURES = 10
BLOCKED_PASSWORD_SHA256 = {
    "421d2f00ccdd4ccccf0455cdd0557d5af23dc70b06c83b94cf210ba9d4f3bf58",
    "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
}

app = Flask(__name__)


def build_asset_version() -> str:
    digest = hashlib.sha256()
    static_root = Path(app.static_folder or BASE / "app" / "static")
    for name in ("app.css", "app.js", "bug-report.js", "favicon.svg"):
        path = static_root / name
        if path.is_file():
            digest.update(name.encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


ASSET_VERSION = build_asset_version()
app.jinja_env.globals["asset_version"] = ASSET_VERSION
DATA.mkdir(parents=True, exist_ok=True)
RUNS.mkdir(parents=True, exist_ok=True)
SECRETS.mkdir(parents=True, exist_ok=True)
POLICY_DRAFTS.mkdir(parents=True, exist_ok=True)
OBJECT_DRAFTS.mkdir(parents=True, exist_ok=True)
OBJECT_CACHE.mkdir(parents=True, exist_ok=True)
CONFIG_WORKSPACES = DATA / "config-workspaces"
CONFIG_WORKSPACES.mkdir(parents=True, exist_ok=True)
MIGRATION_SOURCES = DATA / "migration-sources"
MIGRATION_SOURCES.mkdir(parents=True, exist_ok=True)

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
SCM_POLICY_ENVELOPE_KEYS = {"id", "name", "folder", "snippet", "device", "position", "policy_type"}
TARGET_TYPES = {"scm", "panorama", "panos"}
UNCONFIGURED_TARGET = "unconfigured"
PANOS_POLICY_NODES = {
    "security": "security", "nat": "nat", "qos": "qos", "pbf": "pbf",
    "decryption": "decryption", "application-override": "application-override",
    "authentication": "authentication", "tunnel-inspection": "tunnel-inspect",
    "dos": "dos", "sdwan": "sdwan",
}

PANOS_GEO_REGION_CODES = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM
FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS
IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML
MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM
PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD
TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
""".split())

SCM_OBJECT_TYPES = {
    "addresses": {"label": "Addresses", "creatable": True},
    "address-groups": {"label": "Address Groups", "creatable": True},
    "applications": {"label": "Applications", "creatable": False},
    "application-groups": {"label": "Application Groups", "creatable": True},
    "application-filters": {"label": "Application Filters", "creatable": True, "editable": True, "generic": True},
    "services": {"label": "Services", "creatable": True},
    "service-groups": {"label": "Service Groups", "creatable": True},
    "tags": {"label": "Tags", "creatable": True},
    "regions": {"label": "Regions", "creatable": True, "editable": True, "generic": True},
    "dynamic-user-groups": {"label": "Dynamic User Groups", "creatable": True, "editable": True, "generic": True},
    "external-dynamic-lists": {"label": "External Dynamic Lists", "creatable": True, "editable": True, "generic": True},
    "hip-objects": {"label": "HIP Objects", "creatable": True, "editable": True, "generic": True},
    "hip-profiles": {"label": "HIP Profiles", "creatable": True, "editable": True, "generic": True},
    "schedules": {"label": "Schedules", "creatable": True, "editable": True, "generic": True},
    "log-forwarding": {"label": "Log Forwarding", "creatable": True, "editable": True, "endpoint": "log-forwarding-profiles"},
    "syslog-server-profiles": {"label": "Syslog Server Profiles", "creatable": False, "endpoint": "syslog-server-profiles", "catalog_only": True},
    "email-server-profiles": {"label": "Email Server Profiles", "creatable": False, "endpoint": "email-server-profiles", "catalog_only": True},
    "snmp-trap-server-profiles": {"label": "SNMP Trap Server Profiles", "creatable": False, "endpoint": "snmp-trap-server-profiles", "catalog_only": True},
    "http-server-profiles": {"label": "HTTP Server Profiles", "creatable": False, "endpoint": "http-server-profiles", "catalog_only": True},
    "zones": {"label": "Zones", "creatable": True, "network": True},
    "custom-url-categories": {"label": "Custom URL Categories", "creatable": True, "editable": True, "generic": True, "service": "security", "endpoint": "url-categories"},
    "antivirus": {"label": "Antivirus / WildFire", "creatable": True, "editable": True, "generic": True, "service": "security", "endpoint": "wildfire-anti-virus-profiles"},
    "anti-spyware": {"label": "Anti-Spyware", "creatable": True, "editable": True, "generic": True, "service": "security", "endpoint": "anti-spyware-profiles"},
    "dns-security": {"label": "DNS Security", "creatable": True, "editable": True, "generic": True, "service": "security", "endpoint": "dns-security-profiles"},
    "vulnerability-protection": {"label": "Vulnerability Protection", "creatable": True, "editable": True, "generic": True, "service": "security", "endpoint": "vulnerability-protection-profiles"},
    "url-filtering": {"label": "URL Filtering", "creatable": True, "editable": True, "generic": True, "service": "security", "endpoint": "url-access-profiles"},
    "file-blocking": {"label": "File Blocking", "creatable": True, "editable": True, "generic": True, "service": "security", "endpoint": "file-blocking-profiles"},
    "wildfire-analysis": {"label": "WildFire Analysis", "creatable": True, "editable": True, "generic": True, "service": "security", "endpoint": "wildfire-anti-virus-profiles"},
    "dos-protection": {"label": "DoS Protection", "creatable": True, "editable": True, "generic": True, "service": "security", "endpoint": "dos-protection-profiles"},
    "decryption-profiles": {"label": "Decryption Profiles", "creatable": True, "editable": True, "generic": True, "service": "security", "endpoint": "decryption-profiles"},
    "security-profile-groups": {"label": "Security Profile Groups", "creatable": True, "editable": True, "generic": True, "service": "security", "endpoint": "profile-groups"},
}

SCM_GENERIC_CREATE_DEFAULTS = {
    "regions": {"name": "", "address": []},
    "dynamic-user-groups": {"name": "", "description": "", "filter": ""},
    "application-filters": {
        "name": "", "category": [], "subcategory": [], "technology": [], "risk": [],
        "evasive": False, "excessive_bandwidth_use": False,
        "has_known_vulnerabilities": False, "is_saas": False, "new_appid": False,
        "pervasive": False, "prone_to_misuse": False, "transfers_files": False,
        "tunnels_other_apps": False, "used_by_malware": False,
    },
    "external-dynamic-lists": {
        "name": "", "type": {"ip": {
            "description": "", "url": "", "certificate_profile": "None",
            "recurring": {"five_minute": {}}, "exception_list": [],
        }},
    },
    "hip-objects": {"name": "", "description": "", "host_info": {
        "criteria": {"os": {"contains": {"microsoft": "Microsoft Windows 10"}}},
    }},
    "hip-profiles": {"name": "", "description": "", "match": "any"},
    "schedules": {"name": "", "schedule_type": {"recurring": {"daily": []}}},
    "custom-url-categories": {"name": "", "description": "", "type": "URL List", "list": []},
    "antivirus": {"name": "", "description": "", "packet_capture": False, "rules": []},
    "anti-spyware": {"name": "", "description": "", "cloud_inline_analysis": False, "rules": []},
    "dns-security": {"name": "", "description": ""},
    "vulnerability-protection": {"name": "", "description": "", "rules": []},
    "url-filtering": {
        "name": "", "description": "", "allow": [], "alert": [], "block": [],
        "continue": [], "redirect": [], "safe_search_enforcement": False,
        "log_container_page_only": True, "log_http_hdr_referer": False,
        "log_http_hdr_user_agent": False, "log_http_hdr_xff": False,
    },
    "file-blocking": {"name": "", "description": "", "rules": []},
    "wildfire-analysis": {"name": "", "description": "", "packet_capture": False, "rules": []},
    "dos-protection": {"name": "", "description": "", "type": "aggregate"},
    "decryption-profiles": {"name": "", "ssl_forward_proxy": {
        "auto_include_altname": True, "block_expired_certificate": True,
        "block_untrusted_issuer": True, "block_unknown_cert": True,
    }},
    "security-profile-groups": {
        "name": "", "virus_and_wildfire_analysis": [], "spyware": [],
        "dns_security": [], "vulnerability": [], "url_filtering": [],
        "file_blocking": [], "data_filtering": [], "saas_security": [],
    },
}
SCM_CONFIGURATION_SECTIONS = {
    "network": {
        "interfaces": ("Interfaces", ("aggregate-ethernet-interfaces", "ethernet-interfaces", "layer2-subinterfaces", "layer3-subinterfaces", "loopback-interfaces", "tunnel-interfaces", "vlan-interfaces")),
        "zones": ("Zones", ("zones",)),
        "logical-routers": ("Logical Routers", ("logical-routers",)),
        "ipsec-tunnels": ("IPSec Tunnels", ("ipsec-tunnels",)),
        "dhcp": ("DHCP", ("dhcp-interfaces",)),
        "dns-proxy": ("DNS Proxy", ("dns-proxies",)),
        "network-profiles": ("Network Profiles", ("interface-management-profiles", "zone-protection-profiles")),
    },
    "device": {
        "setup": ("Setup", ("general-settings", "management-interface", "motd-banner-settings", "service-settings", "session-settings", "session-timeouts", "tcp-settings", "vpn-settings")),
        "high-availability": ("High Availability", ("ha-configurations", "ha-devices")),
    },
}
MIGRATION_SCM_EXTRA_OBJECTS = {
    "application_groups": "application-groups", "tags": "tags",
    "custom_url_categories": "custom-url-categories",
    "security_profile_groups": "security-profile-groups",
}
MIGRATION_SCM_SECURITY_PROFILES = {
    "virus": "antivirus", "spyware": "anti-spyware",
    "vulnerability": "vulnerability-protection", "url-filtering": "url-filtering",
    "file-blocking": "file-blocking", "wildfire-analysis": "wildfire-analysis",
}
MIGRATION_SCM_EXTRA_POLICIES = {
    "qos_rules": "qos", "pbf_rules": "pbf", "decryption_rules": "decryption",
    "application_override_rules": "application-override",
    "authentication_rules": "authentication", "dos_rules": "dos",
    "tunnel_inspection_rules": "tunnel-inspection",
}
MIGRATION_SCM_NETWORK_ENDPOINTS = {
    "logical_routers": ("network", "logical-routers"),
    "ipsec_tunnels": ("network", "ipsec-tunnels"),
}
_catalog_refreshing: set[tuple[int, str]] = set()
_catalog_refresh_lock = threading.Lock()
_catalog_errors: dict[tuple[int, str], str] = {}
_catalog_retry_after: dict[tuple[int, str], float] = {}
CATALOG_RETRY_SECONDS = 60
LIVE_PAGE_CACHE_SECONDS = max(5, int(os.getenv("PPF_LIVE_PAGE_CACHE_SECONDS", "30")))
SCM_TOKEN_CACHE_SECONDS = max(60, int(os.getenv("PPF_SCM_TOKEN_CACHE_SECONDS", "600")))
WORKSPACE_OBJECT_PAGE_SIZE = max(50, min(1000, int(os.getenv("PPF_WORKSPACE_OBJECT_PAGE_SIZE", "250"))))
WORKSPACE_POLICY_PAGE_SIZE = max(25, min(500, int(os.getenv("PPF_WORKSPACE_POLICY_PAGE_SIZE", "100"))))
DEFAULT_APPLICATION_CACHE = OBJECT_CACHE / "default-applications-v2.json"
DEFAULT_CATALOG_INITIAL_DELAY = max(30, int(os.getenv("PPF_APP_CATALOG_INITIAL_DELAY", "60")))
_default_catalog_refresh_lock = threading.RLock()
_default_catalog_refreshing = False
_panos_key_cache: dict[int, tuple[str, str, str, float]] = {}
_panos_key_cache_lock = threading.Lock()
_scm_token_cache: dict[int, tuple[str, str, float]] = {}
_scm_token_cache_lock = threading.Lock()
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
appliance_fqdn = configured_fqdn(APPLIANCE_CONFIG)
if appliance_fqdn and appliance_fqdn not in trusted_hosts:
    trusted_hosts.append(appliance_fqdn)
if trusted_hosts: app.config["TRUSTED_HOSTS"] = trusted_hosts
fernet = Fernet(secret_file("encryption.key", Fernet.generate_key))
flow_store = FlowStore(FLOW_DB, retention_days=0)
_login_failures: dict[tuple[str, str], deque[float]] = defaultdict(deque)
_login_failures_lock = threading.Lock()
_syslog_source_policy: dict[str, set[str] | None] = {}
_syslog_source_policy_lock = threading.Lock()
sys.path.insert(0, str(BASE / "vendor"))
from vendor import bdnd_panos_policy_builder as policy_api


def public_ui_record(value):
    """Remove transport/internal fields before serializing records into HTML."""
    if isinstance(value, dict):
        return {key: public_ui_record(item) for key, item in value.items() if not str(key).startswith("_")}
    if isinstance(value, list):
        return [public_ui_record(item) for item in value]
    return value


app.jinja_env.filters["public_ui_record"] = public_ui_record


class ClosingSQLiteConnection(sqlite3.Connection):
    """Keep commit/rollback context semantics and always release the descriptor."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(APP_DB, timeout=30, factory=ClosingSQLiteConnection)
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
          password_hash TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 1,
          is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS profiles (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          system INTEGER NOT NULL DEFAULT 0,
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
        CREATE TABLE IF NOT EXISTS post_deploy_monitors (
          run_id INTEGER PRIMARY KEY, profile_id INTEGER NOT NULL,
          deployed_at TEXT NOT NULL, baseline_json TEXT NOT NULL,
          target_type TEXT NOT NULL DEFAULT 'scm', activation_status TEXT NOT NULL DEFAULT 'active',
          candidate_at TEXT NOT NULL DEFAULT '',
          one_hour_json TEXT NOT NULL DEFAULT '', one_day_json TEXT NOT NULL DEFAULT '',
          last_checked_at TEXT, last_error TEXT NOT NULL DEFAULT '',
          FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE,
          FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS config_workspaces (
          id INTEGER PRIMARY KEY, profile_id INTEGER NOT NULL, name TEXT NOT NULL,
          source TEXT NOT NULL, original_name TEXT NOT NULL, config_path TEXT NOT NULL,
          sha256 TEXT NOT NULL, baseline_config_path TEXT NOT NULL DEFAULT '',
          baseline_sha256 TEXT NOT NULL DEFAULT '', baseline_target_sha256 TEXT NOT NULL DEFAULT '',
          metadata_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          FOREIGN KEY(profile_id) REFERENCES profiles(id)
        );
        CREATE TABLE IF NOT EXISTS config_workspace_commits (
          id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, profile_id INTEGER NOT NULL,
          target_type TEXT NOT NULL, target_endpoint_sha256 TEXT NOT NULL,
          job_id TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'SUBMITTING',
          result TEXT NOT NULL DEFAULT '', progress INTEGER, details_json TEXT NOT NULL DEFAULT '[]',
          submitted_at TEXT NOT NULL, last_checked_at REAL NOT NULL DEFAULT 0,
          last_error TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_workspace_commits_latest
          ON config_workspace_commits(workspace_id, id DESC);
        CREATE TABLE IF NOT EXISTS migration_projects (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, target_profile_id INTEGER NOT NULL,
          base_workspace_id INTEGER, topology TEXT NOT NULL DEFAULT 'active-passive',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          FOREIGN KEY(target_profile_id) REFERENCES profiles(id),
          FOREIGN KEY(base_workspace_id) REFERENCES config_workspaces(id)
        );
        CREATE TABLE IF NOT EXISTS migration_sources (
          id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, vendor TEXT NOT NULL,
          source_name TEXT NOT NULL, model_path TEXT NOT NULL, fingerprint TEXT NOT NULL,
          counts_json TEXT NOT NULL DEFAULT '{}', warnings_json TEXT NOT NULL DEFAULT '[]',
          staging_workspace_id INTEGER, created_at TEXT NOT NULL,
          FOREIGN KEY(project_id) REFERENCES migration_projects(id)
        );
        CREATE TABLE IF NOT EXISTS migration_merge_rules (
          id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, kind TEXT NOT NULL,
          master TEXT NOT NULL, members_json TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'selection',
          created_at TEXT NOT NULL, FOREIGN KEY(project_id) REFERENCES migration_projects(id)
        );
        CREATE TABLE IF NOT EXISTS migration_transform_rules (
          id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, operation TEXT NOT NULL,
          kind TEXT NOT NULL DEFAULT '', selector TEXT NOT NULL DEFAULT '', value TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL, FOREIGN KEY(project_id) REFERENCES migration_projects(id)
        );
        CREATE TABLE IF NOT EXISTS migration_outputs (
          id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, workspace_id INTEGER NOT NULL,
          label TEXT NOT NULL, topology TEXT NOT NULL DEFAULT 'active-passive',
          node_role TEXT NOT NULL DEFAULT '', collision_json TEXT NOT NULL DEFAULT '{}',
          sanity_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
          FOREIGN KEY(project_id) REFERENCES migration_projects(id),
          FOREIGN KEY(workspace_id) REFERENCES config_workspaces(id)
        );
        CREATE TABLE IF NOT EXISTS migration_output_resolutions (
          output_id INTEGER NOT NULL, code TEXT NOT NULL, note TEXT NOT NULL,
          resolved_by TEXT NOT NULL, resolved_at TEXT NOT NULL,
          PRIMARY KEY(output_id,code),
          FOREIGN KEY(output_id) REFERENCES migration_outputs(id)
        );
        CREATE TABLE IF NOT EXISTS migration_family_mappings (
          id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, source_id INTEGER NOT NULL DEFAULT 0,
          kind TEXT NOT NULL, action TEXT NOT NULL DEFAULT 'map', target_context TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          UNIQUE(project_id,source_id,kind),
          FOREIGN KEY(project_id) REFERENCES migration_projects(id),
          FOREIGN KEY(source_id) REFERENCES migration_sources(id)
        );
        CREATE TABLE IF NOT EXISTS migration_saved_filters (
          id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, name TEXT NOT NULL,
          join_mode TEXT NOT NULL DEFAULT 'and', rules_json TEXT NOT NULL DEFAULT '[]',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          FOREIGN KEY(project_id) REFERENCES migration_projects(id)
        );
        CREATE TABLE IF NOT EXISTS migration_catalogs (
          project_id INTEGER NOT NULL, kind TEXT NOT NULL, items_json TEXT NOT NULL DEFAULT '[]',
          updated_at TEXT NOT NULL, PRIMARY KEY(project_id,kind),
          FOREIGN KEY(project_id) REFERENCES migration_projects(id)
        );
        CREATE TABLE IF NOT EXISTS migration_snippets (
          id INTEGER PRIMARY KEY, owner TEXT NOT NULL DEFAULT 'admin', name TEXT NOT NULL,
          settings_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          UNIQUE(owner,name), FOREIGN KEY(owner) REFERENCES users(username)
        );
        CREATE TABLE IF NOT EXISTS migration_project_roles (
          project_id INTEGER NOT NULL, username TEXT NOT NULL, role TEXT NOT NULL,
          created_at TEXT NOT NULL, PRIMARY KEY(project_id,username),
          FOREIGN KEY(project_id) REFERENCES migration_projects(id),
          FOREIGN KEY(username) REFERENCES users(username)
        );
        CREATE TABLE IF NOT EXISTS migration_analysis_runs (
          id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, analysis_json TEXT NOT NULL,
          created_at TEXT NOT NULL, FOREIGN KEY(project_id) REFERENCES migration_projects(id)
        );
        CREATE TABLE IF NOT EXISTS system_settings (
          setting_key TEXT PRIMARY KEY, settings_json TEXT NOT NULL DEFAULT '{}',
          secret_blob BLOB NOT NULL DEFAULT '', updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS bug_reports (
          id INTEGER PRIMARY KEY, reporter_user_id INTEGER NOT NULL, secret_blob BLOB NOT NULL,
          screenshot_blob BLOB,
          status TEXT NOT NULL DEFAULT 'new', created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL DEFAULT '', notified_at TEXT NOT NULL DEFAULT '',
          FOREIGN KEY(reporter_user_id) REFERENCES users(id)
        );
        """)
        user_columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
        if "is_admin" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        # The existing single bootstrap account is the only global administrator.
        # Other accounts, if provisioned later, remain non-admin unless explicitly promoted.
        conn.execute("UPDATE users SET is_admin=1 WHERE username='admin'")
        conn.execute("DELETE FROM bug_reports WHERE created_at<strftime('%Y-%m-%d %H:%M:%S','now','-180 days')")
        prune_bug_reports(conn)
        project_columns = {row[1] for row in conn.execute("PRAGMA table_info(migration_projects)")}
        if "topology" not in project_columns:
            conn.execute("ALTER TABLE migration_projects ADD COLUMN topology TEXT NOT NULL DEFAULT 'active-passive'")
        if "owner" not in project_columns:
            conn.execute("ALTER TABLE migration_projects ADD COLUMN owner TEXT NOT NULL DEFAULT 'admin'")
        profile_columns = {row[1] for row in conn.execute("PRAGMA table_info(profiles)")}
        if "system" not in profile_columns:
            conn.execute("ALTER TABLE profiles ADD COLUMN system INTEGER NOT NULL DEFAULT 0")
        snippet_columns = {row[1] for row in conn.execute("PRAGMA table_info(migration_snippets)")}
        if "owner" not in snippet_columns:
            conn.execute("ALTER TABLE migration_snippets ADD COLUMN owner TEXT NOT NULL DEFAULT 'admin'")
        source_columns = {row[1] for row in conn.execute("PRAGMA table_info(migration_sources)")}
        if "staging_workspace_id" not in source_columns:
            conn.execute("ALTER TABLE migration_sources ADD COLUMN staging_workspace_id INTEGER")
        workspace_columns = {row[1] for row in conn.execute("PRAGMA table_info(config_workspaces)")}
        if "baseline_config_path" not in workspace_columns:
            conn.execute("ALTER TABLE config_workspaces ADD COLUMN baseline_config_path TEXT NOT NULL DEFAULT ''")
        if "baseline_sha256" not in workspace_columns:
            conn.execute("ALTER TABLE config_workspaces ADD COLUMN baseline_sha256 TEXT NOT NULL DEFAULT ''")
        if "baseline_target_sha256" not in workspace_columns:
            conn.execute("ALTER TABLE config_workspaces ADD COLUMN baseline_target_sha256 TEXT NOT NULL DEFAULT ''")
        initialize_workspace_access(conn)
        monitor_columns = {row[1] for row in conn.execute("PRAGMA table_info(post_deploy_monitors)")}
        if "target_type" not in monitor_columns:
            conn.execute("ALTER TABLE post_deploy_monitors ADD COLUMN target_type TEXT NOT NULL DEFAULT 'scm'")
        if "activation_status" not in monitor_columns:
            conn.execute("ALTER TABLE post_deploy_monitors ADD COLUMN activation_status TEXT NOT NULL DEFAULT 'active'")
        if "candidate_at" not in monitor_columns:
            conn.execute("ALTER TABLE post_deploy_monitors ADD COLUMN candidate_at TEXT NOT NULL DEFAULT ''")
        if not conn.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
            bootstrap_password = os.getenv("PPF_BOOTSTRAP_PASSWORD", "")
            if len(bootstrap_password) < 12 or password_is_blocked(bootstrap_password):
                raise RuntimeError(
                    "A new installation requires PPF_BOOTSTRAP_PASSWORD with at least 12 non-default characters"
                )
            conn.execute("INSERT INTO users(username,password_hash,must_change) VALUES(?,?,1)",
                         ("admin", password_hash(bootstrap_password)))
            conn.execute("UPDATE users SET is_admin=1 WHERE username='admin'")
        conn.execute(
            "UPDATE runs SET status='failed',finished_at=strftime('%Y-%m-%d %H:%M:%S','now'),"
            "output=CASE WHEN output='' THEN 'Run onderbroken door een applicatieherstart.' ELSE output END "
            "WHERE status='running'"
        )


init_db()
_dummy_password_hash = password_hash(secrets.token_urlsafe(32))


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


OFFLINE_MIGRATION_TARGETS = {
    "offline-panos": {
        "name": "Offline PAN-OS",
        "target_type": "panos",
        "settings": {"system_offline": True, "vsys": "vsys1"},
    },
    "offline-panorama": {
        "name": "Offline Panorama",
        "target_type": "panorama",
        "settings": {"system_offline": True, "device_group": "Offline", "rulebase": "pre"},
    },
}


def migration_target_profile(conn, choice: str):
    """Resolve a real push target or a hidden local-only migration workspace."""
    choice = str(choice or "offline-panos").strip() or "offline-panos"
    offline = OFFLINE_MIGRATION_TARGETS.get(choice)
    if offline:
        profile = conn.execute(
            "SELECT * FROM profiles WHERE system=1 AND target_type=? ORDER BY id LIMIT 1",
            (offline["target_type"],),
        ).fetchone()
        if profile:
            return profile
        timestamp = now()
        profile_id = int(conn.execute(
            "INSERT INTO profiles(name,enabled,system,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (
                offline["name"], 0, 1, offline["target_type"],
                json.dumps(offline["settings"], sort_keys=True), timestamp, timestamp,
            ),
        ).lastrowid)
        return conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    try:
        profile_id = int(choice)
    except ValueError as exc:
        raise MigrationError("Ongeldig push target") from exc
    profile = conn.execute(
        "SELECT * FROM profiles WHERE id=? AND system=0", (profile_id,)
    ).fetchone()
    if not profile:
        raise MigrationError("Push target bestaat niet")
    return profile


def audit(action: str, detail: str = "", username: str | None = None) -> None:
    with db() as conn:
        conn.execute("INSERT INTO audit(created_at,username,action,detail) VALUES(?,?,?,?)",
                     (now(), username or (session.get("username", "system") if has_request_context() else "system"), action, detail[:1000]))


app.register_blueprint(create_bug_reports_blueprint(db, fernet, now, audit))


def csrf() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf


@app.before_request
def protect_csrf():
    # Flask's integer URL converter accepts values larger than SQLite row ids.
    # Reject only out-of-domain resource ids, before a route binds them to SQL.
    for name, value in (request.view_args or {}).items():
        if name.endswith("_id") and isinstance(value, int) and not 1 <= value <= 2**63 - 1:
            return "Not found", 404
    if request.method == "POST" and request.path == "/bug-reports":
        request.max_content_length = 3 * 1024 * 1024
        if (request.content_length or 0) > request.max_content_length:
            return "Request too large", 413
    if request.method == "POST" and not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "-")):
        return "Invalid CSRF token", 400
    if session.get("user_id") and session.get("must_change") and request.endpoint not in {
        "change_password", "logout", "static", "healthz",
    }:
        return redirect(url_for("change_password"))


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
        "img-src 'self' data: blob:; connect-src 'self'"
    )
    if request.endpoint != "static": response.headers["Cache-Control"] = "no-store"
    if (
        session.get("user_id") and not session.get("must_change")
        and response.status_code == 200
        and response.mimetype == "text/html"
    ):
        csrf_value = html.escape(str(session.get("csrf", "")), quote=True)
        script = (
            f'<script src="{url_for("static", filename="bug-report.js", v=ASSET_VERSION)}" '
            f'data-csrf="{csrf_value}" defer></script>'
        )
        body = response.get_data(as_text=True)
        marker = "</body>"
        if marker in body:
            response.set_data(body.replace(marker, script + marker, 1))
    return response


@app.context_processor
def inject_admin_access():
    user_id = session.get("user_id")
    if not user_id:
        return {"is_admin": False}
    with db() as conn:
        row = conn.execute("SELECT is_admin FROM users WHERE id=?", (user_id,)).fetchone()
    return {"is_admin": bool(row and row["is_admin"])}


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
            session.clear(); session.permanent = True; session["user_id"] = user["id"]; session["username"] = user["username"]; session["must_change"] = bool(user["must_change"]); csrf()
            audit("login")
            if session["must_change"]:
                return redirect(url_for("change_password"))
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


def add_runtime_trusted_host(hostname: str) -> None:
    configured = app.config.get("TRUSTED_HOSTS")
    if configured is None:
        return
    trusted = list(configured)
    if hostname not in trusted:
        trusted.append(hostname)
    app.config["TRUSTED_HOSTS"] = trusted


def schedule_tls_reload() -> None:
    if os.getenv("PPF_TLS_RELOAD_SIGNAL", "0") != "1":
        return

    def reload_gunicorn() -> None:
        try:
            os.kill(os.getppid(), signal.SIGHUP)
        except (OSError, ProcessLookupError):
            app.logger.exception("TLS certificate was installed but Gunicorn could not be reloaded")

    timer = threading.Timer(0.75, reload_gunicorn)
    timer.daemon = True
    timer.start()


@app.post("/settings/certificate")
@login_required
def settings_certificate():
    try:
        certificate_pem = read_upload(
            request.files.get("certificate"), CERTIFICATE_MAX_BYTES, "certificate chain"
        )
        private_key_pem = read_upload(
            request.files.get("private_key"), PRIVATE_KEY_MAX_BYTES, "private key"
        )
        result = install_certificate(
            CERT_DIR,
            APPLIANCE_CONFIG,
            request.form.get("fqdn", ""),
            certificate_pem,
            private_key_pem,
        )
        add_runtime_trusted_host(str(result["fqdn"]))
        audit(
            "tls-certificate-updated",
            f"fqdn={result['fqdn']} fingerprint={result['fingerprint']}",
        )
        schedule_tls_reload()
        flash("FQDN en TLS-certificaat zijn opgeslagen en worden geactiveerd.", "success")
    except CertificateError as exc:
        flash(f"TLS-certificaat niet opgeslagen: {exc}", "error")
    except OSError:
        app.logger.exception("TLS certificate could not be stored")
        flash("TLS-certificaat niet opgeslagen: de certificaatopslag is niet schrijfbaar.", "error")
    return redirect(url_for("index") + "#settings")


@app.post("/settings/application-catalog")
@login_required
def settings_application_catalog():
    try:
        enabled = request.form.get("enabled") == "on"
        folder = request.form.get("folder", "All").strip() or "All"
        if not re.fullmatch(r"[A-Za-z0-9_. -]{1,64}", folder):
            raise ValueError("Ongeldige SCM-folder")
        interval_hours = max(1, min(168, int(request.form.get("interval_hours", "24"))))
        supplied = {
            key: request.form.get(key, "").strip()
            for key in ("client_id", "client_secret", "tsg_id")
        }
        with db() as conn:
            existing = conn.execute(
                "SELECT * FROM system_settings WHERE setting_key='application_catalog'"
            ).fetchone()
            current_secret = (
                json.loads(fernet.decrypt(existing["secret_blob"]).decode())
                if existing and existing["secret_blob"] else {}
            )
            merged_secret = {
                **current_secret,
                **{key: value for key, value in supplied.items() if value},
            }
            if enabled and not all(merged_secret.get(key) for key in ("client_id", "client_secret", "tsg_id")):
                raise ValueError("Client ID, Client secret en TSG ID zijn verplicht")
            old_settings = json.loads(existing["settings_json"] or "{}") if existing else {}
            settings = {
                **old_settings,
                "enabled": enabled,
                "folder": folder,
                "interval_hours": interval_hours,
            }
            blob = fernet.encrypt(json.dumps(merged_secret).encode()) if merged_secret else b""
            conn.execute(
                "INSERT INTO system_settings(setting_key,settings_json,secret_blob,updated_at) VALUES('application_catalog',?,?,?) "
                "ON CONFLICT(setting_key) DO UPDATE SET settings_json=excluded.settings_json,secret_blob=excluded.secret_blob,updated_at=excluded.updated_at",
                (json.dumps(settings), blob, now()),
            )
        audit("application-catalog-settings-saved", f"enabled={enabled} interval_hours={interval_hours}")
        if enabled:
            refresh_default_application_catalog_async()
        flash("Application Database-instellingen opgeslagen.", "success")
    except Exception as exc:
        flash(f"Application Database niet opgeslagen: {exc}", "error")
    return redirect(url_for("index") + "#settings")


@app.post("/settings/application-catalog/refresh")
@login_required
def settings_application_catalog_refresh():
    try:
        count = refresh_default_application_catalog()
        flash(f"SCM-verbinding geslaagd; {count} applications opgeslagen.", "success")
    except Exception as exc:
        flash(f"Application Database refresh mislukt: {type(exc).__name__}.", "error")
    return redirect(url_for("index") + "#settings")


def stats() -> dict:
    result = flow_store.stats()
    with db() as conn:
        result["profiles"] = conn.execute("SELECT COUNT(*) FROM profiles WHERE system=0").fetchone()[0]
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


def profile_has_target(profile) -> bool:
    settings = profile_settings(profile)
    if profile["target_type"] not in TARGET_TYPES:
        return False
    return bool(settings.get("configured", bool(settings.get("zones"))))


def profile_is_configured(profile) -> bool:
    return profile_has_target(profile) and bool(profile_settings(profile).get("zones"))


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
    with db() as conn: profiles = conn.execute("SELECT serial,source_ip,settings_json FROM profiles WHERE system=0").fetchall()
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
    try:
        profile_id = int(profile["id"] or 0)
    except (KeyError, TypeError, ValueError):
        profile_id = 0
    try:
        profile_version = str(profile["updated_at"] or "")
    except (KeyError, TypeError, IndexError):
        profile_version = ""
    token = ""
    if profile_id:
        with _scm_token_cache_lock:
            cached = _scm_token_cache.get(profile_id)
            if cached and cached[0] == profile_version and cached[2] > time.time():
                token = cached[1]
            if not token:
                token = policy_api.get_scm_token(scm)
                _scm_token_cache[profile_id] = (
                    profile_version, token, time.time() + SCM_TOKEN_CACHE_SECONDS,
                )
    else:
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
    if policy_kind == "nat":
        source_translation = copy.deepcopy(rule.get("source_translation") or {})
        destination_translation = copy.deepcopy(rule.get("destination_translation") or {})
        source_mode_raw = next(iter(source_translation), "none")
        source_mode = source_mode_raw.replace("-", "_")
        source_details = source_translation.get(source_mode_raw, {}) if source_mode != "none" else {}
        if not isinstance(source_details, dict):
            source_details = {"translated_address": source_details}
        translated_address = source_details.get("translated_address", source_details.get("translated-address", []))
        if not isinstance(translated_address, list):
            translated_address = [translated_address] if translated_address not in (None, "") else []
        interface_address = source_details.get("interface_address") or source_details.get("interface-address") or {}
        normalized.update({
            "nat_type": str(rule.get("nat_type", "ipv4") or "ipv4"),
            "to_interface": str(rule.get("to_interface", "any") or "any"),
            "source_translation": source_translation,
            "destination_translation": destination_translation,
            "source_translation_mode": source_mode,
            "source_translation_address": ", ".join(str(value) for value in translated_address),
            "source_translation_interface": str(interface_address.get("interface", "") if isinstance(interface_address, dict) else ""),
            "destination_translation_address": str(destination_translation.get("translated_address", destination_translation.get("translated-address", "")) or ""),
            "destination_translation_port": str(destination_translation.get("translated_port", destination_translation.get("translated-port", "")) or ""),
            "source_translation_summary": _policy_value_summary(source_translation),
            "destination_translation_summary": _policy_value_summary(destination_translation),
        })
    normalized["_raw"] = rule
    normalized["_policy_kind"] = policy_kind
    return normalized


def _policy_value_summary(value) -> str:
    if isinstance(value, dict):
        parts = []
        for key, child in value.items():
            rendered = _policy_value_summary(child)
            if rendered:
                parts.append(f"{key.replace('_', ' ')}: {rendered}")
        return "; ".join(parts)
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value or "")


SCM_POLICY_REQUIRED_FIELDS = {
    "security": {"from", "to", "source", "destination", "application", "service", "action"},
    "nat": {"from", "to", "source", "destination", "service"},
    "qos": {"from", "to", "source", "destination"},
    "pbf": {"from", "source", "destination", "action"},
    "decryption": {"from", "to", "source", "destination", "action"},
    "application-override": {"from", "to", "source", "destination", "application"},
    "authentication": {"from", "to", "source", "destination", "action"},
}


def is_complete_scm_policy(rule: dict) -> bool:
    """SCM list endpoints can include scope envelopes that are not policy rules."""
    return bool(set(rule) - SCM_POLICY_ENVELOPE_KEYS)


def is_scm_policy_for_kind(rule: dict, policy_kind: str) -> bool:
    required = SCM_POLICY_REQUIRED_FIELDS.get(policy_kind)
    return is_complete_scm_policy(rule) and (required is None or required.issubset(rule))


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
    pinned_certificate = settings.get("tls_pinned_certificate", "")
    pinned_endpoint = settings.get("tls_pinned_endpoint", "")
    pinned_fingerprint = settings.get("tls_pinned_fingerprint", "")
    allow_pinned_hostname_mismatch = bool(settings.get("tls_allow_hostname_mismatch", False))
    if pinned_certificate:
        try:
            certificate = x509.load_pem_x509_certificate(pinned_certificate.encode("ascii"))
            actual_fingerprint = certificate.fingerprint(hashes.SHA256()).hex().upper()
        except (ValueError, UnicodeEncodeError) as exc:
            raise ValueError("Het opgeslagen firewallcertificaat is ongeldig; controleer het certificaat opnieuw") from exc
        if actual_fingerprint != pinned_fingerprint or pinned_endpoint != endpoint:
            raise ValueError("Het vertrouwde firewallcertificaat hoort niet bij dit endpoint; controleer het certificaat opnieuw")
    ctx = create_panos_ssl_context(
        pinned_certificate=pinned_certificate or None,
        allow_pinned_hostname_mismatch=allow_pinned_hostname_mismatch,
    )
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
            _catalog_retry_after.pop(key, None)
    with _panos_key_cache_lock:
        _panos_key_cache.pop(profile_id, None)
    with _scm_token_cache_lock:
        _scm_token_cache.pop(profile_id, None)


def panos_api_post(endpoint: str, params: dict, ctx: ssl.SSLContext) -> str:
    request_params = dict(params)
    api_key = request_params.pop("key", "")
    request_body = urllib.parse.urlencode(request_params).encode()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if api_key: headers["X-PAN-KEY"] = api_key
    api_request = urllib.request.Request(endpoint.rstrip("/") + "/api/", data=request_body, headers=headers, method="POST")
    with policy_api.credential_urlopen(api_request, context=ctx, timeout=120) as response:
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
    rules = policy_api.scm_fetch_rules(endpoint, token, container, scm.scm_rulebase)
    return [normalize_policy(rule, "security") for rule in rules if is_scm_policy_for_kind(rule, "security")]


def fetch_scm_policy_type(profile, policy_kind: str) -> list[dict]:
    if policy_kind not in SCM_POLICY_TYPES: raise ValueError("Onbekend policytype")
    if profile["target_type"] != "scm": return fetch_panos_policies(profile, policy_kind)
    if policy_kind in SCM_UNAVAILABLE_POLICY_TYPES: return []
    if policy_kind == "security": return fetch_security_policies(profile)
    service, endpoint_name, _ = SCM_POLICY_TYPES[policy_kind]
    scm, token, _, container = scm_client(profile)
    endpoint = policy_api.scm_api_root(scm.scm_api_base) + f"/config/{service}/v1/{endpoint_name}"
    rules = policy_api.scm_fetch_all(endpoint, token, {**container, "position": scm.scm_rulebase})
    return [normalize_policy(rule, policy_kind) for rule in rules if is_scm_policy_for_kind(rule, policy_kind)]


def fetch_scm_objects(profile, object_type: str) -> list[dict]:
    if object_type not in SCM_OBJECT_TYPES:
        raise ValueError("Onbekend objecttype")
    if profile["target_type"] != "scm": return fetch_panos_objects(profile, object_type)
    scm, token, _, _ = scm_client(profile)
    metadata = SCM_OBJECT_TYPES[object_type]
    service = metadata.get("service") or ("network" if object_type == "zones" else "objects")
    endpoint_name = metadata.get("endpoint", object_type)
    root = policy_api.scm_api_root(scm.scm_api_base) + f"/config/{service}/v1"
    container = policy_api.scm_container(folder=scm.scm_folder if object_type == "zones" else scm.scm_object_folder, snippet=scm.scm_snippet, device=scm.scm_device)
    items = policy_api.scm_fetch_all(f"{root}/{endpoint_name}", token, container)
    if not metadata.get("generic"):
        return items
    records = []
    for item in items:
        raw = copy.deepcopy(item)
        record = copy.deepcopy(item)
        fields = _scm_config_fields(raw)
        if object_type == "url-filtering":
            for field in fields:
                top = str(field.get("label", "")).split(" / ", 1)[0].strip().lower()
                if top in URL_PROFILE_ACTIONS: field["group"] = "Categories"
                elif top == "credential enforcement": field["group"] = "User Credential Detection"
                elif "inline" in top or top.startswith("mlav"): field["group"] = "Inline Categorization"
                elif top.startswith("log http") or "header" in top: field["group"] = "HTTP Header Insertion"
                else: field["group"] = "General"
        record["edit_fields"] = fields
        record["generic"] = True
        record["_raw"] = raw
        records.append(record)
    return records


def _read_json_cache(cache_path: Path, max_age: int | None = None):
    try:
        if not cache_path.exists():
            return None
        if max_age is not None and time.time() - cache_path.stat().st_mtime > max_age:
            return None
        return json.loads(cache_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _write_json_cache(cache_path: Path, items) -> None:
    temporary = cache_path.with_name(
        f"{cache_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    temporary.write_text(json.dumps(items))
    temporary.chmod(0o600)
    temporary.replace(cache_path)


def cached_live_items(profile, cache_key: str, loader, force: bool = False):
    """Short-lived page cache; all write paths invalidate it immediately."""
    safe_key = re.sub(r"[^a-zA-Z0-9_.-]+", "-", cache_key)
    cache_path = OBJECT_CACHE / f"{int(profile['id'])}-live-{safe_key}.json"
    if not force:
        cached = _read_json_cache(cache_path, LIVE_PAGE_CACHE_SECONDS)
        if cached is not None:
            return cached
    items = loader()
    _write_json_cache(cache_path, items)
    return items


def cached_object_page(profile, object_type: str, force: bool = False) -> list[dict]:
    cache_path = OBJECT_CACHE / f"{int(profile['id'])}-{object_type}.json"
    if not force:
        cached = _read_json_cache(cache_path, LIVE_PAGE_CACHE_SECONDS)
        if cached is not None:
            return cached
    items = fetch_scm_objects(profile, object_type)
    _write_json_cache(cache_path, items)
    return items


def _scm_config_protected(key: str) -> bool:
    normalized = key.lower().replace("_", "-")
    return normalized in {"password", "phash", "private-key", "secret", "auth-key", "client-secret"} or "password" in normalized or "private-key" in normalized


def _scm_config_fields(payload: dict) -> list[dict]:
    fields = []

    def walk(value, path: list[str], labels: list[str]):
        key = path[-1] if path else "general"
        label = " / ".join(labels) or "General"
        group = labels[0] if labels else "General"
        encoded_path = json.dumps(path, separators=(",", ":"))
        if _scm_config_protected(key):
            fields.append({"path": encoded_path, "label": label, "group": group, "kind": "protected"}); return
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                walk(child_value, path + [str(child_key)], labels + [str(child_key).replace("_", " ").title()])
        elif isinstance(value, list):
            if all(not isinstance(item, (dict, list)) for item in value):
                fields.append({"path": encoded_path, "label": label, "group": group, "kind": "members", "values": [str(item) for item in value]})
            else:
                fields.append({"path": encoded_path, "label": label, "group": group, "kind": "json", "value": json.dumps(value, indent=2, sort_keys=True)})
        elif isinstance(value, bool):
            fields.append({"path": encoded_path, "label": label, "group": group, "kind": "bool", "value": value})
        elif value is None:
            fields.append({"path": encoded_path, "label": label, "group": group, "kind": "text", "value": ""})
        else:
            text = str(value)
            if len(text) > 8192:
                fields.append({"path": encoded_path, "label": label, "group": group, "kind": "protected"})
            else:
                fields.append({"path": encoded_path, "label": label, "group": group, "kind": "text", "value": text})

    for key, value in payload.items():
        if key in {"id", "name", "folder", "snippet", "device", "created_at", "updated_at"}:
            continue
        walk(value, [str(key)], [str(key).replace("_", " ").title()])
    return fields


def scm_generic_create_record(object_type: str, container: dict) -> dict | None:
    raw = copy.deepcopy(SCM_GENERIC_CREATE_DEFAULTS.get(object_type))
    if raw is None:
        return None
    raw.update(container)
    fields = _scm_config_fields(raw)
    if object_type == "url-filtering":
        for field in fields:
            top = str(field.get("label", "")).split(" / ", 1)[0].strip().lower()
            if top in URL_PROFILE_ACTIONS: field["group"] = "Categories"
            elif top == "credential enforcement": field["group"] = "User Credential Detection"
            elif "inline" in top or top.startswith("mlav"): field["group"] = "Inline Categorization"
            elif top.startswith("log http") or "header" in top: field["group"] = "HTTP Header Insertion"
            else: field["group"] = "General"
    return {
        "id": "", "name": "", "generic": True, "create_template": True,
        "edit_fields": fields, "_raw": raw,
    }


def _scm_config_fingerprint(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def fetch_scm_configuration_records(profile, view: str, section: str) -> list[dict]:
    spec = SCM_CONFIGURATION_SECTIONS.get(view, {}).get(section)
    if not spec:
        return []
    scm, token, _, container = scm_client(profile)
    root = policy_api.scm_api_root(scm.scm_api_base) + f"/config/{view}/v1"
    records = []
    failures = []
    for endpoint_name in spec[1]:
        try:
            if view == "device":
                response = policy_api.scm_http_request("GET", f"{root}/{endpoint_name}", token, params=container)
                items = policy_api.response_items(response)
            else:
                items = policy_api.scm_fetch_all(f"{root}/{endpoint_name}", token, container)
        except Exception as exc:
            message = str(exc)
            status = message.split("HTTP ", 1)[1].split(":", 1)[0] if "HTTP " in message else type(exc).__name__
            failures.append(f"{endpoint_name}: {status}")
            continue
        for item in items:
            raw = copy.deepcopy(item)
            item_id = str(item.get("id", ""))
            name = str(item.get("name") or item.get("display_name") or item_id or spec[0])
            fields = _scm_config_fields(raw)
            summary = []
            for field in fields:
                if field["kind"] == "members": summary.extend(field.get("values", [])[:2])
                elif field["kind"] != "protected" and str(field.get("value", "")).strip(): summary.append(str(field["value"]).strip())
                if len(summary) >= 3: break
            record = {
                "id": item_id, "locator": f"{endpoint_name}:{item_id}", "endpoint": endpoint_name,
                "name": name, "owner": next((container[key] for key in ("folder", "snippet", "device") if container.get(key)), "SCM"),
                "kind": endpoint_name.replace("-", " ").title(), "is_entry": True, "editable": True,
                "summary": " · ".join(summary[:3]), "edit_fields": fields,
                "fingerprint": _scm_config_fingerprint(raw), "_raw": raw,
            }
            records.append(panos_ui_decorate_record(record, section))
    if not records and failures:
        raise RuntimeError("; ".join(failures))
    return records


def _scm_config_payload(raw: dict, updates: list[dict], name: str) -> dict:
    payload = copy.deepcopy(raw)
    allowed = {(field["path"], field["kind"]) for field in _scm_config_fields(raw) if field["kind"] != "protected"}
    for update in updates:
        key = (str(update.get("path", "")), str(update.get("kind", "")))
        if key not in allowed:
            raise ValueError("Een SCM-configuratieveld bestaat niet meer of is beschermd")
        path = json.loads(key[0])
        target = payload
        for part in path[:-1]: target = target[part]
        if key[1] == "members": target[path[-1]] = [str(value) for value in update.get("values", [])]
        elif key[1] == "bool": target[path[-1]] = str(update.get("value", "")).lower() == "true"
        elif key[1] == "json": target[path[-1]] = json.loads(str(update.get("value", "[]")))
        else:
            old = target.get(path[-1])
            value = str(update.get("value", ""))
            if isinstance(old, int) and value.strip(): target[path[-1]] = int(value)
            elif isinstance(old, float) and value.strip(): target[path[-1]] = float(value)
            else: target[path[-1]] = value
    if "name" in payload: payload["name"] = name
    return payload


URL_PROFILE_ACTIONS = {"allow", "alert", "block", "continue", "override", "redirect", "none"}


def normalize_url_profile_updates(fields: list[dict], updates: list[dict]) -> list[dict]:
    """Move a URL category to one site-access action atomically.

    The editor submits every visible member list. When a category is newly
    added to an action, remove it from the other top-level action lists so the
    resulting PAN-OS/SCM profile cannot contain contradictory assignments.
    Credential-enforcement lists are deliberately excluded.
    """
    by_key = {(field.get("path"), field.get("kind")): field for field in fields}
    action_updates = {}
    moved = []
    for update in updates:
        field = by_key.get((update.get("path"), update.get("kind")))
        action = str((field or {}).get("label", "")).strip().lower()
        if action not in URL_PROFILE_ACTIONS or update.get("kind") != "members":
            continue
        action_updates[action] = update
        old_values = set(str(value) for value in (field.get("values") or []))
        new_values = [str(value) for value in update.get("values", [])]
        moved.extend((value, action) for value in new_values if value not in old_values)
    for value, target_action in moved:
        for action, update in action_updates.items():
            if action != target_action:
                update["values"] = [candidate for candidate in update.get("values", []) if candidate != value]
    return updates


def managed_view(object_type: str) -> str:
    return "network" if object_type == "zones" else "objects"


PANOS_OBJECT_NODES = {
    "addresses": "address", "address-groups": "address-group", "applications": "application",
    "application-groups": "application-group", "application-filters": "application-filter",
    "services": "service", "service-groups": "service-group", "tags": "tag", "zones": "zone",
    "hip-profiles": "hip-profiles", "schedules": "schedule", "security-profile-groups": "profile-group",
    "log-forwarding": "log-settings/profiles", "syslog-server-profiles": "log-settings/syslog",
    "email-server-profiles": "log-settings/email", "snmp-trap-server-profiles": "log-settings/snmptrap",
    "http-server-profiles": "log-settings/http",
}


def panos_object_bases(profile, object_type: str) -> list[str]:
    settings = json.loads(profile["settings_json"] or "{}")
    if object_type == "applications": return ["/config/predefined"]
    device = policy_api.xpath_literal("localhost.localdomain")
    server_profile_types = {"syslog-server-profiles", "email-server-profiles", "snmp-trap-server-profiles", "http-server-profiles"}
    if object_type in server_profile_types:
        if profile["target_type"] == "panorama":
            return ["/config/shared"]
        vsys = policy_api.xpath_literal(settings.get("vsys", "vsys1"))
        return ["/config/shared", f"/config/devices/entry[@name={device}]/vsys/entry[@name={vsys}]"]
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
    if object_type == "log-forwarding":
        item["match_list"] = []
        for match in entry.findall("./match-list/entry"):
            actions = []
            for action in match.findall("./actions/entry"):
                tagging = action.find("./type/tagging")
                integration = action.find("./type/integration")
                if tagging is not None:
                    actions.append({
                        "name": action.get("name", ""), "type": "tagging",
                        "action": tagging.findtext("./action", "add-tag"),
                        "target": tagging.findtext("./target", "source-address"),
                        "registration": tagging.findtext("./registration", "localhost"),
                        "timeout": tagging.findtext("./timeout", ""),
                        "tags": [node.text or "" for node in tagging.findall("./tags/member") if node.text],
                    })
                elif integration is not None:
                    actions.append({
                        "name": action.get("name", ""), "type": "integration",
                        "integration_action": integration.findtext("./action", ""),
                    })
            item["match_list"].append({
                "name": match.get("name", ""),
                "action_desc": match.findtext("./action-desc", ""),
                "log_type": match.findtext("./log-type", "traffic") or "traffic",
                "filter": match.findtext("./filter", ""),
                "send_to_panorama": match.findtext("./send-to-panorama", "no") == "yes",
                "send_syslog": [node.text or "" for node in match.findall("./send-syslog/member") if node.text],
                "send_email": [node.text or "" for node in match.findall("./send-email/member") if node.text],
                "send_snmptrap": [node.text or "" for node in match.findall("./send-snmptrap/member") if node.text],
                "send_http": [node.text or "" for node in match.findall("./send-http/member") if node.text],
                "quarantine": match.findtext("./quarantine", "no") == "yes",
                "actions": actions,
            })
        item["enhanced_application_logging"] = entry.findtext("./enhanced-application-logging", "no") == "yes"
    return item


def fetch_panos_objects(profile, object_type: str) -> list[dict]:
    _, endpoint, key, ctx = panos_profile_context(profile)
    node = PANOS_OBJECT_NODES[object_type]
    collected = []
    for base in panos_object_bases(profile, object_type):
        response = policy_api.require_success(policy_api.api_get(endpoint, {"type": "config", "action": "get", "xpath": f"{base}/{node}", "key": key}, ctx), f"fetch {object_type}")
        result = response.find("./result")
        containers = list(result) if result is not None else []
        for container in containers:
            collected.extend(xml_object_to_dict(entry, object_type, base) for entry in container.findall("./entry"))
    return collected


def fetch_application_objects(profile) -> list[dict]:
    """Return custom and predefined applications through one flavor-neutral catalog."""
    if profile["target_type"] == "scm":
        return fetch_scm_objects(profile, "applications")
    custom = fetch_panos_objects(profile, "applications")
    _, endpoint, key, ctx = panos_profile_context(profile)
    response = policy_api.require_success(
        policy_api.api_get(endpoint, {"type": "config", "action": "get", "xpath": "/config/predefined/application", "key": key}, ctx),
        "fetch predefined applications",
    )
    combined = {item.get("name", ""): item for item in custom if item.get("name")}
    for entry in response.findall("./result/application/entry"):
        name = entry.get("name", "")
        if name and name not in combined:
            combined[name] = {"id": name, "name": name, "predefined": True}
    return list(combined.values())


def application_catalog_configuration(include_record: bool = False):
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM system_settings WHERE setting_key='application_catalog'"
        ).fetchone()
    settings = {
        "enabled": False,
        "folder": "All",
        "interval_hours": 24,
        "last_success": "",
        "last_error": "",
        "item_count": 0,
    }
    if row:
        try:
            settings.update(json.loads(row["settings_json"] or "{}"))
        except (TypeError, json.JSONDecodeError):
            pass
    settings["enabled"] = bool(settings.get("enabled"))
    settings["folder"] = str(settings.get("folder") or "All")
    settings["interval_hours"] = max(1, min(168, int(settings.get("interval_hours") or 24)))
    settings["item_count"] = max(0, int(settings.get("item_count") or 0))
    settings["credentials_configured"] = bool(row and row["secret_blob"])
    with _default_catalog_refresh_lock:
        settings["refreshing"] = _default_catalog_refreshing
    return (settings, row) if include_record else settings


def update_application_catalog_state(**updates) -> dict:
    settings, row = application_catalog_configuration(include_record=True)
    settings.pop("credentials_configured", None)
    settings.pop("refreshing", None)
    settings.update(updates)
    with db() as conn:
        conn.execute(
            "INSERT INTO system_settings(setting_key,settings_json,secret_blob,updated_at) VALUES('application_catalog',?,?,?) "
            "ON CONFLICT(setting_key) DO UPDATE SET settings_json=excluded.settings_json,updated_at=excluded.updated_at",
            (json.dumps(settings), row["secret_blob"] if row else b"", now()),
        )
    return application_catalog_configuration()


def default_application_items() -> list[dict]:
    try:
        raw = json.loads(DEFAULT_APPLICATION_CACHE.read_text()) if DEFAULT_APPLICATION_CACHE.exists() else []
    except (OSError, json.JSONDecodeError):
        return []
    return [item for item in raw if isinstance(item, dict) and str(item.get("name", "")).strip()]


def refresh_default_application_catalog() -> int:
    global _default_catalog_refreshing
    if not _default_catalog_refresh_lock.acquire(blocking=False):
        raise RuntimeError("De Application Database wordt al vernieuwd")
    _default_catalog_refreshing = True
    try:
        settings, row = application_catalog_configuration(include_record=True)
        if not settings["enabled"]:
            raise ValueError("Activeer eerst de automatische Application Database")
        if not row or not row["secret_blob"]:
            raise ValueError("SCM-credentials ontbreken")
        profile = {
            "id": -1,
            "name": "Default Application Database",
            "target_type": "scm",
            "settings_json": json.dumps({
                "folder": settings["folder"],
                "object_folder": settings["folder"],
                "rulebase": "pre",
            }),
            "secret_blob": row["secret_blob"],
            "updated_at": row["updated_at"],
        }
        fresh = fetch_scm_objects(profile, "applications")
        by_name = {
            str(item.get("name", "")).strip(): item
            for item in fresh
            if str(item.get("name", "")).strip()
        }
        items = [by_name[name] for name in sorted(by_name, key=str.casefold)]
        temporary = DEFAULT_APPLICATION_CACHE.with_suffix(".tmp")
        temporary.write_text(json.dumps(items))
        temporary.chmod(0o600)
        temporary.replace(DEFAULT_APPLICATION_CACHE)
        update_application_catalog_state(
            last_success=now(), last_error="", item_count=len(items)
        )
        audit("application-catalog-refreshed", f"items={len(items)}")
        return len(items)
    except Exception as exc:
        try:
            update_application_catalog_state(
                last_error=f"{type(exc).__name__}: ophalen mislukt"
            )
        except Exception:
            app.logger.exception("Application Database status kon niet worden bijgewerkt")
        raise
    finally:
        _default_catalog_refreshing = False
        _default_catalog_refresh_lock.release()


def refresh_default_application_catalog_async() -> bool:
    with _default_catalog_refresh_lock:
        if _default_catalog_refreshing:
            return False

    def refresh():
        try:
            refresh_default_application_catalog()
        except Exception:
            app.logger.exception("periodieke SCM Application Database refresh mislukt")

    threading.Thread(target=refresh, name="default-application-catalog", daemon=True).start()
    return True


def refresh_catalog_async(profile, kind: str, cache_path: Path) -> None:
    key = (int(profile["id"]), kind)
    with _catalog_refresh_lock:
        if key in _catalog_refreshing or _catalog_retry_after.get(key, 0) > time.monotonic(): return
        _catalog_refreshing.add(key)
    def refresh():
        try:
            fresh = fetch_application_objects(profile) if kind == "applications" else fetch_scm_objects(profile, kind)
            temporary = cache_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(fresh)); temporary.chmod(0o600); temporary.replace(cache_path)
            with _catalog_refresh_lock:
                _catalog_errors.pop(key, None)
                _catalog_retry_after.pop(key, None)
        except Exception as exc:
            with _catalog_refresh_lock:
                _catalog_errors[key] = f"{type(exc).__name__}: ophalen mislukt"
                _catalog_retry_after[key] = time.monotonic() + CATALOG_RETRY_SECONDS
            app.logger.exception("catalog refresh failed for profile=%s kind=%s", profile["id"], kind)
        finally:
            with _catalog_refresh_lock: _catalog_refreshing.discard(key)
    threading.Thread(target=refresh, name=f"catalog-{profile['id']}-{kind}", daemon=True).start()


def application_cache_path(profile_id: int) -> Path:
    return OBJECT_CACHE / f"{int(profile_id)}-applications-v2.json"


def profile_has_live_application_source(profile) -> bool:
    """Avoid a failing device refresh for imported/offline workspaces."""
    try:
        secret = profile["secret_blob"]
    except (KeyError, IndexError):
        secret = b""
    if not secret:
        return False
    if profile["target_type"] == "scm":
        return True
    try:
        settings = json.loads(profile["settings_json"] or "{}")
    except (KeyError, IndexError, TypeError, json.JSONDecodeError):
        return False
    return bool(str(settings.get("endpoint", "")).strip())


def cached_application_catalog(profile) -> dict:
    profile_id = int(profile["id"])
    cache_path = application_cache_path(profile_id)
    items = []
    if cache_path.exists():
        try: items = json.loads(cache_path.read_text())
        except (OSError, json.JSONDecodeError): items = []
    stale = not cache_path.exists() or time.time() - cache_path.stat().st_mtime >= 1800
    if stale and profile_has_live_application_source(profile):
        refresh_catalog_async(profile, "applications", cache_path)
    with _catalog_refresh_lock:
        refreshing = (profile_id, "applications") in _catalog_refreshing
        error = _catalog_errors.get((profile_id, "applications"), "")
    combined = {
        item.get("name", ""): item
        for item in default_application_items()
        if item.get("name")
    }
    combined.update({item.get("name", ""): item for item in items if item.get("name")})
    return {
        "ready": bool(combined),
        "refreshing": refreshing or application_catalog_configuration()["refreshing"],
        "error": error,
        "items": [
            {"name": name, "kind": "applications"}
            for name in sorted(combined, key=str.casefold)
        ],
    }


def fetch_object_catalog(profile, object_type: str) -> list[dict]:
    related = {
        "addresses": ("tags",), "services": ("tags",),
        "address-groups": ("addresses", "address-groups", "tags"),
        "service-groups": ("services", "service-groups", "tags"),
        "application-groups": ("applications", "application-groups", "tags"),
        "zones": ("zones", "interfaces", "zone-protection-profiles", "log-forwarding"),
        "log-forwarding": ("syslog-server-profiles", "email-server-profiles", "snmp-trap-server-profiles", "http-server-profiles", "tags"),
        "policy-picker": (
            "zones", "addresses", "address-groups", "applications", "application-groups",
            "application-filters", "services", "service-groups", "tags", "hip-profiles",
            "custom-url-categories", "schedules", "security-profile-groups", "log-forwarding", "interfaces",
        ),
    }.get(object_type, ())
    profile_id = int(profile["id"])

    def catalog_kind(kind: str) -> list[dict]:
        if kind == "applications":
            return cached_application_catalog(profile)["items"]
        network_reference = kind in {"interfaces", "zone-protection-profiles"}
        cache_path = (
            OBJECT_CACHE / f"{profile_id}-reference-{kind}.json"
            if network_reference else OBJECT_CACHE / f"{profile_id}-{kind}.json"
        )
        cached = _read_json_cache(cache_path)
        stale = cached is None or time.time() - cache_path.stat().st_mtime >= 1800
        server_profile_reference = object_type == "log-forwarding" and kind in {
            "syslog-server-profiles", "email-server-profiles",
            "snmp-trap-server-profiles", "http-server-profiles",
        }
        if server_profile_reference and stale:
            # These options are needed immediately while editing a log-forwarding
            # profile. An asynchronous refresh left an empty/stale picker on the
            # page until the user reloaded it, so refresh these small catalogs
            # synchronously and keep the last cache only as an error fallback.
            try:
                source = fetch_scm_objects(profile, kind)
                _write_json_cache(cache_path, source)
                with _catalog_refresh_lock:
                    _catalog_errors.pop((profile_id, kind), None)
                    _catalog_retry_after.pop((profile_id, kind), None)
            except Exception as exc:
                with _catalog_refresh_lock:
                    _catalog_errors[(profile_id, kind)] = f"{type(exc).__name__}: ophalen mislukt"
                app.logger.warning(
                    "server profile catalog refresh failed for profile=%s kind=%s error=%s",
                    profile_id, kind, type(exc).__name__,
                )
                source = cached if cached is not None else []
        elif cached is not None:
            if stale and not network_reference:
                refresh_catalog_async(profile, kind, cache_path)
            source = cached
        else:
            retry_key = (profile_id, f"reference:{kind}")
            with _catalog_refresh_lock:
                retry_later = _catalog_retry_after.get(retry_key, 0) > time.monotonic()
            if retry_later:
                return []
            try:
                source = (
                    fetch_network_reference_catalog(profile, kind)
                    if network_reference else fetch_scm_objects(profile, kind)
                )
                _write_json_cache(cache_path, source)
                with _catalog_refresh_lock:
                    _catalog_errors.pop(retry_key, None)
                    _catalog_retry_after.pop(retry_key, None)
            except Exception as exc:
                with _catalog_refresh_lock:
                    _catalog_errors[retry_key] = f"{type(exc).__name__}: ophalen mislukt"
                    _catalog_retry_after[retry_key] = time.monotonic() + CATALOG_RETRY_SECONDS
                app.logger.warning(
                    "reference catalog unavailable for profile=%s kind=%s error=%s",
                    profile_id, kind, type(exc).__name__,
                )
                return []
        if network_reference:
            return [
                {"name": item.get("name", ""), "kind": item.get("kind", kind)}
                for item in source if item.get("name")
            ]
        return [
            {"name": item.get("name", ""), "kind": kind}
            for item in source if item.get("name")
        ]

    catalog = []
    if related:
        with ThreadPoolExecutor(max_workers=min(8, len(related)), thread_name_prefix="catalog") as pool:
            for items in pool.map(catalog_kind, related):
                catalog.extend(items)
    if object_type == "policy-picker":
        known = {(item["name"], item["kind"]) for item in catalog}
        catalog.extend(
            {"name": code, "kind": "regions"}
            for code in sorted(PANOS_GEO_REGION_CODES)
            if (code, "regions") not in known
        )
    if object_type == "log-forwarding":
        profiles = _read_json_cache(OBJECT_CACHE / f"{profile_id}-log-forwarding.json")
        if profiles is None:
            try:
                profiles = fetch_scm_objects(profile, "log-forwarding")
            except Exception:
                profiles = []
        known = {(item["name"], item["kind"]) for item in catalog}
        for profile_item in profiles:
            for match in profile_item.get("match_list", []) or []:
                for action in match.get("actions", []) or []:
                    name = str(action.get("integration_action", "")).strip()
                    key = (name, "log-integration-actions")
                    if name and key not in known:
                        known.add(key)
                        catalog.append({"name": name, "kind": "log-integration-actions"})
    return sorted(catalog, key=lambda item: (item["name"].lower(), item["kind"]))


def fetch_network_reference_catalog(profile, kind: str) -> list[dict]:
    """Return existing interface/profile names used by object-backed editor fields."""
    if kind not in {"interfaces", "zone-protection-profiles"}:
        return []
    names = set()
    if profile["target_type"] == "scm":
        section = "interfaces" if kind == "interfaces" else "network-profiles"
        for item in fetch_scm_configuration_records(profile, "network", section):
            if kind == "zone-protection-profiles" and item.get("endpoint") != "zone-protection-profiles":
                continue
            name = str(item.get("name", "")).strip()
            if name:
                names.add(name)
    else:
        _, endpoint, key, ctx = panos_profile_context(profile)
        for zone_base in panos_object_bases(profile, "zones"):
            device_base = zone_base.rsplit("/vsys/entry", 1)[0]
            xpath = (
                f"{device_base}/network/interface"
                if kind == "interfaces"
                else f"{device_base}/network/profiles/zone-protection-profile"
            )
            response = policy_api.require_success(
                policy_api.api_get(endpoint, {"type": "config", "action": "get", "xpath": xpath, "key": key}, ctx),
                f"fetch {kind}",
            )
            if kind == "zone-protection-profiles":
                entries = response.findall("./result/zone-protection-profile/entry")
            else:
                entries = []
                for interface in response.findall("./result/interface"):
                    entries.extend(interface.findall("./*/entry"))
                    entries.extend(interface.findall("./*/units/entry"))
                    entries.extend(interface.findall("./*/entry/*/units/entry"))
            for entry in entries:
                name = str(entry.get("name", "")).strip()
                if name:
                    names.add(name)
    return [{"name": name, "kind": kind} for name in sorted(names, key=str.casefold)]


@app.get("/profiles/<int:profile_id>/catalog/applications")
@login_required
def application_catalog(profile_id):
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile: return {"ready": False, "items": []}, 404
    return cached_application_catalog(profile)


@app.get("/config-workspaces/<int:workspace_id>/catalog/applications")
@login_required
def workspace_application_catalog(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace: return {"ready": False, "items": []}, 404
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)).fetchone()
    if not profile: return {"ready": False, "items": []}, 404
    return cached_application_catalog(profile)


@app.get("/config-workspaces/<int:workspace_id>/catalog/url-categories")
@login_required
def workspace_url_category_catalog(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace: return {"items": []}, 404
    scope = request.args.get("scope", "").strip()
    try:
        xml_bytes, parsed_root, snapshot = cached_workspace_config(workspace["config_path"], workspace["sha256"])
        valid_scopes = set(available_scopes(snapshot))
        if snapshot.kind == "panos": valid_scopes.add("Shared")
        if scope not in valid_scopes: raise OfflineConfigError("De gekozen scope bestaat niet")
        items = []
        for object_type in ("custom-url-categories", "external-dynamic-lists"):
            _, objects = scoped_objects(xml_bytes, scope, object_type, parsed=(parsed_root, snapshot))
            items.extend({"name": item["name"], "kind": object_type} for item in objects)
        return {"items": sorted(items, key=lambda item: (item["name"].lower(), item["kind"]))}
    except Exception as exc:
        return {"items": [], "error": str(exc)}, 400


@app.get("/profiles/<int:profile_id>/catalog/url-categories")
@login_required
def scm_url_category_catalog(profile_id):
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile or profile["target_type"] != "scm": return {"items": []}, 404
    try:
        items = fetch_scm_objects(profile, "custom-url-categories")
        return {"items": [{"name": item["name"], "kind": "custom-url-categories"} for item in items if item.get("name")]}
    except Exception as exc:
        return {"items": [], "error": str(exc)}, 400


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
    elif object_type == "log-forwarding":
        try:
            submitted_matches = json.loads(form.get("match_list_json", "[]"))
        except json.JSONDecodeError as exc:
            raise ValueError("Ongeldige Log Forwarding match list") from exc
        if not isinstance(submitted_matches, list) or not submitted_matches or len(submitted_matches) > 128:
            raise ValueError("Voeg minstens één geldige match-list entry toe")
        allowed_log_types = {"traffic", "threat", "wildfire", "url", "data", "gtp", "sctp", "tunnel", "auth", "decryption", "dns-security"}
        match_list = []
        names = set()
        for raw in submitted_matches:
            if not isinstance(raw, dict):
                raise ValueError("Ongeldige match-list entry")
            match_name = str(raw.get("name", "")).strip()
            if not match_name or len(match_name) > 63:
                raise ValueError("Elke match-list entry heeft een unieke naam nodig")
            if match_name in names:
                raise ValueError(f"Match-list entry {match_name} staat meermaals in het profiel")
            names.add(match_name)
            log_type = str(raw.get("log_type", "traffic")).strip()
            if log_type not in allowed_log_types:
                raise ValueError(f"Ongeldig log type: {log_type}")
            clean = {
                "name": match_name,
                "action_desc": str(raw.get("action_desc", "")).strip()[:255],
                "log_type": log_type,
                "filter": str(raw.get("filter", "")).strip()[:65535],
            }
            for key in ("send_syslog", "send_email", "send_snmptrap", "send_http"):
                values = raw.get(key, [])
                if not isinstance(values, list):
                    raise ValueError(f"Ongeldige destinationlijst voor {match_name}")
                clean[key] = list(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))
            clean["send_to_panorama"] = bool(raw.get("send_to_panorama"))
            clean["quarantine"] = bool(raw.get("quarantine"))
            submitted_actions = raw.get("actions", [])
            if not isinstance(submitted_actions, list) or len(submitted_actions) > 128:
                raise ValueError(f"Ongeldige Actions-lijst voor {match_name}")
            actions = []
            action_names = set()
            for raw_action in submitted_actions:
                if not isinstance(raw_action, dict):
                    raise ValueError(f"Ongeldige Action voor {match_name}")
                action_name = str(raw_action.get("name", "")).strip()
                if not action_name or len(action_name) > 63 or action_name in action_names:
                    raise ValueError(f"Elke Action in {match_name} heeft een unieke naam nodig")
                action_names.add(action_name)
                action_type = str(raw_action.get("type", "tagging")).strip()
                if action_type == "tagging":
                    tag_action = str(raw_action.get("action", "add-tag")).strip()
                    target = str(raw_action.get("target", "source-address")).strip()
                    registration = str(raw_action.get("registration", "localhost")).strip()
                    if tag_action not in {"add-tag", "remove-tag"}:
                        raise ValueError(f"Ongeldige tagging action in {match_name}")
                    if target not in {"source-address", "destination-address", "xff-address", "user"}:
                        raise ValueError(f"Ongeldig tagging target in {match_name}")
                    if registration not in {"remote", "panorama", "localhost"}:
                        raise ValueError(f"Ongeldige tagging registration in {match_name}")
                    timeout = str(raw_action.get("timeout", "")).strip()
                    if timeout:
                        timeout_value = int(timeout)
                        if timeout_value < 0 or timeout_value > 2592000:
                            raise ValueError(f"Tag timeout in {match_name} moet tussen 0 en 2592000 liggen")
                    tags = raw_action.get("tags", [])
                    if not isinstance(tags, list) or not tags:
                        raise ValueError(f"Selecteer minstens één bestaande tag voor Action {action_name}")
                    actions.append({
                        "name": action_name, "type": "tagging", "action": tag_action,
                        "target": target, "registration": registration, "timeout": timeout,
                        "tags": list(dict.fromkeys(str(value).strip() for value in tags if str(value).strip())),
                    })
                elif action_type == "integration":
                    integration_action = str(raw_action.get("integration_action", "")).strip()
                    if not integration_action:
                        raise ValueError(f"Integration Action {action_name} heeft een bestaande integratieactie nodig")
                    actions.append({"name": action_name, "type": "integration", "integration_action": integration_action})
                else:
                    raise ValueError(f"Ongeldig Action type in {match_name}")
            clean["actions"] = actions
            match_list.append(clean)
        payload["match_list"] = match_list
        payload["enhanced_application_logging"] = form.get("enhanced_application_logging") == "on"
    else:
        raise ValueError("Dit objecttype gebruikt een andere configuratie-editor")
    return payload


def object_fingerprint(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def object_payload_xml(payload: dict) -> str:
    entry = ET.Element("entry", {"name": payload["name"]})
    if "match_list" in payload:
        description = str(payload.get("description", "")).strip()
        if description:
            ET.SubElement(entry, "description").text = description
        if payload.get("enhanced_application_logging"):
            ET.SubElement(entry, "enhanced-application-logging").text = "yes"
        match_list = ET.SubElement(entry, "match-list")
        for match in payload["match_list"]:
            match_entry = ET.SubElement(match_list, "entry", {"name": match["name"]})
            if match.get("action_desc"):
                ET.SubElement(match_entry, "action-desc").text = str(match["action_desc"])
            ET.SubElement(match_entry, "log-type").text = str(match["log_type"])
            ET.SubElement(match_entry, "filter").text = str(match.get("filter", ""))
            if match.get("send_to_panorama"):
                ET.SubElement(match_entry, "send-to-panorama").text = "yes"
            if match.get("quarantine"):
                ET.SubElement(match_entry, "quarantine").text = "yes"
            for key in ("send_syslog", "send_email", "send_snmptrap", "send_http"):
                values = match.get(key, [])
                if values:
                    node = ET.SubElement(match_entry, key.replace("_", "-"))
                    for value in values:
                        ET.SubElement(node, "member").text = str(value)
            if match.get("actions"):
                actions_node = ET.SubElement(match_entry, "actions")
                for action in match["actions"]:
                    action_entry = ET.SubElement(actions_node, "entry", {"name": action["name"]})
                    action_type = ET.SubElement(action_entry, "type")
                    if action.get("type") == "integration":
                        integration = ET.SubElement(action_type, "integration")
                        ET.SubElement(integration, "action").text = str(action.get("integration_action", ""))
                    else:
                        tagging = ET.SubElement(action_type, "tagging")
                        for key in ("action", "target", "registration"):
                            ET.SubElement(tagging, key).text = str(action.get(key, ""))
                        if action.get("timeout") not in (None, ""):
                            ET.SubElement(tagging, "timeout").text = str(action["timeout"])
                        tags = ET.SubElement(tagging, "tags")
                        for value in action.get("tags", []):
                            ET.SubElement(tags, "member").text = str(value)
        return ET.tostring(entry, encoding="unicode")
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


def write_panos_object_draft(profile, draft: dict, on_delete=None) -> None:
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
            if on_delete:
                on_delete()


def validate_object_payload(payload: dict, object_type: str, existing: list[dict], own_id: str = "") -> None:
    others = [item for item in existing if str(item.get("id", "")) != own_id]
    same_name = next((item for item in others if item.get("name") == payload["name"]), None)
    if same_name:
        raise ValueError(f"Object {payload['name']} bestaat al; gebruik het bestaande object.")
    comparable_keys = {
        "addresses": ("ip_netmask", "ip_range", "ip_wildcard", "fqdn"),
        "address-groups": ("static", "dynamic"), "application-groups": ("members",),
        "services": ("protocol",), "service-groups": ("members",), "tags": ("color",), "zones": ("network",),
        "log-forwarding": ("match_list", "enhanced_application_logging"),
    }[object_type]
    wanted = {key: payload.get(key) for key in comparable_keys if payload.get(key) is not None}
    equivalent = next((item for item in others if {key: item.get(key) for key in comparable_keys if item.get(key) is not None} == wanted), None)
    if equivalent:
        raise ValueError(f"Een equivalent object bestaat al als {equivalent['name']}; gebruik dat bestaande object.")


def validate_log_forwarding_destinations(payload: dict, catalog: list[dict]) -> None:
    kinds = {
        "send_syslog": "syslog-server-profiles", "send_email": "email-server-profiles",
        "send_snmptrap": "snmp-trap-server-profiles", "send_http": "http-server-profiles",
    }
    available = {}
    for item in catalog:
        available.setdefault(item.get("kind", ""), set()).add(item.get("name", ""))
    for match in payload.get("match_list", []):
        for field, kind in kinds.items():
            missing = sorted(set(match.get(field, [])) - available.get(kind, set()))
            if missing:
                raise ValueError(
                    f"Match-list {match['name']} verwijst naar niet-bestaande {kind}: {', '.join(missing)}"
                )


def validate_object_references(payload: dict, object_type: str, catalog: list[dict]) -> None:
    """Reject object references that cannot be resolved in the selected scope."""
    available: dict[str, set[str]] = {}
    for item in catalog:
        available.setdefault(str(item.get("kind", "")), set()).add(str(item.get("name", "")))

    def require(field: str, values, kinds: tuple[str, ...]) -> None:
        permitted = set().union(*(available.get(kind, set()) for kind in kinds))
        missing = sorted({str(value) for value in values if str(value) and str(value) not in permitted})
        if missing:
            raise ValueError(
                f"{field} verwijst naar niet-bestaande objecten: {', '.join(missing)}. Maak ze eerst aan."
            )

    if object_type != "tags":
        require("Tags", payload.get("tag", []), ("tags",))
    if object_type == "address-groups":
        if "static" in payload:
            require("Static members", payload["static"], ("addresses", "address-groups"))
            if payload.get("name") in payload["static"]:
                raise ValueError("Een Address Group kan zichzelf niet als member bevatten")
        elif "dynamic" in payload:
            expression = str(payload.get("dynamic", {}).get("filter", ""))
            operands = []
            for single, double, bare in re.findall(r"'([^']+)'|\"([^\"]+)\"|([^\s()]+)", expression):
                value = single or double or bare
                if value.lower() not in {"and", "or", "not"}:
                    operands.append(value)
            require("Dynamic filter", operands, ("tags",))
    elif object_type == "application-groups":
        require("Application members", payload.get("members", []), ("applications", "application-groups"))
        if payload.get("name") in payload.get("members", []):
            raise ValueError("Een Application Group kan zichzelf niet als member bevatten")
    elif object_type == "service-groups":
        require("Service members", payload.get("members", []), ("services", "service-groups"))
        if payload.get("name") in payload.get("members", []):
            raise ValueError("Een Service Group kan zichzelf niet als member bevatten")
    elif object_type == "log-forwarding":
        validate_log_forwarding_destinations(payload, catalog)
        for match in payload.get("match_list", []):
            for action in match.get("actions", []):
                if action.get("type") == "tagging":
                    require(f"Action {action['name']} tags", action.get("tags", []), ("tags",))
                elif action.get("type") == "integration":
                    require(
                        f"Action {action['name']} integration",
                        [action.get("integration_action", "")], ("log-integration-actions",),
                    )
    elif object_type == "zones":
        network = payload.get("network", {})
        interfaces = next(iter(network.values()), []) if isinstance(network, dict) else []
        require("Interfaces", interfaces, ("interfaces",))
        require(
            "Zone Protection Profile", [payload.get("zone_protection_profile", "")],
            ("zone-protection-profiles",),
        )
        require("Log Forwarding Profile", [payload.get("log_setting", "")], ("log-forwarding",))


def policy_fingerprint(policy: dict) -> str:
    return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def split_values(value: str) -> list[str]:
    return list(dict.fromkeys(item.strip() for item in value.replace("\n", ",").split(",") if item.strip()))


def validate_policy_zones(policy: dict, zone_names: set[str]) -> None:
    missing = sorted({value for field in ("from", "to") for value in policy.get(field, []) if value != "any" and value not in zone_names})
    if missing: raise ValueError("Onbekende zone(s): " + ", ".join(missing) + ". Maak ze eerst aan onder Network > Zones.")


POLICY_REFERENCE_KINDS = {
    "from": {"zones"}, "to": {"zones"},
    "source": {"addresses", "address-groups", "regions"}, "destination": {"addresses", "address-groups", "regions"},
    "source_hip": {"hip-profiles"}, "destination_hip": {"hip-profiles"},
    "application": {"applications", "application-groups", "application-filters"},
    "service": {"services", "service-groups"}, "tag": {"tags"},
    "log_setting": {"log-forwarding"}, "profile_group": {"security-profile-groups"},
    "schedule": {"schedules"}, "category": {"custom-url-categories", "predefined-url-categories"},
    "to_interface": {"interfaces"}, "source_translation_interface": {"interfaces"},
    "source_translation_address": {"addresses", "address-groups"},
    "destination_translation_address": {"addresses", "address-groups"},
}
POLICY_REFERENCE_BUILTINS = {
    "from": {"any"}, "to": {"any"}, "source": {"any"}, "destination": {"any"},
    "source_hip": {"any"}, "destination_hip": {"any"}, "application": {"any"},
    "service": {"any", "application-default"}, "category": {"any"},
    "log_setting": {"Cortex Data Lake"},
    "to_interface": {"any"},
}


@dataclass(frozen=True)
class PolicyReferenceIndex:
    allowed_by_field: dict[str, frozenset[str]]


def build_policy_reference_index(catalog: list[dict]) -> PolicyReferenceIndex:
    """Precompute each policy field's allowed values for repeated validation."""
    available_by_kind = defaultdict(set)
    for item in catalog:
        name = item.get("name", "")
        if name:
            available_by_kind[item.get("kind", "")].add(name)

    allowed_by_field = {}
    for field, kinds in POLICY_REFERENCE_KINDS.items():
        allowed = set(POLICY_REFERENCE_BUILTINS.get(field, ()))
        for kind in kinds:
            allowed.update(available_by_kind.get(kind, ()))
        allowed_by_field[field] = frozenset(allowed)
    return PolicyReferenceIndex(allowed_by_field)


def normalize_policy_wildcard_members(policy: dict) -> dict:
    """Keep PAN-OS wildcard members exclusive when concrete values are chosen."""
    exclusive = {
        "from": {"any"}, "to": {"any"}, "source": {"any"}, "destination": {"any"},
        "source_user": {"any"}, "source_hip": {"any"},
        "destination_user": {"any"}, "destination_hip": {"any"},
        "application": {"any"}, "service": {"any", "application-default"}, "category": {"any"},
    }
    normalized = dict(policy)
    for field, special_values in exclusive.items():
        values = list(normalized.get(field, []) or [])
        if any(value not in special_values for value in values):
            normalized[field] = [value for value in values if value not in special_values]
    return normalized


def extend_policy_catalog_with_current(catalog: list[dict], policies: list[dict]) -> list[dict]:
    """Add predefined values already in use in the current rulebase."""
    result = list(catalog)
    seen = {(item.get("name", ""), item.get("kind", "")) for item in result}
    current_value_kinds = {
        "application": "applications",
        "service": "services",
        "category": "predefined-url-categories",
    }
    for policy in policies:
        for field, kind in current_value_kinds.items():
            for name in policy.get(field, []) or []:
                key = (name, kind)
                if name and name not in {"any", "application-default"} and key not in seen:
                    seen.add(key)
                    result.append({"name": name, "kind": kind})
    return result


def is_native_policy_address(field: str, value: str) -> bool:
    if field not in {"source", "destination"}:
        return False
    token = str(value or "").strip()
    if token.upper() in PANOS_GEO_REGION_CODES:
        return True
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        return False


def validate_policy_references(
    policy: dict,
    catalog: list[dict] | PolicyReferenceIndex,
    changed_fields: set[str],
    allow_zone_freeform: bool = False,
) -> None:
    reference_index = catalog if isinstance(catalog, PolicyReferenceIndex) else build_policy_reference_index(catalog)
    for field in changed_fields & {"log_setting", "profile_group", "schedule"}:
        value = str(policy.get(field, "") or "")
        if "," in value:
            raise ValueError(f"{field.replace('_', ' ').title()} accepteert maximaal één waarde")
    for field in changed_fields & POLICY_REFERENCE_KINDS.keys():
        if field in {"from", "to"} and allow_zone_freeform:
            continue
        raw = policy.get(field, [])
        values = raw if isinstance(raw, list) else ([raw] if raw else [])
        permitted = reference_index.allowed_by_field[field]
        missing = sorted({
            str(value).strip() for value in values
            if str(value).strip()
            and str(value).strip() not in permitted
            and not is_native_policy_address(field, str(value))
        })
        if missing:
            if field in {"source", "destination"}:
                target = "een address object/groep, regio-landcode of IPv4/IPv6-adres"
            elif field in {"source_translation_address", "destination_translation_address"}:
                target = "een address object of groep"
            else:
                target = sorted(POLICY_REFERENCE_KINDS[field])[0].replace("-", " ")
            raise ValueError(
                f"{field.replace('_', ' ').title()} verwijst naar niet-bestaande waarden: {', '.join(missing)}. "
                f"Gebruik {target}."
            )


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
    if policy_kind == "nat":
        payload["service"] = (policy.get("service") or ["any"])[0]
        for field in ("nat_type", "to_interface", "source_translation", "destination_translation"):
            if field in policy:
                if policy[field] in ({}, ""):
                    payload.pop(field, None)
                else:
                    payload[field] = policy[field]
    payload.update(container)
    return payload


def update_xml_policy(policy: dict) -> str:
    entry = SafeET.fromstring(policy["_xml"])
    if policy.get("name"):
        entry.set("name", policy["name"])
    policy_kind = policy.get("_policy_kind", "security")
    list_fields = set(POLICY_LIST_FIELDS)
    if policy_kind == "nat":
        list_fields.discard("service")
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
    if policy_kind == "nat":
        for field in ("service", "nat_type", "to_interface"):
            if field not in policy: continue
            tag = field.replace("_", "-")
            node = entry.find(f"./{tag}")
            value = policy[field]
            if field == "service" and isinstance(value, list): value = value[0] if value else "any"
            if node is None: node = ET.SubElement(entry, tag)
            node.clear()
            node.text = str(value)
        for field in ("source_translation", "destination_translation"):
            if field not in policy: continue
            tag = field.replace("_", "-")
            existing = entry.find(f"./{tag}")
            if existing is not None: entry.remove(existing)
            if policy[field]:
                node = ET.SubElement(entry, tag)
                _append_xml_payload(node, policy[field])
    if "profile_group" in policy:
        profile_setting = entry.find("./profile-setting")
        group = entry.find("./profile-setting/group")
        member = entry.find("./profile-setting/group/member")
        if policy["profile_group"]:
            if profile_setting is None: profile_setting = ET.SubElement(entry, "profile-setting")
            if group is None: group = ET.SubElement(profile_setting, "group")
            if member is None: member = ET.SubElement(group, "member")
            member.text = str(policy["profile_group"])
        elif group is not None:
            profile_setting.remove(group)
    for field in ("disabled", "negate_source", "negate_destination", "log_start", "log_end"):
        if field not in policy or policy[field] is None: continue
        tag = field.replace("_", "-")
        node = entry.find(f"./{tag}")
        if node is None: node = ET.SubElement(entry, tag)
        node.text = "yes" if policy[field] else "no"
    return ET.tostring(entry, encoding="unicode")


def _append_xml_payload(parent: ET.Element, value) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            node = ET.SubElement(parent, str(key).replace("_", "-"))
            _append_xml_payload(node, child)
    elif isinstance(value, list):
        for child in value:
            ET.SubElement(parent, "member").text = str(child)
    elif value is not None:
        parent.text = str(value)


def nat_translation_replacements(form) -> dict:
    mode = form.get("source_translation_mode", "none").strip()
    source_address = split_values(form.get("source_translation_address", ""))
    source_interfaces = split_values(form.get("source_translation_interface", ""))
    to_interfaces = split_values(form.get("to_interface", ""))
    destination_addresses = split_values(form.get("destination_translation_address", ""))
    if len(source_interfaces) > 1 or len(to_interfaces) > 1 or len(destination_addresses) > 1:
        raise ValueError("NAT-interface en destination translation accepteren elk maximaal één waarde")
    source_interface = source_interfaces[0] if source_interfaces else ""
    if mode == "none":
        source_translation = {}
    elif mode in {"dynamic_ip", "static_ip"}:
        source_translation = {mode: {"translated_address": source_address if mode == "dynamic_ip" else (source_address[0] if source_address else "")}}
    elif mode == "dynamic_ip_and_port":
        details = {"interface_address": {"interface": source_interface}} if source_interface else {"translated_address": source_address}
        source_translation = {mode: details}
    else:
        raise ValueError("Onbekend source translation type")
    destination_address = destination_addresses[0] if destination_addresses else ""
    destination_port = form.get("destination_translation_port", "").strip()
    destination_translation = {}
    if destination_address: destination_translation["translated_address"] = destination_address
    if destination_port:
        if not destination_port.isdigit() or not 1 <= int(destination_port) <= 65535: raise ValueError("Translated port moet tussen 1 en 65535 liggen")
        destination_translation["translated_port"] = int(destination_port)
    return {
        "nat_type": form.get("nat_type", "ipv4").strip() or "ipv4",
        "to_interface": to_interfaces[0] if to_interfaces else "any",
        "source_translation": source_translation,
        "destination_translation": destination_translation,
    }


def nat_bulk_replacements(form) -> dict:
    """Return only NAT fields explicitly selected in the bulk editor."""
    result = {}
    nat_type = form.get("nat_type_bulk", "").strip()
    if nat_type:
        if nat_type not in {"ipv4", "nat64", "nptv6"}:
            raise ValueError("Onbekend NAT type")
        result["nat_type"] = nat_type
    to_interface = split_values(form.get("to_interface_bulk", ""))
    if len(to_interface) > 1:
        raise ValueError("Destination interface accepteert maximaal één waarde")
    if to_interface:
        result["to_interface"] = to_interface[0]

    source_mode = form.get("source_translation_mode_bulk", "").strip()
    if source_mode:
        source_addresses = split_values(form.get("source_translation_address_add", ""))
        source_interfaces = split_values(form.get("source_translation_interface_bulk", ""))
        if len(source_interfaces) > 1:
            raise ValueError("Source translation interface accepteert maximaal één waarde")
        source_interface = source_interfaces[0] if source_interfaces else ""
        if source_mode == "none":
            source_translation = {}
        elif source_mode in {"dynamic_ip", "static_ip"}:
            if not source_addresses:
                raise ValueError("Geef minstens één translated source address op")
            translated = source_addresses if source_mode == "dynamic_ip" else source_addresses[0]
            source_translation = {source_mode: {"translated_address": translated}}
        elif source_mode == "dynamic_ip_and_port":
            if source_interface:
                source_translation = {source_mode: {"interface_address": {"interface": source_interface}}}
            elif source_addresses:
                source_translation = {source_mode: {"translated_address": source_addresses}}
            else:
                raise ValueError("Geef een translated source address of interface op")
        else:
            raise ValueError("Onbekend source translation type")
        result.update({
            "source_translation": source_translation,
            "source_translation_mode": source_mode,
            "source_translation_address": ", ".join(source_addresses),
            "source_translation_interface": source_interface,
        })

    destination_mode = form.get("destination_translation_mode_bulk", "").strip()
    if destination_mode:
        destination_addresses = split_values(form.get("destination_translation_address_bulk", ""))
        if len(destination_addresses) > 1:
            raise ValueError("Destination translation accepteert maximaal één address")
        destination_port = form.get("destination_translation_port_bulk", "").strip()
        if destination_port and (not destination_port.isdigit() or not 1 <= int(destination_port) <= 65535):
            raise ValueError("Translated port moet tussen 1 en 65535 liggen")
        if destination_mode == "clear":
            destination_translation = {}
        elif destination_mode == "set" and (destination_addresses or destination_port):
            destination_translation = {}
            if destination_addresses:
                destination_translation["translated_address"] = destination_addresses[0]
            if destination_port:
                destination_translation["translated_port"] = int(destination_port)
        else:
            raise ValueError("Geef een translated destination address of port op")
        result.update({
            "destination_translation": destination_translation,
            "destination_translation_address": destination_addresses[0] if destination_addresses else "",
            "destination_translation_port": destination_port,
        })
    return result


def write_target_policy(profile, policy_kind: str, policy: dict, original_name: str | None = None) -> None:
    if profile["target_type"] == "scm":
        scm, token, _, container = scm_client(profile)
        service, endpoint_name, _ = SCM_POLICY_TYPES[policy_kind]
        endpoint = policy_api.scm_api_root(scm.scm_api_base) + f"/config/{service}/v1/{endpoint_name}"
        policy_api.scm_http_request("PUT", f"{endpoint}/{policy['id']}", token, payload=target_policy_payload(policy, container, policy_kind), params={"position": scm.scm_rulebase})
        return
    _, endpoint, key, ctx = panos_profile_context(profile)
    current_name = original_name or policy["name"]
    xpath = f"{panos_policy_xpath(profile, policy_kind)}/entry[@name={policy_api.xpath_literal(current_name)}]"
    editable_policy = {**policy, "name": current_name}
    policy_api.require_success(panos_api_post(endpoint, {"type": "config", "action": "edit", "xpath": xpath, "element": update_xml_policy(editable_policy), "key": key}, ctx), f"edit {policy_kind} rule {current_name}")
    if current_name != policy["name"]:
        policy_api.require_success(panos_api_post(endpoint, {"type": "config", "action": "rename", "xpath": xpath, "newname": policy["name"], "key": key}, ctx), f"rename {policy_kind} rule {current_name}")


def workspace_access_allowed(workspace_id: int, write: bool | None = None) -> bool:
    if not has_request_context():
        return True
    if write is None:
        write = request.method not in {"GET", "HEAD", "OPTIONS"}
    with db() as conn:
        return workspace_allowed(conn, workspace_id, str(session.get("username", "")), write)


def workspace_row(workspace_id: int):
    if not workspace_access_allowed(workspace_id):
        return None
    with db() as conn:
        return conn.execute(
            "SELECT config_workspaces.*,profiles.name profile_name,profiles.target_type,profiles.settings_json,profiles.secret_blob,profiles.system profile_system,profiles.updated_at profile_updated_at "
            "FROM config_workspaces JOIN profiles ON profiles.id=config_workspaces.profile_id WHERE config_workspaces.id=?",
            (workspace_id,),
        ).fetchone()


def accessible_workspace_rows(rows):
    if not has_request_context():
        return rows
    username = str(session.get("username", ""))
    with db() as conn:
        return [row for row in rows if workspace_allowed(conn, int(row["id"]), username)]


def store_config_workspace(
    profile, name: str, original_name: str, xml_bytes: bytes, source: str,
    project_id: int | None = None, baseline_workspace=None, baseline_xml: bytes | None = None,
    parsed_config=None,
) -> int:
    expected = "panorama" if profile["target_type"] == "panorama" else "panos"
    if parsed_config is None:
        root, snapshot = parse_snapshot(xml_bytes, expected_kind=expected)
    else:
        root, snapshot = parsed_config
        if snapshot.kind != expected:
            raise OfflineConfigError("Deze configuratie lijkt niet afkomstig van het gekozen platform")
    normalized = normalized_config_xml(root)
    workspace_token = secrets.token_hex(16)
    path = CONFIG_WORKSPACES / f"{workspace_token}.xml"
    path.write_bytes(normalized)
    path.chmod(0o600)
    baseline_path = ""
    baseline_hash = ""
    baseline_target_hash = ""
    created_baseline_path = None
    if baseline_workspace is not None:
        baseline_path = str(baseline_workspace["baseline_config_path"] or "")
        baseline_hash = str(baseline_workspace["baseline_sha256"] or "")
        baseline_target_hash = str(baseline_workspace["baseline_target_sha256"] or "")
        if bool(baseline_path) != bool(baseline_hash) or bool(baseline_path) != bool(baseline_target_hash):
            path.unlink(missing_ok=True)
            raise OfflineConfigError("De oorspronkelijke candidate-snapshot is onvolledig; haal de config opnieuw op")
        if baseline_path and baseline_hash:
            checked_path = safe_workspace_path(CONFIG_WORKSPACES, baseline_path)
            if not checked_path.is_file() or snapshot_sha256(checked_path.read_bytes()) != baseline_hash:
                path.unlink(missing_ok=True)
                raise OfflineConfigError("De oorspronkelijke workspaceconfiguratie ontbreekt of is gewijzigd")
    elif baseline_xml is not None:
        try:
            same_snapshot = baseline_xml == xml_bytes
            if same_snapshot and parsed_config is not None:
                if snapshot.kind != expected:
                    raise OfflineConfigError("De oorspronkelijke config hoort niet bij het gekozen platform")
            else:
                parse_snapshot(baseline_xml, expected_kind=expected)
            endpoint = validate_panos_endpoint(json.loads(profile["settings_json"] or "{}").get("endpoint", ""))
        except Exception:
            path.unlink(missing_ok=True)
            raise
        normalized_baseline = normalized if same_snapshot else normalized_config_xml(SafeET.fromstring(baseline_xml))
        baseline_path_object = CONFIG_WORKSPACES / f"{workspace_token}-baseline.xml"
        baseline_path_object.write_bytes(normalized_baseline)
        baseline_path_object.chmod(0o600)
        baseline_path = str(baseline_path_object)
        baseline_hash = snapshot_sha256(normalized_baseline)
        baseline_target_hash = hashlib.sha256(
            f"{profile['target_type']}\0{endpoint}".encode("utf-8")
        ).hexdigest()
        created_baseline_path = baseline_path_object
    timestamp = now()
    try:
        with db() as conn:
            cursor = conn.execute(
                "INSERT INTO config_workspaces(profile_id,name,source,original_name,config_path,sha256,baseline_config_path,baseline_sha256,baseline_target_sha256,metadata_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (profile["id"], name[:120], source, original_name[:255], str(path), snapshot_sha256(normalized), baseline_path, baseline_hash, baseline_target_hash, json.dumps(snapshot.as_dict()), timestamp, timestamp),
            )
            workspace_id = int(cursor.lastrowid)
            if project_id is None and has_request_context():
                project_id = (request.view_args or {}).get("project_id")
            if project_id and source.startswith("migration-"):
                link_workspace_project(conn, workspace_id, int(project_id))
    except Exception:
        path.unlink(missing_ok=True)
        if created_baseline_path is not None:
            created_baseline_path.unlink(missing_ok=True)
        raise
    audit("config-workspace-created", f"workspace={workspace_id} profile={profile['name']} source={source} kind={snapshot.kind}")
    return workspace_id


def advance_migration_staging_workspace(previous_workspace_id: int, new_workspace_id: int) -> bool:
    """Keep an imported source attached to the newest immutable workspace version."""
    with db() as conn:
        inherit_workspace_access(conn, previous_workspace_id, new_workspace_id)
        linked_sources = conn.execute(
            "SELECT id,project_id FROM migration_sources WHERE staging_workspace_id=?",
            (previous_workspace_id,),
        ).fetchall()
        if not linked_sources:
            return False
        conn.execute(
            "UPDATE migration_sources SET staging_workspace_id=? WHERE staging_workspace_id=?",
            (new_workspace_id, previous_workspace_id),
        )
        project_ids = {int(source["project_id"]) for source in linked_sources}
        for project_id in project_ids:
            conn.execute(
                "UPDATE migration_projects SET base_workspace_id=?,updated_at=? "
                "WHERE id=? AND base_workspace_id=?",
                (new_workspace_id, now(), project_id, previous_workspace_id),
            )
    return True


def workspace_version_source(workspace) -> str:
    return (
        "migration-staging"
        if str(workspace["source"]) in {"migration-staging", "migration-import", "migration-api"}
        else "edit"
    )


def advance_migration_output_workspace(
    previous_workspace_id: int,
    new_workspace_id: int,
    new_xml: bytes,
) -> bool:
    """Keep safety metadata attached to edited migration candidate versions."""
    with db() as conn:
        outputs = conn.execute(
            "SELECT id,sanity_json FROM migration_outputs WHERE workspace_id=?",
            (previous_workspace_id,),
        ).fetchall()
        if not outputs:
            return False
        candidate = panos_candidate_analysis(new_xml)
        candidate_unresolved = len(candidate["unresolved_references"])
        for output in outputs:
            sanity = json.loads(output["sanity_json"] or "{}")
            critical_codes = sanity.get("critical_review_codes", {})
            resolved_codes = {
                row["code"]
                for row in conn.execute(
                    "SELECT code FROM migration_output_resolutions WHERE output_id=?",
                    (output["id"],),
                ).fetchall()
            }
            unresolved_codes = set(critical_codes) - resolved_codes if isinstance(critical_codes, dict) else set()
            sanity.update({
                "unresolved_references": candidate_unresolved,
                "candidate_unresolved_references": candidate_unresolved,
                "unresolved_applications": len(candidate["unresolved_application_references"]),
                "duplicate_rules": len(candidate["duplicate_rules"]),
                "critical_findings": len(unresolved_codes) + (1 if candidate_unresolved else 0),
            })
            conn.execute(
                "UPDATE migration_outputs SET workspace_id=?,sanity_json=? WHERE id=?",
                (new_workspace_id, json.dumps(sanity, sort_keys=True), output["id"]),
            )
    return True


def store_workspace_edit_version(workspace, new_xml: bytes, label: str) -> int:
    """Store one immutable edit and advance any linked migration staging source."""
    with db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)).fetchone()
    if not profile:
        raise OfflineConfigError("Het firewallprofiel bestaat niet meer")
    new_id = store_config_workspace(
        profile,
        f"{workspace['name']} · {label} {now()}",
        workspace["original_name"],
        new_xml,
        workspace_version_source(workspace),
        baseline_workspace=workspace,
    )
    if not advance_migration_staging_workspace(workspace["id"], new_id):
        advance_migration_output_workspace(workspace["id"], new_id, new_xml)
        set_active_config_workspace(workspace["profile_id"], new_id)
    return new_id


def store_migration_output(
    project_id: int,
    workspace_id: int,
    label: str,
    topology: str = "active-passive",
    node_role: str = "",
    collisions: dict | None = None,
    sanity: dict | None = None,
) -> int:
    if topology not in {"active-passive", "active-active"}:
        raise MigrationError("Onbekende migratietopologie")
    with db() as conn:
        project = conn.execute("SELECT * FROM migration_projects WHERE id=?", (project_id,)).fetchone()
        workspace = conn.execute("SELECT * FROM config_workspaces WHERE id=?", (workspace_id,)).fetchone()
        if not project or not workspace:
            raise MigrationError("Migratieproject of output-workspace ontbreekt")
        if int(workspace["profile_id"]) != int(project["target_profile_id"]):
            raise MigrationError("Output-workspace hoort niet bij het targetprofiel")
        link_workspace_project(conn, workspace_id, project_id)
        cursor = conn.execute(
            "INSERT INTO migration_outputs(project_id,workspace_id,label,topology,node_role,collision_json,sanity_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                project_id, workspace_id, label[:120], topology, node_role[:40],
                json.dumps(collisions or {}, sort_keys=True),
                json.dumps(sanity or {}, sort_keys=True), now(),
            ),
        )
        conn.execute("UPDATE migration_projects SET topology=?,updated_at=? WHERE id=?", (topology, now(), project_id))
        return int(cursor.lastrowid)


def migration_output_row(project_id: int, output_id: int):
    with db() as conn:
        return conn.execute(
            "SELECT migration_outputs.*,config_workspaces.config_path,config_workspaces.original_name,"
            "config_workspaces.profile_id FROM migration_outputs JOIN config_workspaces "
            "ON config_workspaces.id=migration_outputs.workspace_id "
            "WHERE migration_outputs.id=? AND migration_outputs.project_id=?",
            (output_id, project_id),
        ).fetchone()


def migration_project_row(project_id: int):
    with db() as conn:
        project = conn.execute(
            "SELECT migration_projects.*,profiles.name profile_name,profiles.target_type,profiles.settings_json,profiles.system profile_system "
            "FROM migration_projects JOIN profiles ON profiles.id=migration_projects.target_profile_id "
            "WHERE migration_projects.id=?", (project_id,),
        ).fetchone()
        if not project or not has_request_context():
            return project
        username = str(session.get("username", ""))
        if username == str(project["owner"] or "admin"):
            role = "owner"
        else:
            assignment = conn.execute(
                "SELECT role FROM migration_project_roles WHERE project_id=? AND username=?",
                (project_id, username),
            ).fetchone()
            role = str(assignment["role"]) if assignment else ""
        if role not in {"owner", "editor", "reviewer", "viewer"}:
            return None
        if request.method not in {"GET", "HEAD", "OPTIONS"} and role not in {"owner", "editor"}:
            return None
        return project


def migration_project_role(project_id: int) -> str:
    username = str(session.get("username", ""))
    with db() as conn:
        project = conn.execute("SELECT owner FROM migration_projects WHERE id=?", (project_id,)).fetchone()
        if not project:
            return ""
        if username == str(project["owner"] or "admin"):
            return "owner"
        row = conn.execute(
            "SELECT role FROM migration_project_roles WHERE project_id=? AND username=?",
            (project_id, username),
        ).fetchone()
        return str(row["role"]) if row else ""


def migration_project_revision(project_id: int) -> str:
    """Bind a preview to every persisted input that can alter its candidate."""
    with db() as conn:
        project = conn.execute(
            "SELECT target_profile_id,base_workspace_id,topology FROM migration_projects WHERE id=?",
            (project_id,),
        ).fetchone()
        if not project:
            return ""
        profile = conn.execute(
            "SELECT target_type,settings_json FROM profiles WHERE id=?",
            (project["target_profile_id"],),
        ).fetchone()
        state = {
            "project": dict(project),
            "profile": dict(profile) if profile else {},
            "sources": [
                tuple(row) for row in conn.execute(
                    "SELECT id,fingerprint,staging_workspace_id FROM migration_sources WHERE project_id=? ORDER BY id",
                    (project_id,),
                ).fetchall()
            ],
            "mappings": [
                tuple(row) for row in conn.execute(
                    "SELECT source_id,kind,action,target_context FROM migration_family_mappings WHERE project_id=? ORDER BY source_id,kind",
                    (project_id,),
                ).fetchall()
            ],
            "merges": [
                tuple(row) for row in conn.execute(
                    "SELECT kind,master,members_json,mode FROM migration_merge_rules WHERE project_id=? ORDER BY id",
                    (project_id,),
                ).fetchall()
            ],
            "transforms": [
                tuple(row) for row in conn.execute(
                    "SELECT operation,kind,selector,value FROM migration_transform_rules WHERE project_id=? ORDER BY id",
                    (project_id,),
                ).fetchall()
            ],
        }
    return hashlib.sha256(
        json.dumps(state, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def migration_source_row(source_id: int):
    with db() as conn:
        return conn.execute("SELECT * FROM migration_sources WHERE id=?", (source_id,)).fetchone()


def migration_model(source) -> MigrationModel:
    path = safe_workspace_path(MIGRATION_SOURCES, source["model_path"])
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(digest, source["fingerprint"]):
        raise MigrationError("De migratiebron is gewijzigd of beschadigd")
    return MigrationModel.from_dict(json.loads(raw.decode()))


@lru_cache(maxsize=16)
def cached_migration_workspace_model(config_path: str, sha256: str) -> MigrationModel:
    path = safe_workspace_path(CONFIG_WORKSPACES, config_path)
    raw = path.read_bytes()
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), sha256):
        raise MigrationError("De base-workspace is gewijzigd of beschadigd")
    return parse_vendor("panos", raw, Path(config_path).name)


def apply_migration_import_policy_status(model: MigrationModel, force_disabled: bool) -> dict[str, int | bool]:
    """Preserve vendor policy state unless the engineer explicitly overrides it."""
    policies = model.security_rules
    source_disabled = sum(1 for rule in policies if rule.disabled)
    changed = 0
    if force_disabled:
        for rule in policies:
            if not rule.disabled:
                rule.disabled = True
                changed += 1
        model.warnings.append(
            f"Importoverride: alle {len(policies)} security policies disabled gemaakt ({changed} gewijzigd)"
        )
    return {
        "force_disabled": force_disabled,
        "total": len(policies),
        "source_disabled": source_disabled,
        "changed": changed,
    }


def migration_project_topology_targets(project, profile, context=None):
    """Only offer topology from the concrete target scope, never other templates."""
    targets = {kind: [] for kind in MIGRATION_TOPOLOGY_KINDS}
    if project["base_workspace_id"]:
        workspace = workspace_row(int(project["base_workspace_id"]))
        if workspace:
            path = safe_workspace_path(CONFIG_WORKSPACES, workspace["config_path"])
            content = path.read_bytes()
            if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), workspace["sha256"]):
                raise MigrationError("De base-workspace is gewijzigd of beschadigd")
            targets.update(migration_topology_targets(
                content, context or migration_profile_target_context(profile),
                panorama=project["target_type"] == "panorama",
            ))
            targets["interface_zone_memberships"] = migration_interface_zone_memberships(
                content, context or migration_profile_target_context(profile),
                panorama=project["target_type"] == "panorama",
            )
    elif project["target_type"] == "scm" and profile:
        targets["zones"] = sorted(profile_settings(profile).get("zones", {}))
    return targets


def migration_saved_interface_zones(project_id: int) -> set[str]:
    """Return valid zones staged by earlier interface mapping rows."""
    with db() as conn:
        rows = conn.execute(
            "SELECT value FROM migration_transform_rules "
            "WHERE project_id=? AND kind='interfaces' AND operation='set_interface_zone'",
            (project_id,),
        ).fetchall()
    zones = set()
    for row in rows:
        try:
            value = json.loads(row["value"] or "{}")
        except (TypeError, json.JSONDecodeError):
            continue
        zone = str(value.get("zone", "")).strip() if isinstance(value, dict) else ""
        if zone and re.fullmatch(r"[A-Za-z0-9 ._-]{1,31}", zone) and zone.casefold() != "any":
            zones.add(zone)
    return zones


def migration_profile_target_context(profile, kind: str = "") -> str:
    """Return the concrete default context used by the selected target adapter."""
    settings = profile_settings(profile)
    if profile["target_type"] == "panorama":
        return str(settings.get("device_group") or "Shared")
    if profile["target_type"] == "panos":
        return str(settings.get("vsys") or "vsys1")
    if kind == "zones":
        return str(settings.get("folder") or settings.get("snippet") or settings.get("device") or "")
    return str(
        settings.get("object_folder") or settings.get("folder")
        or settings.get("snippet") or settings.get("device") or ""
    )


def migration_project_target_context(project_id: int, kind: str = "", connection=None) -> str:
    query = (
        "SELECT profiles.* FROM migration_projects JOIN profiles "
        "ON profiles.id=migration_projects.target_profile_id WHERE migration_projects.id=?"
    )
    if connection is None:
        with db() as conn:
            profile = conn.execute(query, (project_id,)).fetchone()
    else:
        profile = connection.execute(query, (project_id,)).fetchone()
    if not profile:
        raise MigrationError("Migratietarget bestaat niet meer")
    return migration_profile_target_context(profile, kind)


def store_migration_source(project_id: int, vendor: str, source_name: str, model: MigrationModel) -> int:
    raw = json.dumps(model.as_dict(), sort_keys=True, separators=(",", ":")).encode()
    token = secrets.token_hex(16)
    path = MIGRATION_SOURCES / f"{token}.json"
    path.write_bytes(raw); path.chmod(0o600)
    try:
        with db() as conn:
            cursor = conn.execute(
                "INSERT INTO migration_sources(project_id,vendor,source_name,model_path,fingerprint,counts_json,warnings_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (project_id, vendor, source_name[:255], str(path), hashlib.sha256(raw).hexdigest(), json.dumps(model.counts()), json.dumps(model.warnings + model.unsupported), now()),
            )
            source_id = int(cursor.lastrowid)
            for kind, items in model_collections(model).items():
                if not items:
                    continue
                target_context = migration_project_target_context(project_id, kind, conn)
                if not target_context:
                    raise MigrationError(f"Doelcontext ontbreekt voor {MIGRATION_KIND_LABELS.get(kind, kind)}")
                conn.execute(
                    "INSERT OR IGNORE INTO migration_family_mappings(project_id,source_id,kind,action,target_context,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                    (project_id, source_id, kind, "create", target_context, now(), now()),
                )
            conn.execute("UPDATE migration_projects SET updated_at=? WHERE id=?", (now(), project_id))
        return source_id
    except Exception:
        path.unlink(missing_ok=True)
        raise


def ensure_migration_family_mappings(project_id: int, source_rows) -> list[dict]:
    """Backfill concrete create decisions for projects from the cosmetic mapping era."""
    with db() as conn:
        for source in source_rows:
            model = migration_model(source)
            for kind, items in model_collections(model).items():
                if items:
                    target_context = migration_project_target_context(project_id, kind, conn)
                    if not target_context:
                        raise MigrationError(f"Doelcontext ontbreekt voor {MIGRATION_KIND_LABELS.get(kind, kind)}")
                    conn.execute(
                        "INSERT OR IGNORE INTO migration_family_mappings(project_id,source_id,kind,action,target_context,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                        (project_id, int(source["id"]), kind, "create", target_context, now(), now()),
                    )
                    conn.execute(
                        "UPDATE migration_family_mappings SET action='create',target_context=?,updated_at=? "
                        "WHERE project_id=? AND source_id=? AND kind=? AND target_context=''",
                        (target_context, now(), project_id, int(source["id"]), kind),
                    )
        rows = conn.execute(
            "SELECT * FROM migration_family_mappings WHERE project_id=? ORDER BY source_id,kind",
            (project_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def replace_migration_source_model(source, model: MigrationModel) -> None:
    raw = json.dumps(model.as_dict(), sort_keys=True, separators=(",", ":")).encode()
    path = MIGRATION_SOURCES / f"{secrets.token_hex(16)}.json"
    path.write_bytes(raw)
    path.chmod(0o600)
    try:
        with db() as conn:
            conn.execute(
                "UPDATE migration_sources SET vendor=?,source_name=?,model_path=?,fingerprint=?,counts_json=?,warnings_json=? WHERE id=?",
                (
                    model.vendor, model.source_name[:255], str(path), hashlib.sha256(raw).hexdigest(),
                    json.dumps(model.counts()), json.dumps(model.warnings + model.unsupported), source["id"],
                ),
            )
            conn.execute(
                "UPDATE migration_projects SET updated_at=? WHERE id=?",
                (now(), source["project_id"]),
            )
    except Exception:
        path.unlink(missing_ok=True)
        raise


def selected_migration_model(project_id: int, source_ids: list[int]) -> MigrationModel:
    with db() as conn:
        rows = conn.execute(
            f"SELECT * FROM migration_sources WHERE project_id=? AND id IN ({','.join('?' for _ in source_ids)}) ORDER BY id",
            (project_id, *source_ids),
        ).fetchall() if source_ids else []
        mapping_rows = conn.execute(
            "SELECT source_id,kind,action,target_context FROM migration_family_mappings WHERE project_id=?",
            (project_id,),
        ).fetchall()
    if len(rows) != len(set(source_ids)):
        raise MigrationError("Niet alle geselecteerde bronnen behoren tot dit project")
    merged = MigrationModel("merged", " + ".join(row["source_name"] for row in rows))
    for row in rows:
        model = migration_model(row)
        model = apply_family_mappings(
            model,
            [dict(mapping) for mapping in mapping_rows if int(mapping["source_id"]) == int(row["id"])],
        )
        for field in ("addresses", "address_groups", "services", "service_groups", "security_rules", "nat_rules", "interfaces", "zones", "warnings", "unsupported"):
            getattr(merged, field).extend(getattr(model, field))
        for kind, items in model.extras.items():
            merged.extras.setdefault(kind, []).extend(items)
    # Preserve the first definition and make conflicts visible instead of silently overwriting them.
    for field in ("addresses", "address_groups", "services", "service_groups", "security_rules", "nat_rules"):
        values, seen = [], {}
        for item in getattr(merged, field):
            identity = (item.name, item.target_context)
            if identity in seen:
                if migration_item_semantic(item) != migration_item_semantic(seen[identity]):
                    merged.warnings.append(f"Mergeconflict voor {field}: {item.name}; kies de master in Search & Merge")
                    values.append(item)
                continue
            seen[identity] = item; values.append(item)
        setattr(merged, field, values)
    for field in ("interfaces", "zones"):
        values, seen = [], {}
        for item in getattr(merged, field):
            key = (
                item.get("interface_type", ""), item.get("name", ""), item.get("target_context", "")
            ) if field == "interfaces" else (item.get("name", ""), item.get("target_context", ""))
            if key in seen:
                if item.get("xml") != seen[key].get("xml"):
                    merged.warnings.append(f"Mergeconflict voor {field}: {item.get('name', '')}; eerste definitie behouden")
                continue
            seen[key] = item; values.append(item)
        setattr(merged, field, values)
    for kind, items in merged.extras.items():
        values=[]; seen=set()
        for item in items:
            key=(item.get("target_path", ""), item.get("profile_type", ""), item.get("name", ""), item.get("xml", ""), item.get("target_context", ""))
            if key in seen: continue
            seen.add(key); values.append(item)
        merged.extras[kind]=values
    with db() as conn:
        rows=conn.execute("SELECT kind,master,members_json,mode FROM migration_merge_rules WHERE project_id=? ORDER BY id",(project_id,)).fetchall()
        transform_rows=conn.execute("SELECT operation,kind,selector,value FROM migration_transform_rules WHERE project_id=? ORDER BY id",(project_id,)).fetchall()
    rules=[{"kind":row["kind"],"master":row["master"],"members":json.loads(row["members_json"]),"mode":row["mode"]} for row in rows]
    transforms=[dict(row) for row in transform_rows]
    return apply_transform_rules(apply_merge_rules(merged,rules),transforms)


def migration_scm_container(profile, object_type: str, target_context: str = "") -> tuple[object, str, dict]:
    scm, token, _, _ = scm_client(profile)
    container = policy_api.scm_container(
        folder=scm.scm_folder if object_type == "zones" else scm.scm_object_folder,
        snippet=scm.scm_snippet, device=scm.scm_device,
    )
    if target_context:
        key = next((name for name in ("folder", "snippet", "device") if container.get(name)), "")
        if not key:
            raise MigrationError("SCM-doelcontext kan niet aan folder, snippet of device worden gekoppeld")
        container = {key: target_context}
    return scm, token, container


def migration_target_inventory(profile) -> dict[str, list[dict]]:
    return {
        "addresses": fetch_scm_objects(profile, "addresses"),
        "address-groups": fetch_scm_objects(profile, "address-groups"),
        "services": fetch_scm_objects(profile, "services"),
        "service-groups": fetch_scm_objects(profile, "service-groups"),
        "policy:security": fetch_scm_policy_type(profile, "security"),
        "policy:nat": fetch_scm_policy_type(profile, "nat"),
    }


def scm_migration_unsupported(model: MigrationModel) -> list[str]:
    supported_extra=set(MIGRATION_SCM_EXTRA_OBJECTS)|set(MIGRATION_SCM_EXTRA_POLICIES)|set(MIGRATION_SCM_NETWORK_ENDPOINTS)|{"security_profiles"}
    unsupported=[kind for kind,items in model.extras.items() if items and kind not in supported_extra]
    unsupported_profiles=sorted({str(item.get("profile_type", "")) for item in model.extras.get("security_profiles",[]) if str(item.get("profile_type", "")) not in MIGRATION_SCM_SECURITY_PROFILES})
    if unsupported_profiles: unsupported.extend(f"security profile {name}" for name in unsupported_profiles)
    return unsupported


def apply_scm_migration(profile, model: MigrationModel) -> int:
    unsupported=scm_migration_unsupported(model)
    if unsupported:
        raise MigrationError("Nog geen veilige SCM-outputmapping voor: "+", ".join(MIGRATION_KIND_LABELS.get(kind,kind) for kind in unsupported))
    count = 0
    # Referenced tags must exist before SCM accepts security rules that use them.
    for item in model.extras.get("tags", []):
        metadata=SCM_OBJECT_TYPES["tags"]; scm,token,container=migration_scm_container(profile,"tags",str(item.get("target_context", "")))
        service=metadata.get("service") or "objects"; endpoint_name=metadata.get("endpoint","tags")
        endpoint=policy_api.scm_api_root(scm.scm_api_base)+f"/config/{service}/v1/{endpoint_name}"
        policy_api.scm_http_request("POST",endpoint,token,payload={**raw_item_payload(item),**container}); count+=1
    def apply_extra(kind, item):
        payload=raw_item_payload(item)
        if kind in MIGRATION_SCM_EXTRA_OBJECTS or kind == "security_profiles":
            object_type=MIGRATION_SCM_EXTRA_OBJECTS.get(kind)
            if kind == "security_profiles": object_type=MIGRATION_SCM_SECURITY_PROFILES.get(str(item.get("profile_type", "")))
            if not object_type or object_type not in SCM_OBJECT_TYPES:
                raise MigrationError(f"Geen SCM security-profilemapping voor {item.get('profile_type','')}")
            metadata=SCM_OBJECT_TYPES[object_type]; scm,token,container=migration_scm_container(profile,object_type,str(item.get("target_context", "")))
            service=metadata.get("service") or "objects"; endpoint_name=metadata.get("endpoint",object_type)
            endpoint=policy_api.scm_api_root(scm.scm_api_base)+f"/config/{service}/v1/{endpoint_name}"
            policy_api.scm_http_request("POST",endpoint,token,payload={**payload,**container}); return 1
        if kind in MIGRATION_SCM_NETWORK_ENDPOINTS:
            view,endpoint_name=MIGRATION_SCM_NETWORK_ENDPOINTS[kind]; scm,token,container=migration_scm_container(profile,"zones",str(item.get("target_context", "")))
            endpoint=policy_api.scm_api_root(scm.scm_api_base)+f"/config/{view}/v1/{endpoint_name}"
            policy_api.scm_http_request("POST",endpoint,token,payload={**payload,**container}); return 1
        return 0

    # Create all supported object/profile/network dependencies before any policy family.
    for kind,items in model.extras.items():
        if kind in {"tags", *MIGRATION_SCM_EXTRA_POLICIES}:
            continue
        for item in items:
            count += apply_extra(kind, item)
    for item in scm_items(model):
        kind = item["kind"]
        if kind.startswith("policy:"):
            policy_kind = kind.split(":", 1)[1]
            if policy_kind in SCM_UNAVAILABLE_POLICY_TYPES: raise MigrationError(f"{policy_kind} is niet beschikbaar in SCM")
            service, endpoint_name, _ = SCM_POLICY_TYPES[policy_kind]
            scm, token, container = migration_scm_container(profile, "policies", item.get("target_context", ""))
            payload = {**item["payload"], **container}
            endpoint = policy_api.scm_api_root(scm.scm_api_base) + f"/config/{service}/v1/{endpoint_name}"
            policy_api.scm_http_request("POST", endpoint, token, payload=payload, params={"position": scm.scm_rulebase})
        else:
            metadata = SCM_OBJECT_TYPES[kind]
            scm, token, container = migration_scm_container(profile, kind, item.get("target_context", ""))
            payload = {**item["payload"], **container}
            service = metadata.get("service") or "objects"
            endpoint_name = metadata.get("endpoint", kind)
            endpoint = policy_api.scm_api_root(scm.scm_api_base) + f"/config/{service}/v1/{endpoint_name}"
            policy_api.scm_http_request("POST", endpoint, token, payload=payload)
        count += 1
    for kind,items in model.extras.items():
        if kind not in MIGRATION_SCM_EXTRA_POLICIES:
            continue
        for item in items:
            payload=raw_item_payload(item)
            policy_kind=MIGRATION_SCM_EXTRA_POLICIES[kind]
            if policy_kind in SCM_UNAVAILABLE_POLICY_TYPES: raise MigrationError(f"{policy_kind} is niet beschikbaar in SCM")
            service,endpoint_name,_=SCM_POLICY_TYPES[policy_kind]; scm,token,container=migration_scm_container(profile,"policies",str(item.get("target_context", "")))
            endpoint=policy_api.scm_api_root(scm.scm_api_base)+f"/config/{service}/v1/{endpoint_name}"
            policy_api.scm_http_request("POST",endpoint,token,payload={**payload,**container},params={"position":scm.scm_rulebase}); count+=1
    invalidate_profile_caches(profile["id"])
    return count


def apply_xml_migration(profile, model: MigrationModel) -> int:
    settings = profile_settings(profile)
    panorama = profile["target_type"] == "panorama"
    scope = settings.get("device_group", "") if panorama else settings.get("vsys", "vsys1")
    if not scope: raise MigrationError("Doelscope ontbreekt")
    fragment = SafeET.fromstring(panos_fragment(model, scope, panorama, settings.get("rulebase", "pre")))
    _, endpoint, key, ctx = panos_profile_context(profile)
    if panorama:
        source = fragment.find(f"./devices/entry/device-group/entry[@name='{scope}']")
        base = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name={policy_api.xpath_literal(scope)}]"
    else:
        source = fragment.find(f"./devices/entry/vsys/entry[@name='{scope}']")
        base = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name={policy_api.xpath_literal(scope)}]"
    if source is None: raise MigrationError("Gegenereerde doelscope ontbreekt")
    count = 0
    # Create tag objects before objects or policies that reference them.
    ordered_children = sorted(
        source,
        key=lambda child: 0 if child.tag == "tag" else (2 if child.tag.endswith("rulebase") or child.tag == "rulebase" else 1),
    )
    for child in ordered_children:
        if child.tag.endswith("rulebase") or child.tag == "rulebase":
            for policy_type in child:
                rules = policy_type.find("rules")
                if rules is None: continue
                target_rulebase = child.tag if panorama else "rulebase"
                xpath = f"{base}/{target_rulebase}/{policy_type.tag}/rules"
                for entry in rules.findall("entry"):
                    policy_api.require_success(panos_api_post(endpoint, {"type":"config","action":"set","xpath":xpath,"element":ET.tostring(entry,encoding="unicode"),"key":key}, ctx), f"import {policy_type.tag} {entry.get('name')}"); count += 1
        elif child.tag in {"address", "address-group", "service", "service-group", "tag"}:
            xpath = f"{base}/{child.tag}"
            for entry in child.findall("entry"):
                policy_api.require_success(panos_api_post(endpoint, {"type":"config","action":"set","xpath":xpath,"element":ET.tostring(entry,encoding="unicode"),"key":key}, ctx), f"import {child.tag} {entry.get('name')}"); count += 1
    return count


def create_merged_workspace(
    profile,
    project,
    model: MigrationModel,
    approved_reuses: set[str] | None = None,
) -> tuple[int, dict]:
    base_id = int(project["base_workspace_id"] or 0)
    settings = profile_settings(profile)
    panorama = profile["target_type"] == "panorama"
    scope = settings.get("device_group", "") if panorama else settings.get("vsys", "vsys1")
    if not scope:
        raise MigrationError("Doelscope ontbreekt")
    if not base_id:
        base_xml = migration_base_xml(model, scope, panorama)
        base_id = store_config_workspace(
            profile,
            f"{project['name']} · nieuwe configuratie",
            f"{project['name']}-new-config.xml",
            base_xml,
            "migration-generated-base",
            project_id=int(project["id"]),
        )
        with db() as conn:
            conn.execute(
                "UPDATE migration_projects SET base_workspace_id=?,updated_at=? WHERE id=?",
                (base_id, now(), project["id"]),
            )
    workspace = workspace_row(base_id)
    if not workspace or int(workspace["profile_id"]) != int(profile["id"]):
        raise MigrationError("De gekozen base-workspace hoort niet bij het targetprofiel")
    merged_xml, plan = merge_model_into_panos_xml(
        workspace_config_path(workspace).read_bytes(), model, scope, panorama,
        settings.get("rulebase", "pre"), approved_reuses,
    )
    workspace_id = store_config_workspace(
        profile, f"{project['name']} · merged {now()}", workspace["original_name"], merged_xml,
        "migration-merge", project_id=int(project["id"]), baseline_workspace=workspace,
    )
    set_active_config_workspace(profile["id"], workspace_id)
    return workspace_id, plan


def migration_best_practice_base_xml(profile) -> bytes:
    """Build a sanitized BPA-backed base in the selected target flavor/scope."""
    if not BEST_PRACTICE_BASE.is_file():
        raise MigrationError("De ingebouwde best-practice base ontbreekt")
    raw = BEST_PRACTICE_BASE.read_bytes()
    settings = profile_settings(profile)
    if profile["target_type"] == "panos":
        scope = str(settings.get("vsys") or "vsys1")
        root = SafeET.fromstring(raw)
        vsys = root.find("./devices/entry/vsys/entry")
        if vsys is None:
            raise MigrationError("De best-practice base bevat geen VSYS")
        vsys.set("name", scope)
        return normalized_config_xml(root)
    if profile["target_type"] != "panorama":
        raise MigrationError("Een XML-base is alleen beschikbaar voor PAN-OS en Panorama")
    scope = str(settings.get("device_group") or "Shared")
    model = parse_vendor("panos", raw, BEST_PRACTICE_BASE.name)
    for items in model_collections(model).values():
        for item in items:
            if hasattr(item, "target_context"):
                item.target_context = scope
            elif isinstance(item, dict):
                item["target_context"] = scope
    base = migration_base_xml(model, scope, panorama=True, version="11.0.0")
    merged, plan = merge_model_into_panos_xml(
        base, model, scope, panorama=True, rulebase=settings.get("rulebase", "pre")
    )
    if plan.get("conflicts"):
        raise MigrationError("De best-practice Panorama-base bevat mergeconflicten")
    return merged


def create_migration_best_practice_workspace(profile, project_id: int, project_name: str) -> int:
    xml_bytes = migration_best_practice_base_xml(profile)
    workspace_id = store_config_workspace(
        profile,
        f"{project_name} · OCD BPA best practices",
        "ocd-bpa-v11.xml",
        xml_bytes,
        "built-in-best-practice",
        project_id=project_id,
    )
    set_active_config_workspace(int(profile["id"]), workspace_id)
    return workspace_id


def live_profile_migration_source(profile) -> tuple[MigrationModel, bytes | None]:
    """Read a configured target through its native API without changing it."""
    def as_list(value,default):
        if isinstance(value,list): return [str(item) for item in value]
        if value in (None,""): return list(default)
        return [str(value)]
    def clean_payload(item):
        raw=copy.deepcopy(item.get("_raw",item))
        return {key:value for key,value in raw.items() if key not in {"id","folder","snippet","device","position","created_at","updated_at","_raw","edit_fields","generic"}}
    if profile["target_type"] in {"panorama","panos"}:
        _,endpoint,key,ctx=panos_profile_context(profile)
        root=policy_api.require_success(panos_api_post(endpoint,{"type":"config","action":"get","xpath":"/config","key":key},ctx),"volledige configuratie ophalen")
        config=root.find("./result/config")
        if config is None: raise MigrationError("API-antwoord bevat geen volledige configuratie")
        xml_bytes=normalized_config_xml(config)
        return parse_vendor("panos",xml_bytes,f"{profile['name']}-candidate.xml"),xml_bytes
    model=MigrationModel("scm",f"{profile['name']} candidate")
    for item in fetch_scm_objects(profile,"addresses"):
        for key in ("ip_netmask","ip_range","ip_wildcard","fqdn"):
            if item.get(key) is not None:
                model.addresses.append(Address(str(item.get("name","")),str(item[key]),key,str(item.get("description","")),as_list(item.get("tag"),[]),str(item.get("id","")))); break
    for item in fetch_scm_objects(profile,"address-groups"):
        members=item.get("static",item.get("members",[])); model.address_groups.append(AddressGroup(str(item.get("name","")),as_list(members,[]),str(item.get("description","")),as_list(item.get("tag",[]),[]),str(item.get("id",""))))
    for item in fetch_scm_objects(profile,"services"):
        protocol=item.get("protocol",{}); proto=next(iter(protocol),"tcp") if isinstance(protocol,dict) else str(protocol or "tcp"); details=protocol.get(proto,{}) if isinstance(protocol,dict) else {}
        model.services.append(Service(str(item.get("name","")),proto,str(details.get("port",item.get("port","1-65535"))),str(details.get("source_port","")),str(item.get("description","")),list(item.get("tag",[])),str(item.get("id",""))))
    for item in fetch_scm_objects(profile,"service-groups"):
        model.service_groups.append(ServiceGroup(str(item.get("name","")),as_list(item.get("members",[]),[]),str(item.get("description","")),as_list(item.get("tag",[]),[]),str(item.get("id",""))))
    extra_object_kinds={"application-groups":"application_groups","tags":"tags","custom-url-categories":"custom_url_categories","security-profile-groups":"security_profile_groups"}
    profile_type_by_object={value:key for key,value in MIGRATION_SCM_SECURITY_PROFILES.items()}
    for object_type,kind in extra_object_kinds.items():
        for item in fetch_scm_objects(profile,object_type):
            payload=clean_payload(item); model.extras.setdefault(kind,[]).append({"name":str(item.get("name","")),"payload":payload,"source_ref":str(item.get("id","")),"target_path":object_type})
    for object_type,profile_type in profile_type_by_object.items():
        for item in fetch_scm_objects(profile,object_type):
            payload=clean_payload(item); model.extras.setdefault("security_profiles",[]).append({"name":str(item.get("name","")),"payload":payload,"source_ref":str(item.get("id","")),"target_path":object_type,"profile_type":profile_type})
    for kind,attr in (("security","security_rules"),("nat","nat_rules")):
        for item in fetch_scm_policy_type(profile,kind):
            getattr(model,attr).append(Policy(name=str(item.get("name","")),policy_type=kind,from_zones=as_list(item.get("from"),["any"]),to_zones=as_list(item.get("to"),["any"]),source=as_list(item.get("source"),["any"]),destination=as_list(item.get("destination"),["any"]),application=as_list(item.get("application"),["any"]),service=as_list(item.get("service"),["application-default"] if kind=="security" else ["any"]),action=str(item.get("action","allow")),disabled=bool(item.get("disabled",False)),description=str(item.get("description","")),tags=as_list(item.get("tag"),[]),source_translation=dict(item.get("source_translation",{})),destination_translation=dict(item.get("destination_translation",{})),nat_type=str(item.get("nat_type","ipv4")),to_interface=str(item.get("to_interface","any")),source_ref=str(item.get("id",""))))
    for extra_kind,policy_kind in MIGRATION_SCM_EXTRA_POLICIES.items():
        if policy_kind in SCM_UNAVAILABLE_POLICY_TYPES: continue
        for item in fetch_scm_policy_type(profile,policy_kind):
            payload=clean_payload(item); model.extras.setdefault(extra_kind,[]).append({"name":str(item.get("name","")),"payload":payload,"source_ref":str(item.get("id","")),"target_path":policy_kind,"policy_type":policy_kind})
    for kind,(view,endpoint_name) in MIGRATION_SCM_NETWORK_ENDPOINTS.items():
        section="logical-routers" if endpoint_name=="logical-routers" else "ipsec-tunnels"
        for item in fetch_scm_configuration_records(profile,view,section):
            if item.get("endpoint")!=endpoint_name: continue
            payload=clean_payload(item); model.extras.setdefault(kind,[]).append({"name":str(item.get("name","")),"payload":payload,"source_ref":str(item.get("id","")),"target_path":endpoint_name})
    return model,None


def workspace_config_path(workspace) -> Path:
    path = safe_workspace_path(CONFIG_WORKSPACES, workspace["config_path"])
    if not path.is_file():
        raise FileNotFoundError("Workspace XML ontbreekt")
    return path


def workspace_baseline_config(workspace) -> bytes | None:
    """Read a verified immutable target snapshot used as a three-way merge base."""
    stored_path = str(workspace["baseline_config_path"] or "")
    expected_sha256 = str(workspace["baseline_sha256"] or "")
    if not stored_path and not expected_sha256:
        return None
    if not stored_path or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise OfflineConfigError("De oorspronkelijke candidate-snapshot is ongeldig; haal de config opnieuw op")
    path = safe_workspace_path(CONFIG_WORKSPACES, stored_path)
    if not path.is_file():
        raise OfflineConfigError("De oorspronkelijke candidate-snapshot ontbreekt; haal de config opnieuw op")
    baseline = path.read_bytes()
    if not hmac.compare_digest(snapshot_sha256(baseline), expected_sha256):
        raise OfflineConfigError("De oorspronkelijke candidate-snapshot is gewijzigd; haal de config opnieuw op")
    settings = json.loads(workspace["settings_json"] or "{}")
    endpoint = validate_panos_endpoint(settings.get("endpoint", ""))
    target_sha256 = hashlib.sha256(
        f"{workspace['target_type']}\0{endpoint}".encode("utf-8")
    ).hexdigest()
    expected_target_sha256 = str(workspace["baseline_target_sha256"] or "")
    if not expected_target_sha256 or not hmac.compare_digest(target_sha256, expected_target_sha256):
        raise OfflineConfigError("Het firewallendpoint is gewijzigd; haal de config opnieuw op")
    return baseline


def require_workspace_baseline(workspace) -> bytes:
    """Fail closed when an incremental PAN-OS push cannot distinguish stale fields."""
    baseline = workspace_baseline_config(workspace)
    if baseline is None:
        raise OfflineConfigError(
            "Deze workspace heeft geen oorspronkelijke candidate-snapshot. "
            "Forge kan daardoor niet veilig onderscheiden welke velden intussen op de firewall zijn gewijzigd. "
            "Haal de actuele candidate op in een nieuwe workspace en herhaal daarin alleen je bedoelde wijzigingen."
        )
    return baseline


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
    "from", "to", "source", "destination", "source_user", "destination_user",
    "source_hip", "destination_hip", "category", "application", "service", "tag",
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
    "Authentication": "authentication", "Decryption": "decryption-profiles",
    "Schedules": "schedules",
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
    "VM Information Sources": "vm-information-sources",
}
WORKSPACE_STRUCTURED_OBJECT_TYPES = {
    "addresses", "address-groups", "application-groups",
    "services", "service-groups", "tags", "log-forwarding",
}
WORKSPACE_EDITABLE_OBJECT_TYPES = set(OBJECT_NODES)
WORKSPACE_CREATABLE_OBJECT_TYPES = set(OBJECT_NODES)


def validate_workspace_object_deletions(
    xml_bytes: bytes, object_type: str, names: list[str], *, scope_resolvable_names: set[str] | None = None,
    original_xml_bytes: bytes | None = None,
) -> dict[str, list[str]]:
    """Fail closed unless the full PAN-OS/Panorama XML proves objects unused."""
    if object_type not in REFERENCE_CHECK_OBJECT_TYPES:
        raise OfflineConfigError("Veilig verwijderen is voor dit objecttype niet beschikbaar")
    try:
        references = object_reference_index(xml_bytes, object_type, names)
        scope_resolvable_names = set(scope_resolvable_names or ()) & set(names)
        if scope_resolvable_names:
            scoped_references = unresolved_object_reference_index(
                xml_bytes, object_type, sorted(scope_resolvable_names),
                original_xml_bytes=original_xml_bytes,
            )
            for name in scope_resolvable_names:
                references[name] = scoped_references.get(name, [])
    except Exception as exc:
        raise OfflineConfigError("Referentiecontrole van de volledige configuratie is mislukt; niets verwijderd") from exc
    used = {name: paths for name, paths in references.items() if paths}
    if used:
        details = "; ".join(f"{name}: {', '.join(paths[:3])}" for name, paths in list(used.items())[:5])
        raise OfflineConfigError(f"Niet verwijderd: objecten zijn nog in gebruik ({details})")
    return references


def validate_selected_deletion_dependencies(
    current_xml: bytes, desired_xml: bytes, object_type: str, names: list[str], selected_families: set[str],
) -> None:
    """Require the push selection to include edits that release deleted objects."""
    current_refs = object_reference_index(current_xml, object_type, names)
    desired_refs = object_reference_index(desired_xml, object_type, names)
    missing = []
    for name in names:
        for path in sorted(set(current_refs.get(name, ())) - set(desired_refs.get(name, ()))):
            family, label = config_push_family(tuple(path.strip("/").split("/")))
            selection_key = json.dumps(
                [config_push_scope(path), family], ensure_ascii=False, separators=(",", ":")
            )
            if selection_key not in selected_families:
                missing.append((name, label, path))
    if missing:
        details = "; ".join(
            f"{name}: selecteer {label}"
            for name, label, _path in missing[:5]
        )
        raise OfflineConfigError(
            f"Verwijderen vereist ook geselecteerde wijzigingen die de verwijzingen verwijderen ({details})"
        )


def validate_incremental_object_deletions(
    current_xml: bytes, desired_xml: bytes, deleted_objects: dict[str, list[str]],
    selected_families: set[str],
) -> None:
    """Validate all selected object deletions with one scan per XML snapshot."""
    reference_bearing_object_types = {
        "address-groups", "application-groups", "service-groups",
        "dynamic-user-groups", "security-profile-groups", "log-forwarding",
        "hip-profiles",
    }
    names_by_type = {
        object_type: list(dict.fromkeys(str(name) for name in names if str(name)))
        for object_type, names in deleted_objects.items()
        if names
    }
    if not names_by_type:
        return
    current_parsed = parse_snapshot(current_xml)
    desired_parsed = parse_snapshot(desired_xml)
    current_reference_nodes = {}
    desired_reference_nodes = {}
    current_indexes = object_reference_indexes(
        current_xml, names_by_type, parsed_root=current_parsed[0], reference_nodes=current_reference_nodes,
    )
    desired_indexes = object_reference_indexes(
        desired_xml, names_by_type, parsed_root=desired_parsed[0], reference_nodes=desired_reference_nodes,
    )

    missing = []
    for object_type, names in names_by_type.items():
        current_refs = current_indexes[object_type]
        desired_refs = desired_indexes[object_type]
        for name in names:
            for path in sorted(set(current_refs.get(name, ())) - set(desired_refs.get(name, ()))):
                family, label = config_push_family(tuple(path.strip("/").split("/")))
                selection_key = json.dumps(
                    [config_push_scope(path), family], ensure_ascii=False, separators=(",", ":")
                )
                if selection_key not in selected_families:
                    missing.append((name, label, path))
    if missing:
        details = "; ".join(
            f"{name}: selecteer {label}"
            for name, label, _path in missing[:5]
        )
        raise OfflineConfigError(
            f"Verwijderen vereist ook geselecteerde wijzigingen die de verwijzingen verwijderen ({details})"
        )

    # A raw name match is not enough to prove that a delete is unsafe:
    # PAN-OS resolves VSYS references through Shared when the local duplicate
    # is gone. Resolve in scope and compare against the current candidate,
    # reusing the full-config indexes built above to avoid rescanning XML.
    unresolved_references = unresolved_object_reference_indexes(
        desired_xml,
        names_by_type,
        original_xml_bytes=current_xml,
        parsed=desired_parsed,
        original_parsed=current_parsed,
        indexed_references=desired_indexes,
        indexed_reference_nodes=desired_reference_nodes,
        original_indexed_reference_nodes=current_reference_nodes,
        # Resolve ordinary references conservatively. A narrow exception for
        # newly introduced references to unchanged Shared entries follows.
        allowed_reference_scopes={"Shared"},
    )
    current_root, current_snapshot = current_parsed
    desired_root, desired_snapshot = desired_parsed
    for object_type, names in names_by_type.items():
        current_nodes = current_reference_nodes.get(object_type, {})
        desired_nodes = desired_reference_nodes.get(object_type, {})
        for name in names:
            unresolved_list = unresolved_references[object_type].get(name, [])
            unresolved_paths = set(unresolved_list)
            if not unresolved_paths:
                continue
            # A new rule member may name an existing Shared object while the
            # same-named, unused VSYS copy is deleted in this push. Permit that
            # inheritance only when existing references already resolve to
            # Shared or behaviorally identical copies. Comparing paths alone
            # is unsafe: renaming a rule/group changes its XPath without making
            # its object reference new.
            previous_nodes = current_nodes.get(name, ())
            try:
                current_shared = _resolve_scoped_object_entry(
                    current_root, current_snapshot, "Shared", object_type, name,
                )
                desired_shared = _resolve_scoped_object_entry(
                    desired_root, desired_snapshot, "Shared", object_type, name,
                )
            except OfflineConfigError:
                continue
            if (
                current_shared is None
                or desired_shared is None
                or _merge_object_signature(current_shared, object_type)
                != _merge_object_signature(desired_shared, object_type)
            ):
                continue
            current_shared_signature = _merge_object_signature(current_shared, object_type)
            unsafe_previous_reference = False
            current_scope_is_safe: dict[str, bool] = {}
            for path, _node in previous_nodes:
                scope = config_push_scope(path)
                if scope == "Shared":
                    continue
                if scope is None:
                    unsafe_previous_reference = True
                    break
                if scope not in current_scope_is_safe:
                    try:
                        current_effective = _resolve_scoped_object_entry(
                            current_root, current_snapshot, scope, object_type, name,
                        )
                    except OfflineConfigError:
                        current_scope_is_safe[scope] = False
                    else:
                        current_scope_is_safe[scope] = (
                            current_effective is not None
                        and (
                            current_effective is current_shared
                            or (
                                object_type not in reference_bearing_object_types
                                and _merge_object_signature(current_effective, object_type)
                                == current_shared_signature
                            )
                        )
                        )
                if not current_scope_is_safe[scope]:
                    unsafe_previous_reference = True
                    break
            if unsafe_previous_reference:
                continue
            inherited_paths = set()
            desired_scope_inherits_shared: dict[str, bool] = {}
            for path, _node in desired_nodes.get(name, ()):
                if path not in unresolved_paths:
                    continue
                scope = config_push_scope(path)
                if scope in (None, "Shared"):
                    continue
                if scope not in desired_scope_inherits_shared:
                    try:
                        resolved = _resolve_scoped_object_entry(
                            desired_root, desired_snapshot, scope, object_type, name,
                        )
                    except OfflineConfigError:
                        desired_scope_inherits_shared[scope] = False
                    else:
                        desired_scope_inherits_shared[scope] = resolved is desired_shared
                if desired_scope_inherits_shared[scope]:
                    inherited_paths.add(path)
            if inherited_paths:
                unresolved_references[object_type][name] = [
                    path for path in unresolved_list if path not in inherited_paths
                ]
    used = [
        (name, unresolved_references[object_type][name])
        for object_type, names in names_by_type.items()
        for name in names
        if unresolved_references[object_type].get(name)
    ]
    if used:
        details = "; ".join(
            f"{name}: {', '.join(paths[:3])}" for name, paths in used[:5]
        )
        raise OfflineConfigError(f"Niet verwijderd: objecten zijn nog in gebruik ({details})")


def validate_workspace_configuration_deletions(xml_bytes: bytes, view: str, section: str, records: list[dict]) -> None:
    """Block certificate removal while its names appear in certificate use sites."""
    if view != "device" or section != "certificates":
        return
    names = [str(item.get("name", "")) for item in records]
    try:
        references = object_reference_index(xml_bytes, "certificates", names)
    except Exception as exc:
        raise OfflineConfigError("Certificaatreferentiecontrole is mislukt; niets verwijderd") from exc
    used = {name: paths for name, paths in references.items() if paths}
    if used:
        details = "; ".join(f"{name}: {', '.join(paths[:3])}" for name, paths in list(used.items())[:5])
        raise OfflineConfigError(f"Certificaat in gebruik; niet verwijderd ({details})")


def scm_fetch_reference_inventory(endpoint: str, token: str, container: dict[str, str], label: str) -> list[dict]:
    """Fetch all pages from an SCM reference source, rejecting ambiguous responses."""
    items = []
    offset = 0
    while True:
        params = {**container, "limit": "200", "offset": str(offset)}
        if "position" in container:
            params["position"] = container["position"]
        response = policy_api.scm_http_request(
            "GET", endpoint, token, params=params,
        )
        if not isinstance(response, (dict, list)):
            raise RuntimeError(f"SCM-{label}-referentiebron heeft een ongeldig antwoord")
        if isinstance(response, dict) and (
            "_errors" in response or not any(key in response for key in ("data", "items", "results", "entry"))
        ):
            raise RuntimeError(f"SCM-{label}-referentiebron gaf geen volledige gegevens terug")
        page = policy_api.response_items(response)
        items.extend(page)
        total = response.get("total") if isinstance(response, dict) else None
        if total is not None:
            try:
                expected_total = int(total)
            except (TypeError, ValueError) as exc:
                raise RuntimeError(f"SCM-{label}-referentiebron gaf een ongeldige paginatelling") from exc
            if expected_total < 0 or expected_total < len(items):
                raise RuntimeError(f"SCM-{label}-referentiebron gaf een ongeldige paginatelling")
            if len(items) >= expected_total:
                break
            if not page:
                raise RuntimeError(f"SCM-{label}-referentiebron eindigde vóór alle resultaten waren opgehaald")
        elif not page or len(page) < 200:
            break
        offset += len(page)
        if offset > 100_000:
            raise RuntimeError(f"SCM-{label}-referentiebron overschrijdt de veiligheidslimiet")
    return items


def scm_fetch_setup_inventory(endpoint: str, token: str, label: str) -> list[dict]:
    """Fetch a complete unscoped SCM setup inventory or fail closed."""
    return scm_fetch_reference_inventory(endpoint, token, {"pagination": "true"}, label)


def scm_object_reference_index(profile, object_type: str, names: list[str]) -> dict[str, list[str]]:
    """Build a typed reference index from SCM policies and objects.

    Folder objects can be inherited by descendants, so scan the selected folder
    and every descendant folder. An API or parsing failure blocks deletion.
    """
    if object_type not in UNUSED_OBJECT_TYPES:
        raise ValueError("Veilig verwijderen is voor dit objecttype niet beschikbaar")
    references = {str(name): [] for name in names if str(name)}
    if not references:
        return references
    scm, token, _, _ = scm_client(profile)
    if not scm.scm_object_folder or scm.scm_snippet or scm.scm_device:
        # Snippet/device inheritance requires a full attachment inventory; a
        # local-only scan is unsafe, so do not assume the selected scope is isolated.
        raise RuntimeError("SCM-verwijdercontrole kan deze snippet/device-scope niet volledig controleren")
    root = policy_api.scm_api_root(scm.scm_api_base)
    folder_endpoint = f"{root}/config/setup/v1/folders"
    folders = scm_fetch_setup_inventory(folder_endpoint, token, "folder")
    if any(not str(item.get("name", "")).strip() for item in folders):
        raise RuntimeError("SCM-folderlijst bevat een item zonder naam")

    folder_by_name = {str(item["name"]).strip(): item for item in folders}
    target_folders = {scm.scm_object_folder.strip()}
    if scm.scm_folder.strip():
        target_folders.add(scm.scm_folder.strip())
    if not target_folders.issubset(folder_by_name):
        raise RuntimeError("SCM kan de volledige folder-scope niet vaststellen")
    relevant_folders = set(target_folders)
    while True:
        children = {
            str(item["name"]).strip()
            for item in folders
            if str((item.get("parent") or {}).get("name", "") if isinstance(item.get("parent"), dict) else item.get("parent", "")).strip() in relevant_folders
        }
        expanded = relevant_folders | children
        if expanded == relevant_folders:
            break
        relevant_folders = expanded

    # Snippets can attach to folders, devices, and deployments. Scan every
    # tenant snippet, not just the ones listed on a folder, to cover all attachments.
    snippets_endpoint = f"{root}/config/setup/v1/snippets"
    snippets = scm_fetch_setup_inventory(snippets_endpoint, token, "snippet")
    relevant_snippets = {str(item.get("name", "")).strip() for item in snippets}
    if any(not name for name in relevant_snippets):
        raise RuntimeError("SCM-snippetinventaris bevat een item zonder naam")

    # Device-scoped candidate rules can also reference inherited folder objects.
    devices_endpoint = f"{root}/config/setup/v1/devices"
    devices = scm_fetch_setup_inventory(devices_endpoint, token, "device")
    relevant_devices = set()
    for item in devices:
        device_name = str(item.get("name", "")).strip()
        device_folder = str(item.get("folder", "")).strip()
        if not device_name or not device_folder:
            raise RuntimeError("SCM-deviceinventaris is onvolledig; referentiecontrole geblokkeerd")
        if device_folder in relevant_folders:
            relevant_devices.add(device_name)

    object_kinds = {
        "addresses": ("address-groups",),
        "address-groups": ("address-groups",),
        "services": ("service-groups",),
        "service-groups": ("service-groups",),
        "application-groups": ("application-groups",),
        "tags": tuple(
            kind for kind, metadata in SCM_OBJECT_TYPES.items()
            if kind != "applications" and not metadata.get("catalog_only")
        ),
    }[object_type]
    documents = []
    containers = [policy_api.scm_container(folder=folder) for folder in sorted(relevant_folders)]
    containers.extend(policy_api.scm_container(snippet=name) for name in sorted(relevant_snippets))
    containers.extend(policy_api.scm_container(device=name) for name in sorted(relevant_devices))
    for container in containers:
        scope_name = next(iter(container.values()))
        for kind in object_kinds:
            metadata = SCM_OBJECT_TYPES[kind]
            service = metadata.get("service") or "objects"
            endpoint_name = metadata.get("endpoint", kind)
            endpoint = f"{root}/config/{service}/v1/{endpoint_name}"
            for item in scm_fetch_reference_inventory(endpoint, token, container, kind):
                documents.append((f"{scope_name}/{kind}/{item.get('name', 'unnamed')}", item))
        for policy_kind, (service, endpoint_name, _) in SCM_POLICY_TYPES.items():
            endpoint = f"{root}/config/{service}/v1/{endpoint_name}"
            for position in ("pre", "post"):
                policy_container = {**container, "position": position}
                policies = scm_fetch_reference_inventory(endpoint, token, policy_container, policy_kind)
                for policy in policies:
                    documents.append((f"{scope_name}/{policy_kind}/{position}/{policy.get('name', 'unnamed')}", policy))

    def add_values(values, source: str):
        if isinstance(values, dict):
            for key, value in values.items():
                add_values(value, f"{source}/{key}")
        elif isinstance(values, list):
            for value in values:
                add_values(value, source)
        elif isinstance(values, str):
            clean = values.strip()
            if clean in references:
                references[clean].append(source[:240])
            elif object_type == "tags":
                for name in references:
                    if re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w.-])", clean):
                        references[name].append(source[:240])

    for source, document in documents:
        if object_type in {"addresses", "address-groups"}:
            for field in ("source", "destination", "static", "members", "source_translation", "destination_translation"):
                add_values(document.get(field), f"{source}/{field}")
        elif object_type in {"services", "service-groups"}:
            for field in ("service", "members"):
                add_values(document.get(field), f"{source}/{field}")
        elif object_type == "application-groups":
            for field in ("application", "members"):
                add_values(document.get(field), f"{source}/{field}")
        elif object_type == "tags":
            def scan_tag_fields(value, field_path):
                if isinstance(value, dict):
                    for key, child in value.items():
                        child_path = f"{field_path}/{key}"
                        if str(key).casefold() in {"tag", "tags", "filter"}:
                            add_values(child, child_path)
                        else:
                            scan_tag_fields(child, child_path)
                elif isinstance(value, list):
                    for child in value:
                        scan_tag_fields(child, field_path)
            scan_tag_fields(document, source)
    return references


def validate_scm_object_deletions(profile, object_type: str, names: list[str]) -> dict[str, list[str]]:
    try:
        references = scm_object_reference_index(profile, object_type, names)
    except Exception as exc:
        raise ValueError("SCM-referentiecontrole is mislukt; niets verwijderd") from exc
    used = {name: paths for name, paths in references.items() if paths}
    if used:
        details = "; ".join(f"{name}: {', '.join(paths[:3])}" for name, paths in list(used.items())[:5])
        raise ValueError(f"Niet verwijderd: objecten zijn nog in gebruik ({details})")
    return references


def validate_live_object_deletions(profile, object_type: str, names: list[str]) -> dict[str, list[str]]:
    """Validate deletes against the complete target configuration, not the UI scope."""
    if profile["target_type"] == "scm":
        return validate_scm_object_deletions(profile, object_type, names)
    try:
        _, _, _, xml_bytes = fetch_panos_candidate_xml(profile)
    except Exception as exc:
        raise ValueError("Volledige PAN-OS/Panorama-config kon niet worden gecontroleerd; niets verwijderd") from exc
    try:
        references = object_reference_index(xml_bytes, object_type, names)
    except Exception as exc:
        raise ValueError("PAN-OS/Panorama-referentiecontrole is mislukt; niets verwijderd") from exc
    used = {name: paths for name, paths in references.items() if paths}
    if used:
        details = "; ".join(f"{name}: {', '.join(paths[:3])}" for name, paths in list(used.items())[:5])
        raise ValueError(f"Niet verwijderd: objecten zijn nog in gebruik ({details})")
    return references


def workspace_policy_reference_catalog(xml_bytes: bytes, scope: str, parsed, profile) -> tuple[list[dict], dict]:
    parsed_root, snapshot = parsed
    catalog = []
    seen = set()
    for catalog_type in (
        "addresses", "address-groups", "applications", "application-groups", "application-filters",
        "services", "service-groups", "tags", "regions", "hip-profiles", "custom-url-categories", "schedules",
        "security-profile-groups", "log-forwarding",
    ):
        _, object_names = scoped_object_names(xml_bytes, scope, catalog_type, parsed=parsed)
        for name in object_names:
            key = (name, catalog_type)
            if key not in seen:
                seen.add(key)
                catalog.append({"name": name, "kind": catalog_type})
    for code in sorted(PANOS_GEO_REGION_CODES):
        key = (code, "regions")
        if key not in seen:
            seen.add(key)
            catalog.append({"name": code, "kind": "regions"})
    template = referenced_template(snapshot, scope) if snapshot.kind == "panorama" else ""
    zone_inventory = configuration_inventory(xml_bytes, scope, template, parsed=parsed)["network"] if (snapshot.kind != "panorama" or template) else []
    for kind, inventory_name in (("zones", "Zones"), ("interfaces", "Interfaces")):
        for name in next((item.get("names", []) for item in zone_inventory if item["name"] == inventory_name), []):
            key = (name, kind)
            if key not in seen:
                seen.add(key)
                catalog.append({"name": name, "kind": kind})
    application_state = cached_application_catalog(profile)
    for item in application_state["items"]:
        key = (item["name"], "applications")
        if key not in seen:
            seen.add(key)
            catalog.append({"name": item["name"], "kind": "applications"})
    return catalog, application_state


def workspace_object_reference_catalog(xml_bytes: bytes, scope: str, object_type: str, parsed, profile) -> list[dict]:
    related_types = {
        "addresses": ("tags",),
        "address-groups": ("addresses", "address-groups", "tags"),
        "application-groups": ("applications", "application-groups", "tags"),
        "services": ("tags",),
        "service-groups": ("services", "service-groups", "tags"),
    }.get(object_type, ())
    catalog = []
    seen = set()
    for related_type in related_types:
        _, object_names = scoped_object_names(xml_bytes, scope, related_type, parsed=parsed)
        for name in object_names:
            key = (name, related_type)
            if key not in seen:
                seen.add(key)
                catalog.append({"name": name, "kind": related_type})
    if object_type == "application-groups":
        for item in cached_application_catalog(profile)["items"]:
            key = (item["name"], "applications")
            if key not in seen:
                seen.add(key)
                catalog.append({"name": item["name"], "kind": "applications"})
    if object_type == "log-forwarding":
        for item in scoped_server_profiles(xml_bytes, scope, parsed=parsed):
            key = (item["name"], item["kind"])
            if key not in seen:
                seen.add(key)
                catalog.append(item)
        _, tag_names = scoped_object_names(xml_bytes, scope, "tags", parsed=parsed)
        for name in tag_names:
            key = (name, "tags")
            if key not in seen:
                seen.add(key)
                catalog.append({"name": name, "kind": "tags"})
        _, log_profiles = scoped_objects(xml_bytes, scope, "log-forwarding", parsed=parsed)
        for profile_item in log_profiles:
            for match in profile_item.get("match_list", []) or []:
                for action in match.get("actions", []) or []:
                    name = str(action.get("integration_action", "")).strip()
                    key = (name, "log-integration-actions")
                    if name and key not in seen:
                        seen.add(key)
                        catalog.append({"name": name, "kind": "log-integration-actions"})
    return catalog


@app.get("/config-workspaces/<int:workspace_id>/edit")
@login_required
def config_workspace_editor(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    try:
        with db() as conn:
            workspace_profile = conn.execute("SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)).fetchone()
            staging_source = conn.execute(
                "SELECT migration_sources.id source_id,migration_sources.project_id,migration_sources.vendor,migration_sources.source_name,migration_projects.name project_name "
                "FROM migration_sources JOIN migration_projects ON migration_projects.id=migration_sources.project_id "
                "WHERE migration_sources.staging_workspace_id=?",
                (workspace_id,),
            ).fetchone()
            migration_output = conn.execute(
                "SELECT migration_outputs.*,migration_projects.id project_id,migration_projects.name project_name "
                "FROM migration_outputs JOIN migration_projects ON migration_projects.id=migration_outputs.project_id "
                "WHERE migration_outputs.workspace_id=? ORDER BY migration_outputs.id DESC LIMIT 1",
                (workspace_id,),
            ).fetchone()
        if not workspace_profile:
            raise OfflineConfigError("Het gekoppelde firewallprofiel bestaat niet meer")
        xml_bytes, parsed_root, snapshot = cached_workspace_config(workspace["config_path"], workspace["sha256"])
        workspace_view = request.args.get("workspace_view", "policies")
        if workspace_view not in {"policies", "objects", "network", "device"}:
            workspace_view = "policies"
        config_section = request.args.get("config_section", "").strip()
        scopes = available_scopes(snapshot)
        if snapshot.kind == "panos" and (
            workspace_view in {"policies", "objects"}
            or config_section in PANOS_LOCATION_SECTIONS.get(workspace_view, set())
        ):
            scopes = ["Shared", *scopes]
        if not scopes:
            raise OfflineConfigError("Geen device group of VSYS gevonden")
        workspace_contexts = dict(session.get("workspace_contexts") or {})
        saved_context = dict(workspace_contexts.get(str(workspace_id)) or {})
        requested_scope = request.args.get("scope", "").strip()
        if requested_scope and requested_scope not in scopes:
            if requested_scope == "Shared" and snapshot.kind == "panos":
                requested_scope = ""
            else:
                raise OfflineConfigError("De gekozen scope bestaat niet")
        scope = requested_scope or saved_context.get("scope", "")
        if scope not in scopes:
            non_shared_scopes = [value for value in scopes if value != "Shared"]
            scope = non_shared_scopes[0] if non_shared_scopes else scopes[0]
        policy_kind = request.args.get("policy_kind", "security")
        if policy_kind not in POLICY_NODES:
            policy_kind = "security"
        rulebase = request.args.get("rulebase", "pre" if snapshot.kind == "panorama" else "standard")
        if snapshot.kind == "panorama" and rulebase not in {"pre", "post"}:
            rulebase = "pre"
        policy_query = request.args.get("policy_query", "").strip()[:200]
        policy_page = max(1, request.args.get("policy_page", default=1, type=int) or 1)
        policy_total = 0
        policy_inventory_total = 0
        policy_page_count = 1
        edit_name = request.args.get("edit_policy", "")
        edit_policy = None
        object_type = request.args.get("object_type", "addresses")
        if object_type not in OBJECT_NODES:
            object_type = "addresses"
        object_query = request.args.get("object_query", "").strip()[:200]
        object_page = max(1, request.args.get("object_page", default=1, type=int) or 1)
        object_total = 0
        object_page_count = 1
        edit_object_name = request.args.get("edit_object", "")
        templates = available_templates(snapshot)
        requested_template = request.args.get("template", "").strip()
        preferred_template = referenced_template(snapshot, scope)
        template = requested_template or saved_context.get("template", "") or preferred_template or (templates[0] if templates else "")
        if template and template not in templates:
            template = preferred_template or (templates[0] if templates else "")
        workspace_contexts[str(workspace_id)] = {"scope": scope, "template": template}
        session["workspace_contexts"] = dict(list(workspace_contexts.items())[-20:])
        policies = objects = []
        workspace_object_catalog = []
        workspace_object_create_template = None
        workspace_policy_catalog = []
        application_state = {}
        alternate_policy_count = 0
        inventory = {"network": [], "device": []}
        config_records = []
        config_create_templates = []
        if workspace_view == "policies":
            _, all_policies = scoped_policies(xml_bytes, scope, policy_kind, rulebase, parsed=(parsed_root, snapshot))
            if snapshot.kind == "panos" and len(snapshot.vsys) > 1:
                all_policies.sort(key=lambda item: not item["editable"])
            policy_inventory_total = len(all_policies)
            edit_policy = next(
                (item for item in all_policies if item["name"] == edit_name and item["editable"]),
                None,
            )
            filtered_policies = all_policies
            if policy_query:
                needle = policy_query.casefold()

                def policy_search_text(item):
                    values = []
                    for key, value in item.items():
                        if str(key).startswith("_"):
                            continue
                        if isinstance(value, (str, int, float, bool)):
                            values.append(str(value))
                        elif isinstance(value, list):
                            values.extend(str(entry) for entry in value if not isinstance(entry, (dict, list)))
                    return " ".join(values).casefold()

                filtered_policies = [
                    item for item in all_policies if needle in policy_search_text(item)
                ]
            policy_total = len(filtered_policies)
            policy_page_count = max(
                1, (policy_total + WORKSPACE_POLICY_PAGE_SIZE - 1) // WORKSPACE_POLICY_PAGE_SIZE
            )
            if edit_name:
                edit_index = next(
                    (index for index, item in enumerate(filtered_policies) if item["name"] == edit_name),
                    None,
                )
                if edit_index is not None:
                    policy_page = edit_index // WORKSPACE_POLICY_PAGE_SIZE + 1
            policy_page = min(policy_page, policy_page_count)
            offset = (policy_page - 1) * WORKSPACE_POLICY_PAGE_SIZE
            policies = filtered_policies[offset:offset + WORKSPACE_POLICY_PAGE_SIZE]
            if snapshot.kind == "panorama":
                other_rulebase = "post" if rulebase == "pre" else "pre"
                _, alternate_policies = scoped_policies(xml_bytes, scope, policy_kind, other_rulebase, parsed=(parsed_root, snapshot))
                alternate_policy_count = len(alternate_policies)
            workspace_policy_catalog, application_state = workspace_policy_reference_catalog(
                xml_bytes, scope, (parsed_root, snapshot), workspace_profile
            )
            workspace_policy_catalog = extend_policy_catalog_with_current(workspace_policy_catalog, all_policies)
        elif workspace_view == "objects":
            if object_query:
                _, all_objects = scoped_objects(xml_bytes, scope, object_type, parsed=(parsed_root, snapshot))
                if snapshot.kind == "panos" and len(snapshot.vsys) > 1:
                    all_objects.sort(key=lambda item: not item["editable"])
                needle = object_query.casefold()
                all_objects = [
                    item for item in all_objects
                    if needle in " ".join([
                        str(item.get("name", "")), str(item.get("owner", "")),
                        " ".join(str(value) for value in item.get("values", [])),
                        str(item.get("description", "")), str(item.get("comments", "")),
                    ]).casefold()
                ]
                object_total = len(all_objects)
                object_page_count = max(1, (object_total + WORKSPACE_OBJECT_PAGE_SIZE - 1) // WORKSPACE_OBJECT_PAGE_SIZE)
                if edit_object_name:
                    edit_index = next(
                        (index for index, item in enumerate(all_objects) if item.get("name") == edit_object_name),
                        None,
                    )
                    if edit_index is not None:
                        object_page = edit_index // WORKSPACE_OBJECT_PAGE_SIZE + 1
                object_page = min(object_page, object_page_count)
                offset = (object_page - 1) * WORKSPACE_OBJECT_PAGE_SIZE
                objects = all_objects[offset:offset + WORKSPACE_OBJECT_PAGE_SIZE]
            else:
                _, object_total, object_page_count, object_page, objects = scoped_object_page(
                    xml_bytes,
                    scope,
                    object_type,
                    object_page,
                    WORKSPACE_OBJECT_PAGE_SIZE,
                    parsed=(parsed_root, snapshot),
                    editable_first=snapshot.kind == "panos" and len(snapshot.vsys) > 1,
                    selected_name=edit_object_name,
                )
            workspace_object_create_template = object_create_record(object_type, scope)
            workspace_object_catalog = workspace_object_reference_catalog(
                xml_bytes, scope, object_type, (parsed_root, snapshot), workspace_profile
            )
            if object_type == "application-groups":
                application_state = cached_application_catalog(workspace_profile)
        else:
            inventory = configuration_inventory(xml_bytes, scope, template, parsed=(parsed_root, snapshot))
            for item in inventory["network"]:
                item["slug"] = WORKSPACE_NETWORK_NAV.get(item["name"], "")
            for item in inventory["device"]:
                item["slug"] = WORKSPACE_DEVICE_NAV.get(item["name"], "")
            if config_section:
                _, config_records = scoped_configuration_records(
                    xml_bytes, scope, template, workspace_view, config_section,
                    parsed=(parsed_root, snapshot),
                )
                config_create_templates = configuration_create_templates(
                    xml_bytes, scope, template, workspace_view, config_section,
                )
        new_policy = bool(workspace_view == "policies" and request.args.get("add_policy") == "1")
        if new_policy:
            edit_policy = policy_create_record(policy_kind, scope, rulebase)
        migration_output_sanity = json.loads(migration_output["sanity_json"] or "{}") if migration_output else {}
        migration_output_push_blocked = bool(
            migration_output and migration_output_push_block(workspace["id"])[1]
        )
        return render_template(
            "workspace_editor.html", workspace=workspace, snapshot=snapshot,
            scopes=scopes, scope=scope, templates=templates, template=template,
            preferred_template=preferred_template, workspace_view=workspace_view,
            policy_kind=policy_kind, policy_nodes=POLICY_NODES,
            rulebase=rulebase, policies=policies, edit_policy=edit_policy,
            new_policy=new_policy,
            policy_query=policy_query, policy_page=policy_page,
            policy_page_count=policy_page_count, policy_total=policy_total,
            policy_inventory_total=policy_inventory_total,
            workspace_policy_page_size=WORKSPACE_POLICY_PAGE_SIZE,
            alternate_policy_count=alternate_policy_count,
            object_type=object_type, object_nodes=OBJECT_NODES, objects=objects,
            edit_object_name=edit_object_name,
            object_query=object_query, object_page=object_page,
            object_page_count=object_page_count, object_total=object_total,
            workspace_object_page_size=WORKSPACE_OBJECT_PAGE_SIZE,
            # Duplicate merging rewrites PAN-OS XML references; SCM uses a
            # different API model and must not expose this XML-only action.
            workspace_mergeable_object_types=(
                MERGEABLE_OBJECT_TYPES
                if workspace_profile["target_type"] in {"panos", "panorama"}
                else ()
            ),
            workspace_object_catalog=workspace_object_catalog,
            workspace_object_create_template=workspace_object_create_template,
            workspace_policy_catalog=workspace_policy_catalog,
            application_catalog_state=application_state,
            workspace_editable_object_types=WORKSPACE_EDITABLE_OBJECT_TYPES,
            workspace_creatable_object_types=WORKSPACE_CREATABLE_OBJECT_TYPES,
            workspace_structured_object_types=WORKSPACE_STRUCTURED_OBJECT_TYPES,
            config_section=config_section,
            inventory=inventory, config_records=config_records,
            config_create_templates=config_create_templates,
            offline_policy_fields=OFFLINE_POLICY_FIELDS,
            workspace_policy_nav=WORKSPACE_POLICY_NAV, workspace_object_nav=WORKSPACE_OBJECT_NAV,
            workspace_network_nav=WORKSPACE_NETWORK_NAV, workspace_device_nav=WORKSPACE_DEVICE_NAV,
            staging_source=staging_source,
            migration_output=migration_output,
            migration_output_sanity=migration_output_sanity,
            migration_output_push_blocked=migration_output_push_blocked,
            migration_staging=str(workspace["source"]) in {"migration-staging", "migration-import", "migration-api"},
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
        with db() as conn:
            workspace_profile = conn.execute("SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)).fetchone()
        if not workspace_profile:
            raise OfflineConfigError("Het gekoppelde firewallprofiel bestaat niet meer")
        scope = request.form.get("scope", "")
        kind = request.form.get("policy_kind", "security")
        rulebase = request.form.get("rulebase", "pre")
        name = request.form.get("policy_name", "")
        operation = request.form.get("operation", "update")
        if operation not in {"update", "create"}:
            raise OfflineConfigError("Ongeldige policybewerking")
        _, policies = scoped_policies(xml_bytes, scope, kind, rulebase, parsed=(parsed_root, parsed_snapshot))
        before = (
            policy_create_record(kind, scope, rulebase)
            if operation == "create"
            else next((item for item in policies if item["name"] == name and item["editable"]), None)
        )
        if before is None:
            raise OfflineConfigError("Alleen een policy uit de geselecteerde scope kan hier worden gewijzigd")
        updated = copy.deepcopy(before)
        updated_name = request.form.get("name", "").strip()
        if not updated_name:
            raise OfflineConfigError("Policy name is verplicht")
        updated["name"] = updated_name
        for field in OFFLINE_POLICY_FIELDS:
            updated[field] = split_values(request.form.get(field, ""))
        updated = normalize_policy_wildcard_members(updated)
        updated["action"] = request.form.get("action", "").strip()
        updated["description"] = request.form.get("description", "").strip()
        updated["log_setting"] = request.form.get("log_setting", "").strip()
        updated["profile_group"] = request.form.get("profile_group", "").strip()
        updated["schedule"] = request.form.get("schedule", "").strip()
        updated["disabled"] = request.form.get("disabled") == "yes"
        if kind == "nat" and request.form.get("nat_translation_editor") == "yes":
            updated.update(nat_translation_replacements(request.form))
        changed_fields = (
            set(POLICY_REFERENCE_KINDS)
            if operation == "create"
            else {field for field in set(before) | set(updated) if before.get(field) != updated.get(field)}
        )
        reference_catalog, _ = workspace_policy_reference_catalog(
            xml_bytes, scope, (parsed_root, parsed_snapshot), workspace_profile
        )
        reference_catalog = extend_policy_catalog_with_current(reference_catalog, policies)
        validate_policy_references(
            updated, reference_catalog, changed_fields,
            allow_zone_freeform=parsed_snapshot.kind == "panorama" and not referenced_template(parsed_snapshot, scope),
        )
        replacement_xml = update_xml_policy(updated)
        if operation == "update" and replacement_xml == before["_xml"]:
            raise OfflineConfigError("Er zijn geen wijzigingen om te bewaren")
        if request.form.get("direct_save") == "yes":
            if operation == "create":
                new_xml = insert_policy_in_snapshot(
                    workspace_config_path(workspace).read_bytes(), scope, kind, rulebase,
                    replacement_xml, request.form.get("position", "bottom"),
                )
            else:
                new_xml = replace_policy_in_snapshot(
                    workspace_config_path(workspace).read_bytes(), scope, kind, rulebase,
                    name, offline_policy_fingerprint(before), replacement_xml,
                )
            new_id = store_workspace_edit_version(workspace, new_xml, "policy add" if operation == "create" else "policy edit")
            audit("config-workspace-policy-created" if operation == "create" else "config-workspace-policy-edited", f"source={workspace['id']} workspace={new_id} scope={scope} policy={updated_name}")
            flash("Opgeslagen", "success")
            return redirect(url_for(
                "config_workspace_editor", workspace_id=new_id, scope=scope,
                workspace_view="policies", policy_kind=kind, rulebase=rulebase,
            ))
        draft_id = secrets.token_urlsafe(24)
        draft = {
            "workspace_id": workspace_id, "scope": scope, "kind": kind,
            "rulebase": rulebase, "policy_name": name, "operation": operation,
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


@app.post("/config-workspaces/<int:workspace_id>/policies/bulk-preview")
@login_required
def config_workspace_policy_bulk_preview(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace: return "Not found", 404
    try:
        xml_bytes, parsed_root, parsed_snapshot = cached_workspace_config(workspace["config_path"], workspace["sha256"])
        with db() as conn:
            workspace_profile = conn.execute("SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)).fetchone()
        if not workspace_profile:
            raise OfflineConfigError("Het gekoppelde firewallprofiel bestaat niet meer")
        scope = request.form.get("scope", "")
        kind = request.form.get("policy_kind", "security")
        rulebase = request.form.get("rulebase", "pre")
        selected_names = set(request.form.getlist("policy_name"))
        if not selected_names:
            raise OfflineConfigError("Selecteer minstens één policy")
        _, policies = scoped_policies(xml_bytes, scope, kind, rulebase, parsed=(parsed_root, parsed_snapshot))
        selected = [item for item in policies if item["editable"] and item["name"] in selected_names]
        if len(selected) != len(selected_names):
            raise OfflineConfigError("Niet alle geselecteerde policies behoren nog tot deze scope")
        operations = {field: {"add": split_values(request.form.get(f"{field}_add", "")), "remove": split_values(request.form.get(f"{field}_remove", ""))} for field in OFFLINE_POLICY_FIELDS}
        for field in ("action", "log_setting", "profile_group", "schedule"):
            operations[field] = request.form.get(field) or None
        operations["description_append"] = request.form.get("description_append", "").strip()
        disabled = request.form.get("disabled", "")
        operations["disabled"] = disabled == "true" if disabled in {"true", "false"} else None
        if kind == "nat":
            operations.update(nat_bulk_replacements(request.form))
        reference_catalog, _ = workspace_policy_reference_catalog(
            xml_bytes, scope, (parsed_root, parsed_snapshot), workspace_profile
        )
        reference_catalog = extend_policy_catalog_with_current(reference_catalog, policies)
        reference_index = build_policy_reference_index(reference_catalog)
        changes = []
        for before in selected:
            after = apply_bulk_operations(before, operations)
            if after != before:
                changed_fields = {field for field in set(before) | set(after) if before.get(field) != after.get(field)}
                validate_policy_references(
                    after, reference_index, changed_fields,
                    allow_zone_freeform=parsed_snapshot.kind == "panorama" and not referenced_template(parsed_snapshot, scope),
                )
                changes.append({
                    "policy_name": before["name"], "fingerprint": offline_policy_fingerprint(before),
                    "before": before, "after": after, "replacement_xml": update_xml_policy(after),
                })
        if not changes:
            raise OfflineConfigError("De gekozen bulkbewerking veroorzaakt geen wijzigingen")
        if request.form.get("direct_save") == "yes":
            new_xml = replace_policies_in_snapshot(
                xml_bytes, scope, kind, rulebase,
                [{
                    "name": change["policy_name"],
                    "expected_fingerprint": change["fingerprint"],
                    "replacement_xml": change["replacement_xml"],
                } for change in changes],
            )
            new_id = store_workspace_edit_version(workspace, new_xml, "bulk edit")
            audit("config-workspace-policy-bulk-edited", f"source={workspace['id']} workspace={new_id} scope={scope} rules={len(changes)}")
            flash("Opgeslagen", "success")
            return redirect(url_for(
                "config_workspace_editor", workspace_id=new_id, scope=scope,
                workspace_view="policies", policy_kind=kind, rulebase=rulebase,
            ))
        draft_id = secrets.token_urlsafe(24)
        draft = {"workspace_id": workspace_id, "scope": scope, "kind": kind, "rulebase": rulebase, "changes": changes, "created_at": now()}
        draft_path = POLICY_DRAFTS / f"offline-bulk-{draft_id}.json"
        draft_path.write_text(json.dumps(draft)); draft_path.chmod(0o600)
        return render_template("workspace_policy_bulk_preview.html", workspace=workspace, draft_id=draft_id, draft=draft)
    except Exception as exc:
        flash(f"Bulk-preview mislukt: {exc}", "error")
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id, scope=request.form.get("scope", ""), workspace_view="policies", policy_kind=request.form.get("policy_kind", "security"), rulebase=request.form.get("rulebase", "pre")))


@app.post("/config-workspaces/<int:workspace_id>/policies/delete")
@login_required
def config_workspace_policy_delete(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    scope = request.form.get("scope", "")
    kind = request.form.get("policy_kind", "security")
    rulebase = request.form.get("rulebase", "pre")
    try:
        names = set(request.form.getlist("policy_name"))
        if not names:
            raise OfflineConfigError("Selecteer minstens één policy")
        xml_bytes, parsed_root, snapshot = cached_workspace_config(workspace["config_path"], workspace["sha256"])
        _, policies = scoped_policies(xml_bytes, scope, kind, rulebase, parsed=(parsed_root, snapshot))
        editable = {item["name"] for item in policies if item["editable"]}
        if not names.issubset(editable):
            raise OfflineConfigError("Alleen policies uit de geselecteerde scope kunnen worden verwijderd")
        new_xml = delete_policies_from_snapshot(xml_bytes, scope, kind, rulebase, names)
        new_id = store_workspace_edit_version(workspace, new_xml, "policy delete")
        audit("config-workspace-policy-deleted", f"source={workspace_id} workspace={new_id} scope={scope} rules={len(names)}")
        flash(f"{len(names)} policies verwijderd in een nieuwe workspaceversie.", "success")
        return redirect(url_for("config_workspace_editor", workspace_id=new_id, scope=scope, workspace_view="policies", policy_kind=kind, rulebase=rulebase))
    except Exception as exc:
        flash(f"Policies niet verwijderd: {exc}", "error")
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id, scope=scope, workspace_view="policies", policy_kind=kind, rulebase=rulebase))


@app.post("/config-workspaces/<int:workspace_id>/policies/move")
@login_required
def config_workspace_policy_move(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    scope = request.form.get("scope", "")
    kind = request.form.get("policy_kind", "security")
    rulebase = request.form.get("rulebase", "pre")
    try:
        names = set(request.form.getlist("policy_name"))
        direction = request.form.get("direction", "")
        if not names:
            raise OfflineConfigError("Selecteer minstens één policy")
        xml_bytes, parsed_root, snapshot = cached_workspace_config(workspace["config_path"], workspace["sha256"])
        _, policies = scoped_policies(xml_bytes, scope, kind, rulebase, parsed=(parsed_root, snapshot))
        editable = {item["name"] for item in policies if item["editable"]}
        if not names.issubset(editable):
            raise OfflineConfigError("Alleen policies uit de geselecteerde scope kunnen worden verplaatst")
        new_xml = move_policies_in_snapshot(xml_bytes, scope, kind, rulebase, names, direction)
        new_id = store_workspace_edit_version(workspace, new_xml, f"policy move {direction}")
        audit("config-workspace-policy-moved", f"source={workspace_id} workspace={new_id} scope={scope} rules={len(names)} direction={direction}")
        flash(f"{len(names)} policies verplaatst.", "success")
        return redirect(url_for("config_workspace_editor", workspace_id=new_id, scope=scope, workspace_view="policies", policy_kind=kind, rulebase=rulebase))
    except Exception as exc:
        flash(f"Policies niet verplaatst: {exc}", "error")
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id, scope=scope, workspace_view="policies", policy_kind=kind, rulebase=rulebase))


@app.post("/config-workspaces/<int:workspace_id>/scope-move")
@login_required
def config_workspace_scope_move(workspace_id):
    """Move selected PAN-OS entries between VSYS and Shared in an offline workspace."""
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    source_scope = request.form.get("scope", "")
    target_scope = request.form.get("target_scope", "")
    item_kind = request.form.get("item_kind", "")
    item_type = request.form.get("item_type", "")
    workspace_view = request.form.get("workspace_view", "objects")
    query_args = {
        "workspace_view": workspace_view,
        "scope": source_scope,
        "policy_kind": item_type if item_kind == "policy" else "security",
        "rulebase": request.form.get("rulebase", "standard"),
        "object_type": item_type if item_kind == "object" else "addresses",
    }
    try:
        xml_bytes, parsed_root, snapshot = cached_workspace_config(workspace["config_path"], workspace["sha256"])
        if snapshot.kind != "panos" or len(snapshot.vsys) < 2:
            raise OfflineConfigError("Verplaatsen tussen Shared en VSYS is alleen beschikbaar voor standalone PAN-OS met meerdere VSYS")
        scopes = ["Shared", *snapshot.vsys]
        if source_scope not in scopes or target_scope not in scopes or source_scope == target_scope:
            raise OfflineConfigError("Kies een geldige, andere doel-VSYS of Shared")
        if item_kind == "policy" and item_type in POLICY_NODES:
            _, records = scoped_policies(xml_bytes, source_scope, item_type, "standard", parsed=(parsed_root, snapshot))
            names = request.form.getlist("policy_name")
            move_all = request.form.get("move_all") == "yes"
        elif item_kind == "object" and item_type in PANOS_SCOPE_MOVE_OBJECT_TYPES:
            _, records = scoped_objects(xml_bytes, source_scope, item_type, parsed=(parsed_root, snapshot))
            names = request.form.getlist("object_id")
            move_all = request.form.get("move_all") == "yes"
        else:
            raise OfflineConfigError("Dit policy- of objecttype kan niet tussen scopes worden verplaatst")
        available = {item["name"] for item in records if item.get("editable")}
        if move_all:
            if target_scope != "Shared" or source_scope == "Shared":
                raise OfflineConfigError("Alles verplaatsen is alleen beschikbaar van een VSYS naar Shared")
            names = [item["name"] for item in records if item.get("editable")]
        else:
            names = list(dict.fromkeys(name for name in names if name))
        if not names:
            raise OfflineConfigError("Geen lokale items geselecteerd om te verplaatsen")
        if not set(names).issubset(available):
            raise OfflineConfigError("Een selectie is intussen gewijzigd of bevat inherited items")

        with db() as conn:
            move_profile = conn.execute("SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)).fetchone()
        if not move_profile:
            raise OfflineConfigError("Het gekoppelde firewallprofiel bestaat niet meer")
        predefined_applications = [
            item.get("name", "") for item in cached_application_catalog(move_profile).get("items", [])
            if item.get("name")
        ]

        updated_xml, moved, failed = move_panos_scope_entries(
            xml_bytes,
            item_kind=item_kind,
            item_type=item_type,
            names=names,
            source_scope=source_scope,
            target_scope=target_scope,
            predefined_applications=predefined_applications,
            insertion_position=request.form.get("insertion_position", "top"),
        )
        result_workspace_id = workspace_id
        if moved:
            result_workspace_id = store_workspace_edit_version(
                workspace, updated_xml, f"scope move {len(moved)} items"
            )
            audit(
                "config-workspace-scope-moved",
                f"source={workspace_id} workspace={result_workspace_id} kind={item_kind} type={item_type} from={source_scope} to={target_scope} moved={len(moved)} failed={len(failed)}",
            )
        return render_template(
            "workspace_scope_move_result.html",
            workspace=workspace,
            result_workspace_id=result_workspace_id,
            source_scope=source_scope,
            target_scope=target_scope,
            item_kind=item_kind,
            item_type=item_type,
            moved=moved,
            failed=failed,
            return_url=url_for("config_workspace_editor", workspace_id=result_workspace_id, **query_args),
        )
    except Exception as exc:
        flash(f"Scope-verplaatsing niet uitgevoerd: {exc}", "error")
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id, **query_args))


@app.post("/config-workspaces/policy-bulk-drafts/<draft_id>/apply")
@login_required
def config_workspace_policy_bulk_apply(draft_id):
    if not draft_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in draft_id): return "Not found", 404
    draft_path = POLICY_DRAFTS / f"offline-bulk-{draft_id}.json"
    if not draft_path.is_file(): return "Not found", 404
    try:
        draft = json.loads(draft_path.read_text())
        workspace = workspace_row(int(draft["workspace_id"]))
        if not workspace: raise OfflineConfigError("De bronworkspace bestaat niet meer")
        new_xml = replace_policies_in_snapshot(
            workspace_config_path(workspace).read_bytes(),
            draft["scope"], draft["kind"], draft["rulebase"],
            [{
                "name": change["policy_name"],
                "expected_fingerprint": change["fingerprint"],
                "replacement_xml": change["replacement_xml"],
            } for change in draft["changes"]],
        )
        with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)).fetchone()
        if not profile: raise OfflineConfigError("Het firewallprofiel bestaat niet meer")
        new_id = store_config_workspace(profile, f"{workspace['name']} · bulk edit {now()}", workspace["original_name"], new_xml, workspace_version_source(workspace), baseline_workspace=workspace)
        if not advance_migration_staging_workspace(workspace["id"], new_id):
            set_active_config_workspace(workspace["profile_id"], new_id)
        audit("config-workspace-policy-bulk-edited", f"source={workspace['id']} workspace={new_id} scope={draft['scope']} rules={len(draft['changes'])}")
        draft_path.unlink(missing_ok=True)
        flash(f"{len(draft['changes'])} policies gewijzigd in een nieuwe workspaceversie.", "success")
        return redirect(url_for("config_workspace_editor", workspace_id=new_id, scope=draft["scope"], workspace_view="policies", policy_kind=draft["kind"], rulebase=draft["rulebase"]))
    except Exception as exc:
        flash(f"Bulk-wijziging niet bewaard: {exc}", "error")
        workspace_id = json.loads(draft_path.read_text()).get("workspace_id") if draft_path.is_file() else None
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id)) if workspace_id else redirect(url_for("index"))


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
        if draft.get("operation") == "create":
            new_xml = insert_policy_in_snapshot(
                workspace_config_path(workspace).read_bytes(), draft["scope"], draft["kind"],
                draft["rulebase"], draft["replacement_xml"], "bottom",
            )
        else:
            new_xml = replace_policy_in_snapshot(
                workspace_config_path(workspace).read_bytes(), draft["scope"], draft["kind"],
                draft["rulebase"], draft["policy_name"], draft["fingerprint"], draft["replacement_xml"],
            )
        with db() as conn:
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)).fetchone()
        if not profile:
            raise OfflineConfigError("Het firewallprofiel bestaat niet meer")
        new_id = store_config_workspace(
            profile, f"{workspace['name']} · edit {now()}", workspace["original_name"], new_xml,
            workspace_version_source(workspace), baseline_workspace=workspace,
        )
        if not advance_migration_staging_workspace(workspace["id"], new_id):
            set_active_config_workspace(workspace["profile_id"], new_id)
        audit("config-workspace-policy-edited", f"source={workspace['id']} workspace={new_id} scope={draft['scope']} policy={draft['policy_name']}")
        draft_path.unlink(missing_ok=True)
        flash("Policy gewijzigd in een nieuwe workspaceversie; de bronsnapshot bleef onaangeroerd.", "success")
        return redirect(url_for("config_workspace_editor", workspace_id=new_id, scope=draft["scope"], policy_kind=draft["kind"], rulebase=draft["rulebase"]))
    except Exception as exc:
        flash(f"Wijziging niet bewaard: {exc}", "error")
        workspace_id = json.loads(draft_path.read_text()).get("workspace_id") if draft_path.is_file() else None
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id)) if workspace_id else redirect(url_for("index"))


@app.post("/config-workspaces/<int:workspace_id>/objects/preview")
@login_required
def config_workspace_object_preview(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    scope = request.form.get("scope", "")
    object_type = request.form.get("object_type", "")
    try:
        if object_type not in WORKSPACE_EDITABLE_OBJECT_TYPES:
            raise OfflineConfigError("Dit objecttype heeft geen configureerbare candidate-mapping")
        xml_bytes, parsed_root, snapshot = cached_workspace_config(workspace["config_path"], workspace["sha256"])
        _, existing = scoped_objects(xml_bytes, scope, object_type, parsed=(parsed_root, snapshot))
        original_name = request.form.get("object_id", "").strip()
        before = next((item for item in existing if item["name"] == original_name and item["editable"]), None) if original_name else None
        if original_name and before is None:
            raise OfflineConfigError("Alleen een object uit de geselecteerde scope kan worden gewijzigd")
        generic_updates = None
        if object_type in WORKSPACE_STRUCTURED_OBJECT_TYPES:
            payload = scm_object_payload(object_type, request.form, {})
            validate_object_payload(payload, object_type, existing, original_name)
            with db() as conn:
                workspace_profile = conn.execute(
                    "SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)
                ).fetchone()
            if not workspace_profile:
                raise OfflineConfigError("Het gekoppelde firewallprofiel bestaat niet meer")
            validate_object_references(
                payload, object_type,
                workspace_object_reference_catalog(
                    xml_bytes, scope, object_type, (parsed_root, snapshot), workspace_profile
                ),
            )
        else:
            name = request.form.get("name", "").strip()
            if not name:
                raise OfflineConfigError("Name is verplicht")
            if any(item["name"] == name and item["name"] != original_name for item in existing):
                raise OfflineConfigError(f"Object {name} bestaat al in {scope}")
            schema_record = before or object_create_record(object_type, scope)
            if schema_record is None:
                raise OfflineConfigError("Voor dit objecttype is geen veilig PAN-OS create-schema beschikbaar")
            editable_fields = [field for field in schema_record.get("edit_fields", []) if field.get("kind") != "protected"]
            allowed = {(field["path"], field["kind"]) for field in editable_fields}
            try:
                submitted = json.loads(request.form.get("generic_updates", "[]"))
            except json.JSONDecodeError as exc:
                raise OfflineConfigError("Ongeldige objectvelden") from exc
            if not isinstance(submitted, list) or len(submitted) > 5000:
                raise OfflineConfigError("Ongeldige objectvelden")
            generic_updates = []
            for update in submitted:
                if not isinstance(update, dict) or (update.get("path"), update.get("kind")) not in allowed:
                    raise OfflineConfigError("Een objectveld is ongeldig of bestaat niet meer")
                clean = {"path": update["path"], "kind": update["kind"]}
                if update["kind"] == "members":
                    values = update.get("values", [])
                    if not isinstance(values, list) or len(values) > 5000:
                        raise OfflineConfigError("Ongeldige memberlijst")
                    clean["values"] = [str(value).strip() for value in values if str(value).strip()]
                else:
                    clean["value"] = str(update.get("value", ""))[:65535]
                generic_updates.append(clean)
            if object_type == "url-filtering":
                generic_updates = normalize_url_profile_updates(editable_fields, generic_updates)
            payload = {"name": name, "fields": generic_updates}
        operation = "update" if before else "create"
        draft_id = secrets.token_urlsafe(24)
        draft = {
            "workspace_id": workspace_id, "scope": scope, "object_type": object_type,
            "operation": operation, "payload": payload, "before": before,
            "changes": [{
                "operation": operation, "original_name": original_name,
                "fingerprint": offline_object_fingerprint(before) if before else "",
                **({"replacement_xml": object_payload_xml(payload)} if generic_updates is None else {
                    "generic_updates": generic_updates, "name": payload["name"]
                }),
            }], "created_at": now(),
        }
        if request.form.get("direct_save") == "yes":
            new_xml = apply_object_changes(
                workspace_config_path(workspace).read_bytes(), scope, object_type, draft["changes"],
            )
            new_id = store_workspace_edit_version(workspace, new_xml, "object edit")
            audit("config-workspace-object-edited", f"source={workspace['id']} workspace={new_id} scope={scope} type={object_type} operation={operation}")
            flash("Opgeslagen", "success")
            return redirect(url_for(
                "config_workspace_editor", workspace_id=new_id, scope=scope,
                workspace_view="objects", object_type=object_type,
            ))
        draft_path = OBJECT_DRAFTS / f"offline-object-{draft_id}.json"
        draft_path.write_text(json.dumps(draft)); draft_path.chmod(0o600)
        return render_template("workspace_object_preview.html", workspace=workspace, draft=draft, draft_id=draft_id)
    except Exception as exc:
        flash(f"Objectwijziging niet voorbereid: {exc}", "error")
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id, scope=scope, workspace_view="objects", object_type=object_type))


@app.post("/config-workspaces/<int:workspace_id>/objects/merge-preview")
@login_required
def config_workspace_object_merge_preview(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    scope = request.form.get("scope", "")
    return_object_type = request.form.get("object_type", "")
    merge_all_types = request.form.get("merge_all_types") == "yes"
    object_type = "__all__" if merge_all_types else return_object_type
    try:
        if workspace["target_type"] not in {"panos", "panorama"}:
            raise OfflineConfigError("Duplicaten samenvoegen is alleen beschikbaar voor PAN-OS- en Panorama-XML")
        if not merge_all_types and object_type not in MERGEABLE_OBJECT_TYPES:
            raise OfflineConfigError("Samenvoegen is voor dit objecttype niet veilig beschikbaar")
        xml_bytes, parsed_root, snapshot = cached_workspace_config(
            workspace["config_path"], workspace["sha256"],
        )
        if scope not in available_scopes(snapshot) and not (scope == "Shared" and snapshot.kind == "panos"):
            raise OfflineConfigError("De geselecteerde scope bestaat niet meer")
        object_types = sorted(MERGEABLE_OBJECT_TYPES) if merge_all_types else [object_type]
        groups = []
        for candidate_type in object_types:
            label = SCM_OBJECT_TYPES.get(candidate_type, {}).get("label", candidate_type)
            candidate_groups = duplicate_object_groups(
                xml_bytes, scope, candidate_type, parsed=(parsed_root, snapshot),
            )
            groups.extend({
                **group,
                "object_type": candidate_type,
                "object_label": label,
            } for group in candidate_groups)
        if not groups:
            flash(
                f"Geen functioneel identieke objecten gevonden in {len(object_types)} ondersteunde object- en servicetypen binnen {scope}.",
                "info",
            )
            return redirect(url_for(
                "config_workspace_editor", workspace_id=workspace_id, scope=scope,
                workspace_view="objects", object_type=return_object_type,
            ))
        draft_id = secrets.token_urlsafe(24)
        draft = {
            "workspace_id": workspace_id, "scope": scope, "object_type": object_type,
            "return_object_type": return_object_type,
            "object_types": object_types,
            "operation": "merge", "groups": groups, "created_at": now(),
        }
        draft_path = OBJECT_DRAFTS / f"offline-object-{draft_id}.json"
        draft_path.write_text(json.dumps(draft))
        draft_path.chmod(0o600)
        return render_template(
            "workspace_object_merge_preview.html", workspace=workspace,
            draft=draft, draft_id=draft_id,
            object_label=(
                "alle ondersteunde objecten en services"
                if merge_all_types
                else SCM_OBJECT_TYPES.get(object_type, {}).get("label", object_type)
            ),
        )
    except Exception as exc:
        flash(f"Duplicaten niet voorbereid: {exc}", "error")
        return redirect(url_for(
            "config_workspace_editor", workspace_id=workspace_id, scope=scope,
            workspace_view="objects", object_type=return_object_type,
        ))


@app.post("/config-workspaces/<int:workspace_id>/objects/merge-shared-preview")
@login_required
def config_workspace_object_merge_shared_preview(workspace_id):
    """Preview functional duplicates across Shared and all standalone VSYS scopes."""
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    scope = request.form.get("scope", "")
    return_object_type = request.form.get("object_type", "")
    try:
        if workspace["target_type"] != "panos":
            raise OfflineConfigError("Samenvoegen naar Shared vereist standalone PAN-OS")
        xml_bytes, parsed_root, snapshot = cached_workspace_config(
            workspace["config_path"], workspace["sha256"],
        )
        if snapshot.kind != "panos" or len(snapshot.vsys) < 2:
            raise OfflineConfigError("Samenvoegen naar Shared vereist standalone PAN-OS met meerdere VSYS")
        if scope not in available_scopes(snapshot) and scope != "Shared":
            raise OfflineConfigError("De geselecteerde scope bestaat niet meer")

        groups = []
        object_types = sorted(MERGEABLE_OBJECT_TYPES)
        for object_type in object_types:
            label = SCM_OBJECT_TYPES.get(object_type, {}).get("label", object_type)
            groups.extend({
                **group,
                "object_type": object_type,
                "object_label": label,
            } for group in duplicate_object_groups_across_panos_scopes(
                xml_bytes, object_type, parsed=(parsed_root, snapshot),
            ))
        if not groups:
            flash("Geen inhoudelijk identieke objecten gevonden tussen Shared en verschillende VSYS.", "info")
            return redirect(url_for(
                "config_workspace_editor", workspace_id=workspace_id, scope=scope,
                workspace_view="objects", object_type=return_object_type,
            ))

        draft_id = secrets.token_urlsafe(24)
        draft = {
            "workspace_id": workspace_id, "scope": scope,
            "object_type": return_object_type or "__all__",
            "return_object_type": return_object_type,
            "object_types": object_types,
            "operation": "merge_to_shared", "groups": groups, "created_at": now(),
        }
        draft_path = OBJECT_DRAFTS / f"offline-object-{draft_id}.json"
        draft_path.write_text(json.dumps(draft))
        draft_path.chmod(0o600)
        return render_template(
            "workspace_object_merge_preview.html", workspace=workspace,
            draft=draft, draft_id=draft_id,
            object_label="alle ondersteunde objecten en services tussen scopes",
        )
    except Exception as exc:
        flash(f"Duplicaten niet voorbereid: {exc}", "error")
        return redirect(url_for(
            "config_workspace_editor", workspace_id=workspace_id, scope=scope,
            workspace_view="objects", object_type=return_object_type,
        ))


@app.post("/config-workspaces/<int:workspace_id>/objects/delete-preview")
@login_required
def config_workspace_object_delete_preview(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    scope = request.form.get("scope", "")
    object_type = request.form.get("object_type", "")
    try:
        if object_type not in WORKSPACE_EDITABLE_OBJECT_TYPES:
            raise OfflineConfigError("Dit objecttype heeft geen configureerbare candidate-mapping")
        delete_unused = request.form.get("delete_unused") == "yes"
        if delete_unused and object_type not in UNUSED_OBJECT_TYPES:
            raise OfflineConfigError("Ongebruikt verwijderen is niet beschikbaar voor dit objecttype")
        selected_names = list(dict.fromkeys(request.form.getlist("object_id")))
        if not selected_names:
            if not delete_unused:
                raise OfflineConfigError("Selecteer minstens één object")
        xml_bytes, parsed_root, snapshot = cached_workspace_config(workspace["config_path"], workspace["sha256"])
        _, existing = scoped_objects(xml_bytes, scope, object_type, parsed=(parsed_root, snapshot))
        if delete_unused:
            candidates = [item for item in existing if item["editable"]]
            references = object_reference_index(xml_bytes, object_type, [item["name"] for item in candidates])
            selected_names = [item["name"] for item in candidates if not references.get(item["name"])]
            if not selected_names:
                raise OfflineConfigError("Geen ongebruikte objecten gevonden in deze scope")
        selected = [item for item in existing if item["name"] in selected_names and item["editable"]]
        if len(selected) != len(selected_names):
            raise OfflineConfigError("Een geselecteerd object is inherited of bestaat niet meer")
        validate_workspace_object_deletions(xml_bytes, object_type, selected_names)
        changes = [{"operation": "delete", "original_name": item["name"], "fingerprint": offline_object_fingerprint(item)} for item in selected]
        draft_id = secrets.token_urlsafe(24)
        draft = {
            "workspace_id": workspace_id, "scope": scope, "object_type": object_type,
            "operation": "delete", "delete_unused": delete_unused,
            "objects": selected, "changes": changes, "created_at": now(),
        }
        if request.form.get("direct_save") == "yes":
            new_xml = apply_object_changes(
                workspace_config_path(workspace).read_bytes(), scope, object_type, changes,
            )
            new_id = store_workspace_edit_version(workspace, new_xml, "object delete")
            audit("config-workspace-object-edited", f"source={workspace['id']} workspace={new_id} scope={scope} type={object_type} operation=delete")
            flash(f"{len(selected)} objecten verwijderd in een nieuwe workspaceversie.", "success")
            return redirect(url_for(
                "config_workspace_editor", workspace_id=new_id, scope=scope,
                workspace_view="objects", object_type=object_type,
            ))
        draft_path = OBJECT_DRAFTS / f"offline-object-{draft_id}.json"
        draft_path.write_text(json.dumps(draft)); draft_path.chmod(0o600)
        return render_template("workspace_object_preview.html", workspace=workspace, draft=draft, draft_id=draft_id)
    except Exception as exc:
        flash(f"Objecten niet voorbereid voor verwijderen: {exc}", "error")
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id, scope=scope, workspace_view="objects", object_type=object_type))


@app.post("/config-workspaces/object-drafts/<draft_id>/apply")
@login_required
def config_workspace_object_apply(draft_id):
    if not draft_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in draft_id):
        return "Not found", 404
    draft_path = OBJECT_DRAFTS / f"offline-object-{draft_id}.json"
    if not draft_path.is_file():
        return "Not found", 404
    try:
        draft = json.loads(draft_path.read_text())
        workspace = workspace_row(int(draft["workspace_id"]))
        if not workspace:
            raise OfflineConfigError("De bronworkspace bestaat niet meer")
        if draft.get("operation") == "merge_to_shared":
            selections = []
            for group in draft.get("groups", []):
                object_type = group.get("object_type", "")
                if object_type not in MERGEABLE_OBJECT_TYPES:
                    raise OfflineConfigError("Samenvoegen naar Shared is voor dit objecttype niet veilig ondersteund")
                candidate_id = request.form.get(f"master_{group.get('id', '')}", "")
                candidates = [item for item in group.get("objects", []) if item.get("candidate_id") == candidate_id]
                if len(candidates) != 1:
                    raise OfflineConfigError("Kies precies één Shared-master per duplicaatgroep")
                selections.append({
                    "object_type": object_type,
                    "objects": group["objects"],
                    "master": {"scope": candidates[0]["scope"], "name": candidates[0]["name"]},
                })
            new_xml, merge_summary = merge_duplicate_object_groups_to_shared(
                workspace_config_path(workspace).read_bytes(), selections,
            )
        elif draft.get("operation") == "merge":
            selections = []
            for group in draft.get("groups", []):
                object_type = group.get("object_type", draft.get("object_type"))
                if object_type not in MERGEABLE_OBJECT_TYPES:
                    raise OfflineConfigError("Samenvoegen is voor dit objecttype niet veilig ondersteund")
                names = [item["name"] for item in group.get("objects", [])]
                master = request.form.get(f"master_{group.get('id', '')}", "")
                if master not in names:
                    raise OfflineConfigError("Kies precies één masterobject per duplicaatgroep")
                selections.append({
                    "object_type": object_type,
                    "names": names,
                    "master": master,
                    "fingerprints": {item["name"]: item["fingerprint"] for item in group["objects"]},
                })
            new_xml, merge_summary = merge_duplicate_object_groups(
                workspace_config_path(workspace).read_bytes(), draft["scope"], selections,
            )
        elif draft.get("operation") == "delete":
            source_xml = workspace_config_path(workspace).read_bytes()
            validate_workspace_object_deletions(
                source_xml, draft["object_type"],
                [change["original_name"] for change in draft["changes"]],
            )
            new_xml = apply_object_changes(
                source_xml, draft["scope"], draft["object_type"], draft["changes"],
            )
        else:
            new_xml = apply_object_changes(
                workspace_config_path(workspace).read_bytes(), draft["scope"],
                draft["object_type"], draft["changes"],
            )
        with db() as conn:
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)).fetchone()
        if not profile:
            raise OfflineConfigError("Het firewallprofiel bestaat niet meer")
        new_id = store_config_workspace(
            profile, f"{workspace['name']} · object edit {now()}", workspace["original_name"], new_xml,
            workspace_version_source(workspace), baseline_workspace=workspace,
        )
        if not advance_migration_staging_workspace(workspace["id"], new_id):
            set_active_config_workspace(workspace["profile_id"], new_id)
        draft_path.unlink(missing_ok=True)
        audit(
            "config-workspace-object-edited",
            f"source={workspace['id']} workspace={new_id} scope={draft['scope']} "
            f"types={','.join(draft.get('object_types', [draft['object_type']]))} "
            f"operation={draft['operation']}",
        )
        if draft.get("operation") in {"merge", "merge_to_shared"}:
            destination = " naar Shared" if draft.get("operation") == "merge_to_shared" else ""
            flash(
                f"{merge_summary['merged']} duplicaatobject(en){destination} samengevoegd in {merge_summary['groups']} groep(en); referenties bijgewerkt.",
                "success",
            )
        else:
            flash("Opgeslagen", "success")
        return redirect(url_for(
            "config_workspace_editor", workspace_id=new_id, scope=draft["scope"],
            workspace_view="objects",
            object_type=draft.get("return_object_type", draft["object_type"]),
        ))
    except Exception as exc:
        flash(f"Objectwijziging niet bewaard: {exc}", "error")
        workspace_id = json.loads(draft_path.read_text()).get("workspace_id") if draft_path.is_file() else None
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id, workspace_view="objects")) if workspace_id else redirect(url_for("index"))


def _workspace_config_redirect(workspace_id: int, draft: dict):
    return redirect(url_for(
        "config_workspace_editor", workspace_id=workspace_id,
        scope=draft.get("scope", ""), template=draft.get("template", ""),
        workspace_view=draft.get("view", "network"),
        config_section=draft.get("section", ""),
    ))


def _store_workspace_configuration_version(workspace, context: dict, changes: list[dict]) -> int:
    new_xml = apply_configuration_changes(workspace_config_path(workspace).read_bytes(), changes)
    with db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)).fetchone()
    if not profile:
        raise OfflineConfigError("Het firewallprofiel bestaat niet meer")
    new_id = store_config_workspace(
        profile, f"{workspace['name']} · {context['view']} edit {now()}",
        workspace["original_name"], new_xml, workspace_version_source(workspace), baseline_workspace=workspace,
    )
    if not advance_migration_staging_workspace(workspace["id"], new_id):
        set_active_config_workspace(workspace["profile_id"], new_id)
    audit("config-workspace-configuration-edited", f"source={workspace['id']} workspace={new_id} view={context['view']} section={context['section']} operation={context.get('operation','update')}")
    return new_id


@app.post("/config-workspaces/<int:workspace_id>/configuration/create-basic")
@login_required
def config_workspace_configuration_create_basic(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    context = {
        "workspace_id": workspace_id, "scope": request.form.get("scope", ""),
        "template": request.form.get("template", ""),
        "view": request.form.get("workspace_view", "network"),
        "section": request.form.get("config_section", ""),
        "operation": "create",
    }
    try:
        xml_bytes = workspace_config_path(workspace).read_bytes()
        variant = request.form.get("variant", "").strip()
        if variant:
            raw_updates = request.form.get("generic_updates", "[]")
            if len(raw_updates) > 262144:
                raise OfflineConfigError("Te veel velden voor één configuratie-item")
            updates = json.loads(raw_updates)
            if not isinstance(updates, list) or len(updates) > 512 or any(not isinstance(item, dict) for item in updates):
                raise OfflineConfigError("Ongeldige configuratievelden")
            new_xml = create_configuration_entry(
                xml_bytes, context["scope"], context["template"], context["view"],
                context["section"], variant, request.form.get("name", ""), updates,
            )
        else:
            if context["view"] != "network" or context["section"] not in {"interfaces", "zones"}:
                raise OfflineConfigError("Kies het type configuratie-item")
            new_xml = create_basic_network_entry(
                xml_bytes, context["scope"], context["template"],
                context["section"], request.form.get("name", ""),
                request.form.get("interface_type", "ethernet"), request.form.get("zone_type", "layer3"),
            )
        with db() as conn:
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)).fetchone()
        if not profile:
            raise OfflineConfigError("Het firewallprofiel bestaat niet meer")
        new_id = store_config_workspace(
            profile, f"{workspace['name']} · {context['view']} add {now()}", workspace["original_name"],
            new_xml, workspace_version_source(workspace), baseline_workspace=workspace,
        )
        if not advance_migration_staging_workspace(workspace["id"], new_id):
            advance_migration_output_workspace(workspace["id"], new_id, new_xml)
            set_active_config_workspace(workspace["profile_id"], new_id)
        audit("config-workspace-configuration-created", f"source={workspace_id} workspace={new_id} section={context['section']}")
        flash("Opgeslagen", "success")
        return _workspace_config_redirect(new_id, context)
    except Exception as exc:
        flash(f"Configuratie-item niet toegevoegd: {exc}", "error")
        return _workspace_config_redirect(workspace_id, context)


@app.post("/config-workspaces/<int:workspace_id>/configuration/preview")
@login_required
def config_workspace_configuration_preview(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    context = {
        "workspace_id": workspace_id, "scope": request.form.get("scope", ""),
        "template": request.form.get("template", ""),
        "view": request.form.get("workspace_view", "network"),
        "section": request.form.get("config_section", ""),
    }
    try:
        if context["view"] not in {"network", "device"}:
            raise OfflineConfigError("Ongeldige configuratieweergave")
        xml_bytes, parsed_root, snapshot = cached_workspace_config(workspace["config_path"], workspace["sha256"])
        _, records = scoped_configuration_records(
            xml_bytes, context["scope"], context["template"], context["view"], context["section"],
            parsed=(parsed_root, snapshot),
        )
        locator = request.form.get("locator", "")
        before = next((item for item in records if item["locator"] == locator), None)
        if before is None:
            raise OfflineConfigError("Het configuratie-item bestaat niet meer in deze context")
        try:
            submitted = json.loads(request.form.get("generic_updates", "[]"))
        except json.JSONDecodeError as exc:
            raise OfflineConfigError("Ongeldige configuratievelden") from exc
        allowed = {(field["path"], field["kind"]) for field in before["edit_fields"] if field["kind"] != "protected"}
        if not isinstance(submitted, list) or len(submitted) > 10000:
            raise OfflineConfigError("Ongeldige configuratievelden")
        updates = []
        for update in submitted:
            if not isinstance(update, dict) or (update.get("path"), update.get("kind")) not in allowed:
                raise OfflineConfigError("Een configuratieveld bestaat niet meer of is beschermd")
            clean = {"path": update["path"], "kind": update["kind"]}
            if update["kind"] == "members":
                values = update.get("values", [])
                if not isinstance(values, list) or len(values) > 10000:
                    raise OfflineConfigError("Ongeldige memberlijst")
                clean["values"] = [str(value).strip() for value in values if str(value).strip()]
            else:
                clean["value"] = str(update.get("value", ""))[:65535]
            updates.append(clean)
        name = request.form.get("name", "").strip() if before["is_entry"] else before["name"]
        if before["is_entry"] and not name:
            raise OfflineConfigError("Name is verplicht")
        operation = request.form.get("operation", "update")
        if operation not in {"update", "create"}:
            raise OfflineConfigError("Ongeldige configuratiebewerking")
        if operation == "create" and not before["is_entry"]:
            raise OfflineConfigError("Dit configuratieblok kan niet worden gedupliceerd")
        change = {
            "operation": operation, "locator": locator,
            "fingerprint": before["fingerprint"], "name": name, "updates": updates,
        }
        new_xml = apply_configuration_changes(xml_bytes, [change])
        if new_xml == normalized_config_xml(parsed_root):
            raise OfflineConfigError("Er zijn geen wijzigingen om te bewaren")
        if request.form.get("direct_save") == "yes":
            direct_context = {**context, "operation": operation}
            new_id = _store_workspace_configuration_version(workspace, direct_context, [change])
            flash("Opgeslagen", "success")
            return _workspace_config_redirect(new_id, direct_context)
        draft_id = secrets.token_urlsafe(24)
        draft = {**context, "operation": operation, "before": public_ui_record(before), "changes": [change], "created_at": now()}
        draft_path = OBJECT_DRAFTS / f"offline-config-{draft_id}.json"
        draft_path.write_text(json.dumps(draft)); draft_path.chmod(0o600)
        return render_template("workspace_config_preview.html", workspace=workspace, draft=draft, draft_id=draft_id)
    except Exception as exc:
        flash(f"Configuratiewijziging niet voorbereid: {exc}", "error")
        return _workspace_config_redirect(workspace_id, context)


@app.post("/config-workspaces/<int:workspace_id>/configuration/delete-preview")
@login_required
def config_workspace_configuration_delete_preview(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    context = {
        "workspace_id": workspace_id, "scope": request.form.get("scope", ""),
        "template": request.form.get("template", ""),
        "view": request.form.get("workspace_view", "network"),
        "section": request.form.get("config_section", ""),
    }
    try:
        xml_bytes, parsed_root, snapshot = cached_workspace_config(workspace["config_path"], workspace["sha256"])
        _, records = scoped_configuration_records(xml_bytes, context["scope"], context["template"], context["view"], context["section"], parsed=(parsed_root, snapshot))
        selected_locators = list(dict.fromkeys(request.form.getlist("locator")))
        selected = [item for item in records if item["locator"] in selected_locators and item["is_entry"]]
        if not selected_locators or len(selected) != len(selected_locators):
            raise OfflineConfigError("Selecteer minstens één benoemd configuratie-item")
        validate_workspace_configuration_deletions(xml_bytes, context["view"], context["section"], selected)
        changes = [{"operation": "delete", "locator": item["locator"], "fingerprint": item["fingerprint"]} for item in selected]
        if request.form.get("direct_save") == "yes":
            direct_context = {**context, "operation": "delete"}
            new_id = _store_workspace_configuration_version(workspace, direct_context, changes)
            flash("Geselecteerde configuratie-items rechtstreeks verwijderd in een nieuwe workspaceversie.", "success")
            return _workspace_config_redirect(new_id, direct_context)
        draft_id = secrets.token_urlsafe(24)
        draft = {**context, "operation": "delete", "before_items": [public_ui_record(item) for item in selected], "changes": changes, "created_at": now()}
        draft_path = OBJECT_DRAFTS / f"offline-config-{draft_id}.json"
        draft_path.write_text(json.dumps(draft)); draft_path.chmod(0o600)
        return render_template("workspace_config_preview.html", workspace=workspace, draft=draft, draft_id=draft_id)
    except Exception as exc:
        flash(f"Configuratie-items niet voorbereid voor verwijderen: {exc}", "error")
        return _workspace_config_redirect(workspace_id, context)


@app.post("/config-workspaces/configuration-drafts/<draft_id>/apply")
@login_required
def config_workspace_configuration_apply(draft_id):
    if not draft_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in draft_id):
        return "Not found", 404
    draft_path = OBJECT_DRAFTS / f"offline-config-{draft_id}.json"
    if not draft_path.is_file():
        return "Not found", 404
    draft = json.loads(draft_path.read_text())
    try:
        workspace = workspace_row(int(draft["workspace_id"]))
        if not workspace:
            raise OfflineConfigError("De bronworkspace bestaat niet meer")
        if draft.get("operation") == "delete":
            source_xml = workspace_config_path(workspace).read_bytes()
            validate_workspace_configuration_deletions(
                source_xml, draft.get("view", ""), draft.get("section", ""),
                draft.get("before_items", []),
            )
        new_id = _store_workspace_configuration_version(workspace, draft, draft["changes"])
        draft_path.unlink(missing_ok=True)
        flash("Opgeslagen", "success")
        return _workspace_config_redirect(new_id, draft)
    except Exception as exc:
        flash(f"Configuratiewijziging niet bewaard: {exc}", "error")
        return _workspace_config_redirect(int(draft.get("workspace_id", 0)), draft)


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
    error_redirect = (
        url_for("index", run_profile=profile_id) + "#runs"
        if request.form.get("return_to") == "runs"
        else url_for("index", policy_profile=profile_id) + "#policy-management"
    )
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
        expected_kind = "panorama" if profile["target_type"] == "panorama" else "panos"
        parsed_config = parse_snapshot(xml_bytes, expected_kind=expected_kind)
        discovered_vsys_count = None
        expected_vsys_count = None
        if profile["target_type"] == "panos":
            _, snapshot = parsed_config
            discovered_vsys_count = len(available_scopes(snapshot))
            saved_settings = profile_settings(profile)
            if saved_settings.get("vsys_mode") == "multi":
                expected_vsys_count = int(saved_settings.get("vsys_count") or 0)
        workspace_id = store_config_workspace(
            profile,
            request.form.get("name", "").strip() or f"{profile['name']} candidate {now()}",
            "api-candidate.xml",
            xml_bytes,
            "api",
            baseline_xml=xml_bytes,
            parsed_config=parsed_config,
        )
        set_active_config_workspace(profile_id, workspace_id)
        if discovered_vsys_count is None:
            message = "Volledige candidateconfiguratie via API opgehaald."
        elif expected_vsys_count and expected_vsys_count != discovered_vsys_count:
            message = (
                f"Volledige candidateconfiguratie via API opgehaald: "
                f"{discovered_vsys_count} VSYS gevonden, terwijl {expected_vsys_count} verwacht waren. "
                "De volledige config is behouden."
            )
        else:
            message = f"Volledige candidateconfiguratie via API opgehaald: {discovered_vsys_count} VSYS gevonden."
        flash(message, "success")
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id))
    except Exception as exc:
        flash(f"Volledige configuratie niet opgehaald: {exc}", "error")
        return redirect(error_redirect)


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


def migration_output_push_block(workspace_id: int):
    """Return the migration output and a reason when direct API load is unsafe."""
    with db() as conn:
        output = conn.execute(
            "SELECT migration_outputs.*,migration_projects.id project_id FROM migration_outputs "
            "JOIN migration_projects ON migration_projects.id=migration_outputs.project_id "
            "WHERE migration_outputs.workspace_id=? ORDER BY migration_outputs.id DESC LIMIT 1",
            (workspace_id,),
        ).fetchone()
        resolved_codes = {
            row["code"]
            for row in conn.execute(
                "SELECT code FROM migration_output_resolutions WHERE output_id=?",
                (output["id"],),
            ).fetchall()
        } if output else set()
    if not output:
        return None, ""
    sanity = json.loads(output["sanity_json"] or "{}")
    if sanity.get("regenerate_required"):
        return output, "Deze migratiecandidate is verouderd; maak eerst een nieuwe merge."
    if int(sanity.get("candidate_unresolved_references", sanity.get("unresolved_references", 0)) or 0) > 0:
        return output, "Deze migratiecandidate bevat nog onopgeloste referenties."
    critical_codes = sanity.get("critical_review_codes", {})
    if isinstance(critical_codes, dict) and set(critical_codes) - resolved_codes:
        return output, "Deze migratiecandidate bevat nog onbehandelde kritieke reviewpunten."
    if int(sanity.get("critical_findings", 0) or 0) > 0 and not critical_codes:
        return output, "Deze migratiecandidate bevat nog kritieke reviewpunten."
    return output, ""


def panos_management_invariants(xml_bytes: bytes) -> dict[str, object]:
    """Extract access-critical values from a complete PAN-OS configuration."""
    root = SafeET.fromstring(xml_bytes)
    device = root.find("./devices/entry")
    if device is None:
        raise MigrationError("PAN-OS configuratie bevat geen device-root")
    system = device.find("./deviceconfig/system")
    values = {}
    for path in (
        "ip-address", "netmask", "default-gateway", "hostname",
        "dns-setting/servers/primary", "dns-setting/servers/secondary",
    ):
        values[path] = (system.findtext(path) or "").strip() if system is not None else ""
    administrators = {}
    for entry in root.findall("./mgt-config/users/entry"):
        name = entry.get("name", "")
        if name:
            administrators[name] = (entry.findtext("phash") or entry.findtext("password") or "").strip()
    values["administrators"] = administrators
    return values


_PUSH_OBJECT_NODES = {
    "address": "Addresses", "address-group": "Address groups", "application": "Applications",
    "application-group": "Application groups", "application-filter": "Application filters",
    "service": "Services", "service-group": "Service groups", "tag": "Tags",
    "schedule": "Schedules", "region": "Regions", "external-list": "External dynamic lists",
}
_PUSH_POLICY_NODES = {
    "security": "Security policies", "nat": "NAT policies", "qos": "QoS policies",
    "pbf": "PBF policies", "decryption": "Decryption policies",
    "application-override": "Application override policies", "authentication": "Authentication policies",
    "tunnel-inspect": "Tunnel inspection policies", "dos": "DoS policies", "sdwan": "SD-WAN policies",
}
_PUSH_ENTRY_COLLECTIONS = set(_PUSH_OBJECT_NODES) | set(_PUSH_POLICY_NODES) | {
    "rules", "zone", "ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan",
    "virtual-router", "logical-router", "virtual-wire", "ipsec", "gre", "dhcp", "dns-proxy",
    "qos", "lldp", "server-profile", "log-settings", "syslog", "email", "snmptrap", "http", "server",
    "high-availability", "global-protect-portal",
    "global-protect-gateway", "authentication-profile", "authentication-sequence", "user-id-collector",
    "vm-info-source", "routing-profile", "profiles", "local-user-database", "admin-roles",
}
# Existing virtual-router entries can contain certificate material. Diff their
# children independently so route updates stay selectable without resending it.
_PUSH_NARROW_ENTRY_COLLECTIONS = {"virtual-router"}
_PANOS_RESPONSE_METADATA_ATTRIBUTES = frozenset({"admin", "dirtyId", "time"})


def config_push_family(path_parts: tuple[str, ...]) -> tuple[str, str]:
    """Map an XML path to a user-selectable push family and dependency rank."""
    parts = tuple(part.split("[", 1)[0] for part in path_parts)
    for index, part in enumerate(parts):
        if part in _PUSH_POLICY_NODES and any(p in {"rulebase", "pre-rulebase", "post-rulebase"} for p in parts[:index]):
            label = _PUSH_POLICY_NODES[part]
            return f"policy:{part}", label
    for index, part in enumerate(parts):
        if part in _PUSH_OBJECT_NODES and any(p in {"shared", "vsys", "device-group", "template"} for p in parts[:index]):
            label = _PUSH_OBJECT_NODES[part]
            return f"object:{part}", label
    if "deviceconfig" in parts:
        return "protected", "Device identity and management settings"
    if "network" in parts:
        section = parts[parts.index("network") + 1] if parts.index("network") + 1 < len(parts) else "network"
        return f"network:{section}", f"Network · {section.replace('-', ' ').title()}"
    for part in ("zone", "interface", "virtual-router", "logical-router", "ipsec", "global-protect"):
        if part in parts:
            return f"network:{part}", f"Network · {part.replace('-', ' ').title()}"
    if any(part in {"deviceconfig", "mgt-config", "high-availability", "server-profile", "log-settings", "authentication-profile", "authentication-sequence", "user-id-collector", "vm-info-source"} for part in parts):
        # Admin identities and authentication secrets must never be replaced by a stale snapshot.
        if "mgt-config" in parts or "users" in parts or "password" in parts or "phash" in parts:
            return "protected", "Protected access settings"
        section = next((part for part in reversed(parts) if part in {"deviceconfig", "high-availability", "server-profile", "log-settings", "authentication-profile", "authentication-sequence", "user-id-collector", "vm-info-source"}), "device")
        return f"device:{section}", f"Device · {section.replace('-', ' ').title()}"
    if "profiles" in parts:
        index = parts.index("profiles")
        section = parts[index + 1] if index + 1 < len(parts) else "profiles"
        return f"object:profile:{section}", f"Security profiles · {section.replace('-', ' ').title()}"
    top = next((part for part in parts if part not in {"config", "devices", "entry", "shared", "vsys", "device-group", "template", "config"}), "configuration")
    return f"other:{top}", f"Other · {top.replace('-', ' ').title()}"


def config_push_scope(xpath: str) -> str:
    """Return the PAN-OS location that owns an XPath change."""
    if re.search(r"/shared(?:/|$)", xpath):
        return "Shared"
    for node in ("device-group", "template-stack", "template", "vsys"):
        match = re.search(rf"/{re.escape(node)}/entry\[@name\s*=\s*", xpath)
        if not match:
            continue
        value_start = match.end()
        if value_start >= len(xpath):
            return "Scope"

        quote = xpath[value_start] if xpath[value_start] in "'\"" else None
        if quote:
            # PAN-OS API XPaths normally quote scope names. Find the matching
            # delimiter before accepting the closing predicate bracket, so a
            # quoted name containing `]` is not truncated.
            value_end = xpath.find(quote, value_start + 1)
            if value_end < 0:
                return "Scope"
            scope = xpath[value_start + 1:value_end]
            predicate_end = value_end + 1
            while predicate_end < len(xpath) and xpath[predicate_end].isspace():
                predicate_end += 1
            if predicate_end >= len(xpath) or xpath[predicate_end] != "]":
                return "Scope"
        else:
            # The reference index emits generated XPaths with raw @name values
            # (for example, entry[@name=vsys1]). Accept that internal form, but
            # reject predicate syntax that could make a partial value look like
            # a real scope. A closing bracket inside an unquoted name is
            # ambiguous and is rejected by checking the following delimiter.
            predicate_end = xpath.find("]", value_start)
            if predicate_end < 0:
                return "Scope"
            scope = xpath[value_start:predicate_end].strip()
            if not scope or any(char in scope for char in "[]'\"()="):
                return "Scope"

        if predicate_end + 1 < len(xpath) and xpath[predicate_end + 1] != "/":
            return "Scope"
        return scope or "Scope"
    return "Global"


def panos_scope_move_plan(
    current_xml: bytes, desired_xml: bytes, chosen: list[dict],
    object_type_by_node: dict[str, str],
) -> tuple[list[dict], set[tuple[str, str]]]:
    """Use PAN-OS multi-move for objects relocated between scopes.

    A set-then-delete sequence fails when policies still reference a local
    object. PAN-OS's native multi-move preserves those references while it
    relocates the entry. Use it only when the destination collection has no
    same-name entry. If the desired object differs, edit the relocated entry
    afterward; name collisions keep the guarded path.
    """
    selected_sets = [item for item in chosen if item["action"] == "set" and item["family"].startswith("object:")]
    selected_deletes = [item for item in chosen if item["action"] == "delete" and item["family"].startswith("object:")]
    source_records_cache: dict[tuple[str, str], dict[str, str]] = {}
    target_entries_cache: dict[int, dict[str, object]] = {}
    moves_by_target: dict[int, list[dict]] = defaultdict(list)
    consumed_deletes: set[int] = set()
    moved_names: set[tuple[str, str]] = set()
    safe_merge_ops: list[dict] = []
    shared_merge_contexts: dict[str, dict | None] = {}
    shared_merge_names: dict[str, set[str]] = defaultdict(set)
    for removal in selected_deletes:
        node = removal["family"].split(":", 1)[1]
        object_type = object_type_by_node.get(node)
        name = str(removal.get("name", ""))
        if object_type and name:
            shared_merge_names[object_type].add(name)
    parsed_snapshots_cache = None
    parsed_snapshots_attempted = False
    shared_reference_indexes_cache = None
    xml_paths_cache: dict[int, tuple[dict, dict, dict]] = {}
    used_names_cache: set[str] | None = None

    def entry_signature(node):
        return (
            node.tag,
            tuple(sorted((key, value) for key, value in node.attrib.items()
                         if key not in _PANOS_RESPONSE_METADATA_ATTRIBUTES)),
            (node.text or "").strip(),
            tuple(entry_signature(child) for child in list(node)),
        )

    def target_entries(change):
        cache_key = id(change)
        if cache_key not in target_entries_cache:
            try:
                wrapper = SafeET.fromstring(f"<fragment>{change.get('element', '')}</fragment>")
            except Exception as exc:
                raise OfflineConfigError("Objectverplaatsing bevat ongeldige XML; niets geschreven") from exc
            target_entries_cache[cache_key] = {node.get("name", ""): node for node in wrapper.findall("./entry")}
        return target_entries_cache[cache_key]

    def xml_paths(root):
        """Index unambiguous PAN-OS element paths for narrow temporary edits."""
        parent = {child: node for node in root.iter() for child in node}
        api_paths = {root: "/config"}
        reference_paths = {root: "/config"}
        for node in root.iter():
            if node is root:
                continue
            owner = parent.get(node)
            if owner is None:
                continue
            segment = node.tag
            reference_segment = node.tag
            if node.tag == "entry" and node.get("name") is not None:
                segment += f"[@name={policy_api.xpath_literal(node.get('name', ''))}]"
                # object_reference_index stores a compact, unquoted identity
                # path. Keep that representation separate from API-safe XPath.
                reference_segment += f"[@name={node.get('name', '')}]"
            api_paths[node] = f"{api_paths[owner]}/{segment}"
            reference_paths[node] = f"{reference_paths[owner]}/{reference_segment}"
        return api_paths, reference_paths, parent

    def parsed_snapshots():
        nonlocal parsed_snapshots_cache, parsed_snapshots_attempted
        if parsed_snapshots_attempted:
            return parsed_snapshots_cache
        parsed_snapshots_attempted = True
        try:
            parsed_snapshots_cache = (parse_snapshot(current_xml), parse_snapshot(desired_xml))
        except (OfflineConfigError, KeyError, TypeError, ValueError, ET.ParseError):
            parsed_snapshots_cache = None
        return parsed_snapshots_cache

    def cached_xml_paths(root):
        key = id(root)
        if key not in xml_paths_cache:
            xml_paths_cache[key] = xml_paths(root)
        return xml_paths_cache[key]

    def shared_reference_indexes(current_root):
        nonlocal shared_reference_indexes_cache
        if shared_reference_indexes_cache is None:
            shared_reference_indexes_cache = object_reference_indexes(
                current_xml, shared_merge_names, parsed_root=current_root,
            )
        return shared_reference_indexes_cache

    def used_names(current_root):
        nonlocal used_names_cache
        if used_names_cache is None:
            used_names_cache = {
                node.get("name", "") for node in current_root.iter("entry") if node.get("name")
            }
        return used_names_cache

    def shared_merge_context(object_type):
        """Build shared move indexes once per push, reusing parsed XML roots."""
        if object_type in shared_merge_contexts:
            return shared_merge_contexts[object_type]
        try:
            parsed_pair = parsed_snapshots()
            if parsed_pair is None:
                shared_merge_contexts[object_type] = None
                return None
            current_parsed, desired_parsed = parsed_pair
            current_root, current_snapshot = current_parsed
            desired_root, desired_snapshot = desired_parsed
            if current_snapshot.kind not in {"panos", "panorama"} or desired_snapshot.kind != current_snapshot.kind:
                shared_merge_contexts[object_type] = None
                return None
            names = sorted(shared_merge_names.get(object_type, ()))
            current_references = shared_reference_indexes(current_root).get(object_type, {})
            unresolved_references = unresolved_object_reference_index(
                desired_xml, object_type, names,
                parsed=desired_parsed, original_parsed=current_parsed,
            )
            refs, expressions = _typed_object_reference_nodes(current_root, object_type)
            refs_by_name: dict[str, list[ET.Element]] = defaultdict(list)
            for ref in (*refs, *expressions):
                value = (ref.text or "").strip()
                if value in current_references:
                    refs_by_name[value].append(ref)
            current_api_paths, current_reference_paths, parent = cached_xml_paths(current_root)
            desired_api_paths, _, _ = cached_xml_paths(desired_root)
            desired_by_path = {path: node for node, path in desired_api_paths.items()}
            scope_records: dict[tuple[str, str], list[dict]] = {}

            def records(version, scope):
                parsed = current_parsed if version == "current" else desired_parsed
                cache_key = (version, scope)
                if cache_key not in scope_records:
                    source_xml = current_xml if version == "current" else desired_xml
                    _, scope_records[cache_key] = scoped_objects(
                        source_xml, scope, object_type, parsed=parsed,
                    )
                return scope_records[cache_key]

            context = {
                "current_root": current_root,
                "current_snapshot": current_snapshot,
                "desired_root": desired_root,
                "desired_snapshot": desired_snapshot,
                "current_references": current_references,
                "unresolved_references": unresolved_references,
                "refs_by_name": refs_by_name,
                "current_api_paths": current_api_paths,
                "current_reference_paths": current_reference_paths,
                "desired_api_paths": desired_api_paths,
                "desired_by_path": desired_by_path,
                "parent": parent,
                "records": records,
                "used_names": used_names(current_root),
            }
            shared_merge_contexts[object_type] = context
            return context
        except (OfflineConfigError, KeyError, TypeError, ValueError, ET.ParseError):
            shared_merge_contexts[object_type] = None
            return None

    def existing_shared_merge(removal, object_type):
        """Plan a same-name local-to-Shared collapse without deleting live refs.

        When Shared already owns an equivalent object, PAN-OS cannot multi-move
        the local entry into that occupied name. Rename the local entry to a
        short-lived unique name, point its unchanged reference fields back at
        the equivalent Shared object, then delete the now-unused temporary
        entry. The final candidate keeps the original reference names.
        """
        name = str(removal.get("name", ""))
        source_scope = str(removal.get("scope", ""))
        if not name or source_scope == "Shared":
            return None
        # These definitions contain references to other scoped objects. Their
        # identical XML can resolve to different effective members after a
        # move to Shared, so keep the ordinary dependency guard in charge.
        if object_type in {
            "address-groups", "application-groups", "service-groups",
            "dynamic-user-groups", "security-profile-groups",
        }:
            return None
        try:
            context = shared_merge_context(object_type)
            if context is None:
                return None
            current_root = context["current_root"]
            current_snapshot = context["current_snapshot"]
            desired_root = context["desired_root"]
            desired_snapshot = context["desired_snapshot"]
            valid_scopes = (
                set(current_snapshot.vsys)
                if current_snapshot.kind == "panos"
                else {item["name"] for item in current_snapshot.device_groups}
            )
            desired_scopes = (
                set(desired_snapshot.vsys)
                if desired_snapshot.kind == "panos"
                else {item["name"] for item in desired_snapshot.device_groups}
            )
            if source_scope not in valid_scopes or source_scope not in desired_scopes:
                return None
            source_records = context["records"]("current", source_scope)
            shared_records = context["records"]("current", "Shared")
            desired_source_records = context["records"]("desired", source_scope)
            desired_shared_records = context["records"]("desired", "Shared")
            source = next((item for item in source_records if item.get("owner") == source_scope and item.get("name") == name), None)
            shared = next((item for item in shared_records if item.get("owner") == "Shared" and item.get("name") == name), None)
            desired_source = next((item for item in desired_source_records if item.get("owner") == source_scope and item.get("name") == name), None)
            desired_shared = next((item for item in desired_shared_records if item.get("owner") == "Shared" and item.get("name") == name), None)
            if not source or not shared or desired_source or not desired_shared:
                return None
            source_entry = SafeET.fromstring(source["_xml"])
            shared_entry = SafeET.fromstring(shared["_xml"])
            desired_shared_entry = SafeET.fromstring(desired_shared["_xml"])
            source_signature = _merge_object_signature(source_entry, object_type)
            if source_signature != _merge_object_signature(shared_entry, object_type):
                return None
            if source_signature != _merge_object_signature(desired_shared_entry, object_type):
                return None
            current_source_entry = _resolve_scoped_object_entry(
                current_root, current_snapshot, source_scope, object_type, name,
            )
            if current_source_entry is None:
                return None

            reference_inventory = context["current_references"].get(name, [])
            refs_by_name = context["refs_by_name"]
            all_paths = context["current_api_paths"]
            reference_paths = context["current_reference_paths"]
            parent = context["parent"]
            recognized_paths = set()
            source_fields = {}
            source_reference_scopes = set()
            for ref in refs_by_name.get(name, []):
                value = ref.text or ""
                if ref is not None and value.strip() == name:
                    ref_path = reference_paths.get(ref)
                    if ref_path:
                        recognized_paths.add(ref_path[:240])
                if value.strip() != name:
                    continue
                scope = _reference_scope(ref, parent, current_snapshot)
                device_path_monitor_reference = _is_panos_path_monitor_address_reference(
                    ref, parent, current_snapshot, object_type,
                )
                if scope != source_scope and not (scope is None and device_path_monitor_reference):
                    continue
                if not device_path_monitor_reference:
                    try:
                        resolved = _resolve_scoped_object_entry(current_root, current_snapshot, scope, object_type, name)
                    except OfflineConfigError:
                        return None
                    if resolved is not current_source_entry:
                        continue
                    source_reference_scopes.add(scope)
                field = ref if ref.tag != "member" else parent.get(ref)
                if field is None:
                    return None
                field_path = all_paths.get(field)
                if not field_path:
                    return None
                source_fields[field_path] = copy.deepcopy(field)

            if not reference_inventory or not source_fields:
                return None
            if set(reference_inventory) != recognized_paths:
                return None
            desired_shared_entry = _resolve_scoped_object_entry(
                desired_root, desired_snapshot, "Shared", object_type, name,
            )
            if desired_shared_entry is None:
                return None
            # Panorama resolves device-group references through parent groups
            # before Shared. Confirm every affected reference still resolves
            # to the intended Shared entry after the local definition leaves.
            for scope in source_reference_scopes:
                if _resolve_scoped_object_entry(
                    desired_root, desired_snapshot, scope, object_type, name,
                ) is not desired_shared_entry:
                    return None
            unresolved = context["unresolved_references"].get(name, [])
            if unresolved:
                return None

            desired_by_path = context["desired_by_path"]
            selected_policy_changes_by_path = {}
            selected_policy_deletions = []
            for change in chosen:
                if not change["family"].startswith("policy:"):
                    continue
                selected_policy_changes_by_path[change["xpath"]] = change
                if change["action"] == "delete":
                    selected_policy_deletions.append(change)

            def selected_policy_change_for_field(field_path):
                exact = selected_policy_changes_by_path.get(field_path)
                if exact is not None:
                    return exact
                # A selected policy deletion can remove the whole rule that
                # owns this field. Keep its current reference in place during
                # the object transaction; the selected delete runs afterward.
                return next((
                    change for change in selected_policy_deletions
                    if field_path.startswith(change["xpath"].rstrip("/") + "/")
                ), None)

            reference_fields_to_write = {}
            for field_path, field in source_fields.items():
                desired_field = desired_by_path.get(field_path)
                selected_policy_change = selected_policy_change_for_field(field_path)
                if selected_policy_change is not None and selected_policy_change["action"] == "delete":
                    # The current field still points at the original name.
                    # After the local entry is renamed, that name resolves to
                    # the equivalent Shared object until the selected delete.
                    continue
                if desired_field is not None and selected_policy_change is not None:
                    # Include a policy edit only when its scope/family is part
                    # of this push. The transaction then owns the field write,
                    # so the regular plan must not send it a second time.
                    reference_fields_to_write[field_path] = copy.deepcopy(desired_field)
                else:
                    # With no selected policy delta, preserve the live
                    # reference content while re-homing it to Shared. This
                    # prevents an object-only push from smuggling in unrelated
                    # policy edits from the workspace snapshot.
                    reference_fields_to_write[field_path] = field

            used_names = context["used_names"]
            temporary_name = f"PF_TMP_{secrets.token_hex(8)}"
            while temporary_name in used_names:
                temporary_name = f"PF_TMP_{secrets.token_hex(8)}"
            source_collection = removal["xpath"].rsplit("/entry[@name=", 1)[0]
            temporary_xpath = f"{source_collection}/entry[@name={policy_api.xpath_literal(temporary_name)}]"
            label = removal["label"]
            ops = [{
                "action": "rename", "xpath": removal["xpath"], "newname": temporary_name,
                "family": removal["family"], "label": label, "name": name,
            }]
            for field_path, field in reference_fields_to_write.items():
                operation = {
                    "action": "edit", "xpath": field_path,
                    "element": ET.tostring(field, encoding="unicode"),
                    "family": removal["family"], "label": label, "name": name,
                }
                selected_policy_change = selected_policy_change_for_field(field_path)
                desired_field = desired_by_path.get(field_path)
                if (
                    selected_policy_change is not None
                    and desired_field is not None
                    and ET.tostring(desired_field) != ET.tostring(source_fields[field_path])
                ):
                    operation["policy_change_path"] = field_path
                ops.append(operation)
            ops.append({
                "action": "delete", "xpath": temporary_xpath, "element": "",
                "family": removal["family"], "label": label, "name": name,
            })
            return ops
        except (OfflineConfigError, KeyError, TypeError, ValueError, ET.ParseError):
            return None

    def supports_native_scope(xpath):
        return "/shared/" in xpath or bool(re.search(r"/(?:vsys|device-group)/entry\[@name=", xpath))

    removal_counts = defaultdict(int)
    for item in selected_deletes:
        removal_counts[(item["family"], item.get("name", ""))] += 1

    for removal in selected_deletes:
        node = removal["family"].split(":", 1)[1]
        object_type = object_type_by_node.get(node)
        if not object_type or object_type not in PANOS_SCOPE_MOVE_OBJECT_TYPES:
            continue
        name = str(removal.get("name", ""))
        if not name:
            continue
        targets = [
            item for item in selected_sets
            if item["family"] == removal["family"] and item["scope"] != removal["scope"]
            and name in config_push_change_names(item)
        ]
        if not targets:
            merge_ops = existing_shared_merge(removal, object_type)
            if merge_ops:
                safe_merge_ops.extend(merge_ops)
                consumed_deletes.add(id(removal))
                moved_names.add((object_type, name))
                continue
        # Several VSYS can each contain a local duplicate of one Shared
        # object. Collapse each source scope transactionally before applying
        # the uniqueness guard used by ordinary native moves.
        if removal_counts[(removal["family"], name)] != 1:
            continue
        if len(targets) != 1:
            continue
        target = targets[0]
        target_entry = target_entries(target).get(name)
        if target_entry is None:
            continue
        source_xpath = removal["xpath"]
        source_collection_end = source_xpath.rfind("/entry[@name=")
        if source_collection_end <= 0:
            continue
        source_collection = source_xpath[:source_collection_end]
        if not supports_native_scope(source_collection) or not supports_native_scope(target["xpath"]):
            continue
        source_key = (removal["scope"], object_type)
        if source_key not in source_records_cache:
            try:
                _, records = scoped_objects(current_xml, removal["scope"], object_type)
            except Exception as exc:
                raise OfflineConfigError("Bronconfiguratie van objectverplaatsing is onleesbaar; niets geschreven") from exc
            source_records_cache[source_key] = {
                item["name"]: item["_xml"] for item in records if item.get("owner") == removal["scope"]
            }
        source_xml = source_records_cache[source_key].get(name)
        if not source_xml:
            continue
        try:
            source_entry = SafeET.fromstring(source_xml)
        except Exception as exc:
            raise OfflineConfigError("Bronobject van verplaatsing is onleesbaar; niets geschreven") from exc
        selected_list = ET.Element("selected-list")
        source = ET.SubElement(selected_list, "source", {"xpath": source_collection})
        ET.SubElement(source, "member").text = name
        all_errors = ET.Element("all-errors")
        all_errors.text = "no"
        # PAN-OS expects all-errors as a sibling of selected-list in the
        # multi-move element fragment, as shown in its XML API examples.
        move_element = (
            ET.tostring(selected_list, encoding="unicode")
            + ET.tostring(all_errors, encoding="unicode")
        )
        moves_by_target[id(target)].append({
            "action": "multi-move", "xpath": target["xpath"],
            "element": move_element,
            "family": removal["family"], "label": target["label"], "name": name,
            "scope": target["scope"],
        })
        if entry_signature(source_entry) != entry_signature(target_entry):
            # Moving preserves references; editing afterward applies the
            # desired contents without falling back to a reference-breaking delete.
            destination_entry_xpath = (
                f"{target['xpath']}/entry[@name={policy_api.xpath_literal(name)}]"
            )
            moves_by_target[id(target)].append({
                "action": "edit", "xpath": destination_entry_xpath,
                "element": ET.tostring(target_entry, encoding="unicode"),
                "family": removal["family"], "label": target["label"], "name": name,
                "scope": target["scope"],
            })
        consumed_deletes.add(id(removal))
        moved_names.add((object_type, name))

    # Apply each same-name Shared merge as one transactional XML API request.
    # PAN-OS rolls the batch back if one step fails, so a transient rename can
    # never strand the candidate between the rename and reference repair.
    write_plan = []
    embedded_policy_paths = {
        change["policy_change_path"] for change in safe_merge_ops
        if change.get("policy_change_path")
    }
    if safe_merge_ops:
        transaction = ET.Element("multi-config")
        for change in safe_merge_ops:
            attributes = {"xpath": change["xpath"]}
            if change.get("newname"):
                attributes["newname"] = change["newname"]
            action = ET.SubElement(transaction, change["action"], attributes)
            if change.get("element"):
                try:
                    element = SafeET.fromstring(f"<fragment>{change['element']}</fragment>")
                except Exception as exc:
                    raise OfflineConfigError("Shared-merge bevat ongeldige XML; niets geschreven") from exc
                action.extend(copy.deepcopy(list(element)))
        write_plan.append({
            "action": "multi-config", "xpath": "/config", "element": ET.tostring(transaction, encoding="unicode"),
            "family": safe_merge_ops[0]["family"], "label": "Shared object merge",
            "name": ", ".join(dict.fromkeys(change["name"] for change in safe_merge_ops)),
            "operation_count": len(safe_merge_ops),
        })
    for change in chosen:
        if change["family"].startswith("policy:") and change["xpath"] in embedded_policy_paths:
            continue
        move_ops = moves_by_target.get(id(change), [])
        if move_ops:
            write_plan.extend(move_ops)
            moved = {item["name"] for item in move_ops if item["action"] == "multi-move"}
            residual = [
                node for name, node in target_entries(change).items() if name not in moved
            ]
            if residual:
                residual_change = dict(change)
                residual_change["element"] = "".join(ET.tostring(node, encoding="unicode") for node in residual)
                residual_change["name"] = ", ".join(node.get("name", "") for node in residual)
                write_plan.append(residual_change)
            continue
        if id(change) not in consumed_deletes:
            write_plan.append(change)
    return write_plan, moved_names


def normalize_legacy_server_profile_paths(xml_bytes: bytes) -> bytes:
    """Move legacy workspace server profiles under PAN-OS log-settings paths."""
    root = SafeET.fromstring(xml_bytes)
    normalize_legacy_server_profile_root(root)
    return ET.tostring(root, encoding="utf-8")


def normalize_legacy_server_profile_root(root) -> None:
    """Normalize a parsed config root in place without reparsing its XML bytes."""
    profile_types = ("syslog", "email", "snmptrap", "http")
    for scope in list(root.iter()):
        legacy_profiles = scope.find("server-profile")
        if legacy_profiles is None:
            continue
        for profile_type in profile_types:
            legacy = legacy_profiles.find(profile_type)
            if legacy is None:
                continue
            log_settings = scope.find("log-settings")
            if log_settings is None:
                log_settings = ET.Element("log-settings")
                scope.append(log_settings)
            current = log_settings.find(profile_type)
            if current is None:
                legacy_profiles.remove(legacy)
                log_settings.append(legacy)
                continue
            for child in list(legacy):
                name = child.get("name") if child.tag == "entry" else None
                existing = next(
                    (item for item in list(current)
                     if name is not None and item.tag == "entry" and item.get("name") == name),
                    None,
                )
                if existing is not None:
                    position = list(current).index(existing)
                    current.remove(existing)
                    current.insert(position, child)
                else:
                    current.append(child)
            legacy_profiles.remove(legacy)
        if not list(legacy_profiles) and not (legacy_profiles.text or "").strip() and not legacy_profiles.attrib:
            scope.remove(legacy_profiles)


def merge_panos_candidate_xml(base_xml: bytes, desired_xml: bytes, current_xml: bytes) -> tuple[bytes, list[str]]:
    """Normalize PAN-OS response metadata and legacy XML aliases before rebasing."""
    return merge_config_xml(
        base_xml, desired_xml, current_xml,
        ignored_attributes=_PANOS_RESPONSE_METADATA_ATTRIBUTES,
        root_normalizer=normalize_legacy_server_profile_root,
    )


def config_push_delta(base_xml: bytes, desired_xml: bytes, desired_root=None) -> list[dict]:
    """Return exact candidate XML node changes; never constructs a whole-config load."""
    before_root = SafeET.fromstring(base_xml)
    # Cached roots are shared across requests, so normalize a private copy before diffing.
    after_root = copy.deepcopy(desired_root) if desired_root is not None else SafeET.fromstring(desired_xml)
    # PAN-OS adds these response-only attributes to config nodes returned by its
    # XML API. They are not part of the candidate configuration and otherwise
    # make the diff replace a whole device subtree, hiding selectable changes.
    for root in (before_root, after_root):
        for node in root.iter():
            for attribute in _PANOS_RESPONSE_METADATA_ATTRIBUTES:
                node.attrib.pop(attribute, None)
    normalize_legacy_server_profile_root(after_root)
    changes = []
    signature_cache: dict[ET.Element, tuple] = {}

    def node_key(node, ordinal):
        if node.tag == "entry" and node.get("name") is not None:
            return (node.tag, node.get("name"))
        return (node.tag, ordinal)

    def node_path(parent_path, node):
        if node.tag == "entry" and node.get("name") is not None:
            return f"{parent_path}/entry[@name={policy_api.xpath_literal(node.get('name', ''))}]"
        return f"{parent_path}/{node.tag}"

    def add(action, xpath, element, parts, protected_source=None):
        family, label = config_push_family(parts)
        source = element if element is not None else protected_source
        if source is not None and any(
            any(token in str(node.tag).casefold() for token in ("password", "phash", "secret", "private-key"))
            or str(node.tag).casefold() == "certificate"
            for node in source.iter()
        ):
            family, label = "protected", "Credential or certificate configuration"
        change_name = element.get("name", "") if element is not None else str(
            protected_source.get("name", "") if protected_source is not None else ""
        )
        changes.append({"action": action, "xpath": xpath, "element": ET.tostring(element, encoding="unicode") if element is not None else "",
                        "family": family, "label": label, "name": change_name or xpath.rsplit("/", 1)[-1]})

    def xml_content_signature(element):
        # Ignore indentation-only text between XML elements. ElementTree includes
        # an element's tail in tostring(), so appending a sibling can otherwise
        # make the preceding unchanged PAN-OS entry look edited.
        cached = signature_cache.get(element)
        if cached is not None:
            return cached
        value = (
            element.tag,
            tuple(sorted(element.attrib.items())),
            (element.text or "").strip(),
            tuple(xml_content_signature(child) for child in list(element)),
        )
        signature_cache[element] = value
        return value

    def is_admin_role_ui_metadata(xpath):
        # PAN-OS returns UI permission catalogs beneath admin-role entries with
        # inconsistent contents across candidate reads. These are role ACL metadata,
        # not device log settings or server profiles, and must never become push ops.
        return "/admin-role/" in xpath and any(
            marker in xpath
            for marker in (
                "/role/device/webui/device/log-settings",
                "/role/device/webui/device/server-profile",
            )
        )

    def walk(before, after, parent_path, parts):
        node = after if after is not None else before
        # PAN-OS exposes its system-owned predefined catalog in candidate XML,
        # but these entries are immutable through the configuration API. A
        # device/version-specific catalog difference must never become a write.
        if node is not None and (node.tag == "predefined" or "predefined" in parts):
            return
        if node is not None and is_admin_role_ui_metadata(node_path(parent_path, node)):
            return
        if before is None or after is None:
            node = after if after is not None else before
            parent_name = parent_path.rsplit("/", 1)[-1].split("[", 1)[0]
            if node.tag == "entry" and parent_name in {"devices", "vsys", "device-group", "template", "template-stack", "shared"}:
                changes.append({"action": "blocked", "xpath": node_path(parent_path, node), "element": "",
                                "family": "protected", "label": "Structural scopes (not supported)",
                                "name": node.get("name", "scope")})
                return
            if node.tag == "entry" and parent_name in _PUSH_ENTRY_COLLECTIONS:
                add("set" if before is None else "delete", parent_path if before is None else node_path(parent_path, node),
                    node if before is None else None, parts + (node.tag,), protected_source=before)
                return
            if list(node):
                # Descend through containers so deleting a missing stale subtree does
                # not replace/delete a whole VSYS, device group, or object collection.
                for index, child in enumerate(list(node)):
                    walk(None if before is None else child, child if after is not None else None,
                         node_path(parent_path, node), parts + (node.tag,))
                return
            path = node_path(parent_path, node)
            if before is None:
                add("set", parent_path, after, parts + (after.tag,))
            else:
                add("delete", path, None, parts + (before.tag,), protected_source=before)
            return
        here_parts = parts + (after.tag,)
        parent_name = parent_path.rsplit("/", 1)[-1].split("[", 1)[0]
        if before.tag == "entry" and parent_name in _PUSH_ENTRY_COLLECTIONS:
            if xml_content_signature(before) != xml_content_signature(after):
                # Replacing a complete policy entry can undo unrelated edits
                # made on the firewall after this workspace was pulled. Walk
                # into the entry so scalar changes become narrow set requests
                # and repeated-list changes stay confined to their own field.
                if (
                    parent_name in _PUSH_POLICY_NODES
                    or parent_name == "rules"
                    or parent_name in _PUSH_NARROW_ENTRY_COLLECTIONS
                ):
                    before_children = {child.tag: child for child in list(before)}
                    after_children = {child.tag: child for child in list(after)}
                    for tag in dict.fromkeys((*before_children, *after_children)):
                        walk(
                            before_children.get(tag), after_children.get(tag),
                            node_path(parent_path, after), here_parts,
                        )
                else:
                    add("edit", node_path(parent_path, after), after, here_parts, protected_source=before)
            return
        # PAN-OS API XML and workspace XML use different indentation. Container
        # whitespace is formatting, not a configuration edit; comparing it raw
        # can collapse a multi-VSYS change into one protected /config/devices edit.
        if (before.text or "").strip() != (after.text or "").strip() or before.attrib != after.attrib:
            # Keep repeated-list writes scoped to their field container; targeting
            # the parent rule could affect unrelated attributes and sibling fields.
            if "rules" in parts and any(part in _PUSH_POLICY_NODES for part in parts):
                # PAN-OS supports setting individual rule fields at the rule
                # XPath. This leaves every sibling field untouched.
                add("set", parent_path, after, here_parts)
            else:
                add("edit", node_path(parent_path, after), after, here_parts)
            return
        before_children, after_children = list(before), list(after)
        before_counts, after_counts = {}, {}
        for child in before_children: before_counts[child.tag] = before_counts.get(child.tag, 0) + 1
        for child in after_children: after_counts[child.tag] = after_counts.get(child.tag, 0) + 1
        policy_member_list = (
            "rules" in parts
            and any(part in _PUSH_POLICY_NODES for part in parts)
            and before_children
            and after_children
            and all(child.tag == "member" for child in (*before_children, *after_children))
        )
        if policy_member_list:
            # PAN-OS `set` appends members at an existing list XPath. Sending a
            # changed member there can leave an old wildcard such as `any` next
            # to the new value. Replace this one policy field as a whole so the
            # API receives the complete desired list and sibling rule fields stay
            # untouched.
            if xml_content_signature(before) != xml_content_signature(after):
                add("edit", node_path(parent_path, after), after, here_parts, protected_source=before)
            return
        named_entries = bool(before_children or after_children) and all(
            child.tag == "entry" and child.get("name") for child in (*before_children, *after_children)
        )
        if named_entries:
            before_order = [child.get("name") for child in before_children]
            after_order = [child.get("name") for child in after_children]
            before_map = {child.get("name"): child for child in before_children}
            after_map = {child.get("name"): child for child in after_children}
            for name in dict.fromkeys((*before_map.keys(), *after_map.keys())):
                left, right = before_map.get(name), after_map.get(name)
                walk(left, right, node_path(parent_path, after), here_parts)
            if after.tag == "rules" and before_order != after_order:
                after_names = set(after_order)
                simulated_order = [name for name in before_order if name in after_names]
                simulated_order.extend(name for name in after_order if name not in before_map)
                unchanged = set()
                for block in SequenceMatcher(None, simulated_order, after_order, autojunk=False).get_matching_blocks():
                    unchanged.update(after_order[block.b:block.b + block.size])
                previous_name = None
                for position, name in enumerate(after_order):
                    if name not in unchanged:
                        entry_path = f"{node_path(parent_path, after)}/entry[@name={policy_api.xpath_literal(name)}]"
                        family, label = config_push_family(here_parts)
                        change = {"action": "move", "xpath": entry_path, "element": "", "family": family,
                                   "label": label, "name": name, "where": "top" if previous_name is None else "after", "order_index": position}
                        if previous_name is not None:
                            change["dst"] = f"{node_path(parent_path, after)}/entry[@name={policy_api.xpath_literal(previous_name)}]"
                        changes.append(change)
                    previous_name = name
            return
        if any(count > 1 for count in (*before_counts.values(), *after_counts.values())):
            if xml_content_signature(before) != xml_content_signature(after):
                add("edit", node_path(parent_path, after), after, here_parts, protected_source=before)
            return
        before_map = {node_key(node, index): node for index, node in enumerate(before_children)}
        after_map = {node_key(node, index): node for index, node in enumerate(after_children)}
        for key in dict.fromkeys((*before_map.keys(), *after_map.keys())):
            left, right = before_map.get(key), after_map.get(key)
            walk(left, right, node_path(parent_path, after), here_parts)

    # Root node is fixed at /config. Start with direct children to keep API XPaths rooted correctly.
    before_children = {child.tag: child for child in list(before_root)}
    after_children = {child.tag: child for child in list(after_root)}
    for tag in dict.fromkeys((*before_children.keys(), *after_children.keys())):
        walk(before_children.get(tag), after_children.get(tag), "/config", ("config",))
    # A set request can carry several sibling fields (or entries) in one XML
    # fragment. Coalesce compatible writes at the same XPath to avoid one API
    # round-trip per changed field while retaining narrow edit/delete paths.
    coalesced = []
    set_by_path = {}
    for change in changes:
        if change["action"] != "set":
            coalesced.append(change)
            continue
        key = (change["xpath"], change["family"], change["label"])
        existing = set_by_path.get(key)
        if existing is None:
            set_by_path[key] = change
            coalesced.append(change)
        else:
            existing["element"] += change["element"]
    changes = coalesced
    # Keep same-named families separate by owner. A Shared object is a different
    # API write target from an identically named object inside a VSYS.
    for change in changes:
        change["scope"] = config_push_scope(change["xpath"])
        change["selection_key"] = json.dumps(
            [change["scope"], change["family"]], ensure_ascii=False, separators=(",", ":")
        )
    # Prerequisites first; removals in reverse order so consumers go before dependencies.
    rank = {"object": 10, "network": 20, "device": 30, "other": 35, "policy": 40}
    for change in changes:
        prefix = change["family"].split(":", 1)[0]
        change["rank"] = rank.get(prefix, 35)
    return sorted(changes, key=lambda item: (
        1 if item["action"] == "move" else 0,
        item.get("order_index", 0) if item["action"] == "move" else (item["rank"] if item["action"] != "delete" else 100-item["rank"]),
        item["family"], item["name"],
    ))


def config_push_change_names(change: dict) -> list[str]:
    """Return every named entry carried by a coalesced config API write."""
    names = []
    element = str(change.get("element", ""))
    if element:
        try:
            fragment = SafeET.fromstring(f"<fragment>{element}</fragment>")
        except Exception as exc:
            raise OfflineConfigError("Een gebundelde API-wijziging bevat ongeldige XML; niets geschreven") from exc
        entries = list(fragment.findall("./entry"))
        if fragment.tag == "entry":
            entries = [fragment]
        names.extend(entry.get("name", "") for entry in entries if entry.get("name"))
    if not names and change.get("name"):
        names.append(str(change["name"]))
    return list(dict.fromkeys(names))


def fetch_panos_candidate_xml(profile) -> tuple[str, str, object, bytes]:
    _, endpoint, key, ctx = panos_profile_context(profile)
    root = policy_api.require_success(
        panos_api_post(endpoint, {"type": "config", "action": "get", "xpath": "/config", "key": key}, ctx),
        "candidateconfiguratie ophalen",
    )
    config = root.find("./result/config")
    if config is None:
        raise RuntimeError("Target gaf geen candidateconfiguratie terug")
    return endpoint, key, ctx, normalized_config_xml(config)


def fetch_panos_candidate_xml_for_preview(profile) -> tuple[bytes, bool]:
    """Reuse a very recent read for previews; push requests always fetch live XML."""
    cache_key = (int(profile["id"]), str(profile["updated_at"]))
    now_monotonic = time.monotonic()
    with _candidate_preview_cache_lock:
        generation = _candidate_preview_cache_generation
        cached = _candidate_preview_cache.get(cache_key)
        if cached and cached[0] > now_monotonic:
            return cached[1], True
        _candidate_preview_cache.pop(cache_key, None)

    _, _, _, candidate_xml = fetch_panos_candidate_xml(profile)
    if len(candidate_xml) <= CANDIDATE_PREVIEW_CACHE_MAX_BYTES:
        expires_at = time.monotonic() + CANDIDATE_PREVIEW_CACHE_TTL_SECONDS
        with _candidate_preview_cache_lock:
            if _candidate_preview_cache_generation == generation:
                if cache_key not in _candidate_preview_cache and len(_candidate_preview_cache) >= CANDIDATE_PREVIEW_CACHE_MAX_ENTRIES:
                    oldest_key = min(_candidate_preview_cache, key=lambda key: _candidate_preview_cache[key][0])
                    _candidate_preview_cache.pop(oldest_key, None)
                _candidate_preview_cache[cache_key] = (expires_at, candidate_xml)
    return candidate_xml, False


def invalidate_candidate_preview_cache(profile_id: int) -> None:
    """Discard cached candidates after this app starts changing a target."""
    global _candidate_preview_cache_generation
    with _candidate_preview_cache_lock:
        profile_id = int(profile_id)
        _candidate_preview_cache_generation += 1
        for cache_key in [key for key in _candidate_preview_cache if key[0] == profile_id]:
            _candidate_preview_cache.pop(cache_key, None)


def wait_panos_job(endpoint: str, key: str, ctx, job_id: str, timeout: int = 300) -> dict[str, object]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        root = policy_api.require_success(
            panos_api_post(endpoint, {
                "type": "op", "cmd": f"<show><jobs><id>{html.escape(job_id)}</id></jobs></show>", "key": key,
            }, ctx),
            f"PAN-OS job {job_id} ophalen",
        )
        job = root.find(".//job")
        if job is not None and (job.findtext("status") or "") == "FIN":
            details = [value.strip() for value in job.itertext() if value.strip()]
            return {
                "status": "FIN", "result": job.findtext("result") or "",
                "progress": job.findtext("progress") or "", "details": details[-100:],
            }
        time.sleep(2)
    raise TimeoutError(f"PAN-OS job {job_id} duurde langer dan {timeout} seconden")


PANOS_COMMIT_POLL_INTERVAL_SECONDS = 60
PANOS_TERMINAL_JOB_STATES = {"FIN", "FAIL", "ERROR", "CANCEL", "CANCELLED"}


def config_workspace_commit_payload(row, retry_after: int = 0) -> dict[str, object]:
    status = str(row["status"] or "UNKNOWN").upper()
    result = str(row["result"] or "").upper()
    terminal = status in PANOS_TERMINAL_JOB_STATES or status == "FIN" or (status == "UNKNOWN" and not row["job_id"])
    if status == "FIN" and result == "NO_CHANGES":
        label = "Geen wijzigingen om te committen"
    elif status == "FIN" and result == "OK":
        label = "Commit geslaagd"
    elif status in PANOS_TERMINAL_JOB_STATES or (status == "FIN" and result != "OK"):
        label = "Commit mislukt"
    elif status == "ACT":
        label = f"Commit bezig ({row['progress']}%)" if row["progress"] is not None else "Commit bezig"
    elif status == "PEND":
        label = "Commit staat in de wachtrij"
    elif status == "SUBMITTING":
        label = "Commit wordt gestart"
    else:
        label = "Commitstatus onbekend"
    try:
        details = json.loads(row["details_json"] or "[]")
    except (TypeError, json.JSONDecodeError):
        details = []
    if not isinstance(details, list):
        details = []
    return {
        "job_id": row["job_id"],
        "status": status,
        "result": result,
        "progress": row["progress"],
        "label": label,
        "terminal": terminal,
        "details": [str(item)[:500] for item in details[:16]],
        "error": str(row["last_error"] or "")[:500],
        "retry_after": max(0, int(retry_after)),
    }


def panos_commit_job_details(job: ET.Element) -> list[str]:
    details = []
    for path in ("./warnings/line", "./details/line"):
        details.extend((item.text or "").strip() for item in job.findall(path))
    plain_details = (job.findtext("./details") or "").strip()
    if plain_details:
        details.append(plain_details)
    return [item[:500] for item in details if item][:16]


def audit_workspace_commit(action: str, detail: str) -> None:
    try:
        audit(action, detail)
    except Exception:
        # Never turn an already-submitted firewall commit into an apparent failure
        # just because the local audit write had a transient database error.
        app.logger.exception("Failed to write incremental commit audit event")


@app.route("/profiles/<int:profile_id>/tls-certificate", methods=["GET", "POST"])
@login_required
def panos_certificate_review(profile_id):
    """Inspect and explicitly trust a PAN-OS/Panorama endpoint certificate."""
    with db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE id=? AND system=0", (profile_id,)).fetchone()
    if not profile:
        return "Not found", 404
    if profile["target_type"] not in {"panos", "panorama"}:
        flash("Certificaatuitzonderingen gelden alleen voor PAN-OS en Panorama.", "error")
        return redirect(url_for("index", edit_profile=profile_id) + "#profiles")

    return_workspace_id = request.values.get("return_workspace_id", type=int)
    if return_workspace_id:
        with db() as conn:
            matching_workspace = conn.execute(
                "SELECT id FROM config_workspaces WHERE id=? AND profile_id=?",
                (return_workspace_id, profile_id),
            ).fetchone()
        if not matching_workspace:
            return_workspace_id = None

    settings = json.loads(profile["settings_json"] or "{}")
    try:
        endpoint = validate_panos_endpoint(settings.get("endpoint", ""))
    except ValueError as exc:
        flash(f"Het firewallendpoint is ongeldig: {exc}", "error")
        return redirect(url_for("index", edit_profile=profile_id) + "#profiles")
    if not endpoint:
        flash("Sla eerst een HTTPS-endpoint op in het firewallprofiel.", "error")
        return redirect(url_for("index", edit_profile=profile_id) + "#profiles")

    old_fingerprint = settings.get("tls_pinned_fingerprint", "")
    old_endpoint = settings.get("tls_pinned_endpoint", "")
    old_certificate = settings.get("tls_pinned_certificate", "") if old_endpoint == endpoint else ""
    if request.method == "POST" and request.form.get("remove_pin") == "yes":
        for key in (
            "tls_pinned_certificate",
            "tls_pinned_fingerprint",
            "tls_pinned_endpoint",
            "tls_allow_hostname_mismatch",
        ):
            settings.pop(key, None)
        with db() as conn:
            updated = conn.execute(
                "UPDATE profiles SET settings_json=?,updated_at=? "
                "WHERE id=? AND settings_json=? AND updated_at=?",
                (json.dumps(settings), now(), profile_id, profile["settings_json"], profile["updated_at"]),
            )
        if updated.rowcount != 1:
            flash("Het profiel is intussen gewijzigd. Herlaad de certificaatcontrole en probeer opnieuw.", "error")
        else:
            invalidate_profile_caches(profile_id)
            audit("panos-certificate-pin-removed", f"profile={profile['name']}")
            flash("De certificaatpin is verwijderd. Volgende verbindingen gebruiken opnieuw de ingestelde CA-vertrouwensketen.", "success")
        return redirect(url_for(
            "panos_certificate_review",
            profile_id=profile_id,
            return_workspace_id=return_workspace_id,
        ))

    try:
        current = inspect_panos_certificate(
            endpoint,
            context=create_panos_ssl_context(
                pinned_certificate=old_certificate or None,
                allow_pinned_hostname_mismatch=bool(settings.get("tls_allow_hostname_mismatch", False)),
            ),
        )
        current["verified_by_profile_pin"] = bool(
            old_certificate
            and current["fingerprint"] == old_fingerprint
            and old_endpoint == endpoint
        )
        if request.method == "POST":
            submitted_fingerprint = request.form.get("fingerprint", "").strip().upper()
            if submitted_fingerprint != current["fingerprint"]:
                flash("Het certificaat veranderde tijdens de controle. Vergelijk de nieuwe gegevens opnieuw.", "error")
            elif current["verified_by_current_policy"]:
                flash("Dit certificaat wordt al vertrouwd; er is geen uitzondering nodig.", "success")
            elif not current["valid_now"]:
                flash("Dit certificaat is verlopen of nog niet geldig. Het kan niet worden vertrouwd.", "error")
            elif not current["hostname_matches"] and request.form.get("accept_hostname_mismatch") != "yes":
                flash("De endpointnaam staat niet in de SAN van dit certificaat. Herstel de endpoint/certificaatnaam; vertrouw deze mismatch niet.", "error")
            elif current["is_ca_certificate"]:
                flash("Dit is een CA-certificaat, geen endpointcertificaat. Configureer de CA-bundel in plaats van dit certificaat vast te pinnen.", "error")
            else:
                settings.update({
                    "tls_pinned_certificate": current["pem"],
                    "tls_pinned_fingerprint": current["fingerprint"],
                    "tls_pinned_endpoint": endpoint,
                    "tls_allow_hostname_mismatch": not current["hostname_matches"],
                })
                with db() as conn:
                    updated = conn.execute(
                        "UPDATE profiles SET settings_json=?,updated_at=? "
                        "WHERE id=? AND settings_json=? AND updated_at=?",
                        (json.dumps(settings), now(), profile_id, profile["settings_json"], profile["updated_at"]),
                    )
                if updated.rowcount != 1:
                    flash("Het profiel is intussen gewijzigd. Herlaad de certificaatcontrole en vergelijk opnieuw.", "error")
                else:
                    invalidate_profile_caches(profile_id)
                    audit("panos-certificate-pinned", f"profile={profile['name']}")
                    flash("Certificaatfingerprint voor dit endpoint opgeslagen. De volgende API-verbinding blijft de geldigheid en dit certificaat controleren.", "success")
                    old_fingerprint = current["fingerprint"]
                    old_endpoint = endpoint
                    if return_workspace_id:
                        return redirect(url_for("config_workspace_push_preview", workspace_id=return_workspace_id))
    except Exception as exc:
        current = None
        flash(f"Certificaat kon niet worden opgehaald: {exc}", "error")

    return render_template(
        "panos_certificate_review.html",
        profile=profile,
        endpoint=endpoint,
        current=current,
        old_fingerprint=old_fingerprint,
        old_endpoint=old_endpoint,
        return_workspace_id=return_workspace_id,
    )


@app.get("/config-workspaces/<int:workspace_id>/push-preview")
@login_required
def config_workspace_push_preview(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    output, block_reason = migration_output_push_block(workspace_id)
    if int(workspace["profile_system"] or 0):
        flash("Koppel eerst een push target aan het migratieproject.", "error")
        return redirect(url_for("migration_project", project_id=output["project_id"])) if output else redirect(url_for("migration_home"))
    if block_reason:
        flash(f"Incremental push geblokkeerd: {block_reason}", "error")
        return redirect(url_for("migration_project", project_id=output["project_id"]))
    try:
        preview_started = time.perf_counter()
        with db() as conn:
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)).fetchone()
        if not profile or profile["target_type"] not in {"panorama", "panos"}:
            raise RuntimeError("Dit target gebruikt geen PAN-OS XML API")
        expected_kind = "panorama" if profile["target_type"] == "panorama" else "panos"
        phase_started = time.perf_counter()
        desired, desired_root, desired_snapshot = cached_workspace_config(workspace["config_path"], workspace["sha256"])
        if desired_snapshot.kind != expected_kind:
            label = "Panorama" if expected_kind == "panorama" else "standalone firewall"
            raise OfflineConfigError(f"Deze configuratie lijkt niet afkomstig van het gekozen {label}-profiel")
        workspace_parse_ms = (time.perf_counter() - phase_started) * 1000
        phase_started = time.perf_counter()
        baseline = require_workspace_baseline(workspace)
        current, candidate_cache_hit = fetch_panos_candidate_xml_for_preview(profile)
        candidate_fetch_ms = (time.perf_counter() - phase_started) * 1000
        phase_started = time.perf_counter()
        merge_conflicts = []
        push_desired, merge_conflicts = merge_panos_candidate_xml(baseline, desired, current)
        rebase_applied = snapshot_sha256(current) != snapshot_sha256(baseline)
        changes = [] if merge_conflicts else config_push_delta(current, push_desired)
        delta_ms = (time.perf_counter() - phase_started) * 1000
        families = {}
        for item in changes:
            row = families.setdefault(item["selection_key"], {
                "key": item["selection_key"], "scope": item["scope"],
                "family": item["family"],
                "label": item["label"],
                "count": 0, "names": [],
            })
            row["count"] += 1
            if item["name"] and item["name"] not in row["names"] and len(row["names"]) < 8:
                row["names"].append(item["name"])
        families = sorted(families.values(), key=lambda item: (item["scope"].casefold(), item["label"].casefold(), item["key"]))
        selectable_change_count = sum(
            item["count"] for item in families if item["family"] != "protected"
        )
        with db() as conn:
            latest_commit = conn.execute(
                "SELECT id,job_id,status,result,submitted_at FROM config_workspace_commits "
                "WHERE workspace_id=? ORDER BY id DESC LIMIT 1",
                (workspace_id,),
            ).fetchone()
        app.logger.info(
            "Incremental push preview timing workspace_id=%s desired_bytes=%s workspace_parse_ms=%.1f "
            "candidate_fetch_ms=%.1f candidate_cache_hit=%s candidate_bytes=%s delta_ms=%.1f "
            "change_count=%s total_ms=%.1f",
            workspace_id, len(desired), workspace_parse_ms, candidate_fetch_ms, candidate_cache_hit,
            len(current), delta_ms, len(changes), (time.perf_counter() - preview_started) * 1000,
        )
        return render_template(
            "config_workspace_push_preview.html", workspace=workspace, profile=profile,
            families=families, change_count=len(changes), candidate_sha256=hashlib.sha256(current).hexdigest(),
            latest_commit=latest_commit, selectable_change_count=selectable_change_count,
            merge_conflicts=merge_conflicts, rebase_applied=rebase_applied,
            merge_enabled=True,
        )
    except Exception as exc:
        if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, ssl.SSLCertVerificationError):
            flash(
                "Push-preview niet gemaakt: het PAN-OS-certificaat wordt niet vertrouwd of is gewijzigd. "
                "Controleer de fingerprint en bevestig alleen een verwachte wijziging.",
                "error",
            )
            return redirect(url_for(
                "panos_certificate_review",
                profile_id=profile["id"],
                return_workspace_id=workspace_id,
            ))
        else:
            flash(f"Push-preview niet gemaakt: {exc}", "error")
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id))


def config_workspace_commit_row(workspace_id: int, commit_id: int):
    with db() as conn:
        return conn.execute(
            "SELECT * FROM config_workspace_commits WHERE id=? AND workspace_id=?",
            (commit_id, workspace_id),
        ).fetchone()


@app.get("/config-workspaces/<int:workspace_id>/commits/<int:commit_id>")
@login_required
def config_workspace_commit_status(workspace_id: int, commit_id: int):
    workspace = workspace_row(workspace_id)
    commit = config_workspace_commit_row(workspace_id, commit_id)
    if not workspace or not commit or int(commit["profile_id"]) != int(workspace["profile_id"]):
        return "Not found", 404
    profile = {"name": workspace["profile_name"], "target_type": commit["target_type"]}
    return render_template(
        "config_workspace_commit_status.html",
        workspace=workspace,
        profile=profile,
        commit=commit,
        status=config_workspace_commit_payload(commit),
        status_url=url_for("config_workspace_commit_status_api", workspace_id=workspace_id, commit_id=commit_id),
    )


@app.get("/config-workspaces/<int:workspace_id>/commits/<int:commit_id>/status")
@login_required
def config_workspace_commit_status_api(workspace_id: int, commit_id: int):
    workspace = workspace_row(workspace_id)
    commit = config_workspace_commit_row(workspace_id, commit_id)
    if not workspace or not commit or int(commit["profile_id"]) != int(workspace["profile_id"]):
        return {"error": "Not found"}, 404

    if not commit["job_id"] or config_workspace_commit_payload(commit)["terminal"]:
        return config_workspace_commit_payload(commit)

    checked_at = time.time()
    retry_after = max(0, math.ceil(PANOS_COMMIT_POLL_INTERVAL_SECONDS - (checked_at - float(commit["last_checked_at"] or 0))))
    if retry_after:
        return config_workspace_commit_payload(commit, retry_after=retry_after)

    with db() as conn:
        claimed = conn.execute(
            "UPDATE config_workspace_commits SET last_checked_at=? WHERE id=? AND workspace_id=? "
            "AND last_checked_at<=?",
            (checked_at, commit_id, workspace_id, checked_at - PANOS_COMMIT_POLL_INTERVAL_SECONDS),
        ).rowcount
        commit = conn.execute(
            "SELECT * FROM config_workspace_commits WHERE id=? AND workspace_id=?",
            (commit_id, workspace_id),
        ).fetchone()
    if not claimed:
        remaining = max(1, math.ceil(PANOS_COMMIT_POLL_INTERVAL_SECONDS - (time.time() - float(commit["last_checked_at"] or 0))))
        return config_workspace_commit_payload(commit, retry_after=remaining)

    try:
        if not re.fullmatch(r"[0-9]{1,12}", str(commit["job_id"])):
            raise ValueError("PAN-OS gaf geen geldig commit-jobnummer terug")
        with db() as conn:
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (commit["profile_id"],)).fetchone()
        if not profile or profile["target_type"] != commit["target_type"] or profile["target_type"] not in {"panos", "panorama"}:
            raise ValueError("Het push target is gewijzigd; commitstatus wordt niet op een ander target opgevraagd")
        settings = json.loads(profile["settings_json"] or "{}")
        endpoint = validate_panos_endpoint(settings.get("endpoint", ""))
        endpoint_hash = hashlib.sha256(endpoint.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(endpoint_hash, commit["target_endpoint_sha256"]):
            raise ValueError("Het firewallendpoint is gewijzigd; commitstatus wordt niet op een ander target opgevraagd")
        _, endpoint, key, ctx = panos_profile_context(profile)
        root = policy_api.require_success(
            panos_api_post(endpoint, {
                "type": "op", "cmd": f"<show><jobs><id>{commit['job_id']}</id></jobs></show>", "key": key,
            }, ctx),
            f"PAN-OS commitjob {commit['job_id']} ophalen",
        )
        job = root.find(".//job")
        if job is None:
            raise RuntimeError("PAN-OS gaf geen commitjobstatus terug")
        status = (job.findtext("status") or "UNKNOWN").strip().upper()
        if not re.fullmatch(r"[A-Z_]{1,16}", status):
            status = "UNKNOWN"
        result = (job.findtext("result") or "").strip().upper()[:32]
        progress_text = (job.findtext("progress") or "").strip()
        progress = int(progress_text) if progress_text.isdigit() and int(progress_text) <= 100 else None
        details = panos_commit_job_details(job)
        with db() as conn:
            conn.execute(
                "UPDATE config_workspace_commits SET status=?,result=?,progress=?,details_json=?,last_error='' "
                "WHERE id=? AND workspace_id=?",
                (status, result, progress, json.dumps(details, ensure_ascii=False), commit_id, workspace_id),
            )
            updated = conn.execute(
                "SELECT * FROM config_workspace_commits WHERE id=? AND workspace_id=?",
                (commit_id, workspace_id),
            ).fetchone()
        if status in PANOS_TERMINAL_JOB_STATES or (status == "FIN" and result != "OK"):
            audit_workspace_commit(
                "config-workspace-incremental-commit-finished",
                f"workspace={workspace_id} profile={commit['profile_id']} job={commit['job_id']} status={status} result={result}",
            )
        return config_workspace_commit_payload(updated)
    except Exception as exc:
        error = concise_incremental_push_error(exc)
        with db() as conn:
            conn.execute(
                "UPDATE config_workspace_commits SET last_error=? WHERE id=? AND workspace_id=?",
                (error[:500], commit_id, workspace_id),
            )
            updated = conn.execute(
                "SELECT * FROM config_workspace_commits WHERE id=? AND workspace_id=?",
                (commit_id, workspace_id),
            ).fetchone()
        return config_workspace_commit_payload(updated, retry_after=PANOS_COMMIT_POLL_INTERVAL_SECONDS)


def concise_incremental_push_error(exc: Exception) -> str:
    message = str(exc)
    api_error = re.search(r"(?P<context>(?:set|edit|delete|rename|multi-move|multi-config) .*?) failed: status='(?P<status>[^']+)' code='(?P<code>[^']+)' msg=", message)
    if api_error:
        code = api_error.group("code")
        if code == "13":
            reason = "PAN-OS herkent dit configuratiepad niet"
        elif code == "10":
            reason = "PAN-OS kan dit object niet verwijderen zolang er verwijzingen naar bestaan"
        elif code == "16" or api_error.group("status").casefold() == "unauth":
            reason = "PAN-OS weigert de API-aanroep"
        else:
            reason = "PAN-OS heeft de wijziging geweigerd"
        return f"{api_error.group('context')}: {reason} (code {code})"
    return message if len(message) <= 220 else message[:217].rstrip() + "…"


@app.post("/config-workspaces/<int:workspace_id>/push")
@login_required
def config_workspace_push(workspace_id):
    workspace = workspace_row(workspace_id)
    if not workspace:
        return "Not found", 404
    output, block_reason = migration_output_push_block(workspace_id)
    if int(workspace["profile_system"] or 0):
        flash("Koppel eerst een push target aan het migratieproject.", "error")
        return redirect(url_for("migration_project", project_id=output["project_id"])) if output else redirect(url_for("migration_home"))
    if block_reason:
        flash(f"Incremental push geblokkeerd: {block_reason}", "error")
        return redirect(url_for("migration_project", project_id=output["project_id"]))
    applied_changes = 0
    commit_record_id = None
    commit_requested = request.form.get("commit_after_push") == "yes"
    push_started = time.perf_counter()
    push_trace = {
        "phase": "initialize", "phase_started": push_started, "phase_ms": {},
        "api_write_count": 0, "api_write_ms": 0.0, "desired_bytes": 0,
        "candidate_bytes": 0, "delta_count": 0,
    }

    def start_push_phase(name):
        phase_now = time.perf_counter()
        previous = push_trace.get("phase")
        if previous:
            elapsed = max(0.0, phase_now - push_trace["phase_started"])
            push_trace["phase_ms"][previous] = push_trace["phase_ms"].get(previous, 0.0) + elapsed * 1000
        push_trace["phase"] = name
        push_trace["phase_started"] = phase_now

    try:
        start_push_phase("load_workspace")
        with db() as conn:
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (workspace["profile_id"],)).fetchone()
        if not profile or profile["target_type"] not in {"panorama", "panos"}:
            raise RuntimeError("Dit target ondersteunt geen PAN-OS XML candidate-writes")
        selected = set(request.form.getlist("family"))
        if len(selected) > 5000:
            raise RuntimeError("De pushselectie bevat te veel configuratiefamilies")
        expected_kind = "panorama" if profile["target_type"] == "panorama" else "panos"
        workspace_xml, desired_root, desired_snapshot = cached_workspace_config(workspace["config_path"], workspace["sha256"])
        if desired_snapshot.kind != expected_kind:
            label = "Panorama" if expected_kind == "panorama" else "standalone firewall"
            raise OfflineConfigError(f"Deze configuratie lijkt niet afkomstig van het gekozen {label}-profiel")
        baseline = require_workspace_baseline(workspace)
        push_trace["desired_bytes"] = len(workspace_xml)
        start_push_phase("fetch_candidate")
        endpoint, key, ctx, current_xml = fetch_panos_candidate_xml(profile)
        push_trace["candidate_bytes"] = len(current_xml)
        start_push_phase("three_way_merge")
        push_desired_xml, merge_conflicts = merge_panos_candidate_xml(baseline, workspace_xml, current_xml)
        if merge_conflicts:
            examples = ", ".join(merge_conflicts[:3])
            raise RuntimeError(
                f"De candidate heeft conflicterende wijzigingen ({examples}); er is niets geschreven. "
                "Open de workspace opnieuw en los de conflicten op."
            )
        start_push_phase("build_delta")
        changes = config_push_delta(current_xml, push_desired_xml)
        push_trace["delta_count"] = len(changes)
        selectable_changes = [item for item in changes if item["family"] != "protected"]
        if not selected:
            if changes and not selectable_changes:
                raise RuntimeError(
                    "Alle gevonden wijzigingen zijn beschermd en kunnen niet worden gepusht. "
                    "Controleer of de gewenste wijziging in deze workspace is opgeslagen"
                )
            raise RuntimeError("Selecteer minstens één selecteerbare configuratiefamilie")
        available = {item["selection_key"] for item in changes}
        if not selected.issubset(available):
            raise RuntimeError("De geselecteerde scope/familie hoort niet bij deze candidatepreview")
        start_push_phase("plan_and_dependency_checks")
        scope_move_targets = defaultdict(list)
        for target_change in changes:
            # A same-name object may already exist in Shared. Updating that
            # entry is an `edit`, so pair it with the VSYS deletion just like a
            # new Shared `set`; otherwise a partial selection falls through to
            # the generic in-use guard and obscures the missing scope selection.
            if target_change["action"] in {"set", "edit"} and target_change["family"].startswith(("object:", "policy:")):
                for name in config_push_change_names(target_change):
                    scope_move_targets[(target_change["family"], name)].append(target_change)
        scope_move_pairs = []
        for removal in changes:
            if removal["action"] != "delete" or not removal["family"].startswith(("object:", "policy:")):
                continue
            counterparts = [
                target_change for target_change in scope_move_targets.get((removal["family"], removal["name"]), [])
                if target_change["scope"] != removal["scope"]
            ]
            if any(
                (removal["selection_key"] in selected) != (target_change["selection_key"] in selected)
                for target_change in counterparts
            ):
                scope_move_pairs.append(removal["name"])
        if scope_move_pairs:
            examples = ", ".join(dict.fromkeys(scope_move_pairs[:3]))
            raise RuntimeError(
                f"Verplaatsing van {examples} vereist zowel de bron- als doelscope. "
                "Selecteer beide scope/familie-rijen; er is niets geschreven."
            )
        chosen = [item for item in changes if item["selection_key"] in selected]
        if any(item["family"] == "protected" for item in chosen):
            raise RuntimeError("Management-, administrator- en credentialinstellingen zijn beschermd tegen workspace-push")
        if not chosen:
            raise RuntimeError("De selectie bevat geen wijzigingen")
        object_type_by_node = {node: kind for kind, node in OBJECT_NODES.items()}
        write_plan, native_moved_names = panos_scope_move_plan(
            current_xml, push_desired_xml, chosen, object_type_by_node,
        )
        invalidate_candidate_preview_cache(int(profile["id"]))
        if profile["target_type"] == "panos":
            analysis = panos_candidate_analysis(push_desired_xml)
            invalid_zones = analysis.get("unresolved_zone_references", [])
            selected_policy_scopes = {
                item["scope"] for item in chosen if item["family"].startswith("policy:")
            }
            relevant_zone_errors = [
                issue for issue in invalid_zones
                if "Shared" in selected_policy_scopes
                or any(issue.startswith(f"vsys {scope}:") for scope in selected_policy_scopes)
            ]
            if relevant_zone_errors:
                raise RuntimeError(
                    "Candidate bevat zoneverwijzingen die ongeldig zijn voor de geselecteerde VSYS; los die eerst op"
                )
        deleted_objects: dict[str, list[str]] = defaultdict(list)
        for change in chosen:
            if change["action"] != "delete" or not change["family"].startswith("object:"):
                continue
            node = change["family"].split(":", 1)[1]
            object_type = object_type_by_node.get(node)
            if not object_type or object_type not in REFERENCE_CHECK_OBJECT_TYPES:
                raise RuntimeError(f"Veilige verwijdercontrole ontbreekt voor configuratietype {node}; niets geschreven")
            if not change.get("name"):
                raise RuntimeError(f"Verwijdering van {node} heeft geen herkenbare objectnaam; niets geschreven")
            if (object_type, change["name"]) not in native_moved_names:
                deleted_objects[object_type].append(change["name"])
        # PAN-OS rejects deletes that leave references unresolved after scope
        # inheritance is applied. Validate every family before the first API
        # write; the reference indexes are shared across all deleted types.
        validate_incremental_object_deletions(
            current_xml, push_desired_xml, deleted_objects, selected,
        )
        start_push_phase("api_writes")
        for change in write_plan:
            params = {"type": "config", "action": change["action"], "xpath": change["xpath"], "key": key}
            if change["action"] in {"set", "edit", "multi-move", "multi-config"}:
                params["element"] = change["element"]
            if change["action"] == "multi-config":
                # Keep the batch transactional without rolling back other
                # pending candidate changes owned by this administrator.
                params["strict-transactional"] = "no"
            if change["action"] == "rename":
                params["newname"] = change["newname"]
            if change["action"] == "move":
                params["where"] = change["where"]
                if change.get("dst"):
                    params["dst"] = change["dst"]
            api_write_started = time.perf_counter()
            try:
                response = panos_api_post(endpoint, params, ctx)
            finally:
                push_trace["api_write_count"] += 1
                push_trace["api_write_ms"] += (time.perf_counter() - api_write_started) * 1000
            action_label = f"{change['action']} {change['label']} {change['name']}"
            response_root = policy_api.require_success(response, action_label)
            if change["action"] == "multi-config":
                failures = [
                    item for item in response_root.iter("response")
                    if item is not response_root and item.get("status") != "success"
                ]
                if failures:
                    detail = " ".join(" ".join(node.itertext()).strip() for node in failures)
                    code = next((item.get("code", "") for item in failures if item.get("code")), "")
                    raise RuntimeError(
                        f"multi-config {change['label']} failed: status='error' code='{code}' msg={detail[:180]}"
                    )
                applied_changes += int(change.get("operation_count", 1))
            else:
                applied_changes += 1
        start_push_phase("candidate_validation")
        validation_root = policy_api.require_success(
            panos_api_post(endpoint, {"type": "op", "cmd": "<validate><full></full></validate>", "key": key}, ctx),
            "PAN-OS candidatevalidatie starten",
        )
        validation_job = validation_root.findtext(".//job") or ""
        validation = wait_panos_job(endpoint, key, ctx, validation_job) if validation_job else {
            "status": "FIN", "result": "OK", "details": [],
        }
        audit(
            "config-workspace-incremental-push",
            f"workspace={workspace_id} profile={profile['name']} families={','.join(sorted(selected))} changes={len(chosen)} validate={validation.get('result','')}",
        )
        if validation.get("result") != "OK":
            details = [value for value in validation.get("details", []) if "invalid" in value.casefold()]
            message = "; ".join(details[-8:]) or "PAN-OS meldde een ongeldige candidate"
            flash(f"Candidate geladen maar validatie mislukt; er is niet gecommit: {message}", "error")
        elif commit_requested:
            start_push_phase("commit_submission")
            commit_record_id = None
            endpoint_hash = hashlib.sha256(endpoint.encode("utf-8")).hexdigest()
            with db() as conn:
                cursor = conn.execute(
                    "INSERT INTO config_workspace_commits "
                    "(workspace_id,profile_id,target_type,target_endpoint_sha256,status,submitted_at,last_checked_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (workspace_id, profile["id"], profile["target_type"], endpoint_hash,
                     "SUBMITTING", now(), time.time()),
                )
                commit_record_id = int(cursor.lastrowid)
            try:
                status = ""
                result = ""
                commit_response = panos_api_post(
                    endpoint,
                    {"type": "commit", "cmd": f"<commit><description>PA Policy Forge incremental push workspace {workspace_id}</description></commit>", "key": key},
                    ctx,
                )
                commit_root = ET.fromstring(commit_response)
                response_code = commit_root.get("code", "")
                response_text = " ".join(value.strip() for value in commit_root.itertext() if value.strip())
                if commit_root.get("status") != "success":
                    if response_code == "19" and "no changes to commit" in response_text.casefold():
                        status, result = "FIN", "NO_CHANGES"
                        details = ["PAN-OS meldde dat er geen kandidaatwijzigingen meer te committen waren."]
                        last_error = ""
                        with db() as conn:
                            conn.execute(
                                "UPDATE config_workspace_commits SET status=?,result=?,details_json=?,last_error=? WHERE id=?",
                                (status, result, json.dumps(details, ensure_ascii=False), last_error, commit_record_id),
                            )
                        audit_workspace_commit(
                            "config-workspace-incremental-commit-finished",
                            f"workspace={workspace_id} profile={profile['id']} status={status} result={result}",
                        )
                    else:
                        policy_api.require_success(commit_response, "PAN-OS commit starten")
                if commit_root.get("status") != "success":
                    job_id = ""
                else:
                    job_id = (commit_root.findtext(".//job") or "").strip()
                if job_id and re.fullmatch(r"[0-9]{1,12}", job_id):
                    with db() as conn:
                        conn.execute(
                            "UPDATE config_workspace_commits SET job_id=?,status='PEND',result='PEND' WHERE id=?",
                            (job_id, commit_record_id),
                        )
                    audit_workspace_commit(
                        "config-workspace-incremental-commit-started",
                        f"workspace={workspace_id} profile={profile['id']} job={job_id} target={profile['target_type']}",
                    )
                else:
                    if status == "FIN" and result == "NO_CHANGES":
                        pass
                    else:
                        status, result = "UNKNOWN", ""
                        details = []
                        last_error = "PAN-OS gaf geen herkenbaar commit-jobnummer terug; controleer de Tasks op het target."
                        with db() as conn:
                            conn.execute(
                                "UPDATE config_workspace_commits SET status=?,result=?,details_json=?,last_error=? WHERE id=?",
                                (status, result, json.dumps(details, ensure_ascii=False), last_error, commit_record_id),
                            )
                        audit_workspace_commit(
                            "config-workspace-incremental-commit-unknown",
                            f"workspace={workspace_id} profile={profile['id']} status={status} result={result}",
                        )
            except Exception as exc:
                status = "FAIL" if isinstance(exc, RuntimeError) else "UNKNOWN"
                error = concise_incremental_push_error(exc)
                with db() as conn:
                    conn.execute(
                        "UPDATE config_workspace_commits SET status=?,result=?,last_error=? WHERE id=?",
                        (status, "FAIL" if status == "FAIL" else "", error[:500], commit_record_id),
                    )
                audit_workspace_commit(
                    "config-workspace-incremental-commit-failed" if status == "FAIL" else "config-workspace-incremental-commit-unknown",
                    f"workspace={workspace_id} profile={profile['id']} status={status}",
                )
        else:
            flash(f"{len(chosen)} wijzigingen uit {len(selected)} configuratiefamilie(s) naar de candidate geschreven en gevalideerd; niet gecommit.", "success")
        start_push_phase("complete")
        app.logger.info(
            "Incremental push timing workspace_id=%s desired_bytes=%s candidate_bytes=%s "
            "delta_count=%s api_write_count=%s api_write_ms=%.1f phase_ms=%s total_ms=%.1f",
            workspace_id, push_trace["desired_bytes"], push_trace["candidate_bytes"],
            push_trace["delta_count"], push_trace["api_write_count"], push_trace["api_write_ms"],
            {name: round(value, 1) for name, value in push_trace["phase_ms"].items()},
            (time.perf_counter() - push_started) * 1000,
        )
    except Exception as exc:
        app.logger.exception(
            "Incremental push failed for workspace=%s phase=%s phase_ms=%.1f total_ms=%.1f "
            "after %s applied change(s); api_write_count=%s api_write_ms=%.1f "
            "desired_bytes=%s candidate_bytes=%s delta_count=%s completed_phase_ms=%s",
            workspace_id, push_trace["phase"],
            (time.perf_counter() - push_trace["phase_started"]) * 1000,
            (time.perf_counter() - push_started) * 1000,
            applied_changes, push_trace["api_write_count"], push_trace["api_write_ms"],
            push_trace["desired_bytes"], push_trace["candidate_bytes"], push_trace["delta_count"],
            {name: round(value, 1) for name, value in push_trace["phase_ms"].items()},
        )
        state = (
            f"{applied_changes} wijziging(en) staan al in de candidate; niet gecommit"
            if applied_changes else "candidate niet gewijzigd"
        )
        flash(f"Incremental push gestopt: {concise_incremental_push_error(exc)}; {state}.", "error")
    if commit_record_id is not None:
        return redirect(url_for("config_workspace_commit_status", workspace_id=workspace_id, commit_id=commit_record_id))
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
            baseline_path = str(workspace["baseline_config_path"] or "")
            if baseline_path and not conn.execute(
                "SELECT 1 FROM config_workspaces WHERE baseline_config_path=? LIMIT 1", (baseline_path,)
            ).fetchone():
                safe_workspace_path(CONFIG_WORKSPACES, baseline_path).unlink(missing_ok=True)
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
        profile_rows = conn.execute("SELECT * FROM profiles WHERE system=0 ORDER BY name").fetchall()
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
            profile["target_configured"] = profile_has_target(row)
            profile["configured"] = profile_is_configured(row)
            profiles.append(profile)
        run_profile_id = request.args.get("run_profile", type=int)
        selected_run_profile = next((profile for profile in profiles if profile["id"] == run_profile_id), None)
        runs = []
        if selected_run_profile:
            with db() as run_conn:
                run_rows = run_conn.execute(
                    "SELECT runs.*,profiles.name profile_name,profiles.target_type,m.activation_status,m.one_hour_json,m.one_day_json,m.last_error "
                    "FROM runs "
                    "JOIN profiles ON profiles.id=runs.profile_id "
                    "LEFT JOIN post_deploy_monitors m ON m.run_id=runs.id "
                    "WHERE runs.profile_id=? AND runs.mode!='prepared' "
                    "AND (runs.status!='complete' OR runs.id IN ("
                    "SELECT id FROM runs WHERE profile_id=? AND mode!='prepared' AND status='complete' ORDER BY id DESC LIMIT 5"
                    ")) ORDER BY runs.id DESC",
                    (selected_run_profile["id"], selected_run_profile["id"]),
                ).fetchall()
                for row in run_rows:
                    item = dict(row)
                    latest = item.get("one_day_json") or item.get("one_hour_json")
                    report = json.loads(latest) if latest else None
                    item["post_status"] = "error" if item.get("last_error") else report.get("status") if report else "pending" if item["mode"] == "push" else ""
                    item["post_label"] = "fout" if item.get("last_error") else f"{report['checkpoint']} · {report['status']}" if report else "wacht op deployment" if item.get("activation_status") == "pending" else "gepland" if item["post_status"] == "pending" else "—"
                    runs.append(item)
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
    profile_zone_rows = []
    profile_zone_error = ""
    profile_group_options = []
    profile_group_error = ""
    if editing_profile:
        mapped_zones = dict(editing_profile.get("zones", {}))
        live_zone_names = []
        if profile_has_target(editing_profile):
            try:
                live_zones = cached_live_items(
                    editing_profile,
                    "profile-zones",
                    lambda: fetch_scm_objects(editing_profile, "zones"),
                    force=request.args.get("refresh_zones") == "1",
                )
                live_zone_names = sorted(
                    {str(item.get("name", "")).strip() for item in live_zones if str(item.get("name", "")).strip()},
                    key=str.casefold,
                )
            except Exception as exc:
                profile_zone_error = str(exc)
        profile_zone_rows = [
            {"name": name, "role": mapped_zones.get(name, "other"), "live": True}
            for name in live_zone_names
        ]
        live_zone_set = set(live_zone_names)
        profile_zone_rows.extend(
            {"name": name, "role": role, "live": False}
            for name, role in mapped_zones.items()
            if name not in live_zone_set
        )
        if profile_has_target(editing_profile):
            try:
                live_profile_groups = cached_live_items(
                    editing_profile,
                    "profile-security-profile-groups",
                    lambda: fetch_scm_objects(editing_profile, "security-profile-groups"),
                    force=request.args.get("refresh_zones") == "1",
                )
                profile_group_options = sorted(
                    {str(item.get("name", "")).strip() for item in live_profile_groups if str(item.get("name", "")).strip()},
                    key=str.casefold,
                )
            except Exception as exc:
                profile_group_error = str(exc)
    configured_profiles = [profile for profile in profiles if profile["configured"]]
    policy_profile = None; policies = []; policy_error = ""; policy_objects = []; object_catalog = []; policy_catalog = []; policy_workspaces = []; live_application_state = {}; scm_config_records = []; object_create_template = None
    policy_source = request.args.get("policy_source", "").strip()
    force_live_refresh = request.args.get("refresh") == "1"
    policy_view = request.args.get("policy_view", "policies")
    if policy_view not in {"policies", "objects", "network", "device"}: policy_view = "policies"
    config_section = request.args.get("config_section", "").strip()
    if policy_view in {"network", "device"} and config_section not in SCM_CONFIGURATION_SECTIONS.get(policy_view, {}):
        config_section = next(iter(SCM_CONFIGURATION_SECTIONS.get(policy_view, {})), "")
    policy_kind = request.args.get("policy_kind", "security")
    object_type = request.args.get("object_type", "addresses")
    if object_type not in SCM_OBJECT_TYPES: object_type = "addresses"
    if policy_kind not in SCM_POLICY_TYPES: policy_kind = "security"
    policy_profile_id = request.args.get("policy_profile", type=int)
    if policy_profile_id:
        policy_profile = next((profile for profile in profiles if profile["id"] == policy_profile_id), None)
        if policy_profile:
            if force_live_refresh and policy_profile["target_type"] == "scm":
                invalidate_profile_caches(int(policy_profile["id"]))
            if policy_profile["target_type"] in {"panorama", "panos"}:
                with db() as conn:
                    policy_workspaces = conn.execute(
                        "SELECT * FROM config_workspaces WHERE profile_id=? ORDER BY id DESC",
                        (policy_profile["id"],),
                    ).fetchall()
                policy_workspaces = accessible_workspace_rows(policy_workspaces)
                active_id = active_config_workspace_id(policy_profile)
                active_workspace = next((item for item in policy_workspaces if item["id"] == active_id), None)
                if policy_source != "choose" and active_workspace:
                    return redirect(url_for("config_workspace_editor", workspace_id=active_workspace["id"]))
                policy_source = "choose"
            else:
                policy_source = "live"
            if policy_source == "live":
                try:
                    if policy_view in {"network", "device"}:
                        scm_config_records = cached_live_items(
                            policy_profile, f"config-{policy_view}-{config_section}",
                            lambda: fetch_scm_configuration_records(policy_profile, policy_view, config_section),
                            force=force_live_refresh,
                        )
                    elif policy_view == "objects":
                        if object_type == "applications":
                            live_application_state = cached_application_catalog(policy_profile)
                            policy_objects = [
                                {"id": item["name"], "name": item["name"], "predefined": True}
                                for item in live_application_state["items"]
                            ]
                        else:
                            policy_objects = cached_object_page(
                                policy_profile, object_type, force=force_live_refresh
                            )
                        if SCM_OBJECT_TYPES[object_type].get("generic"):
                            object_create_template = scm_generic_create_record(
                                object_type,
                                policy_api.scm_container(
                                    folder=policy_profile.get("object_folder") or policy_profile.get("folder"),
                                    snippet=policy_profile.get("snippet"), device=policy_profile.get("device"),
                                ),
                            )
                        object_catalog = fetch_object_catalog(policy_profile, object_type)
                    else:
                        policies = cached_live_items(
                            policy_profile, f"policies-{policy_kind}",
                            lambda: fetch_scm_policy_type(policy_profile, policy_kind),
                            force=force_live_refresh,
                        )
                        policy_catalog = extend_policy_catalog_with_current(
                            fetch_object_catalog(policy_profile, "policy-picker"), policies
                        )
                except Exception as exc: policy_error = str(exc)
    return render_template("app.html", profiles=profiles, configured_profiles=configured_profiles, editing_profile=editing_profile, profile_zone_rows=profile_zone_rows, profile_zone_error=profile_zone_error, profile_group_options=profile_group_options, profile_group_error=profile_group_error, selected_flow_profile=selected_flow_profile, selected_run_profile=selected_run_profile, policy_profile=policy_profile, policy_source=policy_source, policy_workspaces=policy_workspaces, policies=policies, policy_objects=policy_objects, object_catalog=object_catalog, object_create_template=object_create_template, policy_catalog=policy_catalog, live_application_state=live_application_state, policy_view=policy_view, policy_kind=policy_kind, policy_types=SCM_POLICY_TYPES, unsupported_policy_types=SCM_UNAVAILABLE_POLICY_TYPES, object_type=object_type, object_types=SCM_OBJECT_TYPES, config_section=config_section, scm_configuration_sections=SCM_CONFIGURATION_SECTIONS, config_records=scm_config_records, policy_error=policy_error, sources=sources, runs=runs, flows=flows, audits=audits, stats=stats(), certificate=certificate_summary(CERT_DIR / "tls.crt", APPLIANCE_CONFIG), application_catalog_settings=application_catalog_configuration())


@app.get("/migration")
@login_required
def migration_home():
    with db() as conn:
        projects = conn.execute(
            "SELECT migration_projects.*,profiles.name profile_name,profiles.target_type,profiles.system profile_system "
            "FROM migration_projects JOIN profiles ON profiles.id=migration_projects.target_profile_id "
            "WHERE migration_projects.owner=? OR EXISTS(SELECT 1 FROM migration_project_roles r WHERE r.project_id=migration_projects.id AND r.username=?) "
            "ORDER BY migration_projects.updated_at DESC",
            (session.get("username", ""), session.get("username", "")),
        ).fetchall()
        profiles = conn.execute(
            "SELECT id,name,target_type FROM profiles WHERE system=0 AND target_type IN ('scm','panorama','panos') ORDER BY name"
        ).fetchall()
    selected_target_id = request.args.get("target_profile_id", "")
    draft_project_name = request.args.get("draft_name", "")[:120]
    return render_template(
        "migration.html", projects=projects, profiles=profiles, parsers=PARSERS, project=None,
        selected_target_id=selected_target_id, draft_project_name=draft_project_name,
    )


@app.get("/migration/projects/<int:project_id>/export-project")
@login_required
def migration_project_export(project_id):
    project=migration_project_row(project_id)
    if not project: return "Not found",404
    with db() as conn:
        sources=conn.execute("SELECT * FROM migration_sources WHERE project_id=? ORDER BY id",(project_id,)).fetchall()
        rules=conn.execute("SELECT kind,master,members_json,mode FROM migration_merge_rules WHERE project_id=? ORDER BY id",(project_id,)).fetchall()
        transforms=conn.execute("SELECT operation,kind,selector,value FROM migration_transform_rules WHERE project_id=? ORDER BY id",(project_id,)).fetchall()
        mappings=conn.execute("SELECT source_id,kind,action,target_context FROM migration_family_mappings WHERE project_id=? ORDER BY source_id,kind",(project_id,)).fetchall()
        filters=conn.execute("SELECT name,join_mode,rules_json FROM migration_saved_filters WHERE project_id=? ORDER BY id",(project_id,)).fetchall()
    source_names={int(row["id"]):row["source_name"] for row in sources}
    bundle={"schema":"pa-policy-forge-migration-v2","name":project["name"],"topology":project["topology"],"target_type":project["target_type"],"sources":[{"vendor":row["vendor"],"source_name":row["source_name"],"model":migration_model(row).as_dict()} for row in sources],"merge_rules":[{"kind":row["kind"],"master":row["master"],"members":json.loads(row["members_json"]),"mode":row["mode"]} for row in rules],"transform_rules":[dict(row) for row in transforms],"family_mappings":[{"source_name":source_names.get(int(row["source_id"]),""),"kind":row["kind"],"action":row["action"],"target_context":row["target_context"]} for row in mappings],"saved_filters":[{"name":row["name"],"join_mode":row["join_mode"],"rules":json.loads(row["rules_json"] or "[]")} for row in filters]}
    safe="".join(char if char.isalnum() or char in "-_." else "-" for char in project["name"]).strip("-.") or f"migration-{project_id}"
    return Response(json.dumps(bundle,indent=2),mimetype="application/json",headers={"Content-Disposition":f'attachment; filename="{safe}.migration.json"'})


@app.post("/migration/import-project")
@login_required
def migration_project_import():
    try:
        target_choice=request.form.get("target_profile_id","offline-panos"); uploaded=request.files.get("project_file")
        if not uploaded or not uploaded.filename: raise MigrationError("Kies een projectbestand")
        raw=uploaded.stream.read(100*1024*1024+1)
        if len(raw)>100*1024*1024: raise MigrationError("Projectbestand is groter dan 100 MiB")
        bundle=json.loads(raw)
        if bundle.get("schema")!="pa-policy-forge-migration-v2": raise MigrationError("Onbekend projectformaat")
        if target_choice == "offline-auto":
            target_choice = "offline-panorama" if bundle.get("target_type") == "panorama" else "offline-panos"
        with db() as conn:
            profile=migration_target_profile(conn,target_choice)
            profile_id=int(profile["id"])
            topology=str(bundle.get("topology","active-passive"))
            if topology not in {"active-passive","active-active"}: raise MigrationError("Ongeldige topologie in projectbestand")
            project_id=int(conn.execute("INSERT INTO migration_projects(name,target_profile_id,topology,owner,created_at,updated_at) VALUES(?,?,?,?,?,?)",(str(bundle.get("name") or uploaded.filename)[:120],profile_id,topology,session.get("username","admin"),now(),now())).lastrowid)
        imported_sources={}
        for source in bundle.get("sources",[]):
            model=MigrationModel.from_dict(source["model"]); source_name=str(source.get("source_name",model.source_name)); imported_sources[source_name]=store_migration_source(project_id,str(source.get("vendor",model.vendor)),source_name,model)
        with db() as conn:
            for rule in bundle.get("merge_rules",[]):
                conn.execute("INSERT INTO migration_merge_rules(project_id,kind,master,members_json,mode,created_at) VALUES(?,?,?,?,?,?)",(project_id,str(rule["kind"]),str(rule["master"]),json.dumps(rule.get("members",[])),str(rule.get("mode","selection")),now()))
            for rule in bundle.get("transform_rules",[]):
                conn.execute("INSERT INTO migration_transform_rules(project_id,operation,kind,selector,value,created_at) VALUES(?,?,?,?,?,?)",(project_id,str(rule.get("operation","")),str(rule.get("kind","")),str(rule.get("selector","")),str(rule.get("value","")),now()))
            for mapping in bundle.get("family_mappings",[]):
                source_id=imported_sources.get(str(mapping.get("source_name","")))
                if source_id and str(mapping.get("action","map")) in MIGRATION_MAPPING_ACTIONS:
                    conn.execute("UPDATE migration_family_mappings SET action=?,target_context=?,updated_at=? WHERE project_id=? AND source_id=? AND kind=?",(str(mapping.get("action","map")),str(mapping.get("target_context",""))[:255],now(),project_id,source_id,str(mapping.get("kind",""))))
            for item in bundle.get("saved_filters",[]):
                conn.execute("INSERT INTO migration_saved_filters(project_id,name,join_mode,rules_json,created_at,updated_at) VALUES(?,?,?,?,?,?)",(project_id,str(item.get("name","Filter"))[:80],str(item.get("join_mode","and")),json.dumps(item.get("rules",[])),now(),now()))
        audit("migration-project-imported",f"project={project_id} sources={len(bundle.get('sources',[]))}")
        flash("Migratieproject geïmporteerd.","success"); return redirect(url_for("migration_project",project_id=project_id))
    except Exception as exc:
        flash(f"Migratieproject niet geïmporteerd: {exc}","error"); return redirect(url_for("migration_home"))


@app.get("/migration/projects/<int:project_id>/export-candidate/<kind>")
@login_required
def migration_candidate_export(project_id,kind):
    project=migration_project_row(project_id)
    if not project or kind not in {"xml","set"}: return "Not found",404
    if project["target_type"]=="scm": return "SCM gebruikt een API-candidate en heeft geen PAN-OS XML-output",400
    with db() as conn:
        latest_output = conn.execute(
            "SELECT migration_outputs.*,config_workspaces.config_path FROM migration_outputs "
            "JOIN config_workspaces ON config_workspaces.id=migration_outputs.workspace_id "
            "WHERE migration_outputs.project_id=? ORDER BY migration_outputs.id DESC LIMIT 1",
            (project_id,),
        ).fetchone()
        source_ids=[int(row["id"]) for row in conn.execute("SELECT id FROM migration_sources WHERE project_id=?",(project_id,)).fetchall()]
    if latest_output:
        xml_bytes=workspace_config_path(latest_output).read_bytes()
    else:
        return "Maak en review eerst een candidate voordat je XML of set commands exporteert", 409
    safe="".join(char if char.isalnum() or char in "-_." else "-" for char in project["name"]).strip("-.") or f"migration-{project_id}"
    if kind=="xml": return Response(xml_bytes,mimetype="application/xml",headers={"Content-Disposition":f'attachment; filename="{safe}.xml"'})
    return Response(render_set_commands(xml_bytes),mimetype="text/plain",headers={"Content-Disposition":f'attachment; filename="{safe}.set.txt"'})


@app.get("/migration/projects/<int:project_id>/outputs/<int:output_id>/<kind>")
@login_required
def migration_output_export(project_id, output_id, kind):
    if not migration_project_row(project_id):
        return "Not found", 404
    output = migration_output_row(project_id, output_id)
    if not output or kind not in {"xml", "set"}:
        return "Not found", 404
    xml_bytes = workspace_config_path(output).read_bytes()
    safe = "".join(char if char.isalnum() or char in "-_ ." else "-" for char in output["label"]).strip(" -. ") or f"output-{output_id}"
    if kind == "xml":
        return Response(xml_bytes, mimetype="application/xml", headers={"Content-Disposition": f'attachment; filename="{safe}.xml"'})
    return Response(render_set_commands(xml_bytes), mimetype="text/plain", headers={"Content-Disposition": f'attachment; filename="{safe}.set.txt"'})


@app.post("/migration/projects/<int:project_id>/outputs/<int:output_id>/review/<code>")
@login_required
def migration_output_review_update(project_id, output_id, code):
    project = migration_project_row(project_id)
    output = migration_output_row(project_id, output_id)
    if not project or not output:
        return "Not found", 404
    if migration_project_role(project_id) not in {"owner", "editor"}:
        return "Forbidden", 403
    try:
        sanity = json.loads(output["sanity_json"] or "{}")
        critical_codes = sanity.get("critical_review_codes", {})
        review_codes = sanity.get("review_codes", critical_codes)
        if not isinstance(review_codes, dict) or code not in review_codes:
            raise MigrationError("Dit reviewpunt hoort niet bij deze candidate")
        action = request.form.get("action", "resolve")
        with db() as conn:
            if action == "reopen":
                conn.execute(
                    "DELETE FROM migration_output_resolutions WHERE output_id=? AND code=?",
                    (output_id, code),
                )
                audit_action = "migration-review-reopened"
            else:
                note = request.form.get("note", "").strip()
                if len(note) < 3:
                    raise MigrationError("Geef kort aan hoe dit reviewpunt is behandeld")
                conn.execute(
                    "INSERT INTO migration_output_resolutions(output_id,code,note,resolved_by,resolved_at) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(output_id,code) DO UPDATE SET note=excluded.note,resolved_by=excluded.resolved_by,resolved_at=excluded.resolved_at",
                    (output_id, code, note[:500], session.get("username", "admin"), now()),
                )
                audit_action = "migration-review-resolved"
            resolved = {
                row["code"]
                for row in conn.execute(
                    "SELECT code FROM migration_output_resolutions WHERE output_id=?",
                    (output_id,),
                ).fetchall()
            }
            remaining = set(critical_codes) - resolved
            candidate_unresolved = int(
                sanity.get("candidate_unresolved_references", sanity.get("unresolved_references", 0)) or 0
            )
            sanity["critical_findings"] = len(remaining) + (1 if candidate_unresolved else 0)
            conn.execute(
                "UPDATE migration_outputs SET sanity_json=? WHERE id=?",
                (json.dumps(sanity, sort_keys=True), output_id),
            )
        audit(audit_action, f"project={project_id} output={output_id} code={code}")
        flash("Reviewstatus bijgewerkt.", "success")
    except Exception as exc:
        flash(f"Reviewstatus niet bijgewerkt: {exc}", "error")
    return redirect(url_for("migration_project", project_id=project_id) + "#migration-outputs")


@app.post("/migration/projects/<int:project_id>/outputs/<int:output_id>/review-bulk")
@login_required
def migration_output_review_bulk_update(project_id, output_id):
    project = migration_project_row(project_id)
    output = migration_output_row(project_id, output_id)
    if not project or not output:
        return "Not found", 404
    if migration_project_role(project_id) not in {"owner", "editor"}:
        return "Forbidden", 403
    try:
        sanity = json.loads(output["sanity_json"] or "{}")
        critical_codes = sanity.get("critical_review_codes", {})
        review_codes = sanity.get("review_codes", critical_codes)
        if not isinstance(review_codes, dict):
            raise MigrationError("Deze candidate heeft geen reviewpunten")
        codes = list(dict.fromkeys(request.form.getlist("review_code")))
        if not codes:
            raise MigrationError("Selecteer minstens één reviewpunt")
        unknown = [code for code in codes if code not in review_codes]
        if unknown:
            raise MigrationError("Een geselecteerd reviewpunt hoort niet bij deze candidate")
        action = request.form.get("action", "resolve")
        if action not in {"resolve", "reopen"}:
            raise MigrationError("Ongeldige reviewactie")
        note = request.form.get("note", "").strip()
        if action == "resolve" and len(note) < 3:
            raise MigrationError("Geef kort aan hoe de geselecteerde reviewpunten zijn behandeld")
        with db() as conn:
            if action == "reopen":
                conn.executemany(
                    "DELETE FROM migration_output_resolutions WHERE output_id=? AND code=?",
                    [(output_id, code) for code in codes],
                )
            else:
                conn.executemany(
                    "INSERT INTO migration_output_resolutions(output_id,code,note,resolved_by,resolved_at) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(output_id,code) DO UPDATE SET note=excluded.note,resolved_by=excluded.resolved_by,resolved_at=excluded.resolved_at",
                    [
                        (output_id, code, note[:500], session.get("username", "admin"), now())
                        for code in codes
                    ],
                )
            resolved = {
                row["code"]
                for row in conn.execute(
                    "SELECT code FROM migration_output_resolutions WHERE output_id=?",
                    (output_id,),
                ).fetchall()
            }
            remaining_critical = (
                set(critical_codes) - resolved if isinstance(critical_codes, dict) else set()
            )
            candidate_unresolved = int(
                sanity.get("candidate_unresolved_references", sanity.get("unresolved_references", 0)) or 0
            )
            sanity["critical_findings"] = len(remaining_critical) + (1 if candidate_unresolved else 0)
            conn.execute(
                "UPDATE migration_outputs SET sanity_json=? WHERE id=?",
                (json.dumps(sanity, sort_keys=True), output_id),
            )
        audit_action = "migration-review-bulk-reopened" if action == "reopen" else "migration-review-bulk-resolved"
        audit(audit_action, f"project={project_id} output={output_id} codes={','.join(codes)}")
        flash(f"{len(codes)} reviewpunten bijgewerkt.", "success")
    except Exception as exc:
        flash(f"Reviewstatus niet bijgewerkt: {exc}", "error")
    return redirect(url_for("migration_project", project_id=project_id) + "#migration-outputs")


@app.post("/migration/projects")
@login_required
def migration_project_create():
    try:
        name = request.form.get("name", "").strip()
        target_choice = request.form.get("target_profile_id", "offline-panos")
        if not name: raise MigrationError("Projectnaam is verplicht")
        with db() as conn:
            profile = migration_target_profile(conn, target_choice)
            profile_id = int(profile["id"])
            cursor = conn.execute("INSERT INTO migration_projects(name,target_profile_id,owner,created_at,updated_at) VALUES(?,?,?,?,?)", (name[:120], profile_id,session.get("username","admin"), now(), now()))
            project_id = int(cursor.lastrowid)
        mode = "offline" if int(profile["system"]) else "profile"
        audit("migration-project-created", f"project={project_id} target={mode} profile={profile_id}")
        return redirect(url_for("migration_project", project_id=project_id))
    except Exception as exc:
        flash(f"Migratieproject niet aangemaakt: {exc}", "error")
        return redirect(url_for("migration_home"))


@app.post("/migration/targets")
@login_required
def migration_target_create():
    """Create a real push target without leaving the migration project screen."""
    draft_name = request.form.get("draft_project_name", "").strip()[:120]
    try:
        name = request.form.get("name", "").strip()
        target_type = request.form.get("target_type", "")
        if not name:
            raise MigrationError("Targetnaam is verplicht")
        if target_type not in TARGET_TYPES:
            raise MigrationError("Onbekend targettype")
        rulebase = request.form.get("rulebase", "pre")
        if rulebase not in {"pre", "post"}:
            raise MigrationError("Rulebase moet pre of post zijn")

        settings = {
            "zones": {}, "min_sessions": 10, "disabled": False, "tags": ["AI builder"],
            "global_ping": False, "global_dns": False, "endpoint": "", "vsys": "vsys1",
            "device_group": "", "rulebase": rulebase, "folder": "", "snippet": "",
            "device": "", "object_folder": "", "log_profile": "", "passive_serial": "",
            "passive_source_ip": "",
        }
        credentials = {}
        if target_type == "scm":
            scope_type = request.form.get("scm_scope_type", "folder")
            if scope_type not in {"folder", "snippet", "device"}:
                raise MigrationError("Onbekende SCM-scope")
            scope_value = request.form.get(scope_type, "").strip()
            if not scope_value:
                raise MigrationError(f"SCM {scope_type} is verplicht")
            settings[scope_type] = scope_value
            credentials = {
                key: request.form.get(key, "").strip()
                for key in ("client_id", "client_secret", "tsg_id")
            }
            if not all(credentials.values()):
                raise MigrationError("SCM client ID, client secret en TSG ID zijn verplicht")
        else:
            settings["endpoint"] = validate_panos_endpoint(request.form.get("endpoint", ""))
            credentials = {
                key: request.form.get(key, "").strip() for key in ("username", "password")
            }
            if not all(credentials.values()):
                raise MigrationError("Username en password zijn verplicht")
            if target_type == "panorama":
                settings["device_group"] = request.form.get("device_group", "").strip()
                if not settings["device_group"]:
                    raise MigrationError("Device group is verplicht voor Panorama")
            else:
                settings["vsys"] = request.form.get("vsys", "vsys1").strip() or "vsys1"

        timestamp = now()
        with db() as conn:
            duplicate = conn.execute(
                "SELECT id FROM profiles WHERE system=0 AND lower(name)=lower(?)", (name,)
            ).fetchone()
            if duplicate:
                raise MigrationError("Er bestaat al een target met deze naam")
            profile_id = int(conn.execute(
                "INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    name, 1, "", "", target_type, json.dumps(settings),
                    fernet.encrypt(json.dumps(credentials).encode()), timestamp, timestamp,
                ),
            ).lastrowid)
        invalidate_profile_caches(profile_id)
        audit("migration-target-created", f"profile={profile_id} name={name} type={target_type}")
        flash("Push target aangemaakt en geselecteerd.", "success")
        return redirect(url_for(
            "migration_home", target_profile_id=profile_id, draft_name=draft_name
        ))
    except Exception as exc:
        flash(f"Push target niet aangemaakt: {exc}", "error")
        return redirect(url_for("migration_home", draft_name=draft_name))


@app.post("/migration/projects/<int:project_id>/target")
@login_required
def migration_project_attach_target(project_id):
    project = migration_project_row(project_id)
    if not project:
        return "Not found", 404
    try:
        if not int(project["profile_system"] or 0):
            raise MigrationError("Dit project heeft al een push target")
        profile_id = int(request.form.get("target_profile_id", "0"))
        with db() as conn:
            previous_profile = conn.execute(
                "SELECT * FROM profiles WHERE id=?", (project["target_profile_id"],)
            ).fetchone()
            profile = conn.execute(
                "SELECT * FROM profiles WHERE id=? AND system=0", (profile_id,)
            ).fetchone()
            if not profile:
                raise MigrationError("Push target bestaat niet")
            if profile["target_type"] != project["target_type"]:
                raise MigrationError("Kies een push target met hetzelfde doelformaat")
            outputs = conn.execute(
                "SELECT id,sanity_json FROM migration_outputs WHERE project_id=?", (project_id,)
            ).fetchall()
            for output in outputs:
                sanity = json.loads(output["sanity_json"] or "{}")
                sanity.update({"regenerate_required": True, "superseded": True, "target_changed": True})
                conn.execute(
                    "UPDATE migration_outputs SET sanity_json=? WHERE id=?",
                    (json.dumps(sanity, sort_keys=True), output["id"]),
                )
            conn.execute(
                "UPDATE migration_sources SET staging_workspace_id=NULL WHERE project_id=?", (project_id,)
            )
            mapping_kinds = conn.execute(
                "SELECT DISTINCT kind FROM migration_family_mappings WHERE project_id=?",
                (project_id,),
            ).fetchall()
            for row in mapping_kinds:
                kind = str(row["kind"])
                previous_context = migration_profile_target_context(previous_profile, kind)
                next_context = migration_profile_target_context(profile, kind)
                if previous_context and next_context:
                    conn.execute(
                        "UPDATE migration_family_mappings SET target_context=?,updated_at=? "
                        "WHERE project_id=? AND action='create' AND target_context=?",
                        (next_context, now(), project_id, previous_context),
                    )
            conn.execute(
                "UPDATE migration_projects SET target_profile_id=?,base_workspace_id=NULL,updated_at=? WHERE id=?",
                (profile_id, now(), project_id),
            )
        audit("migration-target-attached", f"project={project_id} profile={profile_id}")
        flash("Push target gekoppeld. Maak een nieuwe merge-preview voor deze target.", "success")
    except Exception as exc:
        flash(f"Push target niet gekoppeld: {exc}", "error")
    return redirect(url_for("migration_project", project_id=project_id))


@app.get("/migration/projects/<int:project_id>")
@login_required
def migration_project(project_id):
    project = migration_project_row(project_id)
    if not project: return "Not found", 404
    with db() as conn:
        source_rows = conn.execute("SELECT * FROM migration_sources WHERE project_id=? ORDER BY id", (project_id,)).fetchall()
        profiles = conn.execute(
            "SELECT id,name,target_type FROM profiles WHERE system=0 AND target_type IN ('scm','panorama','panos') ORDER BY name"
        ).fetchall()
        workspace_rows = conn.execute(
            "SELECT id,name,source,original_name,created_at FROM config_workspaces "
            "WHERE profile_id=? ORDER BY id DESC", (project["target_profile_id"],)
        ).fetchall()
        output_rows = conn.execute("SELECT * FROM migration_outputs WHERE project_id=? ORDER BY id DESC", (project_id,)).fetchall()
        output_resolution_rows = conn.execute(
            "SELECT migration_output_resolutions.* FROM migration_output_resolutions "
            "JOIN migration_outputs ON migration_outputs.id=migration_output_resolutions.output_id "
            "WHERE migration_outputs.project_id=? ORDER BY resolved_at DESC",
            (project_id,),
        ).fetchall()
        profile = conn.execute("SELECT * FROM profiles WHERE id=?", (project["target_profile_id"],)).fetchone()
    workspaces = []
    seen_workspace_families = set()
    selected_base_id = int(project["base_workspace_id"] or 0)
    for row in accessible_workspace_rows(workspace_rows):
        family = str(row["original_name"] or row["name"]).casefold()
        if int(row["id"]) != selected_base_id and family in seen_workspace_families:
            continue
        workspaces.append(row)
        seen_workspace_families.add(family)
    family_mappings = ensure_migration_family_mappings(project_id, source_rows)
    sources = []
    for row in source_rows:
        source = dict(row); source["counts"] = json.loads(row["counts_json"]); source["messages"] = json.loads(row["warnings_json"]); sources.append(source)
    outputs = []
    resolutions_by_output = defaultdict(dict)
    for row in output_resolution_rows:
        resolutions_by_output[int(row["output_id"])][row["code"]] = dict(row)
    for row in output_rows:
        output = dict(row)
        output["collisions"] = json.loads(row["collision_json"] or "{}")
        output["sanity"] = json.loads(row["sanity_json"] or "{}")
        output["conflict_total"] = sum(int(item.get("conflicts", 0)) for item in output["collisions"].values() if isinstance(item, dict))
        output["resolutions"] = resolutions_by_output.get(int(row["id"]), {})
        critical_codes = output["sanity"].get("critical_review_codes", {})
        output["critical_review_codes"] = critical_codes if isinstance(critical_codes, dict) else {}
        review_codes = output["sanity"].get("review_codes", output["critical_review_codes"])
        output["review_codes"] = review_codes if isinstance(review_codes, dict) else output["critical_review_codes"]
        output["unresolved_review_codes"] = {
            code: details for code, details in output["critical_review_codes"].items()
            if code not in output["resolutions"]
        }
        output["unresolved_all_review_codes"] = {
            code: details for code, details in output["review_codes"].items()
            if code not in output["resolutions"]
        }
        output["push_blocked"] = bool(
            output["sanity"].get("regenerate_required")
            or int(output["sanity"].get("candidate_unresolved_references", output["sanity"].get("unresolved_references", 0)) or 0) > 0
            or output["unresolved_review_codes"]
            or (int(output["sanity"].get("critical_findings", 0) or 0) > 0 and not output["critical_review_codes"])
        )
        outputs.append(output)
    source_ids=[int(row["id"]) for row in source_rows]
    combined=selected_migration_model(project_id,source_ids) if source_ids else MigrationModel("merged","")
    merge_query=request.args.get("merge_query","").strip()
    inventory_all=merge_inventory(combined)
    inventory=inventory_all[:100]
    topology_items=[]
    transform_kind=request.args.get("transform_kind", "").strip()
    available_kind_counts={key:len(value) for key,value in model_collections(combined).items() if value}
    if transform_kind not in available_kind_counts:
        transform_kind=next(iter(available_kind_counts), "")
    transform_query=request.args.get("transform_query", "").strip()
    transform_candidates=[]
    transform_candidate_total=0
    for kind,items in model_collections(combined).items():
        for item in items:
            raw=item.__dict__ if hasattr(item,"__dict__") else item
            row={
                "kind":kind,"name":str(raw.get("name","")),
                "source_ref":str(raw.get("source_ref","")),"selector":item_selector(raw),
                "source_vendor":str(raw.get("source_vendor","")),
                "networks":list(raw.get("source_networks",[])),
                "addresses":list(raw.get("source_addresses",[])),
                "topology_role":str(raw.get("topology_role","")),
                "suggested_zone":str(raw.get("suggested_zone","")),
            }
            if kind == transform_kind and (
                not transform_query
                or transform_query.casefold() in " ".join((row["name"], row["source_ref"])).casefold()
            ):
                transform_candidate_total += 1
                if len(transform_candidates) < 200:
                    transform_candidates.append(row)
    # A mapped/ignored source is absent from the transformed model.  Keep its
    # original selector visible so the engineer can revise that decision.
    topology_contexts = {
        (int(mapping["source_id"]), mapping["kind"]): mapping["target_context"]
        for mapping in family_mappings
    }
    topology_by_context = {}
    for source in source_rows:
        for kind, items in model_collections(migration_model(source)).items():
            if kind not in MIGRATION_TOPOLOGY_KINDS:
                continue
            context = topology_contexts.get((int(source["id"]), kind)) or migration_profile_target_context(profile)
            if context not in topology_by_context:
                topology_by_context[context] = migration_project_topology_targets(project, profile, context)
            for item in items:
                raw = item.__dict__ if hasattr(item, "__dict__") else item
                if raw.get("auto_generated"):
                    continue
                topology_items.append({
                    "kind": kind, "name": str(raw.get("name", "")),
                    "source_ref": str(raw.get("source_ref", "")), "selector": item_selector(raw),
                    "source_vendor": str(raw.get("source_vendor", "")),
                    "networks": list(raw.get("source_networks", [])),
                    "addresses": list(raw.get("source_addresses", [])),
                    "topology_role": str(raw.get("topology_role", "")),
                    "suggested_zone": str(raw.get("suggested_zone", "")),
                    "targets": topology_by_context[context].get(kind, []),
                })
    with db() as conn:
        merge_rules=[dict(row) for row in conn.execute("SELECT * FROM migration_merge_rules WHERE project_id=? ORDER BY id DESC",(project_id,)).fetchall()]
        transform_rules=[dict(row) for row in conn.execute("SELECT * FROM migration_transform_rules WHERE project_id=? ORDER BY id DESC",(project_id,)).fetchall()]
        saved_filters=[dict(row) for row in conn.execute("SELECT * FROM migration_saved_filters WHERE project_id=? ORDER BY name",(project_id,)).fetchall()]
        catalogs={row["kind"]:{"items":json.loads(row["items_json"] or "[]"),"updated_at":row["updated_at"]} for row in conn.execute("SELECT * FROM migration_catalogs WHERE project_id=? ORDER BY kind",(project_id,)).fetchall()}
        snippets=[dict(row) for row in conn.execute("SELECT id,name,updated_at FROM migration_snippets WHERE owner=? ORDER BY name",(session.get("username",""),)).fetchall()]
        role_rows=[dict(row) for row in conn.execute("SELECT username,role,created_at FROM migration_project_roles WHERE project_id=? ORDER BY username",(project_id,)).fetchall()]
        users=[row["username"] for row in conn.execute("SELECT username FROM users ORDER BY username").fetchall()]
        audit_candidates=[dict(row) for row in conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 1000").fetchall()]
        latest_analysis=conn.execute("SELECT * FROM migration_analysis_runs WHERE project_id=? ORDER BY id DESC LIMIT 1",(project_id,)).fetchone()
    selected_filter_id=request.args.get("saved_filter", default=0, type=int) or 0
    project_audits=[
        row for row in audit_candidates
        if re.search(rf"(?:^|\s)project={project_id}(?:\s|$)",str(row.get("detail","")))
    ][:100]
    selected_filter=next((item for item in saved_filters if int(item["id"])==selected_filter_id),None)
    filter_results=[]
    if selected_filter:
        filter_results=migration_filter_inventory(combined,json.loads(selected_filter["rules_json"] or "[]"),selected_filter["join_mode"])
    target_model=MigrationModel("panos","target")
    target_context_options=[]
    if project["base_workspace_id"]:
        base_workspace=workspace_row(int(project["base_workspace_id"]))
        if base_workspace:
            target_model=cached_migration_workspace_model(base_workspace["config_path"],base_workspace["sha256"])
            try:
                _, _, target_snapshot = cached_workspace_config(
                    base_workspace["config_path"], base_workspace["sha256"]
                )
                target_context_options.extend(available_scopes(target_snapshot))
            except Exception:
                pass
    profile_settings_value=profile_settings(profile) if profile else {}
    target_context=migration_profile_target_context(profile) if profile else ""
    if target_context:
        target_context_options.append(target_context)
    target_context_options=sorted(set(target_context_options), key=str.casefold)
    staged_actions_all=migration_api_plan(combined,project["target_type"],str(target_context)) if source_ids else []
    staged_action_count=len(staged_actions_all)
    staged_actions=staged_actions_all[:250]
    mappings_by_source=defaultdict(list)
    for mapping in family_mappings: mappings_by_source[int(mapping["source_id"])].append(mapping)
    topology_rules=[rule for rule in transform_rules if str(rule["operation"]).startswith("topology_")]
    interface_zone_rules={
        str(rule["selector"]): json.loads(rule["value"] or "{}")
        for rule in transform_rules
        if rule["operation"] == "set_interface_zone"
    }
    topology_targets = migration_project_topology_targets(project, profile)
    offline_source_zones = {
        str(item.get("name", ""))
        for item in combined.zones
        if int(project["profile_system"] or 0) and str(item.get("name", ""))
    }
    target_zones = sorted(
        set(topology_targets["zones"])
        | set(profile_settings_value.get("zones", {}))
        | offline_source_zones
        | migration_saved_interface_zones(project_id)
    )
    policy_zone_query=request.args.get("zone_query", "").strip()
    policy_zone_items = []
    policy_zone_total = 0
    for kind, rules in (("security_rules", combined.security_rules), ("nat_rules", combined.nat_rules)):
        for rule in rules:
            if "any" not in rule.from_zones and "any" not in rule.to_zones:
                continue
            haystack=" ".join((
                rule.name, rule.source_ref, *rule.source, *rule.destination,
                *rule.from_zones, *rule.to_zones,
            )).casefold()
            if policy_zone_query and policy_zone_query.casefold() not in haystack:
                continue
            policy_zone_total += 1
            if len(policy_zone_items) >= 250:
                continue
            raw = rule.__dict__
            policy_zone_items.append({
                "kind": kind,
                "name": rule.name,
                "selector": item_selector(raw),
                "source_ref": rule.source_ref,
                "from_zones": rule.from_zones,
                "to_zones": rule.to_zones,
                "source": rule.source,
                "destination": rule.destination,
            })
    health=migration_health_dashboard(combined)
    best_practices=migration_best_practices(combined)
    discovery=migration_discovery(combined)
    return render_template(
        "migration.html", projects=[], profiles=profiles, parsers=PARSERS, project=project,
        sources=sources, workspaces=workspaces, migration_kind_labels=MIGRATION_KIND_LABELS,
        available_kinds=available_kind_counts,
        merge_inventory=inventory, merge_rules=merge_rules, migration_analysis=migration_analysis(combined),
        migration_review=migration_review_findings(combined) if source_ids else None,
        merge_query=merge_query, search_results=migration_search(combined,merge_query), transform_rules=transform_rules,
        merge_inventory_total=len(inventory_all), topology_items=topology_items,
        transform_kind=transform_kind, transform_query=transform_query,
        transform_candidates=transform_candidates, transform_candidate_total=transform_candidate_total,
        outputs=outputs, family_mappings=family_mappings,
        mappings_by_source=mappings_by_source, mapping_actions=MIGRATION_MAPPING_ACTIONS,
        default_target_context=target_context, target_context_options=target_context_options,
        topology_rules=topology_rules, topology_targets=topology_targets,
        interface_zone_rules=interface_zone_rules,
        target_zones=target_zones, policy_zone_items=policy_zone_items,
        policy_zone_query=policy_zone_query, policy_zone_total=policy_zone_total,
        zone_freeform_allowed=bool(project["target_type"] == "panorama" and not target_zones),
        saved_filters=saved_filters, selected_filter=selected_filter, filter_results=filter_results,
        filter_fields=["name", "kind", "value", "source_ref", "references", "disabled"],
        filter_operators=["contains", "equals", "not_contains", "starts_with", "ends_with", "regex"],
        migration_health=health, best_practices=best_practices, discovery=discovery,
        staged_actions=staged_actions, staged_action_count=staged_action_count,
        catalogs=catalogs, snippets=snippets,
        project_roles=role_rows, project_users=users, current_project_role=migration_project_role(project_id),
        project_audits=project_audits,
        latest_analysis=json.loads(latest_analysis["analysis_json"]) if latest_analysis else None,
        show_topology_mapping=bool(
            source_ids and (topology_items or policy_zone_items or policy_zone_query)
        ),
    )


@app.post("/migration/projects/<int:project_id>/mappings")
@login_required
def migration_family_mapping_save(project_id):
    project = migration_project_row(project_id)
    if not project: return "Not found", 404
    try:
        source_values = request.form.getlist("source_id")
        kind_values = request.form.getlist("kind")
        action_values = request.form.getlist("action")
        target_values = request.form.getlist("target_context")
        if not source_values or not (
            len(source_values) == len(kind_values) == len(action_values) == len(target_values)
        ):
            raise MigrationError("De mappinglijst is onvolledig")
        updates = []
        with db() as conn:
            for source_value, kind_value, action_value, target_value in zip(
                source_values, kind_values, action_values, target_values
            ):
                source_id = int(source_value)
                kind = kind_value.strip()
                action = action_value.strip()
                target_context = target_value.strip()[:255]
                source = conn.execute(
                    "SELECT * FROM migration_sources WHERE id=? AND project_id=?",
                    (source_id, project_id),
                ).fetchone()
                if not source or kind not in model_collections(migration_model(source)):
                    raise MigrationError("De bronfamilie bestaat niet")
                if action not in MIGRATION_MAPPING_ACTIONS:
                    raise MigrationError("Ongeldige mappingactie")
                if action in {"map", "create"} and not target_context:
                    raise MigrationError(
                        f"Doelcontext ontbreekt voor {MIGRATION_KIND_LABELS.get(kind, kind)}"
                    )
                updates.append((source_id, kind, action, target_context))
        with db() as conn:
            for source_id, kind, action, target_context in updates:
                conn.execute(
                    "INSERT INTO migration_family_mappings(project_id,source_id,kind,action,target_context,created_at,updated_at) VALUES(?,?,?,?,?,?,?) "
                    "ON CONFLICT(project_id,source_id,kind) DO UPDATE SET action=excluded.action,target_context=excluded.target_context,updated_at=excluded.updated_at",
                    (project_id, source_id, kind, action, target_context, now(), now()),
                )
            conn.execute("UPDATE migration_projects SET updated_at=? WHERE id=?", (now(), project_id))
        audit("migration-family-mapping", f"project={project_id} mappings={len(updates)}")
        flash(f"{len(updates)} mappings bijgewerkt.", "success")
    except Exception as exc:
        flash(f"Mapping niet opgeslagen: {exc}", "error")
    return redirect(url_for("migration_project", project_id=project_id) + "#source-mapping")


@app.post("/migration/projects/<int:project_id>/topology")
@login_required
def migration_topology_mapping_save(project_id):
    project = migration_project_row(project_id)
    if not project: return "Not found", 404
    try:
        kind = request.form.get("kind", "").strip()
        selector = request.form.get("selector", "").strip()
        action = request.form.get("action", "review").strip()
        target = request.form.get("target", "").strip()
        requested_zone = request.form.get("zone", "").strip()
        operation = f"topology_{action}"
        if kind not in MIGRATION_TOPOLOGY_KINDS or action not in {"map", "create", "ignore", "review"}:
            raise MigrationError("Ongeldige topologiemapping")
        if action == "map" and not target:
            raise MigrationError("Kies een bestaande targetwaarde")
        if kind == "interfaces" and action == "create" and not target:
            raise MigrationError("Geef de nieuwe PAN-OS interfacenaam op")
        with db() as conn:
            source_rows = conn.execute("SELECT * FROM migration_sources WHERE project_id=?", (project_id,)).fetchall()
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (project["target_profile_id"],)).fetchone()
        available = {}
        source_owners = {}
        for source in source_rows:
            for item in model_collections(migration_model(source)).get(kind, []):
                raw = item if isinstance(item, dict) else item.__dict__
                key = item_selector(raw)
                if key in available and key == selector:
                    raise MigrationError("De bronwaarde komt in meerdere imports voor; maak de bronselectie eerst uniek")
                available[key] = raw
                source_owners[key] = int(source["id"])
        if selector not in available:
            raise MigrationError("De bronwaarde bestaat niet meer")
        selected = available[selector]
        with db() as conn:
            mapping = conn.execute(
                "SELECT target_context FROM migration_family_mappings WHERE project_id=? AND source_id=? AND kind=?",
                (project_id, source_owners[selector], kind),
            ).fetchone()
        context = mapping["target_context"] if mapping else migration_profile_target_context(profile)
        scoped_targets = migration_project_topology_targets(project, profile, context)
        if action == "map" and target not in scoped_targets.get(kind, []):
            raise MigrationError("De gekozen target bestaat niet in de geselecteerde doelcontext; vernieuw de base en kies opnieuw")
        if kind == "interfaces" and action == "create":
            if project["target_type"] == "scm":
                raise MigrationError("Nieuwe interfaces vanuit migratie zijn nog niet veilig beschikbaar voor SCM")
            if not re.fullmatch(r"ethernet[1-9][0-9]*/[1-9][0-9]*", target):
                raise MigrationError(
                    "Gebruik voor een nieuwe fysieke interface de PAN-OS-notatie "
                    "ethernet<slot>/<poort>, bijvoorbeeld ethernet1/1"
                )
            if target in scoped_targets.get("interfaces", []):
                raise MigrationError("Deze interface bestaat al; kies Map")
            with db() as conn:
                duplicate = conn.execute(
                    "SELECT selector FROM migration_transform_rules WHERE project_id=? "
                    "AND kind='interfaces' AND operation='topology_create' AND value=? AND selector<>?",
                    (project_id, target, selector),
                ).fetchone()
            if duplicate:
                raise MigrationError("Deze nieuwe targetinterface is al aan een andere broninterface gekoppeld")
        # A review or ignored interface must not create a usable target zone.
        zone = requested_zone if kind == "interfaces" and action in {"map", "create"} else ""
        if zone and (not re.fullmatch(r"[A-Za-z0-9 ._-]{1,31}", zone) or zone.casefold() == "any"):
            raise MigrationError("Ongeldige zonenaam: maximaal 31 letters, cijfers, spaties, punten, streepjes of underscores; geen any")
        existing_zones = set(scoped_targets.get("zones", []))
        if zone:
            interface = target if action in {"map", "create"} else str(selected.get("name", ""))
            attached = scoped_targets.get("interface_zone_memberships", {}).get(interface, [])
            if (action == "map" and zone in existing_zones and zone not in attached) or any(value != zone for value in attached):
                raise MigrationError("De interface hoort niet bij deze targetzone. Pas de zone-interfacekoppeling eerst aan in de base")
            with db() as conn:
                assignments = conn.execute(
                    "SELECT z.selector,z.value AS zone_value,t.value AS target FROM migration_transform_rules z "
                    "JOIN migration_transform_rules t ON t.project_id=z.project_id AND t.kind=z.kind AND t.selector=z.selector "
                    "WHERE z.project_id=? AND z.kind='interfaces' AND z.operation='set_interface_zone' "
                    "AND t.operation='topology_map' AND z.selector<>?",
                    (project_id, selector),
                ).fetchall()
            if any(row["target"] == interface and json.loads(row["zone_value"] or "{}").get("zone") not in {None, "", zone} for row in assignments):
                raise MigrationError("Deze targetinterface is al aan een andere zone toegewezen")
        with db() as conn:
            conn.execute(
                "DELETE FROM migration_transform_rules WHERE project_id=? AND kind=? AND selector=? AND operation LIKE 'topology_%'",
                (project_id, kind, selector),
            )
            conn.execute(
                "INSERT INTO migration_transform_rules(project_id,operation,kind,selector,value,created_at) VALUES(?,?,?,?,?,?)",
                (project_id, operation, kind, selector, target, now()),
            )
            if kind == "interfaces":
                conn.execute(
                    "DELETE FROM migration_transform_rules WHERE project_id=? AND kind='interfaces' AND selector=? AND operation='set_interface_zone'",
                    (project_id, selector),
                )
                if zone:
                    conn.execute(
                        "INSERT INTO migration_transform_rules(project_id,operation,kind,selector,value,created_at) VALUES(?,?,?,?,?,?)",
                        (
                            project_id, "set_interface_zone", "interfaces", selector,
                            json.dumps({"zone": zone, "create": action == "create" or zone not in existing_zones}, sort_keys=True), now(),
                        ),
                    )
            conn.execute("UPDATE migration_projects SET updated_at=? WHERE id=?", (now(), project_id))
        audit("migration-topology-mapping", f"project={project_id} kind={kind} action={action}")
        flash("Interface- en zonemapping bijgewerkt." if kind == "interfaces" else "Topologiemapping bijgewerkt.", "success")
    except Exception as exc:
        flash(f"Topologiemapping niet opgeslagen: {exc}", "error")
    return redirect(url_for("migration_project", project_id=project_id) + "#topology-mapping")


@app.post("/migration/projects/<int:project_id>/policy-zones")
@login_required
def migration_policy_zone_mapping_save(project_id):
    project = migration_project_row(project_id)
    if not project:
        return "Not found", 404
    try:
        policy_keys = list(dict.fromkeys(request.form.getlist("policy_key")))
        from_zones = list(dict.fromkeys(
            value.strip() for value in request.form.getlist("from_zone") if value.strip()
        ))
        to_zones = list(dict.fromkeys(
            value.strip() for value in request.form.getlist("to_zone") if value.strip()
        ))
        if not policy_keys:
            raise MigrationError("Selecteer minstens één policy")
        if not from_zones and not to_zones:
            raise MigrationError("Kies minstens een source- of destinationzone")
        with db() as conn:
            profile = conn.execute(
                "SELECT * FROM profiles WHERE id=?", (project["target_profile_id"],)
            ).fetchone()
            source_ids = [
                int(row["id"])
                for row in conn.execute(
                    "SELECT id FROM migration_sources WHERE project_id=?", (project_id,)
                ).fetchall()
            ]
        if not profile or not source_ids:
            raise MigrationError("Targetprofiel of migratiebron ontbreekt")
        model = selected_migration_model(project_id, source_ids)
        target_model = MigrationModel("panos", "target")
        if project["base_workspace_id"]:
            base_workspace = workspace_row(int(project["base_workspace_id"]))
            if base_workspace:
                target_model = cached_migration_workspace_model(
                    base_workspace["config_path"], base_workspace["sha256"]
                )
        settings = profile_settings(profile)
        source_zones = {
            str(item.get("name", ""))
            for item in model.zones
            if int(profile["system"] or 0) and str(item.get("name", ""))
        }
        target_zones = (
            set(migration_zone_names(target_model))
            | set(settings.get("zones", {}))
            | source_zones
            | migration_saved_interface_zones(project_id)
        )
        freeform_allowed = bool(
            int(profile["system"] or 0)
            and settings.get("system_offline")
            and not target_zones
        )
        for zone in [*from_zones, *to_zones]:
            if not freeform_allowed and zone not in target_zones:
                raise MigrationError(
                    f"Zone {zone} bestaat niet in de gekozen targetconfiguratie"
                )
            if freeform_allowed and not re.fullmatch(r"[A-Za-z0-9._ -]{1,63}", zone):
                raise MigrationError("Ongeldige zonenaam")
        available = {
            f"{kind}|||{item_selector(rule.__dict__)}": (kind, item_selector(rule.__dict__))
            for kind, rules in (("security_rules", model.security_rules), ("nat_rules", model.nat_rules))
            for rule in rules
        }
        selected = []
        for key in policy_keys:
            if key not in available:
                raise MigrationError("Een geselecteerde policy bestaat niet meer")
            selected.append(available[key])
        timestamp = now()
        with db() as conn:
            for kind, selector in selected:
                for operation, zones in (("set_from_zones", from_zones), ("set_to_zones", to_zones)):
                    if not zones:
                        continue
                    conn.execute(
                        "DELETE FROM migration_transform_rules WHERE project_id=? AND operation=? AND kind=? AND selector=?",
                        (project_id, operation, kind, selector),
                    )
                    conn.execute(
                        "INSERT INTO migration_transform_rules(project_id,operation,kind,selector,value,created_at) VALUES(?,?,?,?,?,?)",
                        (project_id, operation, kind, selector, json.dumps(zones), timestamp),
                    )
            conn.execute(
                "UPDATE migration_projects SET updated_at=? WHERE id=?", (timestamp, project_id)
            )
        audit(
            "migration-policy-zones",
            f"project={project_id} policies={len(selected)} from={len(from_zones)} to={len(to_zones)}",
        )
        flash(f"Zones voor {len(selected)} policies bijgewerkt.", "success")
    except Exception as exc:
        flash(f"Policyzones niet opgeslagen: {exc}", "error")
    return redirect(url_for("migration_project", project_id=project_id) + "#topology-mapping")


@app.post("/migration/projects/<int:project_id>/filters")
@login_required
def migration_filter_save(project_id):
    project = migration_project_row(project_id)
    if not project: return "Not found", 404
    try:
        name = request.form.get("name", "").strip()[:80]
        join_mode = request.form.get("join_mode", "and").strip()
        rules = []
        for field, operator, value in zip(
            request.form.getlist("field"), request.form.getlist("operator"), request.form.getlist("filter_value")
        ):
            if value.strip() or field == "disabled":
                rules.append({"field": field, "operator": operator, "value": value.strip()})
        if not name or not rules or join_mode not in {"and", "or"}:
            raise MigrationError("Geef een naam en minstens één filtervoorwaarde op")
        source_ids = []
        with db() as conn:
            source_ids = [int(row["id"]) for row in conn.execute("SELECT id FROM migration_sources WHERE project_id=?", (project_id,)).fetchall()]
        migration_filter_inventory(selected_migration_model(project_id, source_ids), rules, join_mode)
        with db() as conn:
            conn.execute(
                "INSERT INTO migration_saved_filters(project_id,name,join_mode,rules_json,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                (project_id, name, join_mode, json.dumps(rules), now(), now()),
            )
        audit("migration-filter-saved", f"project={project_id} name={name} rules={len(rules)}")
        flash("Filter opgeslagen.", "success")
    except Exception as exc:
        flash(f"Filter niet opgeslagen: {exc}", "error")
    return redirect(url_for("migration_project", project_id=project_id) + "#filter-builder")


@app.post("/migration/projects/<int:project_id>/filters/<int:filter_id>/delete")
@login_required
def migration_filter_delete(project_id, filter_id):
    if not migration_project_row(project_id): return "Not found", 404
    with db() as conn:
        deleted = conn.execute("DELETE FROM migration_saved_filters WHERE id=? AND project_id=?", (filter_id, project_id)).rowcount
    if deleted:
        audit("migration-filter-deleted", f"project={project_id} filter={filter_id}")
        flash("Filter verwijderd.", "success")
    return redirect(url_for("migration_project", project_id=project_id) + "#filter-builder")


@app.post("/migration/projects/<int:project_id>/bulk-rename")
@login_required
def migration_bulk_rename(project_id):
    if not migration_project_row(project_id): return "Not found", 404
    try:
        kind = request.form.get("kind", "").strip()
        settings = {
            "query": request.form.get("query", "").strip(),
            "prefix": request.form.get("prefix", "").strip(),
            "suffix": request.form.get("suffix", "").strip(),
            "search": request.form.get("search", ""),
            "replace": request.form.get("replace", ""),
        }
        if kind not in MIGRATION_KIND_LABELS or not any(settings.values()):
            raise MigrationError("Kies een type en minstens één wijziging")
        with db() as conn:
            source_ids = [int(row["id"]) for row in conn.execute("SELECT id FROM migration_sources WHERE project_id=?", (project_id,)).fetchall()]
        model = selected_migration_model(project_id, source_ids)
        candidates = [
            item for item in model_collections(model).get(kind, [])
            if not settings["query"] or settings["query"].casefold() in str(item.name if hasattr(item, "name") else item.get("name", "")).casefold()
        ]
        if not candidates:
            raise MigrationError("De bulkbewerking matcht geen items")
        with db() as conn:
            conn.execute(
                "INSERT INTO migration_transform_rules(project_id,operation,kind,selector,value,created_at) VALUES(?,?,?,?,?,?)",
                (project_id, "bulk_rename", kind, settings["query"], json.dumps(settings), now()),
            )
            conn.execute("UPDATE migration_projects SET updated_at=? WHERE id=?", (now(), project_id))
        audit("migration-bulk-rename-staged", f"project={project_id} kind={kind} matches={len(candidates)}")
        flash(f"Bulk rename voor {len(candidates)} items in de reviewqueue geplaatst.", "success")
    except Exception as exc:
        flash(f"Bulk rename niet opgeslagen: {exc}", "error")
    return redirect(url_for("migration_project", project_id=project_id) + "#bulk-refactor")


@app.post("/migration/projects/<int:project_id>/analysis")
@login_required
def migration_analysis_run(project_id):
    if not migration_project_row(project_id): return "Not found", 404
    with db() as conn:
        source_ids = [int(row["id"]) for row in conn.execute("SELECT id FROM migration_sources WHERE project_id=?", (project_id,)).fetchall()]
    result = migration_best_practices(selected_migration_model(project_id, source_ids))
    with db() as conn:
        conn.execute("INSERT INTO migration_analysis_runs(project_id,analysis_json,created_at) VALUES(?,?,?)", (project_id, json.dumps(result), now()))
    audit("migration-best-practice-analysis", f"project={project_id} failed={result['failed']}")
    flash("Best-practiceanalyse vernieuwd.", "success")
    return redirect(url_for("migration_project", project_id=project_id) + "#best-practices")


@app.post("/migration/projects/<int:project_id>/analysis/disable-imported")
@login_required
def migration_disable_imported(project_id):
    if not migration_project_row(project_id): return "Not found", 404
    with db() as conn:
        source_ids = [int(row["id"]) for row in conn.execute("SELECT id FROM migration_sources WHERE project_id=?", (project_id,)).fetchall()]
    model = selected_migration_model(project_id, source_ids)
    enabled = [("security_rules", rule) for rule in model.security_rules if not rule.disabled] + [("nat_rules", rule) for rule in model.nat_rules if not rule.disabled]
    with db() as conn:
        for kind, rule in enabled:
            conn.execute(
                "INSERT INTO migration_transform_rules(project_id,operation,kind,selector,value,created_at) VALUES(?,?,?,?,?,?)",
                (project_id, "disable", kind, item_selector(rule.__dict__), "", now()),
            )
        if enabled:
            conn.execute("UPDATE migration_projects SET updated_at=? WHERE id=?", (now(), project_id))
    audit("migration-disable-imported-staged", f"project={project_id} rules={len(enabled)}")
    flash(f"{len(enabled)} policies disabled in de reviewqueue.", "success")
    return redirect(url_for("migration_project", project_id=project_id) + "#best-practices")


@app.post("/migration/projects/<int:project_id>/catalogs/refresh")
@login_required
def migration_catalog_refresh(project_id):
    project = migration_project_row(project_id)
    if not project: return "Not found", 404
    try:
        with db() as conn:
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (project["target_profile_id"],)).fetchone()
        if not profile:
            raise MigrationError("Targetprofiel bestaat niet meer")
        catalogs = {"applications": cached_application_catalog(profile)["items"]}
        if profile["target_type"] == "scm":
            for kind in ("regions", "custom-url-categories"):
                catalogs[kind] = [
                    {"name": item.get("name", ""), "kind": kind}
                    for item in fetch_scm_objects(profile, kind) if item.get("name")
                ]
        else:
            target = None
            if project["base_workspace_id"]:
                workspace = workspace_row(int(project["base_workspace_id"]))
                if workspace:
                    target = cached_migration_workspace_model(workspace["config_path"], workspace["sha256"])
            if target:
                for kind in ("regions", "custom_url_categories"):
                    catalogs[kind.replace("_", "-")] = [
                        {"name": item.get("name", ""), "kind": kind}
                        for item in target.extras.get(kind, []) if item.get("name")
                    ]
        with db() as conn:
            for kind, items in catalogs.items():
                conn.execute(
                    "INSERT INTO migration_catalogs(project_id,kind,items_json,updated_at) VALUES(?,?,?,?) "
                    "ON CONFLICT(project_id,kind) DO UPDATE SET items_json=excluded.items_json,updated_at=excluded.updated_at",
                    (project_id, kind, json.dumps(items), now()),
                )
        audit("migration-catalogs-refreshed", f"project={project_id} kinds={len(catalogs)}")
        flash("Application-, URL- en region-catalogi bijgewerkt.", "success")
    except Exception as exc:
        flash(f"Catalogi niet bijgewerkt: {exc}", "error")
    return redirect(url_for("migration_project", project_id=project_id) + "#enrichment")


@app.get("/migration/projects/<int:project_id>/api-plan")
@login_required
def migration_api_plan_export(project_id):
    project = migration_project_row(project_id)
    if not project: return "Not found", 404
    with db() as conn:
        source_ids = [int(row["id"]) for row in conn.execute("SELECT id FROM migration_sources WHERE project_id=?", (project_id,)).fetchall()]
    actions = migration_api_plan(selected_migration_model(project_id, source_ids), project["target_type"], project["profile_name"])
    payload = {"schema": "pa-policy-forge-api-plan-v1", "project": project["name"], "target": project["profile_name"], "write_performed": False, "actions": actions}
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", project["name"]).strip("-.") or f"migration-{project_id}"
    return Response(json.dumps(payload, indent=2), mimetype="application/json", headers={"Content-Disposition": f'attachment; filename="{safe}-api-plan.json"'})


@app.post("/migration/projects/<int:project_id>/snippets")
@login_required
def migration_snippet_save(project_id):
    if not migration_project_row(project_id): return "Not found", 404
    try:
        name = request.form.get("name", "").strip()[:80]
        if not name:
            raise MigrationError("Naam ontbreekt")
        with db() as conn:
            mappings = [dict(row) for row in conn.execute("SELECT kind,action,target_context FROM migration_family_mappings WHERE project_id=? ORDER BY kind", (project_id,)).fetchall()]
            transforms = [dict(row) for row in conn.execute("SELECT operation,kind,selector,value FROM migration_transform_rules WHERE project_id=? AND operation='bulk_rename' ORDER BY id", (project_id,)).fetchall()]
            filters = [dict(row) for row in conn.execute("SELECT name,join_mode,rules_json FROM migration_saved_filters WHERE project_id=? ORDER BY id", (project_id,)).fetchall()]
            settings = {"mappings": mappings, "transforms": transforms, "filters": filters}
            conn.execute(
                "INSERT INTO migration_snippets(owner,name,settings_json,created_at,updated_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(owner,name) DO UPDATE SET settings_json=excluded.settings_json,updated_at=excluded.updated_at",
                (session.get("username",""), name, json.dumps(settings), now(), now()),
            )
        audit("migration-snippet-saved", f"project={project_id} name={name}")
        flash("Migratiesnippet opgeslagen.", "success")
    except Exception as exc:
        flash(f"Snippet niet opgeslagen: {exc}", "error")
    return redirect(url_for("migration_project", project_id=project_id) + "#project-tools")


@app.post("/migration/projects/<int:project_id>/snippets/<int:snippet_id>/apply")
@login_required
def migration_snippet_apply(project_id, snippet_id):
    if not migration_project_row(project_id): return "Not found", 404
    try:
        with db() as conn:
            snippet = conn.execute("SELECT * FROM migration_snippets WHERE id=? AND owner=?", (snippet_id,session.get("username",""))).fetchone()
            sources = conn.execute("SELECT * FROM migration_sources WHERE project_id=?", (project_id,)).fetchall()
        if not snippet:
            raise MigrationError("Snippet bestaat niet")
        settings = json.loads(snippet["settings_json"] or "{}")
        mapping_by_kind = {item["kind"]: item for item in settings.get("mappings", [])}
        with db() as conn:
            for source in sources:
                for kind, items in model_collections(migration_model(source)).items():
                    mapping = mapping_by_kind.get(kind)
                    if items and mapping:
                        conn.execute(
                            "INSERT INTO migration_family_mappings(project_id,source_id,kind,action,target_context,created_at,updated_at) VALUES(?,?,?,?,?,?,?) "
                            "ON CONFLICT(project_id,source_id,kind) DO UPDATE SET action=excluded.action,target_context=excluded.target_context,updated_at=excluded.updated_at",
                            (project_id, source["id"], kind, mapping["action"], mapping.get("target_context", ""), now(), now()),
                        )
            for rule in settings.get("transforms", []):
                conn.execute("INSERT INTO migration_transform_rules(project_id,operation,kind,selector,value,created_at) VALUES(?,?,?,?,?,?)", (project_id, rule["operation"], rule["kind"], rule.get("selector", ""), rule.get("value", ""), now()))
            for item in settings.get("filters", []):
                conn.execute("INSERT INTO migration_saved_filters(project_id,name,join_mode,rules_json,created_at,updated_at) VALUES(?,?,?,?,?,?)", (project_id, item["name"], item["join_mode"], item["rules_json"], now(), now()))
            conn.execute("UPDATE migration_projects SET updated_at=? WHERE id=?", (now(), project_id))
        audit("migration-snippet-applied", f"project={project_id} snippet={snippet_id}")
        flash("Migratiesnippet toegepast.", "success")
    except Exception as exc:
        flash(f"Snippet niet toegepast: {exc}", "error")
    return redirect(url_for("migration_project", project_id=project_id) + "#project-tools")


@app.post("/migration/projects/<int:project_id>/roles")
@login_required
def migration_role_save(project_id):
    if migration_project_role(project_id) != "owner": return "Not found", 404
    try:
        username = request.form.get("username", "").strip()
        role = request.form.get("role", "viewer").strip()
        if role not in {"editor", "reviewer", "viewer"}:
            raise MigrationError("Ongeldige projectrol")
        with db() as conn:
            if not conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                raise MigrationError("Gebruiker bestaat niet")
            conn.execute(
                "INSERT INTO migration_project_roles(project_id,username,role,created_at) VALUES(?,?,?,?) "
                "ON CONFLICT(project_id,username) DO UPDATE SET role=excluded.role",
                (project_id, username, role, now()),
            )
        audit("migration-role-saved", f"project={project_id} username={username} role={role}")
        flash("Projectrol bijgewerkt.", "success")
    except Exception as exc:
        flash(f"Projectrol niet opgeslagen: {exc}", "error")
    return redirect(url_for("migration_project", project_id=project_id) + "#project-tools")


@app.post("/migration/projects/<int:project_id>/roles/<username>/delete")
@login_required
def migration_role_delete(project_id, username):
    if migration_project_role(project_id) != "owner": return "Not found", 404
    with db() as conn:
        conn.execute("DELETE FROM migration_project_roles WHERE project_id=? AND username=?", (project_id, username))
    audit("migration-role-deleted", f"project={project_id} username={username}")
    flash("Projectrol verwijderd.", "success")
    return redirect(url_for("migration_project", project_id=project_id) + "#project-tools")


@app.post("/migration/projects/<int:project_id>/source")
@login_required
def migration_source_upload(project_id):
    project = migration_project_row(project_id)
    if not project: return "Not found", 404
    try:
        vendor = request.form.get("vendor", "")
        uploaded = request.files.get("config_file")
        if not uploaded or not uploaded.filename: raise MigrationError("Kies een configuratiebestand")
        content = uploaded.stream.read(100 * 1024 * 1024 + 1)
        model = parse_vendor(vendor, content, uploaded.filename)
        policy_status = apply_migration_import_policy_status(
            model, request.form.get("force_disable_policies") == "yes"
        )
        use_as_full_base = vendor == "panos" and project["target_type"] in {"panos", "panorama"}
        profile = None
        if use_as_full_base:
            with db() as conn:
                profile = conn.execute("SELECT * FROM profiles WHERE id=?", (project["target_profile_id"],)).fetchone()
            if not profile:
                raise MigrationError("Targetprofiel bestaat niet meer")
            expected = "panorama" if project["target_type"] == "panorama" else "panos"
            parse_snapshot(content, expected_kind=expected)
        source_id = store_migration_source(project_id, vendor, uploaded.filename, model)
        workspace_id = None
        base_selected = False
        if use_as_full_base:
            workspace_id = store_config_workspace(
                profile,
                f"Bronconfiguratie - {uploaded.filename}",
                uploaded.filename,
                content,
                "migration-import",
            )
            with db() as conn:
                conn.execute(
                    "UPDATE migration_sources SET staging_workspace_id=? WHERE id=?",
                    (workspace_id, source_id),
                )
            if not int(project["base_workspace_id"] or 0):
                base_selected = True
                with db() as conn:
                    conn.execute(
                        "UPDATE migration_projects SET base_workspace_id=?,updated_at=? WHERE id=?",
                        (workspace_id, now(), project_id),
                    )
        status_mode = "force-disabled" if policy_status["force_disabled"] else "preserved"
        audit(
            "migration-source-imported",
            f"project={project_id} source={source_id} vendor={vendor} policy_status={status_mode} counts={model.counts()}",
        )
        item_count = sum(model.counts()[key] for key in ('addresses','address_groups','services','service_groups','security_rules','nat_rules','interfaces','zones'))
        if base_selected:
            base_message = f" De volledige XML is ook als base-workspace #{workspace_id} geselecteerd."
        elif workspace_id:
            base_message = f" De volledige XML is als workspace #{workspace_id} beschikbaar; de bestaande base bleef geselecteerd."
        else:
            base_message = ""
        if policy_status["force_disabled"]:
            status_message = f" Alle {policy_status['total']} security policies zijn disabled gemaakt."
        else:
            status_message = (
                f" Security-policy-status behouden: {policy_status['source_disabled']} van "
                f"{policy_status['total']} security policies disabled."
            )
        flash(
            f"{PARSERS[vendor].label} geïmporteerd: {item_count} mergeerbare items."
            f"{status_message}{base_message}",
            "success",
        )
    except Exception as exc:
        flash(f"Vendorconfiguratie niet geïmporteerd: {exc}", "error")
    return redirect(url_for("migration_project", project_id=project_id))


@app.post("/migration/projects/<int:project_id>/source-profile")
@login_required
def migration_source_profile(project_id):
    project=migration_project_row(project_id)
    if not project: return "Not found",404
    try:
        profile_id=int(request.form.get("source_profile_id","0"))
        with db() as conn: profile=conn.execute("SELECT * FROM profiles WHERE id=?",(profile_id,)).fetchone()
        if not profile: raise MigrationError("Bronprofiel bestaat niet")
        model,xml_bytes=live_profile_migration_source(profile)
        if xml_bytes is not None and int(profile["id"])==int(project["target_profile_id"]):
            workspace_id=store_config_workspace(
                profile, f"Bronconfiguratie - {profile['name']}",
                f"{profile['name']}-candidate.xml", xml_bytes, "migration-api",
                baseline_xml=xml_bytes,
            )
            with db() as conn:
                conn.execute("UPDATE migration_projects SET base_workspace_id=?,updated_at=? WHERE id=?",(workspace_id,now(),project_id))
            audit("migration-live-base",f"project={project_id} workspace={workspace_id} profile={profile['name']}")
            flash(f"Volledige doelconfiguratie van {profile['name']} als base opgehaald.","success")
        else:
            source_id=store_migration_source(project_id,model.vendor,model.source_name,model)
            audit("migration-live-source",f"project={project_id} source={source_id} profile={profile['name']}")
            flash(f"Live configuratie van {profile['name']} als migratiebron toegevoegd.","success")
    except Exception as exc: flash(f"Live configuratie niet opgehaald: {exc}","error")
    return redirect(url_for("migration_project",project_id=project_id))


def ensure_migration_source_workspace(project, source) -> int:
    existing_workspace_id = int(source["staging_workspace_id"] or 0)
    if existing_workspace_id and workspace_row(existing_workspace_id):
        return existing_workspace_id
    with db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE id=?", (project["target_profile_id"],)).fetchone()
    if not profile:
        raise MigrationError("Targetprofiel bestaat niet meer")
    model = migration_model(source)
    settings = profile_settings(profile)
    panorama = profile["target_type"] == "panorama"
    scope = settings.get("device_group", "") if panorama else settings.get("vsys", "vsys1") or "vsys1"
    base_xml = migration_base_xml(model, scope, panorama)
    merged_xml, _ = merge_model_into_panos_xml(
        base_xml, model, scope, panorama, settings.get("rulebase", "pre")
    )
    safe_source_name = re.sub(
        r"[^A-Za-z0-9._-]+", "-", Path(source["source_name"]).stem
    ).strip("-") or "migration-source"
    workspace_id = store_config_workspace(
        profile,
        f"{source['source_name']} · import editor",
        f"{safe_source_name}.xml",
        merged_xml,
        "migration-staging",
    )
    with db() as conn:
        conn.execute(
            "UPDATE migration_sources SET staging_workspace_id=? WHERE id=?",
            (workspace_id, source["id"]),
        )
    audit(
        "migration-source-editor-created",
        f"project={project['id']} source={source['id']} workspace={workspace_id}",
    )
    return workspace_id


@app.post("/migration/projects/<int:project_id>/sources/<int:source_id>/edit")
@login_required
def migration_source_edit(project_id, source_id):
    project = migration_project_row(project_id)
    source = migration_source_row(source_id)
    if not project or not source or int(source["project_id"]) != project_id:
        return "Not found", 404
    try:
        workspace_id = ensure_migration_source_workspace(project, source)
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id, workspace_view="policies"))
    except Exception as exc:
        flash(f"Importeditor niet geopend: {exc}", "error")
        return redirect(url_for("migration_project", project_id=project_id))


@app.post("/migration/projects/<int:project_id>/review/open")
@login_required
def migration_review_open(project_id):
    project = migration_project_row(project_id)
    if not project:
        return "Not found", 404
    try:
        affected = request.form.get("affected", "").strip()
        if affected:
            parts = affected.split("||||", 2)
            if len(parts) != 3:
                raise MigrationError("Het reviewitem is ongeldig")
            kind, name, source_ref = (part.strip() for part in parts)
        else:
            kind = request.form.get("kind", "").strip()
            name = request.form.get("name", "").strip()
            source_ref = request.form.get("source_ref", "").strip()
        if not name or kind not in MIGRATION_KIND_LABELS:
            raise MigrationError("Het reviewitem bestaat niet meer")
        with db() as conn:
            source_rows = conn.execute(
                "SELECT * FROM migration_sources WHERE project_id=? ORDER BY id",
                (project_id,),
            ).fetchall()
        matched_source = None
        for source in source_rows:
            items = model_collections(migration_model(source)).get(kind, [])
            for item in items:
                raw = item.__dict__ if hasattr(item, "__dict__") else item
                if str(raw.get("name", "")) == name and (
                    not source_ref or str(raw.get("source_ref", "")) == source_ref
                ):
                    matched_source = source
                    break
            if matched_source:
                break
        if not matched_source:
            raise MigrationError("Het reviewitem kon niet meer aan een importbron worden gekoppeld")
        workspace_id = ensure_migration_source_workspace(project, matched_source)
        if kind in {"security_rules", "nat_rules"}:
            return redirect(url_for(
                "config_workspace_editor",
                workspace_id=workspace_id,
                workspace_view="policies",
                policy_kind="security" if kind == "security_rules" else "nat",
                edit_policy=name,
            ))
        object_type = {
            "addresses": "addresses",
            "address_groups": "address-groups",
            "services": "services",
            "service_groups": "service-groups",
        }.get(kind)
        if object_type:
            return redirect(url_for(
                "config_workspace_editor",
                workspace_id=workspace_id,
                workspace_view="objects",
                object_type=object_type,
                edit_object=name,
            ))
        return redirect(url_for("config_workspace_editor", workspace_id=workspace_id))
    except Exception as exc:
        flash(f"Reviewitem niet geopend: {exc}", "error")
        return redirect(url_for("migration_project", project_id=project_id))


@app.post("/migration/projects/<int:project_id>/sources/<int:source_id>/sync-workspace")
@login_required
def migration_source_sync_workspace(project_id, source_id):
    project = migration_project_row(project_id)
    source = migration_source_row(source_id)
    if not project or not source or int(source["project_id"]) != project_id:
        return "Not found", 404
    try:
        workspace_id = int(source["staging_workspace_id"] or 0)
        workspace = workspace_row(workspace_id) if workspace_id else None
        if not workspace or int(workspace["profile_id"]) != int(project["target_profile_id"]):
            raise MigrationError("De importeditor-workspace ontbreekt")
        original = migration_model(source)
        edited = parse_vendor("panos", workspace_config_path(workspace).read_bytes(), source["source_name"])
        edited.vendor = original.vendor
        edited.source_name = original.source_name
        edited = restore_migration_source_topology(original, edited)
        unsupported_action_warnings = [
            message for message in original.warnings
            if "niet-ondersteunde Check Point actie" in message
        ]
        remaining_markers = sum(
            1 for rule in edited.security_rules
            if rule.description.startswith("REVIEW: actie")
        )
        preserved_warnings = [
            message for message in original.warnings
            if "niet-ondersteunde Check Point actie" not in message
        ] + unsupported_action_warnings[:remaining_markers]
        edited.warnings = list(dict.fromkeys([*edited.warnings, *preserved_warnings]))
        edited.unsupported = list(dict.fromkeys([*edited.unsupported, *original.unsupported]))
        replace_migration_source_model(source, edited)
        with db() as conn:
            outputs = conn.execute(
                "SELECT id,sanity_json FROM migration_outputs WHERE project_id=?", (project_id,)
            ).fetchall()
            for output in outputs:
                sanity = json.loads(output["sanity_json"] or "{}")
                sanity.update({"regenerate_required": True, "source_changed": True})
                conn.execute(
                    "UPDATE migration_outputs SET sanity_json=? WHERE id=?",
                    (json.dumps(sanity, sort_keys=True), output["id"]),
                )
        audit("migration-source-editor-synced", f"project={project_id} source={source_id} workspace={workspace_id}")
        flash("Wijzigingen uit de importeditor zijn opgenomen. Maak nu een nieuwe merge-preview.", "success")
    except Exception as exc:
        flash(f"Importwijzigingen niet opgenomen: {exc}", "error")
    return redirect(url_for("migration_project", project_id=project_id))


@app.post("/migration/projects/<int:project_id>/base")
@login_required
def migration_base_select(project_id):
    project = migration_project_row(project_id)
    if not project: return "Not found", 404
    try:
        selected_base = request.form.get("base_workspace_id", "")
        if selected_base == "best-practice":
            with db() as conn:
                profile = conn.execute(
                    "SELECT * FROM profiles WHERE id=?", (project["target_profile_id"],)
                ).fetchone()
            if not profile:
                raise MigrationError("Targetprofiel bestaat niet meer")
            workspace_id = create_migration_best_practice_workspace(
                profile, project_id, str(project["name"])
            )
        else:
            workspace_id = int(selected_base or 0)
        if workspace_id and not workspace_access_allowed(workspace_id, write=True):
            raise MigrationError("Deze base-workspace is niet beschikbaar voor dit project")
        with db() as conn:
            if workspace_id and not conn.execute("SELECT 1 FROM config_workspaces WHERE id=? AND profile_id=?", (workspace_id, project["target_profile_id"])).fetchone(): raise MigrationError("Base-workspace hoort niet bij het target")
            conn.execute("UPDATE migration_projects SET base_workspace_id=?,updated_at=? WHERE id=?", (workspace_id or None, now(), project_id))
            if workspace_id:
                link_workspace_project(conn, workspace_id, project_id)
        audit("migration-base-selected", f"project={project_id} workspace={workspace_id}")
        flash("Basisconfiguratie bijgewerkt.", "success")
    except Exception as exc: flash(f"Base configuration niet gekozen: {exc}", "error")
    return redirect(url_for("migration_project", project_id=project_id))


@app.post("/migration/projects/<int:project_id>/merge-rules")
@login_required
def migration_merge_rule_create(project_id):
    project=migration_project_row(project_id)
    if not project: return "Not found",404
    try:
        kind=request.form.get("kind","").strip(); mode=request.form.get("mode","selection").strip()
        selected=list(dict.fromkeys(value.strip() for value in request.form.getlist("member") if value.strip()))
        master=request.form.get("master","").strip() or (selected[0] if selected else "")
        if kind not in MIGRATION_KIND_LABELS: raise MigrationError("Onbekend configuratietype")
        if mode not in {"name","name_value","value","selection"}: raise MigrationError("Onbekende mergemethode")
        source_ids=[]
        with db() as conn:
            source_ids=[int(row["id"]) for row in conn.execute("SELECT id FROM migration_sources WHERE project_id=?",(project_id,)).fetchall()]
        model=selected_migration_model(project_id,source_ids)
        available={item_selector(item.__dict__ if hasattr(item,"__dict__") else item) for item in model_collections(model).get(kind,[])}
        members=merge_member_names(model,kind,master,mode,selected)
        if master not in members: members.insert(0,master)
        if not master or len(set(members)) < 2: raise MigrationError("Selecteer minstens twee items en één master")
        if not set(members).issubset(available): raise MigrationError("Een geselecteerd item bestaat niet in dit project")
        with db() as conn:
            conn.execute("INSERT INTO migration_merge_rules(project_id,kind,master,members_json,mode,created_at) VALUES(?,?,?,?,?,?)",(project_id,kind,master,json.dumps(members),mode,now()))
            conn.execute("UPDATE migration_projects SET updated_at=? WHERE id=?",(now(),project_id))
        master_name=master.split("|||",1)[0]
        audit("migration-merge-rule-created",f"project={project_id} kind={kind} master={master_name} members={len(members)}")
        flash(f"{len(members)} items worden samengevoegd naar {master_name}.","success")
    except Exception as exc: flash(f"Merge-keuze niet opgeslagen: {exc}","error")
    return redirect(url_for("migration_project",project_id=project_id))


@app.post("/migration/projects/<int:project_id>/merge-rules/<int:rule_id>/delete")
@login_required
def migration_merge_rule_delete(project_id,rule_id):
    if not migration_project_row(project_id): return "Not found",404
    with db() as conn:
        deleted=conn.execute("DELETE FROM migration_merge_rules WHERE id=? AND project_id=?",(rule_id,project_id)).rowcount
    if deleted:
        audit("migration-merge-rule-deleted",f"project={project_id} rule={rule_id}")
        flash("Merge-keuze verwijderd.","success")
    return redirect(url_for("migration_project",project_id=project_id))


@app.post("/migration/projects/<int:project_id>/transforms")
@login_required
def migration_transform_create(project_id):
    if not migration_project_row(project_id): return "Not found",404
    try:
        operation=request.form.get("operation","").strip(); kind=request.form.get("kind","").strip(); selector=request.form.get("selector","").strip(); value=request.form.get("value","").strip()
        if operation!="replace_reference" and "||||" in selector:
            kind,selector=selector.split("||||",1)
        if operation not in {"rename","delete","disable","enable","replace_reference"}: raise MigrationError("Onbekende transformatie")
        if operation!="replace_reference" and kind not in MIGRATION_KIND_LABELS: raise MigrationError("Onbekend configuratietype")
        if not selector: raise MigrationError("Selecteer een item of referentie")
        if operation in {"rename","replace_reference"} and not value: raise MigrationError("Nieuwe waarde ontbreekt")
        if operation!="replace_reference":
            with db() as conn: source_ids=[int(row["id"]) for row in conn.execute("SELECT id FROM migration_sources WHERE project_id=?",(project_id,)).fetchall()]
            model=selected_migration_model(project_id,source_ids)
            available={item_selector(item.__dict__ if hasattr(item,"__dict__") else item) for item in model_collections(model).get(kind,[])}
            if selector not in available: raise MigrationError("Het geselecteerde item hoort niet bij dit type")
        with db() as conn:
            conn.execute("INSERT INTO migration_transform_rules(project_id,operation,kind,selector,value,created_at) VALUES(?,?,?,?,?,?)",(project_id,operation,kind,selector,value,now()))
            conn.execute("UPDATE migration_projects SET updated_at=? WHERE id=?",(now(),project_id))
        audit("migration-transform-created",f"project={project_id} operation={operation} kind={kind}"); flash("Transformatie opgeslagen.","success")
    except Exception as exc: flash(f"Transformatie niet opgeslagen: {exc}","error")
    return redirect(url_for("migration_project",project_id=project_id))


@app.post("/migration/projects/<int:project_id>/transforms/<int:rule_id>/delete")
@login_required
def migration_transform_delete(project_id,rule_id):
    if not migration_project_row(project_id): return "Not found",404
    with db() as conn: deleted=conn.execute("DELETE FROM migration_transform_rules WHERE id=? AND project_id=?",(rule_id,project_id)).rowcount
    if deleted: audit("migration-transform-deleted",f"project={project_id} rule={rule_id}"); flash("Transformatie verwijderd.","success")
    return redirect(url_for("migration_project",project_id=project_id))


@app.post("/migration/projects/<int:project_id>/preview")
@login_required
def migration_merge_preview(project_id):
    project = migration_project_row(project_id)
    if not project: return "Not found", 404
    try:
        source_ids = [int(value) for value in request.form.getlist("source_id")]
        if not source_ids:
            raise MigrationError("Selecteer minstens één bronconfiguratie")
        with db() as conn:
            unresolved_families = conn.execute(
                f"SELECT kind FROM migration_family_mappings WHERE project_id=? AND action='review' "
                f"AND source_id IN ({','.join('?' for _ in source_ids)}) LIMIT 12",
                (project_id, *source_ids),
            ).fetchall()
            topology_decision_rows = conn.execute(
                "SELECT kind,selector,operation FROM migration_transform_rules "
                "WHERE project_id=? AND operation LIKE 'topology_%'",
                (project_id,),
            ).fetchall()
            selected_source_rows = conn.execute(
                f"SELECT * FROM migration_sources WHERE project_id=? "
                f"AND id IN ({','.join('?' for _ in source_ids)})",
                (project_id, *source_ids),
            ).fetchall()
        if unresolved_families:
            labels = ", ".join(
                MIGRATION_KIND_LABELS.get(row["kind"], row["kind"])
                for row in unresolved_families
            )
            raise MigrationError(f"Beslis eerst de bronmapping voor: {labels}")
        model = selected_migration_model(project_id, source_ids)
        selected_kinds = set(request.form.getlist("kind"))
        if not selected_kinds: raise MigrationError("Selecteer minstens één configuratietype")
        topology_decisions = {
            (row["kind"], row["selector"]): row["operation"]
            for row in topology_decision_rows
        }
        pending_topology = []
        for source in selected_source_rows:
            source_model = migration_model(source)
            for kind in MIGRATION_TOPOLOGY_KINDS & selected_kinds:
                for item in model_collections(source_model).get(kind, []):
                    raw = item if isinstance(item, dict) else item.__dict__
                    selector = item_selector(raw)
                    operation = topology_decisions.get((kind, selector), "topology_review")
                    if operation == "topology_review":
                        pending_topology.append(
                            f"{MIGRATION_KIND_LABELS.get(kind, kind)}: {raw.get('name', '')}"
                        )
        if pending_topology:
            raise MigrationError(
                "Beslis eerst de topologiemapping voor: " + ", ".join(pending_topology[:12])
            )
        for attr in ("addresses", "address_groups", "services", "service_groups", "security_rules", "nat_rules", "interfaces", "zones"):
            if attr not in selected_kinds: setattr(model, attr, [])
        model.extras={kind:items for kind,items in model.extras.items() if kind in selected_kinds}
        with db() as conn:
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (project["target_profile_id"],)).fetchone()
        if not profile: raise MigrationError("Targetprofiel bestaat niet meer")
        base_fingerprint = ""
        if profile["target_type"] == "scm":
            if model.interfaces or model.zones:
                raise MigrationError("PAN-OS interfaces en zones kunnen alleen naar een Panorama/PAN-OS XML-workspace worden gemerged; SCM-netwerkmapping is nog niet beschikbaar")
            unsupported=scm_migration_unsupported(model)
            if unsupported: raise MigrationError("Nog geen veilige SCM-outputmapping voor: "+", ".join(MIGRATION_KIND_LABELS.get(kind,kind) for kind in unsupported))
            model, plan = reconcile_model(model, migration_target_inventory(profile))
            plan["create"] += sum(len(items) for items in model.extras.values())
        else:
            base_id = int(project["base_workspace_id"] or 0)
            workspace = workspace_row(base_id) if base_id else None
            if workspace and int(workspace["profile_id"]) != int(profile["id"]):
                raise MigrationError("De gekozen base-workspace hoort niet bij het targetprofiel")
            settings = profile_settings(profile); panorama = profile["target_type"] == "panorama"
            scope = settings.get("device_group", "") if panorama else settings.get("vsys", "vsys1")
            base_xml = workspace_config_path(workspace).read_bytes() if workspace else migration_base_xml(model, scope, panorama)
            base_fingerprint = hashlib.sha256(base_xml).hexdigest()
            nat_topology = auto_map_nat_topology(base_xml, model, scope, panorama)
            _, plan = merge_model_into_panos_xml(
                base_xml, model, scope, panorama, settings.get("rulebase", "pre")
            )
            plan["nat_topology"] = nat_topology
        if int(plan.get("create", 0)) == 0:
            raise MigrationError("De selectie veroorzaakt geen wijziging aan de target candidate")
        family_delta = []
        for kind, items in model_collections(model).items():
            if items:
                family_delta.append({
                    "kind": kind,
                    "label": MIGRATION_KIND_LABELS.get(kind, kind.replace("_", " ").title()),
                    "selected": len(items),
                })
        plan["family_delta"] = family_delta
        draft_id = secrets.token_urlsafe(18)
        review = migration_review_findings(model)
        draft = {
            "project_id": project_id,
            "target_profile_id": project["target_profile_id"],
            "source_ids": source_ids,
            "model": model.as_dict(),
            "fingerprint": model.fingerprint(),
            "plan": plan,
            "review": review,
            "project_revision": migration_project_revision(project_id),
            "project_updated_at": project["updated_at"],
            "profile_settings_fingerprint": hashlib.sha256(
                str(profile["settings_json"] or "{}").encode()
            ).hexdigest(),
            "base_workspace_id": int(project["base_workspace_id"] or 0),
            "base_fingerprint": base_fingerprint,
            "created_at": now(),
        }
        path = OBJECT_DRAFTS / f"migration-{draft_id}.json"; path.write_text(json.dumps(draft)); path.chmod(0o600)
        counts = model.counts()
        if profile["target_type"] != "scm" and not workspace:
            counts["zones"] = len(migration_zone_names(model))
        return render_template(
            "migration_preview.html", project=project, model=model, counts=counts,
            plan=plan, review=review, family_delta=family_delta, draft_id=draft_id,
        )
    except Exception as exc:
        flash(f"Merge-preview mislukt: {exc}", "error")
        return redirect(url_for("migration_project", project_id=project_id))


@app.post("/migration/drafts/<draft_id>/apply")
@login_required
def migration_merge_apply(draft_id):
    if not draft_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in draft_id): return "Not found", 404
    path = OBJECT_DRAFTS / f"migration-{draft_id}.json"
    if not path.is_file(): return "Not found", 404
    draft = json.loads(path.read_text()); project = migration_project_row(int(draft["project_id"]))
    if not project: return "Not found", 404
    try:
        model = MigrationModel.from_dict(draft["model"])
        if not hmac.compare_digest(model.fingerprint(), draft["fingerprint"]): raise MigrationError("Merge-draft is gewijzigd")
        if not hmac.compare_digest(
            migration_project_revision(int(project["id"])), str(draft.get("project_revision", ""))
        ):
            raise MigrationError("Het migratieproject is gewijzigd; maak een nieuwe preview")
        if not hmac.compare_digest(str(project["updated_at"]), str(draft.get("project_updated_at", ""))):
            raise MigrationError("Het migratieproject is gewijzigd; maak een nieuwe preview")
        review = migration_review_findings(model)
        stored_review = draft.get("review")
        if stored_review and not hmac.compare_digest(
            hashlib.sha256(json.dumps(review, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            hashlib.sha256(json.dumps(stored_review, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        ):
            raise MigrationError("Reviewresultaat is gewijzigd; maak een nieuwe preview")
        if request.form.get("review_acknowledged") != "reviewed":
            audit("migration-review-blocked", f"project={project['id']} draft={draft_id}")
            raise MigrationError("Bevestig eerst dat de volledige configuratie handmatig is nagekeken")
        approved_reuses = set(request.form.getlist("approved_reuse"))
        allowed_reuses = {
            str(item.get("key", ""))
            for item in draft.get("plan", {}).get("suggested_reuses", [])
            if str(item.get("key", ""))
        }
        if not approved_reuses.issubset(allowed_reuses):
            raise MigrationError("De gekozen objecthergebruikbeslissing hoort niet bij deze preview")
        audit("migration-review-acknowledged", f"project={project['id']} draft={draft_id} findings={len(review['findings'])}")
        with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (draft["target_profile_id"],)).fetchone()
        if not profile: raise MigrationError("Targetprofiel bestaat niet meer")
        current_profile_fingerprint = hashlib.sha256(
            str(profile["settings_json"] or "{}").encode()
        ).hexdigest()
        if not hmac.compare_digest(current_profile_fingerprint, str(draft.get("profile_settings_fingerprint", ""))):
            raise MigrationError("De targetcontext is gewijzigd; maak een nieuwe preview")
        if int(project["base_workspace_id"] or 0) != int(draft.get("base_workspace_id", 0)):
            raise MigrationError("De base-workspace is gewijzigd; maak een nieuwe preview")
        if profile["target_type"] != "scm" and int(project["base_workspace_id"] or 0):
            current_base = workspace_row(int(project["base_workspace_id"]))
            current_base_hash = hashlib.sha256(workspace_config_path(current_base).read_bytes()).hexdigest() if current_base else ""
            if not hmac.compare_digest(current_base_hash, str(draft.get("base_fingerprint", ""))):
                raise MigrationError("De base-configuratie is gewijzigd; maak een nieuwe preview")
        if profile["target_type"] == "scm":
            if int(review.get("critical", 0)) > 0:
                audit("migration-scm-push-blocked", f"project={project['id']} critical={review['critical']}")
                raise MigrationError("SCM candidate-write geblokkeerd: los eerst de kritieke reviewpunten op")
            model, plan = reconcile_model(model, migration_target_inventory(profile), approved_reuses)
            plan["create"] += sum(len(items) for items in model.extras.values())
            if int(plan.get("create", 0)) == 0:
                raise MigrationError("De target is gewijzigd en de selectie veroorzaakt geen nieuwe candidatewijziging")
            count = apply_scm_migration(profile, model)
            outcome = f"{count} configuratie-items naar SCM candidate geschreven"
        else:
            settings = profile_settings(profile)
            panorama = profile["target_type"] == "panorama"
            scope = settings.get("device_group", "") if panorama else settings.get("vsys", "vsys1")
            base_id = int(project["base_workspace_id"] or 0)
            current_base = workspace_row(base_id) if base_id else None
            preflight_xml = workspace_config_path(current_base).read_bytes() if current_base else migration_base_xml(model, scope, panorama)
            nat_topology = auto_map_nat_topology(preflight_xml, model, scope, panorama)
            _, preflight_plan = merge_model_into_panos_xml(
                preflight_xml, model, scope, panorama, settings.get("rulebase", "pre"), approved_reuses
            )
            preflight_plan["nat_topology"] = nat_topology
            if int(preflight_plan.get("create", 0)) == 0:
                raise MigrationError("De selectie veroorzaakt geen wijziging aan de target candidate")
            workspace_id, plan = create_merged_workspace(profile, project, model, approved_reuses)
            source_analysis = migration_analysis(model)
            candidate_analysis = panos_candidate_analysis(
                workspace_config_path(workspace_row(workspace_id)).read_bytes()
            )
            candidate_unresolved = len(candidate_analysis["unresolved_references"])
            critical_review_codes = {
                str(finding["code"]): {
                    "title": str(finding["title"]),
                    "detail": str(finding["detail"]),
                    "count": int(finding.get("count", 0) or 0),
                    "severity": "critical",
                }
                for finding in review["findings"]
                if finding["severity"] == "critical"
            }
            review_codes = {
                str(finding["code"]): {
                    "title": str(finding["title"]),
                    "detail": str(finding["detail"]),
                    "count": int(finding.get("count", 0) or 0),
                    "severity": str(finding["severity"]),
                }
                for finding in review["findings"]
                if finding["severity"] in {"critical", "warning"}
            }
            output_id = store_migration_output(
                int(project["id"]),
                workspace_id,
                f"{project['name']} · PAN-OS candidate",
                str(project["topology"] or "active-passive"),
                sanity={
                    "unresolved_references": candidate_unresolved,
                    "candidate_unresolved_references": candidate_unresolved,
                    "unresolved_applications": len(candidate_analysis["unresolved_application_references"]),
                    "duplicate_rules": len(candidate_analysis["duplicate_rules"]),
                    "unused_objects": sum(
                        len(source_analysis[key])
                        for key in (
                            "unused_addresses",
                            "unused_address_groups",
                            "unused_services",
                            "unused_service_groups",
                        )
                    ),
                    "critical_findings": len(critical_review_codes) + (1 if candidate_unresolved else 0),
                    "critical_review_codes": critical_review_codes,
                    "review_codes": review_codes,
                    "review_warnings": int(review["warnings"]),
                    "regenerate_required": False,
                },
            )
            with db() as conn:
                older_outputs = conn.execute(
                    "SELECT id,sanity_json FROM migration_outputs WHERE project_id=? AND id<>?",
                    (project["id"], output_id),
                ).fetchall()
                for older in older_outputs:
                    older_sanity = json.loads(older["sanity_json"] or "{}")
                    older_sanity.update({"regenerate_required": True, "superseded": True})
                    conn.execute(
                        "UPDATE migration_outputs SET sanity_json=? WHERE id=?",
                        (json.dumps(older_sanity, sort_keys=True), older["id"]),
                    )
            count = int(plan["create"])
            outcome = f"Werkruimte #{workspace_id} met {count} nieuwe configuratie-items gemaakt en geselecteerd"
        path.unlink(missing_ok=True)
        audit("migration-candidate", f"project={project['id']} profile={profile['name']} target={profile['target_type']} count={count}")
        flash(f"{outcome}; er is niet gecommit of gedeployed.", "success")
    except Exception as exc: flash(f"Merge naar candidate gestopt: {exc}", "error")
    return redirect(url_for("migration_project", project_id=project["id"]))


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


def parse_zone_fields(form) -> dict[str, str]:
    names = form.getlist("zone_name")
    roles = form.getlist("zone_role")
    if not names:
        return parse_zones(form.get("zones", ""))
    if len(names) != len(roles):
        raise ValueError("De zonemapping is onvolledig")
    result = {}
    for name, role in zip(names, roles):
        name = str(name).strip()
        role = str(role).strip()
        if not name:
            raise ValueError("Een zonenaam ontbreekt")
        if role not in {"client", "server", "internet", "other"}:
            raise ValueError(f"Ongeldige rol voor {name}")
        result[name] = role
    if not result:
        raise ValueError("Haal eerst de zones op en wijs ze een rol toe")
    return result


@app.post("/profiles/save")
@login_required
def profile_save():
    profile_id = 0
    saved_profile_id = 0
    try:
        profile_id = int(request.form.get("id") or 0)
        preserved_workspace_id = 0
        existing_profile = None
        if profile_id:
            with db() as conn:
                existing_profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
            if not existing_profile:
                return "Not found", 404
            if int(existing_profile["system"] or 0):
                raise ValueError("Interne offline targets kunnen niet als deviceprofiel worden bewerkt")
            preserved_workspace_id = active_config_workspace_id(existing_profile)
        target_type = request.form.get("target_type", "") if profile_id else UNCONFIGURED_TARGET
        if profile_id and target_type not in TARGET_TYPES: raise ValueError("Kies waar dit device wordt beheerd")
        rulebase = request.form.get("rulebase", "pre")
        if rulebase not in {"pre", "post"}: raise ValueError("Rulebase moet pre of post zijn")
        vsys_mode = request.form.get("vsys_mode", "single")
        if vsys_mode not in {"single", "multi"}: raise ValueError("Kies single-VSYS of multi-VSYS")
        vsys_count_raw = request.form.get("vsys_count", "")
        old_settings = profile_settings(existing_profile) if existing_profile else {}
        vsys_count = int(vsys_count_raw or old_settings.get("vsys_count") or 2)
        if vsys_mode == "multi" and not 2 <= vsys_count <= 32:
            raise ValueError("Het verwachte aantal VSYS moet tussen 2 en 32 liggen")
        active_serial = request.form.get("serial", "").strip()
        if not active_serial:
            raise ValueError("Serienummer van de actieve firewall is verplicht")
        passive_serial = request.form.get("passive_serial", "").strip()
        if passive_serial and passive_serial == active_serial:
            raise ValueError("Passieve serial moet verschillen van de actieve serial")
        zone_rows_submitted = bool(request.form.getlist("zone_name"))
        settings = {
            "configured": bool(profile_id),
            "zones": (
                parse_zone_fields(request.form)
                if profile_id and zone_rows_submitted
                else dict(profile_settings(existing_profile).get("zones", {})) if profile_id else {}
            ),
            "min_sessions": max(1, int(request.form.get("min_sessions", "10"))),
            "disabled": request.form.get("disabled") == "on",
            "tags": [x.strip() for x in request.form.get("tags", "AI builder").split(",") if x.strip()],
            "global_ping": request.form.get("global_ping") == "on" if profile_id else True,
            "global_dns": request.form.get("global_dns") == "on" if profile_id else True,
            "endpoint": validate_panos_endpoint(request.form.get("endpoint", "")) if profile_id and target_type in {"panorama", "panos"} else "",
            "vsys": request.form.get("vsys", "vsys1").strip(),
            "vsys_mode": vsys_mode,
            "vsys_count": vsys_count,
            "device_group": request.form.get("device_group", "").strip(),
            "rulebase": rulebase,
            "folder": request.form.get("folder", "").strip(),
            "snippet": request.form.get("snippet", "").strip(),
            "device": request.form.get("device", "").strip(),
            "object_folder": request.form.get("object_folder", "").strip(),
            "log_profile": request.form.get("log_profile", "").strip(),
            "profile_group": request.form.get("profile_group", "").strip(),
            "passive_serial": passive_serial,
            "passive_source_ip": optional_ip_address(request.form.get("passive_source_ip", "")),
        }
        if (
            existing_profile
            and existing_profile["target_type"] == target_type
            and old_settings.get("endpoint") == settings["endpoint"]
            and target_type in {"panos", "panorama"}
        ):
            # Keep a previously confirmed endpoint certificate only while its exact
            # target identity remains unchanged.
            for key in ("tls_pinned_certificate", "tls_pinned_fingerprint", "tls_pinned_endpoint", "tls_allow_hostname_mismatch"):
                if old_settings.get(key):
                    settings[key] = old_settings[key]
        if preserved_workspace_id:
            settings["config_workspace_id"] = preserved_workspace_id
        supplied = {k: request.form.get(k, "") for k in ("username", "password", "client_id", "client_secret", "tsg_id")}
        if profile_id and target_type in {"panorama", "panos"} and not settings["endpoint"]:
            raise ValueError("Endpoint is verplicht voor Panorama en standalone PAN-OS")
        if profile_id and target_type == "panorama" and not settings["device_group"]:
            raise ValueError("Device group is verplicht voor Panorama")
        if profile_id and target_type == "scm" and sum(bool(settings[k]) for k in ("folder", "snippet", "device")) != 1:
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
            enabled = request.form.get("enabled") == "on" if profile_id else True
            values = (request.form["name"].strip(), enabled, active_serial, optional_ip_address(request.form.get("source_ip", "")), target_type, json.dumps(settings), blob, now())
            if profile_id:
                conn.execute("UPDATE profiles SET name=?,enabled=?,serial=?,source_ip=?,target_type=?,settings_json=?,secret_blob=?,updated_at=? WHERE id=?", (*values, profile_id))
            else:
                cursor = conn.execute("INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", (*values, now()))
                profile_id = int(cursor.lastrowid)
            saved_profile_id = profile_id
        invalidate_profile_caches(profile_id)
        refresh_syslog_source_policy()
        audit("profile-saved", request.form["name"])
        if target_type == UNCONFIGURED_TARGET:
            message = "Device opgeslagen. Configureer nu het beheerplatform en de actuele zones."
        elif not zone_rows_submitted and not settings["zones"]:
            message = "Beheerplatform opgeslagen. De actuele zones zijn opgehaald; wijs nu per zone de rol toe."
        else:
            message = "Device-instellingen en zonemappings opgeslagen."
        flash(message, "success")
    except Exception as exc:
        flash(f"Profiel niet opgeslagen: {exc}", "error")
    target_id = saved_profile_id or profile_id
    return redirect((url_for("index", edit_profile=target_id) if target_id else url_for("index")) + "#profiles")


@app.post("/profiles/<int:profile_id>/delete")
@login_required
def profile_delete(profile_id):
    try:
        with db() as conn:
            row = conn.execute("SELECT name,system FROM profiles WHERE id=?", (profile_id,)).fetchone()
            if not row: return "Not found", 404
            if int(row["system"] or 0): raise ValueError("Interne offline targets kunnen niet worden verwijderd")
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
    if not profile_is_configured(profile): raise ValueError("Open het device en configureer eerst het beheerplatform en de zones")
    if target not in TARGET_TYPES: raise ValueError("Onbekend targettype")
    if target in {"panorama", "panos"}: s["endpoint"] = validate_panos_endpoint(s.get("endpoint", ""))
    generated_disabled = s.get("disabled") if disabled_override is None else disabled_override
    lines = [
        "[deployment]", f"panorama = {'true' if target == 'panorama' else 'false'}", f"scm = {'true' if target == 'scm' else 'false'}", "",
        "[builder]", 'logs = ["flows.csv"]', 'xml_output = "policy.xml"', 'review_csv = "review.csv"', 'ptr_cache_file = "ptr-cache.json"',
        f"disabled = {'true' if generated_disabled else 'false'}", "tags = [" + ",".join(toml_string(x) for x in s.get("tags", [])) + "]",
        f"global_ping_traceroute = {'true' if s.get('global_ping', True) else 'false'}", 'global_ping_traceroute_apps = ["ping","traceroute"]',
        f"global_dns = {'true' if s.get('global_dns', True) else 'false'}", 'global_dns_apps = ["dns-base"]', 'global_dns_internal_resolvers = []', 'global_dns_external_resolvers = ["1.1.1.1","9.9.9.9"]',
        f"min_sessions = {s.get('min_sessions', 10)}", "limit = 0", "group_threshold = 10", "source_any_threshold = 5", f"workers = {max(1, (os.cpu_count() or 1) - 2)}", 'include_actions = ["allow"]', f"log_setting = {toml_string(s.get('log_profile',''))}", "",
        "[panorama]", f"panorama_template = {toml_string(s.get('device_group',''))}", f"panorama_rulebase = {toml_string(s.get('rulebase','pre'))}", f"panorama_log_setting = {toml_string(s.get('log_profile',''))}", "",
        "[panos]", f"panos_vsys = {toml_string(s.get('vsys','vsys1'))}", f"panos_log_setting = {toml_string(s.get('log_profile',''))}", f"panos_endpoint = {toml_string(s.get('endpoint',''))}", 'panos_username = ""', 'panos_password = ""', f"panos_auto_push = {'true' if push else 'false'}", "",
        "[scm]", 'scm_client_id = ""', 'scm_client_secret = ""', 'scm_tsg_id = ""', 'scm_token_url = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"', 'scm_api_base = "https://api.strata.paloaltonetworks.com/config/security/v1"', f"scm_folder = {toml_string(s.get('folder',''))}", f"scm_snippet = {toml_string(s.get('snippet',''))}", f"scm_device = {toml_string(s.get('device',''))}", f"scm_object_folder = {toml_string(s.get('object_folder') or s.get('folder',''))}", f"scm_rulebase = {toml_string(s.get('rulebase','pre'))}", f"scm_log_forwarding_profile = {toml_string(s.get('log_profile',''))}", "",
        "[profile_groups]", f"client = {toml_string(s.get('profile_group',''))}", f"server = {toml_string(s.get('profile_group',''))}", f"internet = {toml_string(s.get('profile_group',''))}", f"other = {toml_string(s.get('profile_group',''))}", "", "[zone_roles]",
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
        reference_catalog = extend_policy_catalog_with_current(fetch_object_catalog(profile, "policy-picker"), current)
        reference_index = build_policy_reference_index(reference_catalog)
        changes = []; zones_changed = profile["target_type"] != "panorama" and any(operations[field]["add"] or operations[field]["remove"] for field in ("from", "to")); zone_names = {item.get("name", "") for item in fetch_scm_objects(profile, "zones")} if zones_changed else set()
        for policy in selected:
            updated = apply_bulk_operations(policy, operations)
            if zones_changed: validate_policy_zones(updated, zone_names)
            if updated != policy:
                changed_fields = {field for field in set(policy) | set(updated) if policy.get(field) != updated.get(field)}
                validate_policy_references(updated, reference_index, changed_fields, allow_zone_freeform=profile["target_type"] == "panorama")
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
        new_name = request.form.get("name", "").strip()
        if not new_name:
            raise ValueError("Policy name is verplicht")
        if any(item["id"] != policy_id and item.get("name") == new_name for item in current):
            raise ValueError(f"Policy {new_name} bestaat al in deze rulebase")
        replacements = {"name": new_name}
        for field in POLICY_LIST_FIELDS:
            if request.form.get(f"{field}_present") == "1":
                values = split_values(request.form.get(field, ""))
                replacements[field] = values or ([] if field == "tag" else ["any"])
        for field in ("action", "log_setting", "profile_group", "schedule"):
            if request.form.get(f"{field}_present") == "1": replacements[field] = request.form.get(field, "").strip()
        if policy_kind == "nat":
            replacements.update(nat_translation_replacements(request.form))
        if request.form.get("description_present") == "1": replacements["description"] = request.form.get("description", "").strip()
        if request.form.get("disabled_present") == "1": replacements["disabled"] = request.form.get("disabled") == "true"
        updated = apply_single_replacements(policy, replacements)
        if profile["target_type"] != "panorama" and (updated.get("from") != policy.get("from") or updated.get("to") != policy.get("to")):
            validate_policy_zones(updated, {item.get("name", "") for item in fetch_scm_objects(profile, "zones")})
        changed_fields = {field for field in set(policy) | set(updated) if policy.get(field) != updated.get(field)}
        validate_policy_references(
            updated, extend_policy_catalog_with_current(fetch_object_catalog(profile, "policy-picker"), current), changed_fields,
            allow_zone_freeform=profile["target_type"] == "panorama",
        )
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
    if object_type not in SCM_OBJECT_TYPES or not SCM_OBJECT_TYPES[object_type].get("editable", SCM_OBJECT_TYPES[object_type].get("creatable", False)): return "Not found", 404
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile: return "Not found", 404
    try:
        metadata = SCM_OBJECT_TYPES[object_type]
        container = {}
        if profile["target_type"] == "scm":
            scm, _, _, _ = scm_client(profile)
            container = policy_api.scm_container(folder=scm.scm_folder if object_type == "zones" else scm.scm_object_folder, snippet=scm.scm_snippet, device=scm.scm_device)
        existing = fetch_scm_objects(profile, object_type)
        object_id = request.form.get("object_id", "").strip()
        before = next((item for item in existing if str(item.get("id", "")) == object_id), None) if object_id else None
        if object_id and not before: raise ValueError("Het object bestaat niet meer. Vernieuw de lijst.")
        if metadata.get("generic"):
            if profile["target_type"] != "scm": raise ValueError("Gebruik de XML-workspace voor dit target")
            name = request.form.get("name", "").strip()
            if not name: raise ValueError("Naam is verplicht")
            if any(item.get("name") == name and str(item.get("id", "")) != object_id for item in existing): raise ValueError(f"Object {name} bestaat al")
            try: submitted = json.loads(request.form.get("generic_updates", "[]"))
            except json.JSONDecodeError as exc: raise ValueError("Ongeldige profielvelden") from exc
            schema_record = before or scm_generic_create_record(object_type, container)
            if schema_record is None: raise ValueError("Voor dit objecttype is geen geldig SCM create-schema beschikbaar")
            editable_fields = [field for field in schema_record.get("edit_fields", []) if field.get("kind") != "protected"]
            allowed = {(field["path"], field["kind"]) for field in editable_fields}
            if not isinstance(submitted, list) or len(submitted) > 10000: raise ValueError("Ongeldige profielvelden")
            updates = []
            for update in submitted:
                if not isinstance(update, dict) or (update.get("path"), update.get("kind")) not in allowed: raise ValueError("Een profielveld bestaat niet meer of is beschermd")
                clean = {"path": update["path"], "kind": update["kind"]}
                if update["kind"] == "members": clean["values"] = [str(value).strip() for value in update.get("values", []) if str(value).strip()]
                else: clean["value"] = str(update.get("value", ""))[:65535]
                updates.append(clean)
            if object_type == "url-filtering": updates = normalize_url_profile_updates(editable_fields, updates)
            payload = _scm_config_payload(schema_record["_raw"], updates, name)
            if before is not None and _scm_config_fingerprint(payload) == _scm_config_fingerprint(before["_raw"]): raise ValueError("Er zijn geen wijzigingen om te bewaren")
        else:
            payload = scm_object_payload(object_type, request.form, container)
            validate_object_payload(payload, object_type, existing, object_id)
            validate_object_references(payload, object_type, fetch_object_catalog(profile, object_type))
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
    if object_type not in SCM_OBJECT_TYPES or not SCM_OBJECT_TYPES[object_type].get("editable", SCM_OBJECT_TYPES[object_type].get("creatable", False)): return "Not found", 404
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile: return "Not found", 404
    try:
        delete_unused = request.form.get("delete_unused") == "yes"
        if delete_unused and object_type not in UNUSED_OBJECT_TYPES:
            raise ValueError("Ongebruikt verwijderen is niet beschikbaar voor dit objecttype")
        selected_ids = set(request.form.getlist("object_id"))
        current = fetch_scm_objects(profile, object_type)
        references = None
        if not selected_ids and not delete_unused:
            raise ValueError("Selecteer minstens één object")
        if delete_unused:
            references = validate_live_object_deletions(profile, object_type, [str(item.get("name", "")) for item in current])
            selected_ids = {
                str(item.get("id", "")) for item in current
                if item.get("name") and not references.get(str(item["name"]))
            }
            if not selected_ids:
                raise ValueError("Geen ongebruikte objecten gevonden in deze scope")
        selected = [item for item in current if str(item.get("id", "")) in selected_ids]
        if len(selected) != len(selected_ids): raise ValueError("Niet alle geselecteerde objecten bestaan nog. Vernieuw de lijst.")
        selected_names = [str(item.get("name", "")) for item in selected]
        if references is None:
            validate_live_object_deletions(profile, object_type, selected_names)
        elif any(references.get(name) for name in selected_names):
            raise ValueError("Een van de geselecteerde objecten wordt inmiddels gebruikt; niets verwijderd")
        draft_id = secrets.token_urlsafe(18)
        draft = {"profile_id": profile_id, "created_at": now(), "object_type": object_type, "operation": "delete", "delete_unused": delete_unused, "objects": [{"value": item, "fingerprint": object_fingerprint(item)} for item in selected]}
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
    deleted_count = 0
    delete_progress = [0]
    try:
        object_type = draft["object_type"]
        metadata = SCM_OBJECT_TYPES[object_type]
        current = fetch_scm_objects(profile, object_type)
        operation = draft.get("operation", "create")
        if operation == "create":
            if metadata.get("generic"):
                if any(item.get("name") == draft["payload"].get("name") for item in current):
                    raise RuntimeError(f"Object {draft['payload'].get('name')} bestaat al")
            else:
                validate_object_payload(draft["payload"], object_type, current)
        elif operation == "update":
            before = draft["before"]; live = next((item for item in current if str(item.get("id", "")) == str(before.get("id", ""))), None)
            if not live or object_fingerprint(live) != draft["fingerprint"]: raise RuntimeError(f"Object {before['name']} is intussen gewijzigd; Push gestopt.")
            if metadata.get("generic"):
                if any(item.get("name") == draft["payload"].get("name") and str(item.get("id", "")) != str(before["id"]) for item in current): raise RuntimeError(f"Object {draft['payload'].get('name')} bestaat al")
            else:
                validate_object_payload(draft["payload"], object_type, current, str(before["id"]))
        elif operation == "delete":
            current_by_id = {str(item.get("id", "")): item for item in current}
            current_by_name = {str(item.get("name", "")): item for item in current}
            pending_entries = []
            for entry in draft["objects"]:
                before = entry["value"]
                live = current_by_id.get(str(before.get("id", "")))
                if not live:
                    if str(before.get("name", "")) in current_by_name:
                        raise RuntimeError(f"Object {before['name']} heeft intussen een andere identiteit; Delete gestopt.")
                    # A previous multi-delete may have completed before a later API error.
                    # Treat an already absent object as complete on retry.
                    continue
                if object_fingerprint(live) != entry["fingerprint"]:
                    raise RuntimeError(f"Object {before['name']} is intussen gewijzigd; Delete gestopt.")
                pending_entries.append(entry)
            draft = {**draft, "objects": pending_entries}
            if pending_entries:
                validate_live_object_deletions(
                    profile, object_type,
                    [str(entry["value"].get("name", "")) for entry in pending_entries],
                )
        else: raise RuntimeError("Onbekende objectbewerking")
        if operation in {"create", "update"} and not metadata.get("generic"):
            validate_object_references(
                draft["payload"], object_type, fetch_object_catalog(profile, object_type)
            )
        if profile["target_type"] == "scm":
            scm, token, _, _ = scm_client(profile)
            service = metadata.get("service") or ("network" if object_type == "zones" else "objects")
            endpoint_name = metadata.get("endpoint", object_type)
            root = policy_api.scm_api_root(scm.scm_api_base) + f"/config/{service}/v1"
            container = policy_api.scm_container(folder=scm.scm_folder if object_type == "zones" else scm.scm_object_folder, snippet=scm.scm_snippet, device=scm.scm_device)
            payload = copy.deepcopy(draft.get("payload") or {})
            if object_type == "log-forwarding":
                payload.pop("enhanced_application_logging", None)
                for match in payload.get("match_list", []):
                    match.pop("send_to_panorama", None)
                    match.pop("quarantine", None)
                    match.pop("actions", None)
            if operation == "create": policy_api.scm_http_request("POST", f"{root}/{endpoint_name}", token, payload=payload)
            elif operation == "update": policy_api.scm_http_request("PUT", f"{root}/{endpoint_name}/{draft['before']['id']}", token, payload=payload)
            else:
                for entry in draft["objects"]:
                    policy_api.scm_http_request("DELETE", f"{root}/{endpoint_name}/{entry['value']['id']}", token, params=container)
                    deleted_count += 1
        else:
            write_panos_object_draft(
                profile, draft,
                on_delete=lambda: delete_progress.__setitem__(0, delete_progress[0] + 1),
            )
            deleted_count = delete_progress[0]
        path.unlink()
        count = len(draft.get("objects", [])) or 1
        audit("object-candidate", f"profile={profile['name']} operation={operation} type={object_type} count={count}")
        flash(f"Objectbewerking ({operation}) geschreven naar {profile['target_type'].upper()} candidate.", "success")
    except Exception as exc:
        deleted_count = max(deleted_count, delete_progress[0])
        partial = f" ({deleted_count} object(en) al verwijderd; herhaal dezelfde preview om verder te gaan)" if deleted_count else ""
        flash(f"Object-Push gestopt: {exc}{partial}", "error")
    return redirect(url_for("index", policy_profile=profile["id"], policy_view=managed_view(draft["object_type"]), object_type=draft["object_type"]) + "#policy-management")


def _scm_config_redirect(profile_id: int, view: str, section: str):
    return redirect(url_for("index", policy_profile=profile_id, policy_view=view, config_section=section) + "#policy-management")


def _write_scm_configuration_draft(profile, draft: dict) -> None:
    current = fetch_scm_configuration_records(profile, draft["view"], draft["section"])
    scm, token, _, container = scm_client(profile)
    root = policy_api.scm_api_root(scm.scm_api_base) + f"/config/{draft['view']}/v1"
    if draft["operation"] in {"update", "create"}:
        before = next((item for item in current if item["endpoint"] == draft["endpoint"] and item["id"] == draft["before_id"]), None)
        if not before or before["fingerprint"] != draft["fingerprint"]:
            raise RuntimeError(f"Configuratie-item {draft['before_name']} is intussen gewijzigd; Save gestopt.")
        if draft["operation"] == "update":
            policy_api.scm_http_request("PUT", f"{root}/{draft['endpoint']}/{draft['before_id']}", token, payload=draft["payload"])
        else:
            policy_api.scm_http_request("POST", f"{root}/{draft['endpoint']}", token, payload=draft["payload"])
    else:
        for item in draft["items"]:
            before = next((record for record in current if record["endpoint"] == item["endpoint"] and record["id"] == item["id"]), None)
            if not before or before["fingerprint"] != item["fingerprint"]:
                raise RuntimeError(f"Configuratie-item {item['name']} is intussen gewijzigd; Delete gestopt.")
        for item in draft["items"]:
            policy_api.scm_http_request("DELETE", f"{root}/{item['endpoint']}/{item['id']}", token, params=container)


@app.post("/scm-configuration/<int:profile_id>/<view>/<section>/preview")
@login_required
def scm_configuration_preview(profile_id, view, section):
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile or profile["target_type"] != "scm" or section not in SCM_CONFIGURATION_SECTIONS.get(view, {}): return "Not found", 404
    try:
        records = fetch_scm_configuration_records(profile, view, section)
        before = next((item for item in records if item["locator"] == request.form.get("locator", "")), None)
        if before is None: raise ValueError("Het SCM-configuratie-item bestaat niet meer")
        submitted = json.loads(request.form.get("generic_updates", "[]"))
        allowed = {(field["path"], field["kind"]) for field in before["edit_fields"] if field["kind"] != "protected"}
        if not isinstance(submitted, list) or len(submitted) > 10000: raise ValueError("Ongeldige SCM-configuratievelden")
        updates = []
        for update in submitted:
            if not isinstance(update, dict) or (update.get("path"), update.get("kind")) not in allowed: raise ValueError("Een SCM-configuratieveld bestaat niet meer of is beschermd")
            clean = {"path": update["path"], "kind": update["kind"]}
            if update["kind"] == "members": clean["values"] = [str(value).strip() for value in update.get("values", []) if str(value).strip()]
            else: clean["value"] = str(update.get("value", ""))[:65535]
            updates.append(clean)
        operation = request.form.get("operation", "update")
        if operation not in {"update", "create"}: raise ValueError("Ongeldige SCM-configuratiebewerking")
        name = request.form.get("name", "").strip()
        if not name: raise ValueError("Name is verplicht")
        payload = _scm_config_payload(before["_raw"], updates, name)
        if operation == "create": payload.pop("id", None)
        elif _scm_config_fingerprint(payload) == before["fingerprint"]: raise ValueError("Er zijn geen wijzigingen om te bewaren")
        draft_id = secrets.token_urlsafe(18)
        draft = {"profile_id": profile_id, "view": view, "section": section, "operation": operation, "endpoint": before["endpoint"], "before_id": before["id"], "before_name": before["name"], "fingerprint": before["fingerprint"], "name": name, "payload": payload, "created_at": now()}
        if request.form.get("direct_save") == "yes":
            _write_scm_configuration_draft(profile, draft)
            invalidate_profile_caches(profile["id"])
            audit("scm-configuration-candidate", f"profile={profile['name']} view={view} section={section} operation={operation}")
            flash("Configuratie rechtstreeks naar de SCM candidate bewaard.", "success")
            return _scm_config_redirect(profile_id, view, section)
        path = OBJECT_DRAFTS / f"scm-config-{draft_id}.json"; path.write_text(json.dumps(draft)); path.chmod(0o600)
        return render_template("scm_config_preview.html", profile=profile, draft=draft, draft_id=draft_id)
    except Exception as exc:
        flash(f"SCM-configuratiepreview mislukt: {exc}", "error")
        return _scm_config_redirect(profile_id, view, section)


@app.post("/scm-configuration/<int:profile_id>/<view>/<section>/delete-preview")
@login_required
def scm_configuration_delete_preview(profile_id, view, section):
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile or profile["target_type"] != "scm" or section not in SCM_CONFIGURATION_SECTIONS.get(view, {}): return "Not found", 404
    try:
        locators = set(request.form.getlist("locator")); records = fetch_scm_configuration_records(profile, view, section)
        selected = [item for item in records if item["locator"] in locators]
        if not locators or len(selected) != len(locators): raise ValueError("Selecteer minstens één bestaand SCM-configuratie-item")
        draft_id = secrets.token_urlsafe(18)
        draft = {"profile_id": profile_id, "view": view, "section": section, "operation": "delete", "items": [{"endpoint": item["endpoint"], "id": item["id"], "name": item["name"], "fingerprint": item["fingerprint"]} for item in selected], "created_at": now()}
        if request.form.get("direct_save") == "yes":
            _write_scm_configuration_draft(profile, draft)
            invalidate_profile_caches(profile["id"])
            audit("scm-configuration-candidate", f"profile={profile['name']} view={view} section={section} operation=delete")
            flash("Configuratie-items rechtstreeks uit de SCM candidate verwijderd.", "success")
            return _scm_config_redirect(profile_id, view, section)
        path = OBJECT_DRAFTS / f"scm-config-{draft_id}.json"; path.write_text(json.dumps(draft)); path.chmod(0o600)
        return render_template("scm_config_preview.html", profile=profile, draft=draft, draft_id=draft_id)
    except Exception as exc:
        flash(f"SCM-deletepreview mislukt: {exc}", "error")
        return _scm_config_redirect(profile_id, view, section)


@app.post("/scm-configuration/drafts/<draft_id>/push")
@login_required
def scm_configuration_push(draft_id):
    if not draft_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in draft_id): return "Not found", 404
    path = OBJECT_DRAFTS / f"scm-config-{draft_id}.json"
    if not path.is_file(): return "Not found", 404
    draft = json.loads(path.read_text())
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (draft["profile_id"],)).fetchone()
    if not profile or profile["target_type"] != "scm": return "Not found", 404
    try:
        _write_scm_configuration_draft(profile, draft)
        path.unlink(missing_ok=True); invalidate_profile_caches(profile["id"])
        audit("scm-configuration-candidate", f"profile={profile['name']} view={draft['view']} section={draft['section']} operation={draft['operation']}")
        flash("SCM-configuratiebewerking naar candidate geschreven. Gebruik Push om ze uit te rollen.", "success")
    except Exception as exc:
        flash(f"SCM-configuratie-Push gestopt: {exc}", "error")
    return _scm_config_redirect(profile["id"], draft["view"], draft["section"])


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
            write_target_policy(profile, policy_kind, change["after"], change["before"].get("name"))
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
        "panos_tls": hashlib.sha256((BASE / "vendor/panos_tls.py").read_bytes()).hexdigest(),
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


def policy_rule_counters(serials: list[str], names: set[str]) -> dict[str, dict[str, int]]:
    selected_serials = list(dict.fromkeys(value for value in serials if value))
    selected_names = sorted(value for value in names if value)
    counters = {name: {"sessions": 0, "bytes": 0} for name in selected_names}
    if not selected_serials or not selected_names:
        return counters
    serial_marks = ",".join("?" for _ in selected_serials)
    name_marks = ",".join("?" for _ in selected_names)
    with flow_store.lock, flow_store._connect() as conn:
        rows = conn.execute(
            f"SELECT rule,COALESCE(SUM(repeat),0) sessions,COALESCE(SUM(bytes),0) bytes "
            f"FROM flows WHERE serial IN ({serial_marks}) AND rule IN ({name_marks}) GROUP BY rule",
            [*selected_serials, *selected_names],
        ).fetchall()
    for row in rows:
        counters[row["rule"]] = {"sessions": int(row["sessions"]), "bytes": int(row["bytes"])}
    return counters


def post_deploy_review(run_dir: str) -> tuple[dict[str, dict], set[str]]:
    path = Path(run_dir) / "review.csv"
    rules: dict[str, dict] = {}
    anchors: set[str] = set()
    if not path.exists():
        return rules, anchors
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            name = str(row.get("name", "")).strip()
            if not name or row.get("preflight_status") == "duplicate-match-skip":
                continue
            disabled = str(row.get("disabled", "no")).lower() in {"yes", "true", "1"}
            try:
                learned_sessions = int(row.get("sessions") or 0)
            except (TypeError, ValueError):
                learned_sessions = 0
            rules[name] = {
                "disabled": disabled,
                "learned_sessions": learned_sessions,
                "application": row.get("application", ""),
                "service": row.get("service", ""),
                "anchor_rule": row.get("anchor_rule", ""),
            }
            if row.get("anchor_rule"):
                anchors.add(row["anchor_rule"])
    return rules, anchors


def start_post_deploy_monitor(run_id: int, profile) -> None:
    with db() as conn:
        run = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if not run or run["mode"] != "push":
        return
    rules, anchors = post_deploy_review(run["run_dir"])
    names = set(rules) | anchors
    active = profile["target_type"] == "scm"
    baseline = {
        "rules": rules,
        "anchors": sorted(anchors),
        "counts": policy_rule_counters(profile_serials(profile), names) if active else {name: {"sessions": 0, "bytes": 0} for name in names},
        "serials": profile_serials(profile),
    }
    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO post_deploy_monitors(run_id,profile_id,deployed_at,baseline_json,target_type,activation_status,candidate_at) VALUES(?,?,?,?,?,?,?)",
            (run_id, profile["id"], run["finished_at"] or now(), json.dumps(baseline, sort_keys=True), profile["target_type"], "active" if active else "pending", run["finished_at"] or now()),
        )
    audit("post-deploy-monitor-started", f"profile={profile['name']} run={run_id} target={profile['target_type']} activation={'active' if active else 'pending'} rules={len(rules)}")


def running_panos_rule_names(profile) -> set[str]:
    _, endpoint, key, ctx = panos_profile_context(profile)
    serials = profile_serials(profile) if profile["target_type"] == "panorama" else [""]
    if profile["target_type"] == "panorama" and not serials:
        raise RuntimeError("Panorama activation check requires at least one managed-device serial")
    xpaths = [
        "/config/devices/entry/vsys/entry/rulebase/security/rules",
        "/config/devices/entry/vsys/entry/pre-rulebase/security/rules",
        "/config/devices/entry/vsys/entry/post-rulebase/security/rules",
    ]
    common_names: set[str] | None = None
    for serial in serials:
        device_names: set[str] = set()
        for xpath in xpaths:
            params = {"type": "config", "action": "show", "xpath": xpath, "key": key}
            if serial:
                params["target"] = serial
            root = policy_api.require_success(policy_api.api_get(endpoint, params, ctx), "fetch running security rules")
            device_names.update(entry.attrib["name"] for entry in root.findall(".//entry") if entry.attrib.get("name"))
        common_names = device_names if common_names is None else common_names & device_names
    return common_names or set()


def activate_post_deploy_monitor(row, profile) -> bool:
    baseline = json.loads(row["baseline_json"])
    expected = set(baseline.get("rules", {}))
    if not expected or not expected.issubset(running_panos_rule_names(profile)):
        return False
    names = expected | set(baseline.get("anchors", []))
    baseline["counts"] = policy_rule_counters(list(baseline.get("serials", [])), names)
    activated_at = now()
    with db() as conn:
        conn.execute(
            "UPDATE post_deploy_monitors SET activation_status='active',deployed_at=?,baseline_json=?,last_checked_at=?,last_error='' WHERE run_id=?",
            (activated_at, json.dumps(baseline, sort_keys=True), activated_at, row["run_id"]),
        )
    audit("post-deploy-monitor-activated", f"run={row['run_id']} target={row['target_type']} rules={len(expected)}")
    return True


def post_deploy_report(baseline: dict, current: dict[str, dict[str, int]], checkpoint: str) -> dict:
    before = baseline.get("counts", {})
    rules = baseline.get("rules", {})
    deltas = {
        name: {
            "sessions": max(0, current.get(name, {}).get("sessions", 0) - before.get(name, {}).get("sessions", 0)),
            "bytes": max(0, current.get(name, {}).get("bytes", 0) - before.get(name, {}).get("bytes", 0)),
        }
        for name in set(before) | set(current)
    }
    enabled = [name for name, details in rules.items() if not details.get("disabled")]
    zero_hits = sorted(name for name in enabled if deltas.get(name, {}).get("sessions", 0) == 0)
    threshold = 10000 if checkpoint == "1h" else 100000
    high_volume = sorted(
        ({"name": name, **deltas[name]} for name in enabled if deltas.get(name, {}).get("sessions", 0) >= threshold),
        key=lambda item: item["sessions"], reverse=True,
    )
    generated_sessions = sum(deltas.get(name, {}).get("sessions", 0) for name in enabled)
    fallback = sorted(
        ({"name": name, **deltas.get(name, {"sessions": 0, "bytes": 0})} for name in baseline.get("anchors", [])),
        key=lambda item: item["sessions"], reverse=True,
    )
    fallback_sessions = sum(item["sessions"] for item in fallback)
    ratio = round(fallback_sessions / max(1, generated_sessions + fallback_sessions), 4)
    significant_fallback = fallback_sessions >= 100 and ratio >= 0.10
    status = "warning" if high_volume or significant_fallback or (checkpoint == "24h" and zero_hits) else "healthy"
    return {
        "checkpoint": checkpoint,
        "status": status,
        "checked_at": now(),
        "generated_sessions": generated_sessions,
        "zero_hits": zero_hits,
        "high_volume": high_volume,
        "fallback": fallback,
        "fallback_sessions": fallback_sessions,
        "fallback_ratio": ratio,
        "significant_fallback": significant_fallback,
        "rule_deltas": {name: deltas.get(name, {"sessions": 0, "bytes": 0}) for name in enabled},
    }


def evaluate_post_deploy_monitor(row, checkpoint: str) -> dict:
    baseline = json.loads(row["baseline_json"])
    names = set(baseline.get("counts", {}))
    report = post_deploy_report(
        baseline,
        policy_rule_counters(list(baseline.get("serials", [])), names),
        checkpoint,
    )
    column = "one_hour_json" if checkpoint == "1h" else "one_day_json"
    with db() as conn:
        conn.execute(
            f"UPDATE post_deploy_monitors SET {column}=?,last_checked_at=?,last_error='' WHERE run_id=?",
            (json.dumps(report, sort_keys=True), report["checked_at"], row["run_id"]),
        )
    audit("post-deploy-monitor-checked", f"run={row['run_id']} checkpoint={checkpoint} status={report['status']}")
    return report


def post_deploy_monitor_loop() -> None:
    time.sleep(30)
    while True:
        try:
            current = datetime.now(timezone.utc)
            with db() as conn:
                monitors = conn.execute("SELECT * FROM post_deploy_monitors ORDER BY run_id").fetchall()
            for monitor in monitors:
                if monitor["activation_status"] == "pending":
                    try:
                        with db() as conn:
                            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (monitor["profile_id"],)).fetchone()
                        if not profile or not activate_post_deploy_monitor(monitor, profile):
                            continue
                        with db() as conn:
                            monitor = conn.execute("SELECT * FROM post_deploy_monitors WHERE run_id=?", (monitor["run_id"],)).fetchone()
                    except Exception as exc:
                        with db() as conn:
                            conn.execute("UPDATE post_deploy_monitors SET last_error=?,last_checked_at=? WHERE run_id=?", (str(exc)[:1000], now(), monitor["run_id"]))
                        app.logger.exception("post-deploy activation check failed for run %s", monitor["run_id"])
                        continue
                deployed = datetime.strptime(monitor["deployed_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                checkpoints = []
                if not monitor["one_hour_json"] and current >= deployed + timedelta(hours=1):
                    checkpoints.append("1h")
                if not monitor["one_day_json"] and current >= deployed + timedelta(hours=24):
                    checkpoints.append("24h")
                for checkpoint in checkpoints:
                    try:
                        evaluate_post_deploy_monitor(monitor, checkpoint)
                    except Exception as exc:
                        with db() as conn:
                            conn.execute("UPDATE post_deploy_monitors SET last_error=?,last_checked_at=? WHERE run_id=?", (str(exc)[:1000], now(), monitor["run_id"]))
                        app.logger.exception("post-deploy monitor failed for run %s", monitor["run_id"])
        except Exception:
            app.logger.exception("post-deploy monitor scheduler failed")
        time.sleep(300)


def create_run(profile, mode: str) -> tuple[int, Path]:
    run_dir = RUNS / (datetime.now().strftime("%Y%m%d-%H%M%S") + f"-{profile['id']}-{secrets.token_hex(3)}")
    run_dir.mkdir(mode=0o700)
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO runs(profile_id,mode,status,started_at,run_dir) VALUES(?,?,?,?,?)",
            (profile["id"], mode, "running", now(), str(run_dir)),
        )
        return int(cur.lastrowid), run_dir


def reserve_manual_run(profile, mode: str) -> tuple[int, Path | None, bool]:
    """Atomically reserve a user run, or return its already-running predecessor."""
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        active = conn.execute(
            "SELECT id FROM runs WHERE profile_id=? AND mode IN ('preview','push') "
            "AND status='running' ORDER BY id DESC LIMIT 1",
            (profile["id"],),
        ).fetchone()
        if active:
            return int(active["id"]), None, False
        run_dir = RUNS / (datetime.now().strftime("%Y%m%d-%H%M%S") + f"-{profile['id']}-{secrets.token_hex(3)}")
        cur = conn.execute(
            "INSERT INTO runs(profile_id,mode,status,started_at,run_dir) VALUES(?,?,?,?,?)",
            (profile["id"], mode, "running", now(), str(run_dir)),
        )
        run_id = int(cur.lastrowid)
    try:
        run_dir.mkdir(mode=0o700)
    except Exception as exc:
        with db() as conn:
            conn.execute(
                "UPDATE runs SET status='failed',finished_at=?,output=? WHERE id=?",
                (now(), str(exc)[-12000:], run_id),
            )
        raise
    return run_id, run_dir, True


def execute_run(
    profile, mode: str, disabled_override: bool | None = None, prepared=None,
    *, reserved_run: tuple[int, Path] | None = None, username: str | None = None,
) -> int:
    push = mode == "push"
    run_id, run_dir = reserved_run or create_run(profile, mode)
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
        shutil.copy(BASE / "vendor/panos_tls.py", run_dir)
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
        artifact_hashes = {
            name: hashlib.sha256((run_dir / name).read_bytes()).hexdigest()
            for name in ("flows.csv", "policy.xml", "review.csv")
        }
        (run_dir / "fingerprint").write_text(json.dumps({
            "profile": profile_fingerprint,
            "flows": flow_fingerprint,
            "artifacts": artifact_hashes,
            "prepared_at": int(time.time()),
        }))
        with db() as conn: conn.execute("UPDATE runs SET status='complete',finished_at=?,rule_count=?,output=? WHERE id=?", (now(), rules, output, run_id))
        if push:
            start_post_deploy_monitor(run_id, profile)
        if mode != "prepared":
            try:
                removed = prune_successful_run_history(profile["id"])
                if removed:
                    audit("policy-run-retention", f"profile={profile['name']} removed={removed} kept=5", username)
            except Exception:
                app.logger.exception("policy-run retention cleanup failed for profile %s", profile["id"])
        audit("policy-prepared" if mode == "prepared" else "candidate-written" if push else "policy-preview", f"profile={profile['name']} run={run_id} rules={rules} reused={bool(prepared)} disabled={disabled_override if push else 'profile-default'}", username)
        return run_id
    except Exception as exc:
        with db() as conn: conn.execute("UPDATE runs SET status='failed',finished_at=?,output=? WHERE id=?", (now(), str(exc)[-12000:], run_id))
        audit("build-failed", f"profile={profile['name']} run={run_id} mode={mode}", username)
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


def reviewed_preview_for_push(run_id: int):
    """Return the exact reviewed preview and its unchanged target profile."""
    with db() as conn:
        run = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        profile = conn.execute("SELECT * FROM profiles WHERE id=?", (run["profile_id"],)).fetchone() if run else None
    if not run or not profile:
        raise ValueError("De gekozen policy-run bestaat niet meer.")
    if run["mode"] != "preview" or run["status"] != "complete":
        raise ValueError("Alleen een voltooide preview kan via API worden gepusht.")

    runs_root = RUNS.resolve()
    run_dir = Path(run["run_dir"]).resolve()
    try:
        run_dir.relative_to(runs_root)
    except ValueError as exc:
        raise ValueError("De preview heeft een ongeldig artifactpad.") from exc
    if run_dir == runs_root or not run_dir.is_dir():
        raise ValueError("De preview-artifacts zijn niet meer beschikbaar.")
    required = ("flows.csv", "policy.xml", "review.csv", "fingerprint")
    missing = [name for name in required if not (run_dir / name).is_file()]
    if missing:
        raise ValueError("De preview is onvolledig: " + ", ".join(missing))
    try:
        metadata = json.loads((run_dir / "fingerprint").read_text())
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("De preview-fingerprint is ongeldig.") from exc
    if not hmac.compare_digest(str(metadata.get("profile", "")), build_fingerprint(profile, include_flows=False)):
        raise ValueError("Het device, target of de policy-instellingen zijn gewijzigd. Maak eerst een nieuwe check.")
    expected_hashes = metadata.get("artifacts")
    if not isinstance(expected_hashes, dict):
        raise ValueError("Deze oudere preview heeft nog geen artifactcontrole. Maak eerst een nieuwe check.")
    for name in required[:3]:
        actual = hashlib.sha256((run_dir / name).read_bytes()).hexdigest()
        if not hmac.compare_digest(str(expected_hashes.get(name, "")), actual):
            raise ValueError(f"Preview-artifact {name} is gewijzigd. Maak eerst een nieuwe check.")
    with (run_dir / "review.csv").open(newline="") as handle:
        review_rows = [row for row in csv.DictReader(handle) if row.get("preflight_status") != "duplicate-match-skip"]
    if not review_rows or any(not row.get("name", "").strip() or not row.get("anchor_rule", "").strip() for row in review_rows):
        raise ValueError("Niet elke gegenereerde regel heeft één bronregel voor positionering. API-push is geblokkeerd.")
    return run, profile


def execute_run_background(profile, mode, disabled_override, prepared, run_id, run_dir, username):
    try:
        execute_run(
            profile, mode, disabled_override, prepared,
            reserved_run=(run_id, run_dir), username=username,
        )
    except Exception:
        app.logger.exception("policy run %s failed", run_id)


def policy_run_failure_details(output: str) -> dict[str, str | bool]:
    text = str(output or "")
    missing = re.search(
        r"Cannot position generated policy (.+?): source policy (.+?) matched 0 rules",
        text,
    )
    if missing:
        generated = missing.group(1).strip().strip("'\"")
        anchor = missing.group(2).strip().strip("'\"")
        return {
            "title": "Check geblokkeerd: bronregel ontbreekt",
            "message": (
                f"De opgeslagen logs voor {generated} verwijzen naar bronregel {anchor}, maar die bestaat niet "
                "meer in de gekozen rulebase. Controleer of de regel werd verwijderd of hernoemd en of het "
                "juiste target, VSYS of device group is gekozen. Zet de bronregel terug, of purge de oude flows "
                "en verzamel nieuwe logs voordat je opnieuw controleert. Er is niets naar het target geschreven."
            ),
            "anchor_missing": True,
        }
    ambiguous = re.search(
        r"Cannot position generated policy (.+?): source policy (.+?) matched (\d+) rules",
        text,
    )
    if ambiguous:
        anchor = ambiguous.group(2).strip().strip("'\"")
        return {
            "title": "Check geblokkeerd: bronregel is niet uniek",
            "message": (
                f"Bronregel {anchor} komt {ambiguous.group(3)} keer voor in de gekozen rulebase. "
                "Maak de naam uniek of selecteer het juiste target en voer daarna een nieuwe check uit. "
                "Er is niets naar het target geschreven."
            ),
            "anchor_missing": False,
        }
    return {
        "title": "Run mislukt",
        "message": "De run kon niet veilig worden afgerond. Bekijk de technische details of voer een nieuwe check uit.",
        "anchor_missing": False,
    }


@app.post("/profiles/<int:profile_id>/build")
@login_required
def build(profile_id):
    push = request.form.get("mode") == "push"
    disabled_override = None
    if push and request.form.get("disabled_override") in {"true", "false"}:
        disabled_override = request.form["disabled_override"] == "true"
    with db() as conn: profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not profile: return "Not found", 404
    if push:
        flash("Open eerst een voltooide preview en gebruik daar de API-push. Zo wordt exact de nagekeken run gebruikt.", "warning")
        return redirect(url_for("index", run_profile=profile_id) + "#runs")
    mode = "push" if push else "preview"
    prepared = fresh_prepared_run(profile) if push else None
    try:
        run_id, run_dir, created = reserve_manual_run(profile, mode)
    except Exception as exc:
        flash(f"Run kon niet worden gestart: {exc}", "error")
        return redirect(url_for("index", edit_profile=profile_id))
    if not created:
        flash(f"Er loopt al een policy-run voor dit device (run #{run_id}).", "warning")
        return redirect(url_for("run_detail", run_id=run_id))
    username = session.get("username", "system")
    threading.Thread(
        target=execute_run_background,
        args=(profile, mode, disabled_override, prepared, run_id, run_dir, username),
        daemon=True,
        name=f"policy-run-{run_id}",
    ).start()
    suffix = " De voorbereide berekening wordt hergebruikt." if prepared else ""
    flash(f"{'Push' if push else 'Policy-preview'} gestart als run #{run_id}.{suffix}", "success")
    return redirect(url_for("run_detail", run_id=run_id))


@app.post("/runs/<int:run_id>/push")
@login_required
def run_push(run_id):
    try:
        prepared, profile = reviewed_preview_for_push(run_id)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("run_detail", run_id=run_id))
    disabled_override = None
    if request.form.get("disabled_override") in {"true", "false"}:
        disabled_override = request.form["disabled_override"] == "true"
    try:
        push_run_id, run_dir, created = reserve_manual_run(profile, "push")
    except Exception as exc:
        flash(f"API-push kon niet worden gestart: {exc}", "error")
        return redirect(url_for("run_detail", run_id=run_id))
    if not created:
        flash(f"Er loopt al een policy-run voor dit device (run #{push_run_id}).", "warning")
        return redirect(url_for("run_detail", run_id=push_run_id))
    username = session.get("username", "system")
    threading.Thread(
        target=execute_run_background,
        args=(profile, "push", disabled_override, prepared, push_run_id, run_dir, username),
        daemon=True,
        name=f"policy-run-{push_run_id}",
    ).start()
    if profile["target_type"] == "scm":
        message = f"API-push en SCM-deployment gestart als run #{push_run_id}, exact vanuit preview #{run_id}."
    else:
        message = f"API-push naar de candidate gestart als run #{push_run_id}, exact vanuit preview #{run_id}; er volgt geen commit."
    flash(message, "success")
    return redirect(url_for("run_detail", run_id=push_run_id))


def prepare_loop():
    time.sleep(PREPARE_INITIAL_DELAY)
    while True:
        try:
            with db() as conn: profiles = conn.execute("SELECT * FROM profiles WHERE enabled=1 ORDER BY id").fetchall()
            for profile in profiles:
                if not profile_is_configured(profile):
                    continue
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


def application_catalog_loop():
    time.sleep(DEFAULT_CATALOG_INITIAL_DELAY)
    while True:
        try:
            settings = application_catalog_configuration()
            if settings["enabled"] and settings["credentials_configured"]:
                due = not settings.get("last_success")
                if not due:
                    try:
                        last_success = datetime.strptime(
                            settings["last_success"], "%Y-%m-%d %H:%M:%S"
                        ).replace(tzinfo=timezone.utc)
                        due = datetime.now(timezone.utc) >= last_success + timedelta(
                            hours=settings["interval_hours"]
                        )
                    except (TypeError, ValueError):
                        due = True
                if due:
                    refresh_default_application_catalog_async()
        except Exception:
            app.logger.exception("Application Database scheduler mislukt")
        time.sleep(300)


@app.get("/runs/<int:run_id>")
@login_required
def run_detail(run_id):
    with db() as conn:
        run = conn.execute("SELECT runs.*,profiles.name profile_name,profiles.target_type FROM runs JOIN profiles ON profiles.id=runs.profile_id WHERE runs.id=?", (run_id,)).fetchone()
        monitor_row = conn.execute("SELECT * FROM post_deploy_monitors WHERE run_id=?", (run_id,)).fetchone()
    if not run: return "Not found", 404
    review=[]; path=Path(run["run_dir"])/"review.csv"
    if path.exists():
        with path.open(newline="") as fh: review=list(csv.DictReader(fh))
    positioned_review = [row for row in review if row.get("preflight_status") != "duplicate-match-skip"]
    anchors = sorted({row.get("anchor_rule", "").strip() for row in positioned_review if row.get("anchor_rule", "").strip()})
    pushable_preview = bool(positioned_review) and all(
        row.get("name", "").strip() and row.get("anchor_rule", "").strip() for row in positioned_review
    )
    push_block_reason = ""
    if run["mode"] == "preview" and run["status"] == "complete":
        try:
            reviewed_preview_for_push(run_id)
        except ValueError as exc:
            pushable_preview = False
            push_block_reason = str(exc)
    monitor = None
    if monitor_row:
        monitor = dict(monitor_row)
        monitor["one_hour"] = json.loads(monitor["one_hour_json"]) if monitor["one_hour_json"] else None
        monitor["one_day"] = json.loads(monitor["one_day_json"]) if monitor["one_day_json"] else None
    run_error = policy_run_failure_details(run["output"]) if run["status"] == "failed" else None
    return render_template(
        "run.html", run=run, review=review, monitor=monitor, anchors=anchors,
        pushable_preview=pushable_preview, push_block_reason=push_block_reason,
        run_error=run_error,
    )


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


def ingest_syslog(payload: bytes, source: str) -> None:
    flow = parse_panos_syslog(payload.decode("utf-8", errors="replace"))
    if not flow or not syslog_source_allowed(flow.serial, source):
        return
    flow_store.add_flow(flow)
    timestamp = now()
    with db() as conn:
        conn.execute(
            "INSERT INTO sources(serial,source_ip,first_seen,last_seen,messages) "
            "VALUES(?,?,?,?,1) ON CONFLICT(serial,source_ip) DO UPDATE SET "
            "last_seen=excluded.last_seen,messages=messages+1",
            (flow.serial, source, timestamp, timestamp),
        )


def udp_loop():
    server = udp_server(
        ("0.0.0.0", int(os.getenv("PPF_SYSLOG_PORT", "514"))),
        ingest_syslog,
        max_workers=env_int("PPF_SYSLOG_UDP_MAX_WORKERS", 32),
    )
    server.serve_forever()


def tcp_loop():
    server = tcp_server(
        ("0.0.0.0", int(os.getenv("PPF_SYSLOG_PORT", "514"))),
        ingest_syslog,
        max_message_bytes=env_int("PPF_SYSLOG_MAX_MESSAGE_BYTES", 1048576),
        connection_timeout=env_int("PPF_SYSLOG_TCP_TIMEOUT", 30),
        max_connections=env_int("PPF_SYSLOG_TCP_MAX_CONNECTIONS", 64),
    )
    server.serve_forever()


refresh_syslog_source_policy()
if os.getenv("PPF_BACKGROUND_WORKERS", "1") != "0":
    threading.Thread(target=udp_loop,daemon=True,name="syslog-udp").start()
    threading.Thread(target=tcp_loop,daemon=True,name="syslog-tcp").start()
    threading.Thread(target=quota_loop,daemon=True,name="storage-quota").start()
    threading.Thread(target=prepare_loop,daemon=True,name="policy-prepare").start()
    threading.Thread(target=application_catalog_loop,daemon=True,name="application-catalog-scheduler").start()
    threading.Thread(target=post_deploy_monitor_loop,daemon=True,name="post-deploy-monitor").start()

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=8080)
