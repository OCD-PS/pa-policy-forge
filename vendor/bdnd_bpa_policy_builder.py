#!/usr/bin/env python3
"""
Build candidate security policies from local firewall logs.

Default behavior is fully local: parse log files, aggregate flows, and write a
reviewable policy plan. Network actions are driven by TOML configuration, with
SCM or Panorama selected explicitly.
"""

from __future__ import annotations

import argparse
import base64
import csv
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable
import tomllib


DEFAULT_CONFIG_PATH = Path(__file__).with_name("bdnd_bpa_policy_builder.toml")
DEFAULT_LOG_PATTERN = "*.csv"
DEFAULT_LOG_SEARCH_DIR = "logs"
GENERATED_FILE_PATTERNS = (
    "bdnd_bpa_policy_plan*.json",
    "bdnd_bpa_policy_review*.csv",
    "bdnd_panos_review*.csv",
    "bdnd_panos_import*.xml",
    "bpa_*.xml",
)

# Keep environment fallbacks so existing automation still works if TOML values
# are omitted, but the standalone workflow reads its defaults from TOML.
SCM_CLIENT_ID = os.getenv("SCM_CLIENT_ID", "")
SCM_CLIENT_SECRET = os.getenv("SCM_CLIENT_SECRET", "")
SCM_TSG_ID = os.getenv("SCM_TSG_ID", "")
SCM_TOKEN_URL = os.getenv(
    "SCM_TOKEN_URL", "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
)
SCM_API_BASE = os.getenv(
    "SCM_API_BASE", "https://api.strata.paloaltonetworks.com/config/security/v1"
)
SCM_FOLDER = os.getenv("SCM_FOLDER", "Shared")
SCM_SNIPPET = os.getenv("SCM_SNIPPET", "")
SCM_DEVICE = os.getenv("SCM_DEVICE", "")
DEFAULT_TAGS = [t for t in os.getenv("SCM_POLICY_TAGS", "BDND_BPA,log-derived").split(",") if t]
DEFAULT_LOG_SETTING = os.getenv("SCM_LOG_SETTING", "")


@dataclass(frozen=True)
class BPAConfig:
    logs: list[Path]
    input_search_dir: Path
    input_pattern: str
    output: Path
    review_csv: Path
    min_sessions: int
    limit: int
    max_members: int
    source_any_threshold: int
    destination_any_threshold: int
    service_mode: str
    include_actions: set[str]
    apply: bool
    apply_target: str
    apply_delay: float
    panorama_zone_role_config: Path
    panorama_xml_output: Path
    panorama_group_threshold: int
    panorama_log_setting: str
    scm_client_id: str
    scm_client_secret: str
    scm_tsg_id: str
    scm_token_url: str
    scm_api_base: str
    scm_folder: str
    scm_snippet: str
    scm_device: str
    scm_tags: list[str]
    scm_log_setting: str


FIELD_ALIASES = {
    "src": {
        "src",
        "source",
        "source_ip",
        "src_ip",
        "source address",
        "srcaddr",
        "source_address",
        "addr_src",
    },
    "dst": {
        "dst",
        "destination",
        "destination_ip",
        "dst_ip",
        "destination address",
        "dstaddr",
        "destination_address",
        "addr_dst",
    },
    "src_zone": {"from", "from_zone", "src_zone", "source_zone", "zone_src"},
    "dst_zone": {"to", "to_zone", "dst_zone", "destination_zone", "zone_dst"},
    "app": {"app", "application", "app_name"},
    "proto": {"proto", "protocol", "ip_protocol"},
    "dport": {"dport", "dst_port", "destination_port", "port", "dstport"},
    "action": {"action", "session_action", "rule_action"},
    "rule": {"rule", "rule_name", "policy", "policy_name"},
    "serial": {"serial", "serial_number", "device_serial"},
    "repeat": {"repeatcnt", "repeat_count", "count", "sessions"},
    "bytes": {"bytes", "bytes_total", "total_bytes"},
}

# Common PAN-OS traffic log CSV positions when there is no header row.
PANOS_TRAFFIC_INDEX = {
    "serial": 2,
    "src": 7,
    "dst": 8,
    "rule": 11,
    "app": 14,
    "src_zone": 16,
    "dst_zone": 17,
    "repeat": 22,
    "dport": 25,
    "proto": 29,
    "action": 30,
    "bytes": 31,
}

KEY_VALUE_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_. -]*)=(\"[^\"]*\"|'[^']*'|\\S+)")


@dataclass(frozen=True)
class FlowKey:
    src_zone: str
    dst_zone: str
    app: str
    proto: str
    dport: str
    action: str
    rule: str = ""


@dataclass(frozen=True)
class ZoneRoleConfig:
    zone_roles: dict[str, str]

    def role_for(self, zone: str) -> str:
        return self.zone_roles.get(zone, "other")

    def is_client(self, zone: str) -> bool:
        return self.role_for(zone) == "client"


@dataclass
class FlowAggregate:
    key: FlowKey
    sources: Counter[str] = field(default_factory=Counter)
    destinations: Counter[str] = field(default_factory=Counter)
    source_destination_pairs: Counter[tuple[str, str]] = field(default_factory=Counter)
    rules: Counter[str] = field(default_factory=Counter)
    serials: Counter[str] = field(default_factory=Counter)
    sessions: int = 0
    bytes_total: int = 0


def norm_header(value: str) -> str:
    return re.sub(r"[\s-]+", "_", value.strip().lower())


def first_present(row: dict[str, str], canonical: str) -> str:
    value = row.get(canonical)
    if value:
        return value.strip()
    aliases = FIELD_ALIASES[canonical]
    for key, value in row.items():
        if norm_header(key) in aliases and value:
            return value.strip()
    return ""


def clean(value: str, default: str = "any") -> str:
    value = (value or "").strip().strip('"').strip("'")
    if not value or value.lower() in {"n/a", "none", "null", "(empty)"}:
        return default
    return value


def parse_int(value: str, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def is_ipish(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return value.lower() == "any"


def split_multi(value: str) -> list[str]:
    parts = re.split(r"[;,\\s]+", value.strip())
    return [p for p in parts if p]


def parse_key_value_line(line: str) -> dict[str, str]:
    row: dict[str, str] = {}
    for key, value in KEY_VALUE_RE.findall(line):
        row[key] = value.strip().strip('"').strip("'")
    return row


def looks_like_header(fields: list[str]) -> bool:
    normalized = {norm_header(f) for f in fields}
    alias_hits = sum(1 for aliases in FIELD_ALIASES.values() if normalized & aliases)
    return alias_hits >= 3


def header_alias_indexes(headers: list[str]) -> dict[str, list[int]]:
    indexes: dict[str, list[int]] = {}
    for index, header in enumerate(headers):
        normalized = norm_header(header)
        for canonical, aliases in FIELD_ALIASES.items():
            if normalized in aliases:
                indexes.setdefault(canonical, []).append(index)
    return indexes


def row_from_header_fields(fields: list[str], indexes: dict[str, list[int]]) -> dict[str, str]:
    row: dict[str, str] = {}
    for canonical, field_indexes in indexes.items():
        for index in field_indexes:
            if index < len(fields) and fields[index]:
                row[canonical] = fields[index].strip()
                break
    return row


def rows_from_csv(path: Path) -> Iterable[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        sample = handle.read(8192)
        handle.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample)
        except csv.Error:
            dialect = csv.excel
        reader = csv.reader(handle, dialect)
        first = next(reader, None)
        if not first:
            return
        if looks_like_header(first):
            indexes = header_alias_indexes(first)
            for fields in reader:
                yield row_from_header_fields(fields, indexes)
        else:
            yield row_from_panos_fields(first)
            for fields in reader:
                yield row_from_panos_fields(fields)


def row_from_panos_fields(fields: list[str]) -> dict[str, str]:
    row = {}
    for key, index in PANOS_TRAFFIC_INDEX.items():
        if index < len(fields):
            row[key] = fields[index].strip()
    return row


def iter_log_rows(paths: list[Path]) -> Iterable[dict[str, str]]:
    for path in paths:
        if path.is_dir():
            yield from iter_log_rows(sorted(p for p in path.rglob("*") if p.is_file()))
            continue
        if path.suffix.lower() in {".csv", ".tsv"}:
            yield from rows_from_csv(path)
            continue
        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                if "=" in line:
                    row = parse_key_value_line(line)
                    if row:
                        yield row
                        continue
                if "," in line:
                    fields = next(csv.reader([line]))
                    if looks_like_header(fields):
                        continue
                    yield row_from_panos_fields(fields)


def canonical_flow(row: dict[str, str]) -> tuple[FlowKey, list[str], list[str], int, int, str, str]:
    src = clean(first_present(row, "src"))
    dst = clean(first_present(row, "dst"))
    src_zone = clean(first_present(row, "src_zone"))
    dst_zone = clean(first_present(row, "dst_zone"))
    app = clean(first_present(row, "app"))
    proto = clean(first_present(row, "proto"), "tcp").lower()
    dport = clean(first_present(row, "dport"), "application-default")
    action = clean(first_present(row, "action"), "allow").lower()
    rule = clean(first_present(row, "rule"), "")
    serial = clean(first_present(row, "serial"), "")
    repeat = max(parse_int(first_present(row, "repeat"), 1), 1)
    bytes_total = parse_int(first_present(row, "bytes"), 0)
    key = FlowKey(src_zone, dst_zone, app, proto, dport, action, rule)
    return key, split_multi(src), split_multi(dst), repeat, bytes_total, rule, serial


def aggregate_flows(rows: Iterable[dict[str, str]], include_actions: set[str]) -> dict[FlowKey, FlowAggregate]:
    aggregates: dict[FlowKey, FlowAggregate] = {}
    ipish_cache: dict[str, bool] = {}
    for row in rows:
        key, sources, destinations, repeat, bytes_total, rule, serial = canonical_flow(row)
        if key.action not in include_actions:
            continue
        if not sources or not destinations:
            continue
        aggregate = aggregates.setdefault(key, FlowAggregate(key))
        aggregate.sessions += repeat
        aggregate.bytes_total += bytes_total
        for src in sources:
            if src not in ipish_cache:
                ipish_cache[src] = is_ipish(src)
            if ipish_cache[src]:
                aggregate.sources[src] += repeat
        for dst in destinations:
            if dst not in ipish_cache:
                ipish_cache[dst] = is_ipish(dst)
            if ipish_cache[dst]:
                aggregate.destinations[dst] += repeat
        for src in sources:
            if not ipish_cache.get(src, False):
                continue
            for dst in destinations:
                if ipish_cache.get(dst, False):
                    aggregate.source_destination_pairs[(src, dst)] += repeat
        if rule:
            aggregate.rules[rule] += repeat
        if serial:
            aggregate.serials[serial] += repeat
    return aggregates


def merge_flow_aggregate(target: FlowAggregate, source: FlowAggregate) -> None:
    target.sessions += source.sessions
    target.bytes_total += source.bytes_total
    target.sources.update(source.sources)
    target.destinations.update(source.destinations)
    target.source_destination_pairs.update(source.source_destination_pairs)
    target.rules.update(source.rules)
    target.serials.update(source.serials)


def merge_aggregate_maps(
    aggregate_maps: Iterable[dict[FlowKey, FlowAggregate]],
) -> dict[FlowKey, FlowAggregate]:
    merged: dict[FlowKey, FlowAggregate] = {}
    for aggregate_map in aggregate_maps:
        for key, source in aggregate_map.items():
            target = merged.get(key)
            if target is None:
                merged[key] = source
            else:
                merge_flow_aggregate(target, source)
    return merged


def aggregate_log_path(args: tuple[Path, set[str]]) -> dict[FlowKey, FlowAggregate]:
    path, include_actions = args
    return aggregate_flows(iter_log_rows([path]), include_actions)


def aggregate_log_paths(
    paths: list[Path],
    include_actions: set[str],
    workers: int | None = None,
) -> dict[FlowKey, FlowAggregate]:
    if len(paths) <= 1:
        return aggregate_flows(iter_log_rows(paths), include_actions)

    worker_count = workers or min(len(paths), os.cpu_count() or 1)
    if worker_count <= 1:
        return aggregate_flows(iter_log_rows(paths), include_actions)

    with ProcessPoolExecutor(max_workers=worker_count) as executor:
        aggregate_maps = executor.map(
            aggregate_log_path,
            ((path, include_actions) for path in paths),
        )
        return merge_aggregate_maps(aggregate_maps)


def scm_scope(folder: str = SCM_FOLDER, snippet: str = SCM_SNIPPET, device: str = SCM_DEVICE) -> dict[str, str]:
    if snippet:
        return {"snippet": snippet}
    if device:
        return {"device": device}
    return {"folder": folder}


def safe_name(value: str, max_len: int = 63) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")
    return value[:max_len].rstrip("-") or "policy"


def service_value(proto: str, dport: str, service_mode: str) -> list[str]:
    if service_mode == "application-default":
        return ["application-default"]
    if dport in {"application-default", "any"}:
        return [dport]
    return [safe_name(f"svc-{proto}-{dport}", 31)]


def is_client_to_internet(key: FlowKey, zone_roles: ZoneRoleConfig | None) -> bool:
    return bool(zone_roles and zone_roles.is_client(key.src_zone) and zone_roles.role_for(key.dst_zone) == "internet")


def make_policy_payload(
    aggregate: FlowAggregate,
    index: int,
    max_members: int,
    service_mode: str,
    source_any_threshold: int,
    destination_any_threshold: int,
    zone_roles: ZoneRoleConfig | None = None,
    scope: dict[str, str] | None = None,
    tags: list[str] | None = None,
    log_setting: str = "",
) -> dict[str, Any]:
    key = aggregate.key
    client_to_internet = is_client_to_internet(key, zone_roles)
    top_sources = [item for item, _ in aggregate.sources.most_common(max_members)]
    top_destinations = [item for item, _ in aggregate.destinations.most_common(max_members)]
    source = top_sources
    if client_to_internet:
        destination = ["any"]
    else:
        destination = top_destinations
    web_service = client_to_internet and key.proto.lower() == "tcp" and key.dport in {"80", "443"}
    app = "any" if web_service else (
        key.app if key.app not in {"any", "not-applicable", "incomplete", "unknown"} else "any"
    )
    if not source:
        raise RuntimeError(f"Refusing overly broad generated policy for {key.src_zone} to {key.dst_zone}: no source")
    if not destination:
        raise RuntimeError(f"Refusing generated policy for {key.src_zone} to {key.dst_zone}: no destination")
    if app == "any" and not web_service:
        raise RuntimeError(f"Refusing overly broad generated policy for {key.src_zone} to {key.dst_zone}: unknown application")
    name = safe_name(
        f"AUTO-BDND-BPA-{key.src_zone}-{key.dst_zone}-{app}-{key.proto}-{key.dport}-{index:03d}"
    )
    description = (
        f"Generated locally from BDND_BPA firewall logs. "
        f"sessions={aggregate.sessions}; bytes={aggregate.bytes_total}; "
        f"observed_rules={','.join(r for r, _ in aggregate.rules.most_common(5)) or 'none'}"
    )
    payload: dict[str, Any] = {
        "name": name,
        **(scope or scm_scope()),
        "disabled": False,
        "description": description[:1023],
        "from": [key.src_zone],
        "to": [key.dst_zone],
        "source": source,
        "destination": destination,
        "source_user": ["any"],
        "category": ["any"],
        "application": [app],
        "service": [{"80": "service-http", "443": "service-https"}[key.dport]]
        if web_service
        else service_value(key.proto, key.dport, service_mode),
        "action": "allow",
        "tag": tags if tags is not None else DEFAULT_TAGS,
    }
    if log_setting:
        payload["log_setting"] = log_setting
    return payload


def build_plan(
    aggregates: dict[FlowKey, FlowAggregate],
    min_sessions: int,
    limit: int,
    max_members: int,
    service_mode: str,
    source_any_threshold: int,
    destination_any_threshold: int,
    zone_roles: ZoneRoleConfig | None = None,
    scope: dict[str, str] | None = None,
    tags: list[str] | None = None,
    log_setting: str = "",
) -> list[dict[str, Any]]:
    eligible = [agg for agg in aggregates.values() if agg.sessions >= min_sessions and agg.key.action == "allow"]
    eligible.sort(key=lambda agg: (agg.sessions, agg.bytes_total), reverse=True)
    if limit:
        eligible = eligible[:limit]
    return [
        make_policy_payload(
            agg,
            index + 1,
            max_members,
            service_mode,
            source_any_threshold,
            destination_any_threshold,
            zone_roles,
            scope,
            tags,
            log_setting,
        )
        for index, agg in enumerate(eligible)
    ]


def write_review_csv(path: Path, policies: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["name", "from", "to", "source", "destination", "application", "service", "action"])
        for policy in policies:
            writer.writerow(
                [
                    policy["name"],
                    ",".join(policy["from"]),
                    ",".join(policy["to"]),
                    ",".join(policy["source"]),
                    ",".join(policy["destination"]),
                    ",".join(policy["application"]),
                    ",".join(policy["service"]),
                    policy["action"],
                ]
            )


class NoCredentialRedirect(urllib.request.HTTPRedirectHandler):
    """API credentials may only be sent to the configured HTTPS endpoint."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # urllib otherwise retains Authorization/X-PAN-KEY across origins and
        # permits HTTPS-to-HTTP redirects. APIs must return a direct response.
        return None


def credential_urlopen(request: urllib.request.Request, *, context=None, timeout=120):
    parsed = urllib.parse.urlsplit(request.full_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Credential-bearing API requests require an HTTPS URL without embedded credentials")
    opener = urllib.request.build_opener(
        NoCredentialRedirect(), urllib.request.HTTPSHandler(context=context),
    )
    return opener.open(request, timeout=timeout)


def http_request(method: str, url: str, headers: dict[str, str], data: bytes | None = None) -> Any:
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with credential_urlopen(request, timeout=60) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} failed: HTTP {exc.code}: {body}") from exc


def get_scm_token(
    client_id: str = SCM_CLIENT_ID,
    client_secret: str = SCM_CLIENT_SECRET,
    tsg_id: str = SCM_TSG_ID,
    token_url: str = SCM_TOKEN_URL,
) -> str:
    missing = [
        name
        for name, value in {
            "SCM_CLIENT_ID": client_id,
            "SCM_CLIENT_SECRET": client_secret,
            "SCM_TSG_ID": tsg_id,
        }.items()
        if not value
    ]
    if missing:
        raise RuntimeError(f"Missing SCM service-account variables: {', '.join(missing)}")
    form = urllib.parse.urlencode(
        {"grant_type": "client_credentials", "scope": f"tsg_id:{tsg_id}"}
    ).encode("utf-8")
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
    response = http_request(
        "POST",
        token_url,
        {
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        form,
    )
    token = response.get("access_token")
    if not token:
        raise RuntimeError("Token response did not contain access_token")
    return token


def apply_policies(
    policies: list[dict[str, Any]],
    delay: float,
    api_base: str = SCM_API_BASE,
    client_id: str = SCM_CLIENT_ID,
    client_secret: str = SCM_CLIENT_SECRET,
    tsg_id: str = SCM_TSG_ID,
    token_url: str = SCM_TOKEN_URL,
) -> None:
    token = get_scm_token(client_id=client_id, client_secret=client_secret, tsg_id=tsg_id, token_url=token_url)
    url = api_base.rstrip("/") + "/security-rules"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    for policy in policies:
        print(f"Creating {policy['name']}", file=sys.stderr)
        http_request("POST", url, headers, json.dumps(policy).encode("utf-8"))
        if delay:
            time.sleep(delay)


def load_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return tomllib.loads(path.read_text(encoding="utf-8"))


def load_zone_roles(path: Path) -> ZoneRoleConfig:
    data = load_toml(path)
    zone_roles_raw = data.get("zone_roles", {})
    if zone_roles_raw and not isinstance(zone_roles_raw, dict):
        raise ValueError(f"{path} [zone_roles] section must be a table")

    zone_roles: dict[str, str] = {}
    valid_roles = {"client", "internet", "server", "other"}
    for zone, role in zone_roles_raw.items():
        if not isinstance(zone, str) or not isinstance(role, str):
            raise ValueError(f"Invalid zone role mapping in {path}: {zone!r} -> {role!r}")
        normalized_role = role.strip().lower()
        if normalized_role not in valid_roles:
            raise ValueError(
                f"Unsupported role {role!r} for zone {zone!r} in {path}. "
                f"Valid roles: {', '.join(sorted(valid_roles))}"
            )
        zone_roles[zone] = normalized_role
    return ZoneRoleConfig(zone_roles)


def resolve_relative_path(value: str | Path, base_dir: Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base_dir / path


def normalize_csv_list(value: Any, default: str = "") -> list[str]:
    if value is None:
        value = default
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value).split(",") if item.strip()]


def discover_log_paths(base_dir: Path, pattern: str = DEFAULT_LOG_PATTERN, recursive: bool = False) -> list[Path]:
    base_dir = base_dir.resolve()
    iterator = base_dir.rglob(pattern) if recursive else base_dir.glob(pattern)
    return sorted(path for path in iterator if path.is_file())


def load_builder_config(config_path: Path) -> BPAConfig:
    data = load_toml(config_path)
    base_dir = config_path.resolve().parent

    input_raw = data.get("input", {})
    if input_raw and not isinstance(input_raw, dict):
        raise ValueError(f"{config_path} [input] section must be a table")
    output_raw = data.get("output", {})
    if output_raw and not isinstance(output_raw, dict):
        raise ValueError(f"{config_path} [output] section must be a table")
    policy_raw = data.get("policy", {})
    if policy_raw and not isinstance(policy_raw, dict):
        raise ValueError(f"{config_path} [policy] section must be a table")
    apply_raw = data.get("apply", {})
    if apply_raw and not isinstance(apply_raw, dict):
        raise ValueError(f"{config_path} [apply] section must be a table")
    panorama_raw = data.get("panorama", {})
    if panorama_raw and not isinstance(panorama_raw, dict):
        raise ValueError(f"{config_path} [panorama] section must be a table")
    scm_raw = data.get("scm", {})
    if scm_raw and not isinstance(scm_raw, dict):
        raise ValueError(f"{config_path} [scm] section must be a table")

    input_paths_raw = input_raw.get("paths", [])
    if not isinstance(input_paths_raw, list):
        raise ValueError(f"{config_path} [input].paths must be an array of paths")
    input_paths = [resolve_relative_path(path, base_dir) for path in input_paths_raw]
    input_search_dir = resolve_relative_path(input_raw.get("search_dir", DEFAULT_LOG_SEARCH_DIR), base_dir)
    input_pattern = str(input_raw.get("pattern", DEFAULT_LOG_PATTERN))
    input_recursive = bool(input_raw.get("recursive", False))

    output = resolve_relative_path(output_raw.get("plan", "bdnd_bpa_policy_plan.json"), base_dir)
    review_csv = resolve_relative_path(output_raw.get("review_csv", "bdnd_bpa_policy_review.csv"), base_dir)

    include_actions = {action.lower() for action in normalize_csv_list(policy_raw.get("include_actions", "allow"))}
    service_mode = str(policy_raw.get("service_mode", "application-default")).strip()
    if service_mode not in {"application-default", "port"}:
        raise ValueError(
            f"{config_path} [policy].service_mode must be application-default or port"
        )

    apply_target = str(apply_raw.get("target", "panorama")).strip().lower()
    if apply_target not in {"panorama", "scm"}:
        raise ValueError(f"{config_path} [apply].target must be panorama or scm")

    scm_tags = normalize_csv_list(scm_raw.get("tags", ["BDND_BPA", "log-derived"]))
    if not scm_tags:
        scm_tags = DEFAULT_TAGS

    return BPAConfig(
        logs=input_paths or discover_log_paths(input_search_dir, input_pattern, input_recursive),
        input_search_dir=input_search_dir,
        input_pattern=input_pattern,
        output=output,
        review_csv=review_csv,
        min_sessions=int(policy_raw.get("min_sessions", 10)),
        limit=int(policy_raw.get("limit", 100)),
        max_members=int(policy_raw.get("max_members", 20)),
        source_any_threshold=int(policy_raw.get("source_any_threshold", 200)),
        destination_any_threshold=int(policy_raw.get("destination_any_threshold", 200)),
        service_mode=service_mode,
        include_actions=include_actions,
        apply=bool(apply_raw.get("enabled", False)),
        apply_target=apply_target,
        apply_delay=float(apply_raw.get("delay", 0.25)),
        panorama_zone_role_config=resolve_relative_path(
            panorama_raw.get("zone_role_config", "bdnd_panos_zone_roles.toml"),
            base_dir,
        ),
        panorama_xml_output=resolve_relative_path(
            panorama_raw.get("xml_output", "bdnd_panos_import.xml"),
            base_dir,
        ),
        panorama_group_threshold=int(panorama_raw.get("group_threshold", 10)),
        panorama_log_setting=str(panorama_raw.get("log_setting", "")).strip(),
        scm_client_id=str(scm_raw.get("client_id", "")).strip(),
        scm_client_secret=str(scm_raw.get("client_secret", "")).strip(),
        scm_tsg_id=str(scm_raw.get("tsg_id", "")).strip(),
        scm_token_url=str(scm_raw.get("token_url", SCM_TOKEN_URL)).strip() or SCM_TOKEN_URL,
        scm_api_base=str(scm_raw.get("api_base", SCM_API_BASE)).strip() or SCM_API_BASE,
        scm_folder=str(scm_raw.get("folder", SCM_FOLDER)).strip(),
        scm_snippet=str(scm_raw.get("snippet", SCM_SNIPPET)).strip(),
        scm_device=str(scm_raw.get("device", SCM_DEVICE)).strip(),
        scm_tags=scm_tags,
        scm_log_setting=str(scm_raw.get("log_setting", DEFAULT_LOG_SETTING)).strip(),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="*", type=Path, help="Local exported log files or directories")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--review-csv", type=Path)
    parser.add_argument("--min-sessions", type=int)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--max-members", type=int)
    parser.add_argument("--source-any-threshold", type=int)
    parser.add_argument("--destination-any-threshold", type=int)
    parser.add_argument(
        "--service-mode",
        choices=["application-default", "port"],
        default=None,
        help="Use application-default services, or generated service object names based on protocol/port.",
    )
    parser.add_argument("--include-actions", help="Comma-separated log actions to aggregate.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Force network apply using the target configured in TOML.",
    )
    parser.add_argument("--apply-delay", type=float)
    parser.add_argument(
        "--delete-files",
        "--delete_files",
        dest="delete_files",
        action="store_true",
        help="Delete generated output files and exit.",
    )
    return parser.parse_args()


def delete_generated_files(config: BPAConfig, output: Path, review_csv: Path) -> int:
    deleted = 0
    kept = 0
    base_dir = output.parent.resolve()
    today = datetime.now().date()
    targets = generated_file_candidates(base_dir, output, review_csv, config.panorama_xml_output)

    for path in sorted(targets):
        file_day = generated_file_day(path)
        if file_day >= today:
            kept += 1
            print(f"Kept current business day file: {path}")
            continue
        path.unlink()
        deleted += 1
        print(f"Deleted {path}")

    if deleted == 0 and kept == 0:
        print(f"No generated files found in {base_dir}")
    return deleted


def generated_file_candidates(base_dir: Path, *configured_paths: Path) -> set[Path]:
    candidates: set[Path] = set()
    for pattern in GENERATED_FILE_PATTERNS:
        candidates.update(path.resolve() for path in base_dir.glob(pattern) if path.is_file())
    for path in configured_paths:
        if path.exists() and path.is_file():
            candidates.add(path.resolve())
    return candidates


def generated_file_day(path: Path) -> date:
    filename = path.name
    range_match = re.search(r"(\d{4}-\d{2}-\d{2})_to_(\d{4}-\d{2}-\d{2})", filename)
    if range_match:
        return date.fromisoformat(range_match.group(2))

    iso_dates = re.findall(r"\d{4}-\d{2}-\d{2}", filename)
    if iso_dates:
        return max(date.fromisoformat(value) for value in iso_dates)

    short_range_match = re.search(r"_(\d{4})_(\d{4})", filename)
    if short_range_match:
        year = datetime.now().year
        start = short_range_match.group(1)
        end = short_range_match.group(2)
        return date(year, int(end[:2]), int(end[2:]))

    return datetime.fromtimestamp(path.stat().st_mtime).date()


def apply_policies_to_panorama(
    config: BPAConfig,
    logs: list[Path],
    review_csv: Path,
    min_sessions: int,
    limit: int,
    source_any_threshold: int,
    include_actions: set[str],
) -> None:
    script_path = Path(__file__).with_name("bdnd_panos_policy_builder.py")
    if not script_path.exists():
        raise RuntimeError(f"Panorama builder script not found: {script_path}")
    if not config.panorama_zone_role_config.exists():
        raise RuntimeError(f"Panorama zone-role config not found: {config.panorama_zone_role_config}")

    cmd = [
        sys.executable,
        str(script_path),
        "--zone-role-config",
        str(config.panorama_zone_role_config),
        "--xml-output",
        str(config.panorama_xml_output),
        "--review-csv",
        str(review_csv),
        "--min-sessions",
        str(min_sessions),
        "--limit",
        str(limit),
        "--group-threshold",
        str(config.panorama_group_threshold),
        "--source-any-threshold",
        str(source_any_threshold),
        "--include-actions",
        ",".join(sorted(include_actions)),
    ]
    if config.panorama_log_setting:
        cmd.extend(["--log-setting", config.panorama_log_setting])
    cmd.extend(str(path) for path in logs)
    subprocess.run(cmd, check=True)


def main() -> int:
    args = parse_args()
    config = load_builder_config(args.config)
    output = args.output if args.output is not None else config.output
    review_csv = args.review_csv if args.review_csv is not None else config.review_csv
    if args.delete_files:
        delete_generated_files(config, output, review_csv)
        return 0
    logs = args.logs or config.logs
    if not logs:
        raise SystemExit(
            f"No traffic CSV files found. Expected files matching {config.input_pattern} "
            f"in {config.input_search_dir}"
        )
    include_actions = (
        {a.strip().lower() for a in args.include_actions.split(",") if a.strip()}
        if args.include_actions
        else config.include_actions
    )
    missing = [str(path) for path in logs if not path.exists()]
    if missing:
        print(f"Missing log path(s): {', '.join(missing)}", file=sys.stderr)
        return 2
    aggregates = aggregate_log_paths(logs, include_actions)
    min_sessions = args.min_sessions if args.min_sessions is not None else config.min_sessions
    limit = args.limit if args.limit is not None else config.limit
    max_members = args.max_members if args.max_members is not None else config.max_members
    source_any_threshold = (
        args.source_any_threshold if args.source_any_threshold is not None else config.source_any_threshold
    )
    destination_any_threshold = (
        args.destination_any_threshold
        if args.destination_any_threshold is not None
        else config.destination_any_threshold
    )
    service_mode = args.service_mode if args.service_mode is not None else config.service_mode
    apply_enabled = args.apply or config.apply
    apply_delay = args.apply_delay if args.apply_delay is not None else config.apply_delay
    scope = scm_scope(config.scm_folder, config.scm_snippet, config.scm_device)
    zone_roles = load_zone_roles(config.panorama_zone_role_config)
    policies = build_plan(
        aggregates,
        min_sessions,
        limit,
        max_members,
        service_mode,
        source_any_threshold,
        destination_any_threshold,
        zone_roles,
        scope,
        config.scm_tags,
        config.scm_log_setting,
    )
    output.write_text(json.dumps(policies, indent=2) + "\n", encoding="utf-8")
    write_review_csv(review_csv, policies)
    print(f"Wrote {len(policies)} candidate policies to {output}")
    print(f"Wrote review CSV to {review_csv}")
    if apply_enabled:
        if config.apply_target == "panorama":
            apply_policies_to_panorama(
                config,
                logs,
                review_csv,
                min_sessions,
                limit,
                source_any_threshold,
                include_actions,
            )
        else:
            apply_policies(
                policies,
                apply_delay,
                api_base=config.scm_api_base,
                client_id=config.scm_client_id,
                client_secret=config.scm_client_secret,
                tsg_id=config.scm_tsg_id,
                token_url=config.scm_token_url,
            )
    else:
        print("Dry run only. No network calls were made. Enable [apply].enabled in TOML or use --apply.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
