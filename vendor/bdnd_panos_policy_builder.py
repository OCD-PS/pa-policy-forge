#!/usr/bin/env python3
"""
Build PAN-OS import artifacts from firewall traffic logs.

Unlike the SCM-oriented builder, this exporter creates a partial PAN-OS XML
configuration with reusable address objects, address groups, and security rules.
"""

from __future__ import annotations

import csv
import fnmatch
import hashlib
import ipaddress
import json
import os
import ssl
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from defusedxml import ElementTree as SafeET

from bdnd_bpa_policy_builder import (
    GENERATED_FILE_PATTERNS,
    aggregate_log_paths,
    safe_name,
)

DEFAULT_GLOBAL_PING_TRACEROUTE_APPS = ("ping", "traceroute")
GLOBAL_PING_TRACEROUTE_RULE_NAME = "Global-Ping-Traceroute-allow"
DEFAULT_GLOBAL_DNS_APPS = ("dns-base",)
GLOBAL_INTERNAL_DNS_RULE_NAME = "Global-Internal-DNS-allow"
GLOBAL_DNS_EGRESS_RULE_NAME = "Global-DNS-Egress-allow"
GLOBAL_DNS_INTERNAL_RESOLVERS_GROUP = "Global-Internal-DNS-Resolvers"
GLOBAL_DNS_EXTERNAL_RESOLVERS_GROUP = "Global-External-DNS-Resolvers"


def is_internal(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def resolve_ptr(value: str) -> str:
    try:
        result = subprocess.run(
            ["getent", "hosts", value],
            capture_output=True,
            text=True,
            timeout=1,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.split()
            if len(parts) >= 2:
                return parts[1].rstrip(".").lower()
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def compact_name(prefix: str, value: str, max_len: int = 32) -> str:
    normalized = safe_name(f"{prefix}-{value}", max_len=128)
    if len(normalized) <= max_len:
        return normalized
    digest = hashlib.sha1(normalized.encode("utf-8"), usedforsecurity=False).hexdigest()[:7]
    return f"{normalized[: max_len - 8]}-{digest}"


def suffix_name(value: str, suffix: str, max_len: int = 32) -> str:
    normalized = safe_name(f"{value}-{suffix}", max_len=128)
    if len(normalized) <= max_len:
        return normalized
    digest = hashlib.sha1(normalized.encode("utf-8"), usedforsecurity=False).hexdigest()[:7]
    return f"{normalized[: max_len - 8]}-{digest}"


def unique_rule_name(base_name: str, used: set[str], max_len: int = 32) -> str:
    normalized = safe_name(base_name, max_len=128)
    if len(normalized) <= max_len:
        candidate = normalized or "rule"
    else:
        head, sep, tail = normalized.rpartition("-")
        if sep and tail:
            head_len = max_len - len(tail) - 1
            if head_len > 0:
                candidate = f"{head[:head_len].rstrip('-')}-{tail}".rstrip("-")
            else:
                candidate = normalized[:max_len].rstrip("-")
        else:
            candidate = normalized[:max_len].rstrip("-")
        candidate = candidate or "rule"
    if candidate not in used:
        used.add(candidate)
        return candidate

    digest = hashlib.sha1(base_name.encode("utf-8"), usedforsecurity=False).hexdigest()[:7]
    candidate = f"{candidate[: max_len - 8].rstrip('-')}-{digest}"
    if candidate not in used:
        used.add(candidate)
        return candidate

    counter = 2
    while True:
        suffix = f"-{counter}"
        fallback = f"{candidate[: max_len - len(suffix)].rstrip('-')}{suffix}"
        if fallback not in used:
            used.add(fallback)
            return fallback
        counter += 1


def object_name_for_ip(value: str, ptr_cache: dict[str, str]) -> tuple[str, str, str]:
    ptr = ptr_cache.setdefault(value, resolve_ptr(value))
    host_prefix = "128" if ipaddress.ip_address(value).version == 6 else "32"
    if ptr:
        # PTR is useful for a readable name, but the policy observed an IP.
        # Keep the object value exact so an existing IP object can be reused.
        return suffix_name(ptr, "ip"), "ip-netmask", f"{value}/{host_prefix}"
    return compact_name("ip", value.replace(".", "-").replace(":", "-")), "ip-netmask", f"{value}/{host_prefix}"


def object_name_for_literal_ip(value: str) -> tuple[str, str, str]:
    host_prefix = "128" if ipaddress.ip_address(value).version == 6 else "32"
    return compact_name("ip", value.replace(".", "-").replace(":", "-")), "ip-netmask", f"{value}/{host_prefix}"


def load_ptr_cache(path: Path | None) -> dict[str, str]:
    if path is None or not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {
        str(ip): str(ptr).rstrip(".").lower()
        for ip, ptr in raw.items()
        if isinstance(ip, str) and isinstance(ptr, str)
    }


def save_ptr_cache(path: Path | None, ptr_cache: dict[str, str]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(dict(sorted(ptr_cache.items())), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    tmp_path.replace(path)


def add_member_list(parent: ET.Element, values: Iterable[str]) -> None:
    for value in values:
        ET.SubElement(parent, "member").text = value


def ensure_address_object(
    addresses: ET.Element,
    name: str,
    kind: str,
    value: str,
    created: set[str],
) -> None:
    if name in created:
        return
    entry = ET.SubElement(addresses, "entry", {"name": name})
    ET.SubElement(entry, kind).text = value
    created.add(name)


def ensure_address_group(
    groups: ET.Element,
    name: str,
    members: list[str],
    created: set[str],
) -> None:
    if name in created:
        return
    entry = ET.SubElement(groups, "entry", {"name": name})
    static = ET.SubElement(entry, "static")
    add_member_list(static, members)
    created.add(name)


def ensure_service_object(
    services: ET.Element,
    name: str,
    proto: str,
    port: str,
    created: set[str],
) -> None:
    if name in created:
        return
    entry = ET.SubElement(services, "entry", {"name": name})
    protocol = ET.SubElement(entry, "protocol")
    proto_node = ET.SubElement(protocol, proto.lower())
    ET.SubElement(proto_node, "port").text = port
    created.add(name)


def ensure_tag_object(tags_root: ET.Element, name: str, created: set[str]) -> None:
    if name in created:
        return
    ET.SubElement(tags_root, "entry", {"name": name})
    created.add(name)


@dataclass
class RuleCandidate:
    src_zone: str
    dst_zone: str
    app: str
    service_members: tuple[str, ...]
    action: str
    anchor_rule: str
    sources: Counter[str]
    destinations: Counter[str]
    sessions: int = 0
    bytes_total: int = 0
    transports: Counter[str] | None = None


@dataclass(frozen=True)
class ZoneRoleConfig:
    zone_roles: dict[str, str]

    def role_for(self, zone: str) -> str:
        return self.zone_roles.get(zone, "other")

    def is_client(self, zone: str) -> bool:
        return self.role_for(zone) == "client"

    def is_internet(self, zone: str) -> bool:
        return self.role_for(zone) == "internet"


@dataclass(frozen=True)
class DeploymentConfig:
    panorama: bool
    scm: bool
    panorama_template: str
    panorama_rulebase: str
    panorama_log_setting: str
    panos_vsys: str
    panos_log_setting: str
    panos_endpoint: str
    panos_username: str
    panos_password: str
    panos_auto_push: bool


@dataclass(frozen=True)
class SCMConfig:
    scm_client_id: str
    scm_client_secret: str
    scm_tsg_id: str
    scm_token_url: str
    scm_api_base: str
    scm_folder: str
    scm_object_folder: str
    scm_snippet: str
    scm_device: str
    scm_rulebase: str
    scm_log_forwarding_profile: str


@dataclass(frozen=True)
class ProfileGroupConfig:
    client: str
    server: str
    internet: str
    other: str


@dataclass(frozen=True)
class BuilderConfig:
    logs: tuple[Path, ...]
    xml_output: Path
    review_csv: Path
    ptr_cache_file: Path | None
    disabled: bool
    tags: tuple[str, ...]
    global_ping_traceroute: bool
    global_ping_traceroute_apps: tuple[str, ...]
    global_dns: bool
    global_dns_apps: tuple[str, ...]
    global_dns_internal_resolvers: tuple[str, ...]
    global_dns_external_resolvers: tuple[str, ...]
    min_sessions: int
    limit: int
    group_threshold: int
    source_any_threshold: int
    workers: int
    include_actions: frozenset[str]
    log_setting: str | None


@dataclass
class ExistingConfigInventory:
    addresses: dict[tuple[str, str], str]
    address_groups: dict[frozenset[str], str]
    services: dict[tuple[str, str], str]
    service_groups: dict[frozenset[str], str]
    application_groups: dict[frozenset[str], str]
    address_names: set[str]
    address_group_names: set[str]
    service_names: set[str]
    service_group_names: set[str]

    @classmethod
    def empty(cls) -> "ExistingConfigInventory":
        return cls({}, {}, {}, {}, {}, set(), set(), set(), set())

    def summary(self) -> str:
        return (
            f"addresses={len(self.address_names)}, address-groups={len(self.address_group_names)}, "
            f"services={len(self.service_names)}, service-groups={len(self.service_group_names)}, "
            f"application-groups={len(self.application_groups)}"
        )


def normalize_app(value: str) -> str:
    return value if value not in {"any", "insufficient-data", "not-applicable", "incomplete", "unknown"} else "any"


def zone_order(value: str, zone_roles: ZoneRoleConfig) -> tuple[int, str]:
    return (0, value) if zone_roles.is_internet(value) else (1, value)


def candidate_order(candidate: RuleCandidate, zone_roles: ZoneRoleConfig) -> tuple[tuple[int, str], tuple[int, str], str, str, int, int]:
    return (
        zone_order(candidate.src_zone, zone_roles),
        zone_order(candidate.dst_zone, zone_roles),
        candidate.src_zone,
        candidate.app,
        candidate.sessions,
        candidate.bytes_total,
    )


def profile_group_for_rule(
    dst_zone: str,
    zone_roles: ZoneRoleConfig,
    profile_groups: ProfileGroupConfig,
) -> str:
    role = zone_roles.role_for(dst_zone)
    if role == "client":
        return profile_groups.client
    if role == "server":
        return profile_groups.server
    if role == "internet":
        return profile_groups.internet
    return profile_groups.other


def service_name(proto: str, port: str) -> str:
    return f"{port}_{proto.upper()}"


def parse_transport(value: str) -> tuple[str, str]:
    proto, _, port = value.partition("/")
    return proto.lower(), port


def service_member_for_flow(app: str, proto: str, dport: str) -> str:
    proto = proto.lower()
    if app == "ssl" and proto == "tcp" and dport != "443":
        return service_name(proto, dport)
    return "application-default"


def is_client_to_internet(src_zone: str, dst_zone: str, zone_roles: ZoneRoleConfig) -> bool:
    return zone_roles.is_client(src_zone) and zone_roles.is_internet(dst_zone)


def client_internet_web_service(proto: str, dport: str) -> str | None:
    if proto.lower() != "tcp":
        return None
    return {"80": "service-http", "443": "service-https"}.get(dport)


def is_global_ping_traceroute_app(app: str, apps: tuple[str, ...]) -> bool:
    return normalize_app(app) in set(apps)


def is_suppressed_global_app(app: str, apps: tuple[str, ...]) -> bool:
    return normalize_app(app) in set(apps)


def merge_candidates(
    aggregates: dict,
    min_sessions: int,
    limit: int,
    zone_roles: ZoneRoleConfig,
    suppressed_apps: tuple[str, ...] = (),
) -> list[RuleCandidate]:
    eligible = [agg for agg in aggregates.values() if agg.sessions >= min_sessions and agg.key.action == "allow"]
    eligible.sort(key=lambda agg: (agg.sessions, agg.bytes_total), reverse=True)
    if limit:
        eligible = eligible[:limit]

    merged: dict[tuple[str, str, str, str, str, str], RuleCandidate] = {}
    for agg in eligible:
        key = agg.key
        if is_global_ping_traceroute_app(key.app, suppressed_apps):
            continue
        web_service = client_internet_web_service(key.proto, key.dport)
        if is_client_to_internet(key.src_zone, key.dst_zone, zone_roles) and web_service:
            app = "any"
            service_members = (web_service,)
            bucket_service_key = web_service
        else:
            app = normalize_app(key.app)
            service_members = (service_member_for_flow(app, key.proto, key.dport),)
            bucket_service_key = service_members[0]
        anchor_rule = key.rule.strip()
        bucket_key = (key.src_zone, key.dst_zone, app, bucket_service_key, key.action, anchor_rule)
        candidate = merged.get(bucket_key)
        if candidate is None:
            candidate = RuleCandidate(
                src_zone=key.src_zone,
                dst_zone=key.dst_zone,
                app=app,
                service_members=service_members,
                action=key.action,
                anchor_rule=anchor_rule,
                sources=Counter(),
                destinations=Counter(),
                transports=Counter(),
            )
            merged[bucket_key] = candidate
        candidate.sessions += agg.sessions
        candidate.bytes_total += agg.bytes_total
        candidate.sources.update(agg.sources)
        candidate.destinations.update(agg.destinations)
        if candidate.transports is not None:
            candidate.transports[f"{key.proto}/{key.dport}"] += agg.sessions

    return sorted(
        merged.values(),
        key=lambda cand: (
            candidate_order(cand, zone_roles)[0],
            candidate_order(cand, zone_roles)[1],
            cand.app,
            ",".join(cand.service_members),
            cand.sessions,
            cand.bytes_total,
        ),
    )


def members_for_side(
    observed: Counter[str],
    side: str,
    zone: str,
    zone_roles: ZoneRoleConfig,
    ptr_cache: dict[str, str],
    addresses: ET.Element,
    groups: ET.Element,
    address_names: set[str],
    group_names: set[str],
    group_threshold: int,
    source_any_threshold: int,
) -> list[str]:
    if side == "destination" and any(not is_internal(value) for value in observed):
        return ["any"]
    if side == "source" and zone_roles.is_client(zone):
        return ["any"]
    if side == "source" and zone_roles.is_internet(zone):
        return ["any"]
    if side == "source" and len(observed) > source_any_threshold:
        return ["any"]

    object_names: list[str] = []
    for value, _ in observed.most_common():
        name, kind, object_value = object_name_for_ip(value, ptr_cache)
        ensure_address_object(addresses, name, kind, object_value, address_names)
        object_names.append(name)

    if len(object_names) > group_threshold:
        group_name = compact_name("grp", f"{side}-{','.join(object_names[:3])}-{len(object_names):02d}")
        ensure_address_group(groups, group_name, object_names, group_names)
        return [group_name]
    return object_names or ["any"]


def ensure_literal_ip_group(
    ips: tuple[str, ...],
    group_name: str,
    addresses: ET.Element,
    groups: ET.Element,
    address_names: set[str],
    group_names: set[str],
) -> str:
    object_names: list[str] = []
    for value in ips:
        ipaddress.ip_address(value)
        name, kind, object_value = object_name_for_literal_ip(value)
        ensure_address_object(addresses, name, kind, object_value, address_names)
        object_names.append(name)
    ensure_address_group(groups, group_name, object_names, group_names)
    return group_name


def infer_dns_egress_source_zones(
    aggregates: dict,
    resolver_ips: tuple[str, ...],
    dns_apps: tuple[str, ...],
    zone_roles: ZoneRoleConfig,
) -> list[str]:
    resolver_set = set(resolver_ips)
    dns_app_set = {normalize_app(app) for app in dns_apps}
    zones: Counter[str] = Counter()
    for aggregate in aggregates.values():
        key = aggregate.key
        if key.action != "allow":
            continue
        if normalize_app(key.app) not in dns_app_set:
            continue
        if not zone_roles.is_internet(key.dst_zone):
            continue
        if not resolver_set.intersection(aggregate.sources):
            continue
        zones[key.src_zone] += aggregate.sessions
    return sorted(zones, key=lambda zone: (-zones[zone], zone))


def build_xml(
    aggregates: dict,
    min_sessions: int,
    limit: int,
    group_threshold: int,
    source_any_threshold: int,
    disabled: bool,
    tags: tuple[str, ...],
    global_ping_traceroute: bool,
    global_ping_traceroute_apps: tuple[str, ...],
    global_dns: bool,
    global_dns_apps: tuple[str, ...],
    global_dns_internal_resolvers: tuple[str, ...],
    global_dns_external_resolvers: tuple[str, ...],
    zone_roles: ZoneRoleConfig,
    deployment: DeploymentConfig,
    log_setting: str,
    profile_groups: ProfileGroupConfig,
    ptr_cache: dict[str, str] | None = None,
) -> tuple[ET.ElementTree, list[dict[str, str]]]:
    config = ET.Element("config")
    devices = ET.SubElement(config, "devices")
    device = ET.SubElement(devices, "entry", {"name": "localhost.localdomain"})

    if deployment.panorama:
        shared = ET.SubElement(config, "shared")
        addresses = ET.SubElement(shared, "address")
        groups = ET.SubElement(shared, "address-group")
        services = ET.SubElement(shared, "service")
        tag_objects = ET.SubElement(shared, "tag")
        device_group_root = ET.SubElement(device, "device-group")
        device_group = ET.SubElement(device_group_root, "entry", {"name": deployment.panorama_template})
        rulebase = ET.SubElement(device_group, f"{deployment.panorama_rulebase}-rulebase")
        security = ET.SubElement(rulebase, "security")
        rules = ET.SubElement(security, "rules")
    else:
        vsys_root = ET.SubElement(device, "vsys")
        vsys_entry = ET.SubElement(vsys_root, "entry", {"name": deployment.panos_vsys})
        addresses = ET.SubElement(vsys_entry, "address")
        groups = ET.SubElement(vsys_entry, "address-group")
        services = ET.SubElement(vsys_entry, "service")
        tag_objects = ET.SubElement(vsys_entry, "tag")
        rulebase = ET.SubElement(vsys_entry, "rulebase")
        security = ET.SubElement(rulebase, "security")
        rules = ET.SubElement(security, "rules")

    ptr_cache = ptr_cache if ptr_cache is not None else {}
    address_names: set[str] = set()
    group_names: set[str] = set()
    service_names: set[str] = set()
    tag_names: set[str] = set()
    rule_names: set[str] = set()
    review_rows: list[dict[str, str]] = []
    observed_anchor_rules: Counter[str] = Counter()
    for aggregate in aggregates.values():
        if aggregate.key.rule:
            observed_anchor_rules[aggregate.key.rule] += aggregate.sessions
    default_anchor_rule = observed_anchor_rules.most_common(1)[0][0] if observed_anchor_rules else ""

    for tag in tags:
        ensure_tag_object(tag_objects, tag, tag_names)

    if global_ping_traceroute:
        global_zones = sorted(zone for zone in zone_roles.zone_roles if not zone_roles.is_internet(zone))
        if global_zones:
            rule_names.add(GLOBAL_PING_TRACEROUTE_RULE_NAME)
            entry = ET.SubElement(rules, "entry", {"name": GLOBAL_PING_TRACEROUTE_RULE_NAME})
            for element_name, values in {
                "from": global_zones,
                "to": global_zones,
                "source": ["any"],
                "destination": ["any"],
                "source-user": ["any"],
                "category": ["any"],
                "application": list(global_ping_traceroute_apps),
                "service": ["application-default"],
            }.items():
                add_member_list(ET.SubElement(entry, element_name), values)
            ET.SubElement(entry, "action").text = "allow"
            if disabled:
                ET.SubElement(entry, "disabled").text = "yes"
            if tags:
                add_member_list(ET.SubElement(entry, "tag"), tags)
            if log_setting:
                ET.SubElement(entry, "log-setting").text = log_setting
            profile_setting = ET.SubElement(entry, "profile-setting")
            group = ET.SubElement(profile_setting, "group")
            ET.SubElement(group, "member").text = profile_groups.other
            ET.SubElement(entry, "description").text = (
                "Generated global internal diagnostic rule. "
                "Internet-mapped zones are excluded; per-zone ping/traceroute rules are suppressed."
            )
            review_rows.append(
                {
                    "name": GLOBAL_PING_TRACEROUTE_RULE_NAME,
                    "from": ",".join(global_zones),
                    "to": ",".join(global_zones),
                    "source": "any",
                    "destination": "any",
                    "application": ",".join(global_ping_traceroute_apps),
                    "service": "application-default",
                    "sessions": "",
                    "destination_mode": "global-internal",
                    "disabled": "yes" if disabled else "no",
                    "tags": ",".join(tags),
                    "preflight_status": "not-checked",
                    "log_setting": log_setting,
                    "profile_group": profile_groups.other,
                    "anchor_rule": default_anchor_rule,
                }
            )

    if global_dns:
        internal_zones = sorted(zone for zone in zone_roles.zone_roles if not zone_roles.is_internet(zone))
        internet_zones = sorted(zone for zone in zone_roles.zone_roles if zone_roles.is_internet(zone))
        dns_egress_source_zones = infer_dns_egress_source_zones(
            aggregates,
            global_dns_internal_resolvers,
            global_dns_apps,
            zone_roles,
        ) or internal_zones
        internal_resolver_group = ""
        external_resolver_group = ""
        if global_dns_internal_resolvers:
            internal_resolver_group = ensure_literal_ip_group(
                global_dns_internal_resolvers,
                GLOBAL_DNS_INTERNAL_RESOLVERS_GROUP,
                addresses,
                groups,
                address_names,
                group_names,
            )
        if global_dns_external_resolvers:
            external_resolver_group = ensure_literal_ip_group(
                global_dns_external_resolvers,
                GLOBAL_DNS_EXTERNAL_RESOLVERS_GROUP,
                addresses,
                groups,
                address_names,
                group_names,
            )

        if internal_zones and internal_resolver_group:
            rule_names.add(GLOBAL_INTERNAL_DNS_RULE_NAME)
            entry = ET.SubElement(rules, "entry", {"name": GLOBAL_INTERNAL_DNS_RULE_NAME})
            for element_name, values in {
                "from": internal_zones,
                "to": internal_zones,
                "source": ["any"],
                "destination": [internal_resolver_group],
                "source-user": ["any"],
                "category": ["any"],
                "application": list(global_dns_apps),
                "service": ["application-default"],
            }.items():
                add_member_list(ET.SubElement(entry, element_name), values)
            ET.SubElement(entry, "action").text = "allow"
            if disabled:
                ET.SubElement(entry, "disabled").text = "yes"
            if tags:
                add_member_list(ET.SubElement(entry, "tag"), tags)
            if log_setting:
                ET.SubElement(entry, "log-setting").text = log_setting
            profile_setting = ET.SubElement(entry, "profile-setting")
            group = ET.SubElement(profile_setting, "group")
            ET.SubElement(group, "member").text = profile_groups.server
            ET.SubElement(entry, "description").text = (
                "Generated global internal DNS rule. "
                "Internal clients may query approved internal resolver objects."
            )
            review_rows.append(
                {
                    "name": GLOBAL_INTERNAL_DNS_RULE_NAME,
                    "from": ",".join(internal_zones),
                    "to": ",".join(internal_zones),
                    "source": "any",
                    "destination": internal_resolver_group,
                    "application": ",".join(global_dns_apps),
                    "service": "application-default",
                    "sessions": "",
                    "destination_mode": "global-dns-internal",
                    "disabled": "yes" if disabled else "no",
                    "tags": ",".join(tags),
                    "preflight_status": "not-checked",
                    "log_setting": log_setting,
                    "profile_group": profile_groups.server,
                    "anchor_rule": default_anchor_rule,
                }
            )

        if dns_egress_source_zones and internet_zones and internal_resolver_group and external_resolver_group:
            rule_names.add(GLOBAL_DNS_EGRESS_RULE_NAME)
            entry = ET.SubElement(rules, "entry", {"name": GLOBAL_DNS_EGRESS_RULE_NAME})
            for element_name, values in {
                "from": dns_egress_source_zones,
                "to": internet_zones,
                "source": [internal_resolver_group],
                "destination": [external_resolver_group],
                "source-user": ["any"],
                "category": ["any"],
                "application": list(global_dns_apps),
                "service": ["application-default"],
            }.items():
                add_member_list(ET.SubElement(entry, element_name), values)
            ET.SubElement(entry, "action").text = "allow"
            if disabled:
                ET.SubElement(entry, "disabled").text = "yes"
            if tags:
                add_member_list(ET.SubElement(entry, "tag"), tags)
            if log_setting:
                ET.SubElement(entry, "log-setting").text = log_setting
            profile_setting = ET.SubElement(entry, "profile-setting")
            group = ET.SubElement(profile_setting, "group")
            ET.SubElement(group, "member").text = profile_groups.internet
            ET.SubElement(entry, "description").text = (
                "Generated global DNS egress rule. "
                "Approved internal resolvers may query approved external resolver objects."
            )
            review_rows.append(
                {
                    "name": GLOBAL_DNS_EGRESS_RULE_NAME,
                    "from": ",".join(dns_egress_source_zones),
                    "to": ",".join(internet_zones),
                    "source": internal_resolver_group,
                    "destination": external_resolver_group,
                    "application": ",".join(global_dns_apps),
                    "service": "application-default",
                    "sessions": "",
                    "destination_mode": "global-dns-egress",
                    "disabled": "yes" if disabled else "no",
                    "tags": ",".join(tags),
                    "preflight_status": "not-checked",
                    "log_setting": log_setting,
                    "profile_group": profile_groups.internet,
                    "anchor_rule": default_anchor_rule,
                }
            )

    suppressed_apps = ()
    if global_ping_traceroute:
        suppressed_apps += global_ping_traceroute_apps
    if global_dns:
        suppressed_apps += global_dns_apps
    candidates = merge_candidates(aggregates, min_sessions, limit, zone_roles, suppressed_apps)

    for index, candidate in enumerate(candidates, start=1):
        name_parts = [candidate.src_zone, candidate.dst_zone, candidate.app]
        if candidate.service_members != ("application-default",):
            name_parts.extend(candidate.service_members)
        rule_name = unique_rule_name(
            f"{'-'.join(name_parts)}-{index:03d}",
            rule_names,
        )
        profile_group = profile_group_for_rule(
            candidate.dst_zone,
            zone_roles,
            profile_groups,
        )
        source_members = members_for_side(
            candidate.sources,
            "source",
            candidate.src_zone,
            zone_roles,
            ptr_cache,
            addresses,
            groups,
            address_names,
            group_names,
            group_threshold,
            source_any_threshold,
        )
        destination_members = members_for_side(
            candidate.destinations,
            "destination",
            candidate.dst_zone,
            zone_roles,
            ptr_cache,
            addresses,
            groups,
            address_names,
            group_names,
            group_threshold,
            source_any_threshold,
        )
        if candidate.service_members != ("application-default",) and candidate.transports:
            proto, port = parse_transport(next(iter(candidate.transports)))
            if candidate.service_members == ("service-http", "service-https"):
                pass
            else:
                ensure_service_object(services, candidate.service_members[0], proto, port, service_names)

        entry = ET.SubElement(rules, "entry", {"name": rule_name})
        for element_name, values in {
            "from": [candidate.src_zone],
            "to": [candidate.dst_zone],
            "source": source_members,
            "destination": destination_members,
            "source-user": ["any"],
            "category": ["any"],
            "application": [candidate.app],
            "service": list(candidate.service_members),
        }.items():
            add_member_list(ET.SubElement(entry, element_name), values)
        ET.SubElement(entry, "action").text = "allow"
        if disabled:
            ET.SubElement(entry, "disabled").text = "yes"
        if tags:
            add_member_list(ET.SubElement(entry, "tag"), tags)
        if log_setting:
            ET.SubElement(entry, "log-setting").text = log_setting
        profile_setting = ET.SubElement(entry, "profile-setting")
        group = ET.SubElement(profile_setting, "group")
        ET.SubElement(group, "member").text = profile_group
        transport_note = ""
        if candidate.transports:
            transport_note = f"; transports={','.join(candidate.transports)}"
        ET.SubElement(entry, "description").text = (
            f"Generated from traffic logs. sessions={candidate.sessions}; "
            f"bytes={candidate.bytes_total}; public_destination="
            f"{'yes' if destination_members == ['any'] else 'no'}{transport_note}"
        )

        review_rows.append(
            {
                "name": rule_name,
                "from": candidate.src_zone,
                "to": candidate.dst_zone,
                "source": ",".join(source_members),
                "destination": ",".join(destination_members),
                "application": candidate.app,
                "service": ",".join(candidate.service_members),
                "sessions": str(candidate.sessions),
                "destination_mode": "internet-any" if destination_members == ["any"] else "internal-objects",
                "disabled": "yes" if disabled else "no",
                "tags": ",".join(tags),
                "preflight_status": "not-checked",
                "log_setting": log_setting,
                "profile_group": profile_group,
                "anchor_rule": candidate.anchor_rule,
            }
        )

    return ET.ElementTree(config), review_rows


def write_review_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "name",
                "from",
                "to",
                "source",
                "destination",
                "application",
                "service",
                "sessions",
                "destination_mode",
                "disabled",
                "tags",
                "preflight_status",
                "config_reuse",
                "log_setting",
                "profile_group",
                "anchor_rule",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def import_name_for_path(path: Path, max_len: int = 32) -> str:
    suffix = path.suffix or ".xml"
    stem_max = max_len - len(suffix)
    stem = safe_name(path.stem, max_len=128)
    if len(stem) <= stem_max:
        return f"{stem}{suffix}"
    digest = hashlib.sha1(path.name.encode("utf-8"), usedforsecurity=False).hexdigest()[:7]
    trimmed = stem[: stem_max - 8].rstrip("-") or "import"
    return f"{trimmed}-{digest}{suffix}"


def api_get(endpoint: str, params: dict[str, str], ctx: ssl.SSLContext) -> str:
    request_params = dict(params)
    api_key = request_params.pop("key", "")
    url = endpoint.rstrip("/") + "/api?" + urllib.parse.urlencode(request_params)
    headers = {"X-PAN-KEY": api_key} if api_key else {}
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, context=ctx, timeout=120) as response:
        return response.read().decode("utf-8", errors="replace")


def api_post_form(endpoint: str, params: dict[str, str], ctx: ssl.SSLContext) -> str:
    request_params = dict(params)
    api_key = request_params.pop("key", "")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if api_key: headers["X-PAN-KEY"] = api_key
    request = urllib.request.Request(
        endpoint.rstrip("/") + "/api/",
        data=urllib.parse.urlencode(request_params).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, context=ctx, timeout=120) as response:
        return response.read().decode("utf-8", errors="replace")


def api_post_multipart(endpoint: str, params: dict[str, str], file_path: Path, ctx: ssl.SSLContext) -> str:
    request_params = dict(params)
    api_key = request_params.pop("key", "")
    boundary = "----bdndPanosBoundary"
    body: list[bytes] = []
    for key, value in request_params.items():
        body.append(f"--{boundary}\r\n".encode())
        body.append(f'Content-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode())
    body.append(f"--{boundary}\r\n".encode())
    body.append(
        f'Content-Disposition: form-data; name="file"; filename="{file_path.name}"\r\n'
        f"Content-Type: application/xml\r\n\r\n".encode()
    )
    body.append(file_path.read_bytes())
    body.append(b"\r\n")
    body.append(f"--{boundary}--\r\n".encode())
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    if api_key: headers["X-PAN-KEY"] = api_key
    request = urllib.request.Request(
        endpoint.rstrip("/") + "/api/",
        data=b"".join(body),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, context=ctx, timeout=300) as response:
        return response.read().decode("utf-8", errors="replace")


def parse_api_response(xml_text: str) -> tuple[str | None, str | None, ET.Element]:
    root = SafeET.fromstring(xml_text)
    return root.attrib.get("status"), root.attrib.get("code"), root


def require_success(xml_text: str, action: str) -> ET.Element:
    status, code, root = parse_api_response(xml_text)
    if status != "success":
        message = "".join(root.itertext()).strip()
        raise RuntimeError(f"{action} failed: status={status!r} code={code!r} msg={message}")
    return root


def xpath_literal(value: str) -> str:
    if "'" not in value:
        return f"'{value}'"
    if '"' not in value:
        return f'"{value}"'
    raise ValueError(f"XPath value cannot contain both quote types: {value!r}")


def xml_section_has_entries(tree: ET.ElementTree, path: str) -> bool:
    section = tree.getroot().find(path)
    return section is not None and section.find("./entry") is not None


def partial_load_sections(xml_path: Path, deployment: DeploymentConfig) -> list[tuple[str, str]]:
    tree = SafeET.parse(xml_path)
    device_name = xpath_literal("localhost.localdomain")
    sections: list[tuple[str, str, str]] = []
    format_values = {
        "device_name": device_name,
        "device_group": "",
        "rulebase": f"{deployment.panorama_rulebase}-rulebase",
        "vsys": "",
    }

    if deployment.panorama:
        device_group = xpath_literal(deployment.panorama_template)
        format_values["device_group"] = device_group
        sections = [
            ("/config/shared/address", "./shared/address", "/config/shared/address"),
            ("/config/shared/address-group", "./shared/address-group", "/config/shared/address-group"),
            ("/config/shared/service", "./shared/service", "/config/shared/service"),
            ("/config/shared/service-group", "./shared/service-group", "/config/shared/service-group"),
            ("/config/shared/tag", "./shared/tag", "/config/shared/tag"),
            (
                "/config/devices/entry[@name={device_name}]/device-group/entry[@name={device_group}]/{rulebase}/security/rules",
                "./devices/entry/device-group/entry[@name={device_group}]/{rulebase}/security/rules",
                "/config/devices/entry[@name={device_name}]/device-group/entry[@name={device_group}]/{rulebase}/security/rules",
            ),
        ]
    else:
        vsys = xpath_literal(deployment.panos_vsys)
        format_values["vsys"] = vsys
        sections = [
            (
                "/config/devices/entry[@name={device_name}]/vsys/entry[@name={vsys}]/address",
                "./devices/entry/vsys/entry[@name={vsys}]/address",
                "/config/devices/entry[@name={device_name}]/vsys/entry[@name={vsys}]/address",
            ),
            (
                "/config/devices/entry[@name={device_name}]/vsys/entry[@name={vsys}]/address-group",
                "./devices/entry/vsys/entry[@name={vsys}]/address-group",
                "/config/devices/entry[@name={device_name}]/vsys/entry[@name={vsys}]/address-group",
            ),
            (
                "/config/devices/entry[@name={device_name}]/vsys/entry[@name={vsys}]/service",
                "./devices/entry/vsys/entry[@name={vsys}]/service",
                "/config/devices/entry[@name={device_name}]/vsys/entry[@name={vsys}]/service",
            ),
            (
                "/config/devices/entry[@name={device_name}]/vsys/entry[@name={vsys}]/service-group",
                "./devices/entry/vsys/entry[@name={vsys}]/service-group",
                "/config/devices/entry[@name={device_name}]/vsys/entry[@name={vsys}]/service-group",
            ),
            (
                "/config/devices/entry[@name={device_name}]/vsys/entry[@name={vsys}]/tag",
                "./devices/entry/vsys/entry[@name={vsys}]/tag",
                "/config/devices/entry[@name={device_name}]/vsys/entry[@name={vsys}]/tag",
            ),
            (
                "/config/devices/entry[@name={device_name}]/vsys/entry[@name={vsys}]/rulebase/security/rules",
                "./devices/entry/vsys/entry[@name={vsys}]/rulebase/security/rules",
                "/config/devices/entry[@name={device_name}]/vsys/entry[@name={vsys}]/rulebase/security/rules",
            ),
        ]

    load_sections: list[tuple[str, str]] = []
    for from_template, xml_find_path, to_template in sections:
        if xml_section_has_entries(tree, xml_find_path.format(**format_values)):
            load_sections.append(
                (
                    from_template.format(**format_values),
                    to_template.format(**format_values),
                )
            )
    return load_sections


def scm_api_root(api_base: str) -> str:
    trimmed = api_base.rstrip("/")
    marker = "/config/"
    if marker in trimmed:
        return trimmed.split(marker, 1)[0]
    return trimmed


def scm_container(folder: str = "", snippet: str = "", device: str = "") -> dict[str, str]:
    values = {
        "folder": folder.strip(),
        "snippet": snippet.strip(),
        "device": device.strip(),
    }
    selected = {key: value for key, value in values.items() if value}
    if len(selected) != 1:
        raise RuntimeError("SCM configuration requires exactly one of folder, snippet, or device")
    return selected


def scm_http_request(
    method: str,
    url: str,
    token: str,
    payload: dict[str, Any] | None = None,
    params: dict[str, str] | None = None,
) -> Any:
    full_url = url
    if params:
        full_url = f"{url}?{urllib.parse.urlencode(params)}"
    data = None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(full_url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            body = response.read().decode("utf-8", errors="replace")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {full_url} failed: HTTP {exc.code}: {body}") from exc


def response_items(response: Any) -> list[dict[str, Any]]:
    if isinstance(response, list):
        return [item for item in response if isinstance(item, dict)]
    if not isinstance(response, dict):
        return []
    for key in ("data", "items", "results", "entry"):
        value = response.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = response_items(value)
            if nested:
                return nested
    return [response] if response.get("id") or response.get("name") else []


def normalized_address_value(kind: str, value: str) -> tuple[str, str]:
    value = str(value).strip()
    if kind == "ip-netmask":
        try:
            value = str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            pass
    elif kind == "fqdn":
        value = value.rstrip(".").lower()
    return kind, value


def preferred(existing: dict[Any, str], key: Any, name: str) -> None:
    current = existing.get(key)
    if current is None or (len(name), name.lower()) < (len(current), current.lower()):
        existing[key] = name


def add_scm_inventory_items(inventory: ExistingConfigInventory, kind: str, items: list[dict[str, Any]]) -> None:
    for item in items:
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        if kind == "addresses":
            inventory.address_names.add(name)
            for payload_key, xml_key in (("ip_netmask", "ip-netmask"), ("ip_range", "ip-range"), ("ip_wildcard", "ip-wildcard"), ("fqdn", "fqdn")):
                if item.get(payload_key):
                    preferred(inventory.addresses, normalized_address_value(xml_key, str(item[payload_key])), name)
                    break
        elif kind == "address-groups":
            inventory.address_group_names.add(name)
            members = payload_members(item, "static")
            if members:
                preferred(inventory.address_groups, frozenset(members), name)
        elif kind == "services":
            inventory.service_names.add(name)
            protocol = item.get("protocol") or {}
            if isinstance(protocol, dict):
                for proto in ("tcp", "udp", "sctp"):
                    details = protocol.get(proto)
                    if isinstance(details, dict) and details.get("port"):
                        preferred(inventory.services, (proto, str(details["port"]).strip()), name)
                        break
        elif kind == "service-groups":
            inventory.service_group_names.add(name)
            members = payload_members(item, "members")
            if members:
                preferred(inventory.service_groups, frozenset(members), name)
        elif kind == "application-groups":
            members = payload_members(item, "members", "applications")
            if members:
                preferred(inventory.application_groups, frozenset(members), name)


def scm_fetch_all(endpoint: str, token: str, container: dict[str, str]) -> list[dict[str, Any]]:
    offset = 0
    collected: list[dict[str, Any]] = []
    while True:
        params = {**container, "limit": "200", "offset": str(offset)}
        response = scm_http_request("GET", endpoint, token, params=params)
        page = response_items(response)
        collected.extend(page)
        total = response.get("total") if isinstance(response, dict) else None
        if not page or len(page) < 200 or not isinstance(total, int) or len(collected) >= total:
            break
        offset += len(page)
    return collected


def fetch_scm_inventory(scm: SCMConfig) -> ExistingConfigInventory:
    token = get_scm_token(scm)
    root = scm_api_root(scm.scm_api_base) + "/config/objects/v1"
    container = scm_container(folder=scm.scm_object_folder, snippet=scm.scm_snippet, device=scm.scm_device)
    inventory = ExistingConfigInventory.empty()
    for kind in ("addresses", "address-groups", "services", "service-groups", "application-groups"):
        add_scm_inventory_items(inventory, kind, scm_fetch_all(f"{root}/{kind}", token, container))
    return inventory


def panos_api_key(deployment: DeploymentConfig, ctx: ssl.SSLContext) -> str:
    key_root = require_success(
        api_post_form(deployment.panos_endpoint, {"type": "keygen", "user": deployment.panos_username, "password": deployment.panos_password}, ctx),
        "keygen",
    )
    key = key_root.findtext(".//key")
    if not key:
        raise RuntimeError("keygen succeeded but did not return an API key")
    return key


def add_xml_inventory_section(inventory: ExistingConfigInventory, kind: str, entries: Iterable[ET.Element]) -> None:
    for entry in entries:
        name = entry.attrib.get("name", "").strip()
        if not name:
            continue
        if kind == "addresses":
            inventory.address_names.add(name)
            for xml_key in ("ip-netmask", "ip-range", "ip-wildcard", "fqdn"):
                value = entry.findtext(f"./{xml_key}")
                if value:
                    preferred(inventory.addresses, normalized_address_value(xml_key, value), name)
                    break
        elif kind == "address-groups":
            inventory.address_group_names.add(name)
            members = frozenset(rule_member_values(entry, "./static/member"))
            if members:
                preferred(inventory.address_groups, members, name)
        elif kind == "services":
            inventory.service_names.add(name)
            for proto in ("tcp", "udp", "sctp"):
                port = entry.findtext(f"./protocol/{proto}/port")
                if port:
                    preferred(inventory.services, (proto, port.strip()), name)
                    break
        elif kind == "service-groups":
            inventory.service_group_names.add(name)
            members = frozenset(rule_member_values(entry, "./members/member"))
            if members:
                preferred(inventory.service_groups, members, name)
        elif kind == "application-groups":
            members = frozenset(rule_member_values(entry, "./members/member"))
            if members:
                preferred(inventory.application_groups, members, name)


def fetch_panos_inventory(deployment: DeploymentConfig) -> ExistingConfigInventory:
    ctx = ssl._create_unverified_context()
    key = panos_api_key(deployment, ctx)
    device_name = xpath_literal("localhost.localdomain")
    if deployment.panorama:
        dg = xpath_literal(deployment.panorama_template)
        bases = [
            "/config/shared",
            f"/config/devices/entry[@name={device_name}]/device-group/entry[@name={dg}]",
        ]
    else:
        vsys = xpath_literal(deployment.panos_vsys)
        bases = [f"/config/devices/entry[@name={device_name}]/vsys/entry[@name={vsys}]"]
    inventory = ExistingConfigInventory.empty()
    for base in bases:
        for kind, node in (("addresses", "address"), ("address-groups", "address-group"), ("services", "service"), ("service-groups", "service-group"), ("application-groups", "application-group")):
            response = require_success(
                api_get(deployment.panos_endpoint, {"type": "config", "action": "get", "xpath": f"{base}/{node}", "key": key}, ctx),
                f"fetch existing {kind}",
            )
            add_xml_inventory_section(inventory, kind, response.findall(".//entry"))
    return inventory


def replace_members(root: ET.Element | None, path: str, replacements: dict[str, str]) -> None:
    if root is None:
        return
    for member in root.findall(path):
        if member.text in replacements:
            member.text = replacements[member.text]


def collision_safe_name(name: str, semantic: str, occupied: set[str]) -> str:
    if name not in occupied:
        occupied.add(name)
        return name
    digest = hashlib.sha1(semantic.encode("utf-8"), usedforsecurity=False).hexdigest()[:7]
    candidate = suffix_name(name, f"forge-{digest}")
    counter = 2
    while candidate in occupied:
        candidate = suffix_name(name, f"forge-{digest}-{counter}")
        counter += 1
    occupied.add(candidate)
    return candidate


def apply_existing_inventory(
    tree: ET.ElementTree,
    rows: list[dict[str, str]],
    deployment: DeploymentConfig,
    inventory: ExistingConfigInventory,
) -> Counter[str]:
    addresses, address_groups, services, service_groups, rules = extract_xml_sections(tree, deployment)
    replacements: dict[str, str] = {}
    reused: Counter[str] = Counter()

    if addresses is not None:
        for entry in list(addresses.findall("./entry")):
            old = entry.attrib["name"]
            semantic = None
            for kind in ("ip-netmask", "ip-range", "ip-wildcard", "fqdn"):
                value = entry.findtext(f"./{kind}")
                if value:
                    semantic = normalized_address_value(kind, value)
                    break
            existing = inventory.addresses.get(semantic) if semantic else None
            if existing:
                replacements[old] = existing
                addresses.remove(entry)
                reused["addresses"] += 1
            elif old in inventory.address_names:
                new = collision_safe_name(old, repr(semantic), inventory.address_names)
                entry.attrib["name"] = new
                replacements[old] = new

    if services is not None:
        for entry in list(services.findall("./entry")):
            old = entry.attrib["name"]
            semantic = None
            for proto in ("tcp", "udp", "sctp"):
                port = entry.findtext(f"./protocol/{proto}/port")
                if port:
                    semantic = (proto, port.strip())
                    break
            existing = inventory.services.get(semantic) if semantic else None
            if existing:
                replacements[old] = existing
                services.remove(entry)
                reused["services"] += 1
            elif old in inventory.service_names:
                new = collision_safe_name(old, repr(semantic), inventory.service_names)
                entry.attrib["name"] = new
                replacements[old] = new

    replace_members(address_groups, ".//static/member", replacements)
    replace_members(service_groups, ".//members/member", replacements)
    replace_members(rules, ".//source/member", replacements)
    replace_members(rules, ".//destination/member", replacements)
    replace_members(rules, ".//service/member", replacements)

    group_replacements: dict[str, str] = {}
    if address_groups is not None:
        for entry in list(address_groups.findall("./entry")):
            old = entry.attrib["name"]
            members = frozenset(rule_member_values(entry, "./static/member"))
            existing = inventory.address_groups.get(members)
            if existing:
                group_replacements[old] = existing
                address_groups.remove(entry)
                reused["address-groups"] += 1
            elif old in inventory.address_group_names:
                new = collision_safe_name(old, repr(sorted(members)), inventory.address_group_names)
                entry.attrib["name"] = new
                group_replacements[old] = new
    if service_groups is not None:
        for entry in list(service_groups.findall("./entry")):
            old = entry.attrib["name"]
            members = frozenset(rule_member_values(entry, "./members/member"))
            existing = inventory.service_groups.get(members)
            if existing:
                group_replacements[old] = existing
                service_groups.remove(entry)
                reused["service-groups"] += 1
            elif old in inventory.service_group_names:
                new = collision_safe_name(old, repr(sorted(members)), inventory.service_group_names)
                entry.attrib["name"] = new
                group_replacements[old] = new
    replace_members(rules, ".//source/member", group_replacements)
    replace_members(rules, ".//destination/member", group_replacements)
    replace_members(rules, ".//service/member", group_replacements)

    if rules is not None:
        for entry in rules.findall("./entry"):
            for node_name in ("source", "destination"):
                node = entry.find(f"./{node_name}")
                members = frozenset(rule_member_values(entry, f"./{node_name}/member"))
                existing_group = inventory.address_groups.get(members)
                if node is not None and existing_group and members != {"any"}:
                    for member in list(node):
                        node.remove(member)
                    ET.SubElement(node, "member").text = existing_group
                    reused["address-groups"] += 1
            service_node = entry.find("./service")
            service_members = frozenset(rule_member_values(entry, "./service/member"))
            existing_service_group = inventory.service_groups.get(service_members)
            if service_node is not None and existing_service_group and service_members != {"application-default"}:
                for member in list(service_node):
                    service_node.remove(member)
                ET.SubElement(service_node, "member").text = existing_service_group
                reused["service-groups"] += 1
            app_node = entry.find("./application")
            if app_node is not None:
                members = frozenset(rule_member_values(entry, "./application/member"))
                existing = inventory.application_groups.get(members)
                if existing:
                    for member in list(app_node):
                        app_node.remove(member)
                    ET.SubElement(app_node, "member").text = existing
                    reused["application-groups"] += 1
            row = next((item for item in rows if item.get("name") == entry.attrib.get("name")), None)
            if row is not None:
                row["source"] = ",".join(rule_member_values(entry, "./source/member"))
                row["destination"] = ",".join(rule_member_values(entry, "./destination/member"))
                row["application"] = ",".join(rule_member_values(entry, "./application/member"))
                row["service"] = ",".join(rule_member_values(entry, "./service/member"))
                row["config_reuse"] = ",".join(f"{key}={value}" for key, value in sorted(reused.items())) or "none"
    return reused


def get_scm_token(scm: SCMConfig) -> str:
    missing = [
        name
        for name, value in {
            "scm_client_id": scm.scm_client_id,
            "scm_client_secret": scm.scm_client_secret,
            "scm_tsg_id": scm.scm_tsg_id,
        }.items()
        if not value
    ]
    if missing:
        raise RuntimeError(f"SCM configuration is incomplete: missing {', '.join(missing)}")
    form = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": scm.scm_client_id,
            "client_secret": scm.scm_client_secret,
            "scope": f"tsg_id:{scm.scm_tsg_id}",
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        scm.scm_token_url,
        data=form,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            token_data = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"SCM token request failed: HTTP {exc.code}: {body}") from exc
    token = token_data.get("access_token")
    if not token:
        raise RuntimeError("SCM token response did not contain access_token")
    return token


def scm_fetch_existing(
    endpoint: str,
    token: str,
    name: str,
    container_params: dict[str, str],
    extra_params: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    params = dict(container_params)
    params["name"] = name
    if extra_params:
        params.update(extra_params)
    try:
        response = scm_http_request("GET", endpoint, token, params=params)
    except RuntimeError as exc:
        if "HTTP 404" in str(exc):
            return None
        raise
    if isinstance(response, dict) and response.get("id"):
        return response
    return None


def scm_fetch_rules(endpoint: str, token: str, container_params: dict[str, str], rulebase: str) -> list[dict[str, Any]]:
    params = dict(container_params)
    params["position"] = rulebase
    response = scm_http_request("GET", endpoint, token, params=params)
    return response_items(response)


def scm_upsert(
    endpoint: str,
    token: str,
    payload: dict[str, Any],
    container_params: dict[str, str],
    extra_params: dict[str, str] | None = None,
) -> dict[str, Any]:
    existing = scm_fetch_existing(
        endpoint,
        token,
        str(payload["name"]),
        container_params,
        extra_params,
    )
    if existing and existing.get("id"):
        update_url = f"{endpoint}/{existing['id']}"
        return scm_http_request("PUT", update_url, token, payload=payload, params=extra_params)
    return scm_http_request("POST", endpoint, token, payload=payload, params=extra_params)


def rule_member_values(entry: ET.Element, path: str) -> list[str]:
    return [member.text for member in entry.findall(path) if member.text]


def normalized_members(values: Any) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, Iterable):
        return (str(values).strip(),)
    return tuple(sorted(str(value).strip() for value in values if str(value).strip()))


def payload_members(payload: dict[str, Any], *keys: str) -> tuple[str, ...]:
    for key in keys:
        if key in payload:
            return normalized_members(payload.get(key))
    return ()


def payload_rule_key(payload: dict[str, Any]) -> tuple[tuple[str, ...], ...]:
    return (
        payload_members(payload, "from"),
        payload_members(payload, "to"),
        payload_members(payload, "source"),
        payload_members(payload, "destination"),
        payload_members(payload, "source_user", "source-user"),
        payload_members(payload, "category"),
        payload_members(payload, "application"),
        payload_members(payload, "service"),
        normalized_members(payload.get("action", "allow")),
    )


def xml_rule_key(entry: ET.Element) -> tuple[tuple[str, ...], ...]:
    return (
        normalized_members(rule_member_values(entry, "./from/member")),
        normalized_members(rule_member_values(entry, "./to/member")),
        normalized_members(rule_member_values(entry, "./source/member")),
        normalized_members(rule_member_values(entry, "./destination/member")),
        normalized_members(rule_member_values(entry, "./source-user/member") or ["any"]),
        normalized_members(rule_member_values(entry, "./category/member") or ["any"]),
        normalized_members(rule_member_values(entry, "./application/member") or ["any"]),
        normalized_members(rule_member_values(entry, "./service/member") or ["application-default"]),
        normalized_members(entry.findtext("./action", "allow")),
    )


def set_preflight_statuses(
    rows: list[dict[str, str]],
    generated_rules: list[tuple[str, tuple[tuple[str, ...], ...]]],
    existing_name_keys: dict[str, tuple[tuple[str, ...], ...]],
    existing_rule_keys: set[tuple[tuple[str, ...], ...]],
) -> Counter[str]:
    row_by_name = {row["name"]: row for row in rows}
    statuses: Counter[str] = Counter()
    for name, rule_key in generated_rules:
        if name in existing_name_keys:
            status = "same-name-update" if existing_name_keys[name] == rule_key else "changed"
        elif rule_key in existing_rule_keys:
            status = "duplicate-match-skip"
        else:
            status = "new"
        if name in row_by_name:
            row_by_name[name]["preflight_status"] = status
        statuses[status] += 1
    for row in rows:
        row.setdefault("preflight_status", "not-checked")
    return statuses


def remove_skipped_xml_rules(tree: ET.ElementTree, deployment: DeploymentConfig, rows: list[dict[str, str]]) -> int:
    skip_names = {row["name"] for row in rows if row.get("preflight_status") == "duplicate-match-skip"}
    if not skip_names:
        return 0
    *_, rules_root = extract_xml_sections(tree, deployment)
    if rules_root is None:
        return 0
    removed = 0
    for entry in list(rules_root.findall("./entry")):
        if entry.attrib.get("name") in skip_names:
            rules_root.remove(entry)
            removed += 1
    return removed


def preflight_scm_rules(
    tree: ET.ElementTree,
    rows: list[dict[str, str]],
    deployment: DeploymentConfig,
    scm: SCMConfig,
    zone_roles: ZoneRoleConfig,
    profile_groups: ProfileGroupConfig,
) -> Counter[str]:
    token = get_scm_token(scm)
    api_root = scm_api_root(scm.scm_api_base)
    security_base = api_root + "/config/security/v1"
    rule_container = scm_container(
        folder=scm.scm_folder,
        snippet=scm.scm_snippet,
        device=scm.scm_device,
    )
    existing_rules = scm_fetch_rules(f"{security_base}/security-rules", token, rule_container, scm.scm_rulebase)
    existing_name_keys = {
        normalized_scm_rule_name(str(rule["name"])): payload_rule_key(rule)
        for rule in existing_rules
        if rule.get("name")
    }
    existing_rule_keys = {payload_rule_key(rule) for rule in existing_rules}
    generated_rules = [
        (str(rule["name"]), payload_rule_key(rule))
        for rule in build_scm_payloads(tree, deployment, scm, zone_roles, profile_groups)["rules"]
    ]
    return set_preflight_statuses(rows, generated_rules, existing_name_keys, existing_rule_keys)


def rules_xpath(deployment: DeploymentConfig) -> str:
    device_name = xpath_literal("localhost.localdomain")
    if deployment.panorama:
        device_group = xpath_literal(deployment.panorama_template)
        return (
            f"/config/devices/entry[@name={device_name}]/device-group/entry[@name={device_group}]/"
            f"{deployment.panorama_rulebase}-rulebase/security/rules"
        )
    vsys = xpath_literal(deployment.panos_vsys)
    return f"/config/devices/entry[@name={device_name}]/vsys/entry[@name={vsys}]/rulebase/security/rules"


def fetch_panos_rule_entries(deployment: DeploymentConfig) -> list[ET.Element]:
    ctx = ssl._create_unverified_context()
    key = panos_api_key(deployment, ctx)
    response = require_success(
        api_get(
            deployment.panos_endpoint,
            {"type": "config", "action": "get", "xpath": rules_xpath(deployment), "key": key},
            ctx,
        ),
        "fetch existing security rules",
    )
    return list(response.findall(".//entry"))


def preflight_panos_rules(
    tree: ET.ElementTree,
    rows: list[dict[str, str]],
    deployment: DeploymentConfig,
) -> Counter[str]:
    existing_entries = fetch_panos_rule_entries(deployment)
    existing_name_keys = {
        entry.attrib["name"]: xml_rule_key(entry)
        for entry in existing_entries
        if entry.attrib.get("name")
    }
    existing_rule_keys = {xml_rule_key(entry) for entry in existing_entries}
    *_, rules_root = extract_xml_sections(tree, deployment)
    generated_rules = [
        (entry.attrib["name"], xml_rule_key(entry))
        for entry in rules_root.findall("./entry")
    ] if rules_root is not None else []
    return set_preflight_statuses(rows, generated_rules, existing_name_keys, existing_rule_keys)


def movable_anchor_map(rows: list[dict[str, str]]) -> dict[str, str]:
    return {
        row["name"]: row["anchor_rule"]
        for row in rows
        if row.get("name") and row.get("anchor_rule") and row.get("preflight_status") != "duplicate-match-skip"
    }


def rule_move_destination(anchor_name: str, existing_names: set[str], normalizer=lambda value: value) -> tuple[str, str]:
    return ("before", anchor_name) if normalizer(anchor_name) in existing_names else ("bottom", "")


def normalized_scm_rule_name(name: str) -> str:
    return name[2:] if name.startswith("r-") else name


def extract_xml_sections(tree: ET.ElementTree, deployment: DeploymentConfig) -> tuple[ET.Element | None, ET.Element | None, ET.Element | None, ET.Element | None, ET.Element | None]:
    root = tree.getroot()
    if deployment.panorama:
        shared = root.find("./shared")
        if shared is None:
            raise RuntimeError("Generated XML is missing shared objects for Panorama mode")
        rule_path = (
            "./devices/entry/device-group/entry"
            f"[@name='{deployment.panorama_template}']/{deployment.panorama_rulebase}-rulebase/security/rules"
        )
        rules = root.find(rule_path)
        return (
            shared.find("./address"),
            shared.find("./address-group"),
            shared.find("./service"),
            shared.find("./service-group"),
            rules,
        )

    vsys = root.find(f"./devices/entry/vsys/entry[@name='{deployment.panos_vsys}']")
    if vsys is None:
        raise RuntimeError(f"Generated XML is missing vsys {deployment.panos_vsys!r}")
    return (
        vsys.find("./address"),
        vsys.find("./address-group"),
        vsys.find("./service"),
        vsys.find("./service-group"),
        vsys.find("./rulebase/security/rules"),
    )


def build_scm_payloads(
    tree: ET.ElementTree,
    deployment: DeploymentConfig,
    scm: SCMConfig,
    zone_roles: ZoneRoleConfig,
    profile_groups: ProfileGroupConfig,
) -> dict[str, list[dict[str, Any]]]:
    addresses_root, address_groups_root, services_root, service_groups_root, rules_root = extract_xml_sections(
        tree,
        deployment,
    )
    object_container = scm_container(
        folder=scm.scm_object_folder,
        snippet=scm.scm_snippet,
        device=scm.scm_device,
    )
    rule_container = scm_container(
        folder=scm.scm_folder,
        snippet=scm.scm_snippet,
        device=scm.scm_device,
    )
    rule_tags: set[str] = set()

    address_payloads: list[dict[str, Any]] = []
    if addresses_root is not None:
        for entry in addresses_root.findall("./entry"):
            payload: dict[str, Any] = {"name": entry.attrib["name"], **object_container}
            for xml_key, payload_key in {
                "ip-netmask": "ip_netmask",
                "ip-range": "ip_range",
                "ip-wildcard": "ip_wildcard",
                "fqdn": "fqdn",
            }.items():
                value = entry.findtext(f"./{xml_key}")
                if value:
                    payload[payload_key] = value
                    break
            description = entry.findtext("./description")
            if description:
                payload["description"] = description
            address_payloads.append(payload)

    address_group_payloads: list[dict[str, Any]] = []
    if address_groups_root is not None:
        for entry in address_groups_root.findall("./entry"):
            payload = {
                "name": entry.attrib["name"],
                "static": rule_member_values(entry, "./static/member"),
                **object_container,
            }
            description = entry.findtext("./description")
            if description:
                payload["description"] = description
            address_group_payloads.append(payload)

    service_payloads: list[dict[str, Any]] = []
    if services_root is not None:
        for entry in services_root.findall("./entry"):
            protocol_payload: dict[str, Any] = {}
            for proto in ("tcp", "udp", "sctp"):
                port = entry.findtext(f"./protocol/{proto}/port")
                if port:
                    protocol_payload[proto] = {"port": port}
                    break
            if not protocol_payload:
                continue
            payload = {
                "name": entry.attrib["name"],
                "protocol": protocol_payload,
                **object_container,
            }
            description = entry.findtext("./description")
            if description:
                payload["description"] = description
            service_payloads.append(payload)

    service_group_payloads: list[dict[str, Any]] = []
    if service_groups_root is not None:
        for entry in service_groups_root.findall("./entry"):
            members = rule_member_values(entry, "./members/member")
            if not members:
                continue
            payload = {
                "name": entry.attrib["name"],
                "members": members,
                **object_container,
            }
            description = entry.findtext("./description")
            if description:
                payload["description"] = description
            service_group_payloads.append(payload)

    rule_payloads: list[dict[str, Any]] = []
    if rules_root is not None:
        for entry in rules_root.findall("./entry"):
            from_members = rule_member_values(entry, "./from/member")
            to_members = rule_member_values(entry, "./to/member")
            src_zone = from_members[0] if from_members else "any"
            dst_zone = to_members[0] if to_members else "any"
            source_members = rule_member_values(entry, "./source/member")
            if zone_roles.is_client(src_zone):
                source_members = ["any"]
            profile_group = rule_member_values(entry, "./profile-setting/group/member")
            if not profile_group:
                profile_group = [profile_group_for_rule(dst_zone, zone_roles, profile_groups)]
            payload = {
                "name": normalized_scm_rule_name(entry.attrib["name"]),
                "from": from_members,
                "to": to_members,
                "source": source_members or ["any"],
                "destination": rule_member_values(entry, "./destination/member"),
                "source_user": rule_member_values(entry, "./source-user/member") or ["any"],
                "category": rule_member_values(entry, "./category/member") or ["any"],
                "application": rule_member_values(entry, "./application/member") or ["any"],
                "service": rule_member_values(entry, "./service/member") or ["application-default"],
                "action": entry.findtext("./action", "allow"),
                "disabled": entry.findtext("./disabled", "no").lower() == "yes",
                **rule_container,
            }
            description = entry.findtext("./description")
            if description:
                payload["description"] = description
            log_setting = entry.findtext("./log-setting")
            if log_setting:
                payload["log_setting"] = log_setting
            tags = rule_member_values(entry, "./tag/member")
            if tags:
                payload["tag"] = tags
                rule_tags.update(tags)
            if profile_group:
                payload["profile_setting"] = {"group": profile_group}
            rule_payloads.append(payload)

    rule_payloads.sort(
        key=lambda payload: (
            0 if payload["name"] == GLOBAL_PING_TRACEROUTE_RULE_NAME else 1,
            zone_order(payload["from"][0] if payload["from"] else "any", zone_roles),
            zone_order(payload["to"][0] if payload["to"] else "any", zone_roles),
            payload["name"],
        )
    )

    return {
        "tags": [{"name": tag, **object_container} for tag in sorted(rule_tags)],
        "addresses": address_payloads,
        "address_groups": address_group_payloads,
        "services": service_payloads,
        "service_groups": service_group_payloads,
        "rules": rule_payloads,
    }


def push_to_scm(
    tree: ET.ElementTree,
    deployment: DeploymentConfig,
    scm: SCMConfig,
    zone_roles: ZoneRoleConfig,
    profile_groups: ProfileGroupConfig,
    review_rows: list[dict[str, str]],
) -> None:
    token = get_scm_token(scm)
    api_root = scm_api_root(scm.scm_api_base)
    objects_base = api_root + "/config/objects/v1"
    security_base = api_root + "/config/security/v1"
    payloads = build_scm_payloads(tree, deployment, scm, zone_roles, profile_groups)
    object_container = scm_container(
        folder=scm.scm_object_folder,
        snippet=scm.scm_snippet,
        device=scm.scm_device,
    )
    rule_container = scm_container(
        folder=scm.scm_folder,
        snippet=scm.scm_snippet,
        device=scm.scm_device,
    )
    rule_params = {"position": scm.scm_rulebase}

    for payload in payloads["tags"]:
        scm_upsert(f"{objects_base}/tags", token, payload, object_container)
    for payload in payloads["addresses"]:
        scm_upsert(f"{objects_base}/addresses", token, payload, object_container)
    for payload in payloads["address_groups"]:
        scm_upsert(f"{objects_base}/address-groups", token, payload, object_container)
    for payload in payloads["services"]:
        scm_upsert(f"{objects_base}/services", token, payload, object_container)
    for payload in payloads["service_groups"]:
        scm_upsert(f"{objects_base}/service-groups", token, payload, object_container)
    for payload in payloads["rules"]:
        scm_upsert(f"{security_base}/security-rules", token, payload, rule_container, rule_params)

    current_rules = scm_fetch_rules(f"{security_base}/security-rules", token, rule_container, scm.scm_rulebase)
    rules_by_name = {
        normalized_scm_rule_name(str(rule["name"])): rule
        for rule in current_rules
        if rule.get("name") and rule.get("id")
    }
    for generated_name, anchor_name in movable_anchor_map(review_rows).items():
        generated = rules_by_name.get(normalized_scm_rule_name(generated_name))
        anchor = rules_by_name.get(normalized_scm_rule_name(anchor_name))
        if not generated:
            raise RuntimeError(f"Cannot move generated policy {generated_name!r}: rule was not returned by SCM")
        destination, _ = rule_move_destination(anchor_name, set(rules_by_name), normalized_scm_rule_name)
        move_payload = {"destination": "before", "rulebase": scm.scm_rulebase, "destination_rule": anchor["id"]} if destination == "before" else {"destination": "bottom", "rulebase": scm.scm_rulebase}
        scm_http_request(
            "POST",
            f"{security_base}/security-rules/{generated['id']}:move",
            token,
            payload=move_payload,
        )

    # PA Policy Forge intentionally stops after writing candidate objects and
    # rules. It must never trigger an SCM candidate push/deployment job.


def push_to_device(xml_path: Path, deployment: DeploymentConfig, review_rows: list[dict[str, str]]) -> None:
    if not deployment.panos_endpoint or not deployment.panos_username or not deployment.panos_password:
        raise RuntimeError("Auto-push requested but panos endpoint/username/password is incomplete")

    ctx = ssl._create_unverified_context()
    key = panos_api_key(deployment, ctx)
    existing_rule_names = {entry.attrib["name"] for entry in fetch_panos_rule_entries(deployment) if entry.attrib.get("name")}

    import_name = import_name_for_path(xml_path)
    upload_path = xml_path if xml_path.name == import_name else xml_path.with_name(import_name)
    copied = False
    if upload_path != xml_path:
        upload_path.write_bytes(xml_path.read_bytes())
        copied = True
    try:
        require_success(
            api_post_multipart(
                deployment.panos_endpoint,
                {"type": "import", "category": "configuration", "key": key},
                upload_path,
                ctx,
            ),
            "import",
        )

        load_cmds = [
            (
                "<load><config><partial><mode>merge</mode>"
                f"<from>{upload_path.name}</from>"
                f"<from-xpath>{from_xpath}</from-xpath>"
                f"<to-xpath>{to_xpath}</to-xpath>"
                "</partial></config></load>"
            )
            for from_xpath, to_xpath in partial_load_sections(upload_path, deployment)
        ]

        for cmd in load_cmds:
            require_success(
                api_get(deployment.panos_endpoint, {"type": "op", "key": key, "cmd": cmd}, ctx),
                "load partial config",
            )
        for generated_name, anchor_name in movable_anchor_map(review_rows).items():
            xpath = f"{rules_xpath(deployment)}/entry[@name={xpath_literal(generated_name)}]"
            destination, destination_rule = rule_move_destination(anchor_name, existing_rule_names)
            position = {"where": "before", "dst": destination_rule} if destination == "before" else {"where": "bottom"}
            require_success(
                api_get(
                    deployment.panos_endpoint,
                    {"type": "config", "action": "move", "xpath": xpath, "key": key, **position},
                    ctx,
                ),
                f"move {generated_name} before {anchor_name}" if destination == "before" else f"move {generated_name} to bottom",
            )
    finally:
        if copied and upload_path.exists():
            upload_path.unlink()


def config_path(value: Any, base_dir: Path) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else base_dir / path


def config_optional_path(value: Any, base_dir: Path) -> Path | None:
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    return config_path(value, base_dir)


def config_int(raw: dict[str, Any], key: str, default: int, path: Path) -> int:
    value = raw.get(key, default)
    if isinstance(value, bool):
        raise ValueError(f"{path} builder.{key} must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{path} builder.{key} must be an integer") from exc


def config_bool(raw: dict[str, Any], key: str, default: bool, path: Path) -> bool:
    value = raw.get(key, default)
    if isinstance(value, bool):
        return value
    raise ValueError(f"{path} builder.{key} must be true or false")


def config_string_tuple(raw: dict[str, Any], key: str, default: tuple[str, ...], path: Path) -> tuple[str, ...]:
    value = raw.get(key, default)
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split(",") if item.strip())
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError(f"{path} builder.{key} must contain only strings")
            item = item.strip()
            if item:
                values.append(item)
        return tuple(values)
    raise ValueError(f"{path} builder.{key} must be a string or string list")


def config_action_set(value: Any, path: Path) -> frozenset[str]:
    if isinstance(value, str):
        actions = [item.strip().lower() for item in value.split(",")]
    elif isinstance(value, list):
        actions = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError(f"{path} builder.include_actions must contain only strings")
            actions.append(item.strip().lower())
    else:
        raise ValueError(f"{path} builder.include_actions must be a string or string list")
    return frozenset(action for action in actions if action)


def load_builder_config(path: Path) -> tuple[BuilderConfig, ZoneRoleConfig, DeploymentConfig, SCMConfig, ProfileGroupConfig]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    base_dir = path.resolve().parent
    builder_raw = data.get("builder", {})
    if builder_raw and not isinstance(builder_raw, dict):
        raise ValueError(f"{path} [builder] section must be a table")
    logs_raw = builder_raw.get("logs", [])
    if isinstance(logs_raw, str):
        log_paths = (config_path(logs_raw, base_dir),)
    elif isinstance(logs_raw, list):
        log_paths = tuple(config_path(item, base_dir) for item in logs_raw)
    else:
        raise ValueError(f"{path} builder.logs must be a string or string list")
    log_setting_raw = builder_raw.get("log_setting")
    log_setting = str(log_setting_raw).strip() if log_setting_raw is not None else None
    builder = BuilderConfig(
        logs=log_paths,
        xml_output=config_path(builder_raw.get("xml_output", "bdnd_panos_import.xml"), base_dir),
        review_csv=config_path(builder_raw.get("review_csv", "bdnd_panos_review.csv"), base_dir),
        ptr_cache_file=config_optional_path(builder_raw.get("ptr_cache_file", "ptr-cache.json"), base_dir),
        disabled=config_bool(builder_raw, "disabled", False, path),
        tags=config_string_tuple(builder_raw, "tags", (), path),
        global_ping_traceroute=config_bool(builder_raw, "global_ping_traceroute", False, path),
        global_ping_traceroute_apps=config_string_tuple(
            builder_raw,
            "global_ping_traceroute_apps",
            DEFAULT_GLOBAL_PING_TRACEROUTE_APPS,
            path,
        ),
        global_dns=config_bool(builder_raw, "global_dns", False, path),
        global_dns_apps=config_string_tuple(
            builder_raw,
            "global_dns_apps",
            DEFAULT_GLOBAL_DNS_APPS,
            path,
        ),
        global_dns_internal_resolvers=config_string_tuple(
            builder_raw,
            "global_dns_internal_resolvers",
            (),
            path,
        ),
        global_dns_external_resolvers=config_string_tuple(
            builder_raw,
            "global_dns_external_resolvers",
            (),
            path,
        ),
        min_sessions=config_int(builder_raw, "min_sessions", 3, path),
        limit=config_int(builder_raw, "limit", 100, path),
        group_threshold=config_int(builder_raw, "group_threshold", 10, path),
        source_any_threshold=config_int(builder_raw, "source_any_threshold", 5, path),
        workers=max(1, config_int(builder_raw, "workers", max(1, (os.cpu_count() or 1) - 2), path)),
        include_actions=config_action_set(builder_raw.get("include_actions", ["allow"]), path),
        log_setting=log_setting or None,
    )
    zone_roles_raw = data.get("zone_roles", {})
    if not isinstance(zone_roles_raw, dict):
        raise ValueError(f"{path} must define a [zone_roles] table")
    zone_roles: dict[str, str] = {}
    valid_roles = {"client", "internet", "server", "other"}
    for zone, role in zone_roles_raw.items():
        if not isinstance(zone, str) or not isinstance(role, str):
            raise ValueError(f"Invalid zone role mapping in {path}: {zone!r} -> {role!r}")
        normalized_role = role.strip().lower()
        if normalized_role not in valid_roles:
            raise ValueError(
                f"Unsupported role {role!r} for zone {zone!r} in {path}. Valid roles: {', '.join(sorted(valid_roles))}"
            )
        zone_roles[zone] = normalized_role
    deployment_raw = data.get("deployment", {})
    if deployment_raw and not isinstance(deployment_raw, dict):
        raise ValueError(f"{path} [deployment] section must be a table")
    panorama = bool(deployment_raw.get("panorama", False))
    scm_enabled = bool(deployment_raw.get("scm", False))
    if panorama and scm_enabled:
        raise ValueError(f"{path} cannot enable both deployment.panorama and deployment.scm")

    panorama_raw = data.get("panorama", {})
    if panorama_raw and not isinstance(panorama_raw, dict):
        raise ValueError(f"{path} [panorama] section must be a table")
    panorama_rulebase = str(panorama_raw.get("panorama_rulebase", "pre")).strip().lower()
    if panorama_rulebase not in {"pre", "post"}:
        raise ValueError(f"Unsupported panorama.panorama_rulebase {panorama_rulebase!r} in {path}. Valid values: pre, post")

    panos_raw = data.get("panos", {})
    if panos_raw and not isinstance(panos_raw, dict):
        raise ValueError(f"{path} [panos] section must be a table")

    scm_raw = data.get("scm", {})
    if scm_raw and not isinstance(scm_raw, dict):
        raise ValueError(f"{path} [scm] section must be a table")
    scm_rulebase = str(scm_raw.get("scm_rulebase", "pre")).strip().lower()
    if scm_rulebase not in {"pre", "post"}:
        raise ValueError(f"Unsupported scm.scm_rulebase {scm_rulebase!r} in {path}. Valid values: pre, post")
    scm_folder = str(scm_raw.get("scm_folder", "")).strip()
    scm_object_folder = str(scm_raw.get("scm_object_folder", "Global")).strip()
    scm_snippet = str(scm_raw.get("scm_snippet", "")).strip()
    scm_device = str(scm_raw.get("scm_device", "")).strip()
    if scm_enabled:
        selected_targets = [value for value in (scm_folder, scm_snippet, scm_device) if value]
        if len(selected_targets) != 1:
            raise ValueError(f"{path} [scm] must set exactly one of scm_folder, scm_snippet, or scm_device for rules")
        if not scm_object_folder:
            raise ValueError(f"{path} scm.scm_object_folder cannot be empty")

    profile_raw = data.get("profile_groups", {})
    if profile_raw and not isinstance(profile_raw, dict):
        raise ValueError(f"{path} [profile_groups] section must be a table")
    default_profile = "best-practice"

    return builder, ZoneRoleConfig(zone_roles), DeploymentConfig(
        panorama=panorama,
        scm=scm_enabled,
        panorama_template=str(panorama_raw.get("panorama_template", "Branches")).strip(),
        panorama_rulebase=panorama_rulebase,
        panorama_log_setting=str(panorama_raw.get("panorama_log_setting", "Cortex Data Lake")).strip(),
        panos_vsys=str(panos_raw.get("panos_vsys", "vsys1")).strip(),
        panos_log_setting=str(panos_raw.get("panos_log_setting", "Cortex Data Lake")).strip(),
        panos_endpoint=str(panos_raw.get("panos_endpoint", "")).strip(),
        panos_username=os.getenv("PPF_PANOS_USERNAME", str(panos_raw.get("panos_username", ""))).strip(),
        panos_password=os.getenv("PPF_PANOS_PASSWORD", str(panos_raw.get("panos_password", ""))),
        panos_auto_push=bool(panos_raw.get("panos_auto_push", False)),
    ), SCMConfig(
        scm_client_id=os.getenv("PPF_SCM_CLIENT_ID", str(scm_raw.get("scm_client_id", ""))).strip(),
        scm_client_secret=os.getenv("PPF_SCM_CLIENT_SECRET", str(scm_raw.get("scm_client_secret", ""))).strip(),
        scm_tsg_id=os.getenv("PPF_SCM_TSG_ID", str(scm_raw.get("scm_tsg_id", ""))).strip(),
        scm_token_url=str(
            scm_raw.get("scm_token_url", "https://auth.apps.paloaltonetworks.com/oauth2/access_token")
        ).strip(),
        scm_api_base=str(
            scm_raw.get("scm_api_base", "https://api.strata.paloaltonetworks.com/config/security/v1")
        ).strip(),
        scm_folder=scm_folder,
        scm_object_folder=scm_object_folder,
        scm_snippet=scm_snippet,
        scm_device=scm_device,
        scm_rulebase=scm_rulebase,
        scm_log_forwarding_profile=str(scm_raw.get("scm_log_forwarding_profile", "default-1")).strip(),
    ), ProfileGroupConfig(
        client=str(profile_raw.get("client", default_profile)).strip() or default_profile,
        server=str(profile_raw.get("server", default_profile)).strip() or default_profile,
        internet=str(profile_raw.get("internet", default_profile)).strip() or default_profile,
        other=str(profile_raw.get("other", default_profile)).strip() or default_profile,
    )


def discover_log_paths(script_path: Path) -> list[Path]:
    base_dir = script_path.resolve().parent
    return sorted(
        path
        for path in base_dir.rglob("*.csv")
        if path.is_file() and not any(fnmatch.fnmatch(path.name, pattern) for pattern in GENERATED_FILE_PATTERNS)
    )


def push_prebuilt_candidate(
    builder: BuilderConfig,
    zone_roles: ZoneRoleConfig,
    deployment: DeploymentConfig,
    scm: SCMConfig,
    profile_groups: ProfileGroupConfig,
) -> int:
    if not builder.xml_output.exists() or not builder.review_csv.exists():
        raise SystemExit("Prepared policy.xml or review.csv is missing")
    tree = SafeET.parse(builder.xml_output)
    with builder.review_csv.open(newline="") as handle:
        review_rows = list(csv.DictReader(handle))
    for entry in tree.findall(".//rules/entry"):
        disabled = entry.find("disabled")
        if builder.disabled:
            if disabled is None:
                disabled = ET.SubElement(entry, "disabled")
            disabled.text = "yes"
        elif disabled is not None:
            entry.remove(disabled)
    for row in review_rows:
        row["disabled"] = "yes" if builder.disabled else "no"

    if deployment.scm:
        inventory = fetch_scm_inventory(scm)
        reused = apply_existing_inventory(tree, review_rows, deployment, inventory)
        statuses = preflight_scm_rules(tree, review_rows, deployment, scm, zone_roles, profile_groups)
    else:
        inventory = fetch_panos_inventory(deployment)
        reused = apply_existing_inventory(tree, review_rows, deployment, inventory)
        statuses = preflight_panos_rules(tree, review_rows, deployment)
    skipped = remove_skipped_xml_rules(tree, deployment, review_rows)
    ET.indent(tree, space="  ")
    tree.write(builder.xml_output, encoding="utf-8", xml_declaration=True)
    write_review_csv(builder.review_csv, review_rows)
    print(f"Refreshed target inventory: {inventory.summary()}")
    print("Reused existing config: " + (", ".join(f"{kind}={count}" for kind, count in sorted(reused.items())) or "none"))
    print("Preflight existing policy check: " + ", ".join(f"{status}={count}" for status, count in sorted(statuses.items())) + f"; skipped duplicate matches={skipped}")
    if deployment.scm:
        push_to_scm(tree, deployment, scm, zone_roles, profile_groups, review_rows)
    else:
        push_to_device(builder.xml_output, deployment, review_rows)
    print("Pushed prepared candidate after fresh target validation")
    return 0


def main() -> int:
    if len(sys.argv) > 1:
        raise SystemExit("This script does not accept arguments. Edit bdnd_panos_zone_roles.toml instead.")

    config_file = Path(__file__).resolve().with_name("bdnd_panos_zone_roles.toml")
    if not config_file.exists():
        raise SystemExit(f"Missing builder config: {config_file}")

    builder, zone_roles, deployment, scm, profile_groups = load_builder_config(config_file)
    if os.getenv("PPF_PUSH_PREBUILT") == "1":
        if not deployment.panos_auto_push:
            raise SystemExit("Prepared push requires panos_auto_push=true")
        return push_prebuilt_candidate(builder, zone_roles, deployment, scm, profile_groups)
    logs = list(builder.logs) or discover_log_paths(Path(__file__))
    if not logs:
        raise SystemExit(
            "No traffic CSV files found under the script directory. "
            "Expected one or more .csv files in this tree."
        )
    missing = [str(path) for path in logs if not path.exists()]
    if missing:
        raise SystemExit(f"Missing log path(s): {', '.join(missing)}")
    aggregates = aggregate_log_paths(logs, builder.include_actions, workers=builder.workers)
    ptr_cache = load_ptr_cache(builder.ptr_cache_file)
    selected_log_setting = builder.log_setting
    if selected_log_setting is None:
        if deployment.scm:
            selected_log_setting = scm.scm_log_forwarding_profile
        elif deployment.panorama:
            selected_log_setting = deployment.panorama_log_setting
        else:
            selected_log_setting = deployment.panos_log_setting

    tree, review_rows = build_xml(
        aggregates,
        builder.min_sessions,
        builder.limit,
        builder.group_threshold,
        builder.source_any_threshold,
        builder.disabled,
        builder.tags,
        builder.global_ping_traceroute,
        builder.global_ping_traceroute_apps,
        builder.global_dns,
        builder.global_dns_apps,
        builder.global_dns_internal_resolvers,
        builder.global_dns_external_resolvers,
        zone_roles,
        deployment,
        selected_log_setting,
        profile_groups,
        ptr_cache,
    )
    if deployment.scm:
        inventory = fetch_scm_inventory(scm)
        reused = apply_existing_inventory(tree, review_rows, deployment, inventory)
        statuses = preflight_scm_rules(tree, review_rows, deployment, scm, zone_roles, profile_groups)
    else:
        inventory = fetch_panos_inventory(deployment)
        reused = apply_existing_inventory(tree, review_rows, deployment, inventory)
        statuses = preflight_panos_rules(tree, review_rows, deployment)
    skipped = remove_skipped_xml_rules(tree, deployment, review_rows)
    print(f"Fresh target inventory: {inventory.summary()}")
    print("Reused existing config: " + (", ".join(f"{kind}={count}" for kind, count in sorted(reused.items())) or "none"))
    print(
        "Preflight existing policy check: "
        + ", ".join(f"{status}={count}" for status, count in sorted(statuses.items()))
        + f"; skipped duplicate matches={skipped}"
    )
    save_ptr_cache(builder.ptr_cache_file, ptr_cache)
    ET.indent(tree, space="  ")
    tree.write(builder.xml_output, encoding="utf-8", xml_declaration=True)
    write_review_csv(builder.review_csv, review_rows)
    print(f"Wrote {len(review_rows)} PAN-OS candidate policies to {builder.xml_output}")
    print(f"Wrote review CSV to {builder.review_csv}")
    if deployment.panos_auto_push:
        if deployment.scm:
            push_to_scm(tree, deployment, scm, zone_roles, profile_groups, review_rows)
            print(
                f"Auto-pushed generated config to SCM folder {scm.scm_folder} "
                f"with objects in {scm.scm_object_folder}"
            )
        else:
            push_to_device(builder.xml_output, deployment, review_rows)
            print(f"Auto-pushed generated XML to {deployment.panos_endpoint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
