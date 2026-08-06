from __future__ import annotations

import hashlib
import copy
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
import xml.etree.ElementTree as ET

from defusedxml import ElementTree as SafeET


class OfflineConfigError(ValueError):
    pass


PANORAMA_TREE = [
    ("Policies", ["Security", "NAT", "QoS", "Policy Based Forwarding", "Decryption", "Tunnel Inspection", "Application Override", "Authentication", "DoS Protection", "SD-WAN"]),
    ("Objects", ["Addresses", "Address Groups", "Regions", "Dynamic User Groups", "Applications", "Application Groups", "Application Filters", "Services", "Service Groups", "Tags", "GlobalProtect", "External Dynamic Lists", "Custom Objects", "Security Profiles", "Security Profile Groups", "Log Forwarding", "Authentication", "Decryption"]),
    ("Network", ["Interfaces", "Zones", "VLANs", "Virtual Wires", "Virtual Routers", "Logical Routers", "Routing Profiles", "IPSec Tunnels", "GRE Tunnels", "GlobalProtect Portals", "GlobalProtect Gateways", "DHCP", "DNS Proxy", "QoS", "LLDP", "Network Profiles"]),
    ("Device", ["Setup", "Administrators", "Admin Roles", "Authentication Profile", "Authentication Sequence", "Certificates", "Certificate Management", "Local User Database", "Server Profiles", "Log Settings", "High Availability", "User Identification", "VM Information Sources", "Licenses", "Dynamic Updates", "Software"]),
]

POLICY_NODES = {
    "security": "security", "nat": "nat", "qos": "qos", "pbf": "pbf",
    "decryption": "decryption", "tunnel-inspection": "tunnel-inspect",
    "application-override": "application-override", "authentication": "authentication",
    "dos": "dos", "sdwan": "sdwan",
}
OBJECT_NODES = {
    "addresses": "address", "address-groups": "address-group", "regions": "region",
    "applications": "application", "application-groups": "application-group",
    "application-filters": "application-filter", "services": "service",
    "service-groups": "service-group", "tags": "tag", "external-dynamic-lists": "external-list",
    "schedules": "schedule", "security-profile-groups": "profile-group",
    "log-forwarding": "log-settings", "authentication": "authentication-profile",
}
POLICY_LIST_FIELDS = (
    "from", "to", "source", "destination", "source-user", "category",
    "application", "service", "tag",
)


@dataclass(frozen=True)
class ConfigSnapshot:
    kind: str
    version: str
    device_groups: list[dict]
    templates: list[str]
    template_stacks: list[dict]
    vsys: list[str]
    navigation: list[tuple[str, list[str]]]
    counts: dict[str, int]

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "version": self.version,
            "device_groups": self.device_groups,
            "templates": self.templates,
            "template_stacks": self.template_stacks,
            "vsys": self.vsys,
            "navigation": self.navigation,
            "counts": self.counts,
        }


def _entry_names(root: ET.Element, path: str) -> list[str]:
    return sorted({entry.get("name", "") for entry in root.findall(path) if entry.get("name")})


def _first_text(entry: ET.Element, names: Iterable[str]) -> str:
    for name in names:
        value = entry.findtext(name, "").strip()
        if value:
            return value
    return ""


def parse_snapshot(xml_bytes: bytes, expected_kind: str | None = None) -> tuple[ET.Element, ConfigSnapshot]:
    if not xml_bytes.strip():
        raise OfflineConfigError("Het XML-bestand is leeg")
    try:
        parsed = SafeET.fromstring(xml_bytes)
    except Exception as exc:
        raise OfflineConfigError(f"Ongeldige of onveilige XML-configuratie: {exc}") from exc
    if parsed.tag == "config":
        root = parsed
    else:
        root = parsed.find("./result/config")
        if root is None:
            root = parsed.find(".//config")
    if root is None or root.tag != "config":
        raise OfflineConfigError("Geen PAN-OS <config>-root gevonden")

    dg_entries = root.findall("./devices/entry/device-group/entry")
    template_entries = root.findall("./devices/entry/template/entry")
    stack_entries = root.findall("./devices/entry/template-stack/entry")
    vsys_names = _entry_names(root, "./devices/entry/vsys/entry")
    kind = "panorama" if dg_entries or template_entries or stack_entries else "panos"
    if expected_kind and kind != expected_kind:
        label = "Panorama" if expected_kind == "panorama" else "standalone firewall"
        raise OfflineConfigError(f"Deze configuratie lijkt niet afkomstig van het gekozen {label}-profiel")

    device_groups = []
    for entry in dg_entries:
        device_groups.append({
            "name": entry.get("name", ""),
            "parent": _first_text(entry, ("./parent-dg", "./parent-device-group")) or "Shared",
            "reference_template": _first_text(entry, ("./reference-template", "./reference-template-stack")),
            "pre_rules": len(entry.findall("./pre-rulebase/*/rules/entry")),
            "post_rules": len(entry.findall("./post-rulebase/*/rules/entry")),
            "objects": len(entry.findall("./address/entry")) + len(entry.findall("./address-group/entry")) + len(entry.findall("./service/entry")) + len(entry.findall("./service-group/entry")),
        })
    stacks = []
    for entry in stack_entries:
        stacks.append({
            "name": entry.get("name", ""),
            "templates": [node.text or "" for node in entry.findall("./templates/member") if node.text],
        })
    counts = {
        "policies": len(root.findall(".//rulebase/*/rules/entry")) + len(root.findall(".//pre-rulebase/*/rules/entry")) + len(root.findall(".//post-rulebase/*/rules/entry")),
        "objects": sum(len(root.findall(path)) for path in (".//address/entry", ".//address-group/entry", ".//service/entry", ".//service-group/entry", ".//tag/entry")),
        "interfaces": len(root.findall(".//network/interface//entry")),
        "zones": len(root.findall(".//zone/entry")),
    }
    snapshot = ConfigSnapshot(
        kind=kind,
        version=root.get("version", ""),
        device_groups=device_groups,
        templates=sorted(entry.get("name", "") for entry in template_entries if entry.get("name")),
        template_stacks=stacks,
        vsys=vsys_names,
        navigation=PANORAMA_TREE,
        counts=counts,
    )
    return root, snapshot


def normalized_config_xml(root: ET.Element) -> bytes:
    clone = copy.deepcopy(root)
    ET.indent(clone, space="  ")
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(clone, encoding="utf-8") + b"\n"


def snapshot_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _set_walk(node: ET.Element, tokens: list[str], lines: list[str]) -> None:
    current = list(tokens)
    if node.tag == "config":
        pass
    elif node.tag == "devices" or (node.tag == "entry" and node.get("name") == "localhost.localdomain" and tokens == ["devices"]):
        if node.tag == "entry":
            current = []
        else:
            current.append(node.tag)
    elif node.tag == "entry":
        current.append(node.get("name", ""))
    elif node.tag == "member":
        value = (node.text or "").strip()
        if value:
            lines.append("set " + " ".join(shlex.quote(part) for part in current + [value]))
        return
    else:
        current.append(node.tag)

    children = list(node)
    text = (node.text or "").strip()
    if not children and node.tag == "entry" and node.get("name"):
        lines.append("set " + " ".join(shlex.quote(part) for part in current))
        return
    if not children and text:
        lines.append("set " + " ".join(shlex.quote(part) for part in current + [text]))
        return
    for child in children:
        _set_walk(child, current, lines)


def render_set_commands(xml_bytes: bytes) -> str:
    root, _ = parse_snapshot(xml_bytes)
    lines: list[str] = []
    _set_walk(root, [], lines)
    unique = list(dict.fromkeys(line for line in lines if line != "set"))
    return "# Generated from a PA Policy Forge offline snapshot\n" + "\n".join(unique) + "\n"


def _scope_chain(snapshot: ConfigSnapshot, scope: str) -> list[str]:
    if snapshot.kind != "panorama" or scope == "Shared":
        return ["Shared"]
    parents = {item["name"]: item.get("parent") or "Shared" for item in snapshot.device_groups}
    if scope not in parents:
        raise OfflineConfigError(f"Onbekende device group: {scope}")
    chain = [scope]
    seen = {scope}
    while chain[-1] != "Shared":
        parent = parents.get(chain[-1], "Shared") or "Shared"
        if parent in seen:
            raise OfflineConfigError("Cyclische device-grouphiërarchie")
        chain.append(parent)
        seen.add(parent)
    return list(reversed(chain))


def available_scopes(snapshot: ConfigSnapshot) -> list[str]:
    if snapshot.kind == "panorama":
        return ["Shared"] + [item["name"] for item in snapshot.device_groups]
    return snapshot.vsys


def _scope_root(root: ET.Element, snapshot: ConfigSnapshot, scope: str) -> ET.Element | None:
    if scope == "Shared":
        return root.find("./shared")
    if snapshot.kind == "panorama":
        return next((entry for entry in root.findall("./devices/entry/device-group/entry") if entry.get("name") == scope), None)
    return next((entry for entry in root.findall("./devices/entry/vsys/entry") if entry.get("name") == scope), None)


def _members(entry: ET.Element, field: str) -> list[str]:
    return [node.text or "" for node in entry.findall(f"./{field}/member") if node.text]


def policy_record(entry: ET.Element, kind: str, owner: str, rulebase: str, editable: bool) -> dict:
    record = {
        "name": entry.get("name", ""), "kind": kind, "owner": owner,
        "rulebase": rulebase, "editable": editable,
        "action": entry.findtext("./action", ""),
        "description": entry.findtext("./description", ""),
        "disabled": entry.findtext("./disabled", "no") == "yes",
        "log_setting": entry.findtext("./log-setting", ""),
        "schedule": entry.findtext("./schedule", ""),
        "_xml": ET.tostring(entry, encoding="unicode"),
    }
    for field in POLICY_LIST_FIELDS:
        record[field.replace("-", "_")] = _members(entry, field)
    return record


def scoped_policies(xml_bytes: bytes, scope: str, kind: str, rulebase: str = "pre") -> tuple[ConfigSnapshot, list[dict]]:
    root, snapshot = parse_snapshot(xml_bytes)
    if kind not in POLICY_NODES:
        raise OfflineConfigError(f"Onbekend policytype: {kind}")
    if snapshot.kind == "panorama" and rulebase not in {"pre", "post"}:
        raise OfflineConfigError("Panorama rulebase moet pre of post zijn")
    records = []
    chain = _scope_chain(snapshot, scope) if snapshot.kind == "panorama" else (["Shared", scope] if root.find("./shared") is not None else [scope])
    for owner in chain:
        scope_root = _scope_root(root, snapshot, owner)
        if scope_root is None:
            continue
        base = f"./{rulebase}-rulebase" if snapshot.kind == "panorama" else "./rulebase"
        entries = scope_root.findall(f"{base}/{POLICY_NODES[kind]}/rules/entry")
        records.extend(policy_record(entry, kind, owner, rulebase, owner == scope) for entry in entries)
    return snapshot, records


def _object_summary(entry: ET.Element) -> str:
    for path in ("./ip-netmask", "./ip-range", "./ip-wildcard", "./fqdn", "./color"):
        value = entry.findtext(path, "").strip()
        if value:
            return value
    members = [node.text or "" for node in entry.findall(".//member") if node.text]
    if members:
        return ", ".join(members)
    return ""


def scoped_objects(xml_bytes: bytes, scope: str, object_type: str) -> tuple[ConfigSnapshot, list[dict]]:
    root, snapshot = parse_snapshot(xml_bytes)
    node = OBJECT_NODES.get(object_type)
    if not node:
        raise OfflineConfigError(f"Onbekend objecttype: {object_type}")
    chain = _scope_chain(snapshot, scope) if snapshot.kind == "panorama" else (["Shared", scope] if root.find("./shared") is not None else [scope])
    records = []
    for owner in chain:
        scope_root = _scope_root(root, snapshot, owner)
        if scope_root is None:
            continue
        for entry in scope_root.findall(f"./{node}/entry"):
            records.append({
                "name": entry.get("name", ""), "owner": owner, "editable": owner == scope,
                "summary": _object_summary(entry), "description": entry.findtext("./description", ""),
                "_xml": ET.tostring(entry, encoding="unicode"),
            })
    return snapshot, records


def configuration_inventory(xml_bytes: bytes, scope: str) -> dict[str, list[dict]]:
    root, snapshot = parse_snapshot(xml_bytes)
    scope_root = _scope_root(root, snapshot, scope)
    if scope_root is None:
        return {"network": [], "device": []}
    device_root = root.find("./devices/entry")
    if device_root is None:
        device_root = root
    # On a standalone firewall, zones live in VSYS while interfaces and routing
    # live at device level. Panorama network settings belong to templates; until
    # template editing lands we inventory the full snapshot without pretending
    # that a device-group owns those nodes.
    network_root = device_root if snapshot.kind == "panos" else root
    network_paths = {
        "Interfaces": ".//network/interface", "Virtual Routers": ".//virtual-router",
        "Logical Routers": ".//logical-router", "IPSec Tunnels": ".//tunnel/ipsec",
        "GlobalProtect Portals": ".//global-protect/global-protect-portal",
        "GlobalProtect Gateways": ".//global-protect/global-protect-gateway",
        "Network Profiles": ".//network/profiles",
    }
    device_paths = {
        "Setup": ".//deviceconfig", "Administrators": ".//mgt-config/users",
        "Certificates": ".//certificate", "Server Profiles": ".//server-profile",
        "Log Settings": ".//log-settings", "High Availability": ".//high-availability",
    }
    return {
        "network": (
            [{"name": "Zones", "present": scope_root.find(".//zone") is not None, "entries": len(scope_root.findall(".//zone/entry"))}]
            + [{"name": name, "present": network_root.find(path) is not None, "entries": len(network_root.findall(path + "//entry"))} for name, path in network_paths.items()]
        ),
        "device": [{"name": name, "present": root.find(path) is not None, "entries": len(root.findall(path + "//entry"))} for name, path in device_paths.items()],
    }


def policy_fingerprint(record: dict) -> str:
    return hashlib.sha256(record["_xml"].encode()).hexdigest()


def replace_policy_in_snapshot(xml_bytes: bytes, scope: str, kind: str, rulebase: str, name: str, expected_fingerprint: str, replacement_xml: str) -> bytes:
    root, snapshot = parse_snapshot(xml_bytes)
    scope_root = _scope_root(root, snapshot, scope)
    if scope_root is None:
        raise OfflineConfigError("De gekozen scope bestaat niet meer")
    base = f"./{rulebase}-rulebase" if snapshot.kind == "panorama" else "./rulebase"
    rules = scope_root.find(f"{base}/{POLICY_NODES[kind]}/rules")
    if rules is None:
        raise OfflineConfigError("De gekozen rulebase bestaat niet")
    current = next((entry for entry in rules.findall("./entry") if entry.get("name") == name), None)
    if current is None:
        raise OfflineConfigError("De policy bestaat niet meer")
    current_record = policy_record(current, kind, scope, rulebase, True)
    if policy_fingerprint(current_record) != expected_fingerprint:
        raise OfflineConfigError("De policy is intussen gewijzigd; pas de wijziging opnieuw toe")
    replacement = SafeET.fromstring(replacement_xml)
    if replacement.tag != "entry" or replacement.get("name") != name:
        raise OfflineConfigError("Ongeldige vervangende policy")
    index = list(rules).index(current)
    rules.remove(current)
    rules.insert(index, replacement)
    return normalized_config_xml(root)


def safe_workspace_path(root: Path, stored_path: str) -> Path:
    base = root.resolve()
    path = Path(stored_path).resolve()
    try:
        path.relative_to(base)
    except ValueError as exc:
        raise OfflineConfigError("Ongeldig workspacepad") from exc
    if path == base:
        raise OfflineConfigError("Ongeldig workspacepad")
    return path
