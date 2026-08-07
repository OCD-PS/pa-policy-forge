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
    ("Objects", ["Addresses", "Address Groups", "Regions", "Dynamic User Groups", "Applications", "Application Groups", "Application Filters", "Services", "Service Groups", "Tags", "HIP Objects", "HIP Profiles", "External Dynamic Lists", "Custom URL Categories", "Security Profiles", "↳ Antivirus", "↳ Anti-Spyware", "↳ Vulnerability Protection", "↳ URL Filtering", "↳ File Blocking", "↳ WildFire Analysis", "↳ DoS Protection", "Security Profile Groups", "Log Forwarding", "Authentication", "Decryption"]),
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
    "dynamic-user-groups": "dynamic-user-group",
    "applications": "application", "application-groups": "application-group",
    "application-filters": "application-filter", "services": "service",
    "service-groups": "service-group", "tags": "tag", "external-dynamic-lists": "external-list",
    "hip-objects": "hip-objects", "hip-profiles": "hip-profiles",
    "custom-url-categories": "profiles/custom-url-category",
    "antivirus": "profiles/virus", "anti-spyware": "profiles/spyware",
    "vulnerability-protection": "profiles/vulnerability", "url-filtering": "profiles/url-filtering",
    "file-blocking": "profiles/file-blocking", "wildfire-analysis": "profiles/wildfire-analysis",
    "dos-protection": "profiles/dos-protection",
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


def available_templates(snapshot: ConfigSnapshot) -> list[str]:
    if snapshot.kind != "panorama":
        return snapshot.vsys
    return snapshot.templates + [item["name"] for item in snapshot.template_stacks]


def referenced_template(snapshot: ConfigSnapshot, device_group: str) -> str:
    if snapshot.kind != "panorama" or device_group == "Shared":
        return ""
    current = device_group
    groups = {item["name"]: item for item in snapshot.device_groups}
    seen = set()
    while current and current not in seen:
        seen.add(current)
        item = groups.get(current) or {}
        if item.get("reference_template"):
            return item["reference_template"]
        parent = item.get("parent") or "Shared"
        current = "" if parent == "Shared" else parent
    return ""


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


def scoped_policies(xml_bytes: bytes, scope: str, kind: str, rulebase: str = "pre", parsed=None) -> tuple[ConfigSnapshot, list[dict]]:
    root, snapshot = parsed if parsed is not None else parse_snapshot(xml_bytes)
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


def _object_values(entry: ET.Element) -> list[str]:
    values = []
    for path in ("./ip-netmask", "./ip-range", "./ip-wildcard", "./fqdn", "./color", "./filter"):
        value = entry.findtext(path, "").strip()
        if value:
            values.append(value)
    values.extend(node.text or "" for node in entry.findall(".//member") if node.text)
    return list(dict.fromkeys(values))


def _object_fields(entry: ET.Element) -> list[dict]:
    fields = []
    for child in entry:
        values = [node.text or "" for node in child.findall(".//member") if node.text]
        text = (child.text or "").strip()
        if values:
            fields.append({"name": child.tag, "values": values})
        elif text:
            fields.append({"name": child.tag, "values": [text]})
        elif list(child):
            fields.append({"name": child.tag, "values": [ET.tostring(child, encoding="unicode")]})
    return fields


def object_fingerprint(record: dict) -> str:
    return hashlib.sha256(record["_xml"].encode()).hexdigest()


def object_record(entry: ET.Element, owner: str, editable: bool, object_type: str) -> dict:
    record = {
        "id": entry.get("name", ""), "name": entry.get("name", ""),
        "owner": owner, "editable": editable, "description": entry.findtext("./description", ""),
        "comments": entry.findtext("./comments", ""), "tag": _members(entry, "tag"),
        "summary": _object_summary(entry), "values": _object_values(entry),
        "fields": _object_fields(entry), "_xml": ET.tostring(entry, encoding="unicode"),
    }
    for key in ("ip-netmask", "ip-range", "ip-wildcard", "fqdn", "color"):
        value = entry.findtext(f"./{key}", "").strip()
        if value:
            record[key.replace("-", "_")] = value
    if object_type == "address-groups":
        record["static"] = _members(entry, "static")
        dynamic = entry.findtext("./dynamic/filter", "").strip()
        if dynamic:
            record["dynamic"] = {"filter": dynamic}
    elif object_type in {"application-groups", "service-groups"}:
        record["members"] = _members(entry, "members")
    elif object_type == "services":
        for protocol in ("tcp", "udp"):
            node = entry.find(f"./protocol/{protocol}")
            if node is None:
                continue
            details = {}
            for child in node:
                value = (child.text or "").strip()
                details[child.tag.replace("-", "_")] = value == "yes" if child.tag == "override" else value
            record["protocol"] = {protocol: details}
            break
    return record


def scoped_objects(xml_bytes: bytes, scope: str, object_type: str, parsed=None) -> tuple[ConfigSnapshot, list[dict]]:
    root, snapshot = parsed if parsed is not None else parse_snapshot(xml_bytes)
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
            records.append(object_record(entry, owner, owner == scope, object_type))
    return snapshot, records


EDITABLE_OBJECT_TAGS = {
    "addresses": {"description", "tag", "ip-netmask", "ip-range", "ip-wildcard", "fqdn"},
    "address-groups": {"description", "tag", "static", "dynamic"},
    "application-groups": {"description", "tag", "members"},
    "services": {"description", "tag", "protocol"},
    "service-groups": {"description", "tag", "members"},
    "tags": {"comments", "color"},
}


def apply_object_changes(xml_bytes: bytes, scope: str, object_type: str, changes: list[dict]) -> bytes:
    if object_type not in EDITABLE_OBJECT_TAGS:
        raise OfflineConfigError("Dit objecttype is momenteel alleen-lezen")
    root, snapshot = parse_snapshot(xml_bytes)
    scope_root = _scope_root(root, snapshot, scope)
    if scope_root is None:
        raise OfflineConfigError("De gekozen scope bestaat niet meer")
    node_path = OBJECT_NODES[object_type]
    container = scope_root
    for part in node_path.split("/"):
        child = container.find(f"./{part}")
        if child is None:
            child = ET.SubElement(container, part)
        container = child
    for change in changes:
        operation = change.get("operation")
        original_name = change.get("original_name", "")
        current = next((entry for entry in container.findall("./entry") if entry.get("name") == original_name), None)
        if operation in {"update", "delete"}:
            if current is None:
                raise OfflineConfigError(f"Object {original_name} bestaat niet meer")
            current_record = object_record(current, scope, True, object_type)
            if object_fingerprint(current_record) != change.get("fingerprint"):
                raise OfflineConfigError(f"Object {original_name} is intussen gewijzigd")
        if operation == "delete":
            container.remove(current)
            continue
        replacement = SafeET.fromstring(change.get("replacement_xml", ""))
        if replacement.tag != "entry" or not replacement.get("name"):
            raise OfflineConfigError("Ongeldig vervangend object")
        collision = next((entry for entry in container.findall("./entry") if entry.get("name") == replacement.get("name") and entry is not current), None)
        if collision is not None:
            raise OfflineConfigError(f"Object {replacement.get('name')} bestaat al in {scope}")
        if operation == "create":
            container.append(replacement)
            continue
        current.set("name", replacement.get("name", original_name))
        editable_tags = EDITABLE_OBJECT_TAGS[object_type]
        for child in list(current):
            if child.tag in editable_tags:
                current.remove(child)
        for child in list(replacement):
            current.append(copy.deepcopy(child))
    return normalized_config_xml(root)


def configuration_inventory(xml_bytes: bytes, scope: str, template: str = "", parsed=None) -> dict[str, list[dict]]:
    root, snapshot = parsed if parsed is not None else parse_snapshot(xml_bytes)
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
    if snapshot.kind == "panorama":
        template_root = next((entry for entry in root.findall("./devices/entry/template/entry") if entry.get("name") == template), None)
        template_roots = [template_root] if template_root is not None else []
        if template_root is None:
            stack = next((entry for entry in root.findall("./devices/entry/template-stack/entry") if entry.get("name") == template), None)
            template_names = [member.text or "" for member in stack.findall("./templates/member")] if stack is not None else []
            by_name = {entry.get("name", ""): entry for entry in root.findall("./devices/entry/template/entry")}
            template_roots = [by_name[name] for name in template_names if name in by_name]
        network_root = template_roots or [root]
        device_inventory_root = network_root
    else:
        network_root = [device_root]
        device_inventory_root = [root]
    network_paths = {
        "Interfaces": ".//network/interface", "VLANs": ".//network/vlan",
        "Virtual Wires": ".//network/virtual-wire", "Virtual Routers": ".//virtual-router",
        "Logical Routers": ".//logical-router", "IPSec Tunnels": ".//tunnel/ipsec",
        "Routing Profiles": ".//network/routing-profile", "GRE Tunnels": ".//tunnel/gre",
        "GlobalProtect Portals": ".//global-protect/global-protect-portal",
        "GlobalProtect Gateways": ".//global-protect/global-protect-gateway",
        "DHCP": ".//network/dhcp", "DNS Proxy": ".//network/dns-proxy",
        "QoS": ".//network/qos", "LLDP": ".//network/lldp",
        "Network Profiles": ".//network/profiles",
    }
    device_paths = {
        "Setup": ".//deviceconfig", "Administrators": ".//mgt-config/users",
        "Admin Roles": ".//mgt-config/admin-roles", "Authentication Profile": ".//authentication-profile",
        "Authentication Sequence": ".//authentication-sequence", "Certificates": ".//certificate",
        "Certificate Management": ".//ssl-decrypt", "Local User Database": ".//local-user-database",
        "Server Profiles": ".//server-profile",
        "Log Settings": ".//log-settings", "High Availability": ".//high-availability",
        "User Identification": ".//user-id-collector", "VM Information Sources": ".//vm-info-source",
        "Licenses": ".//license", "Dynamic Updates": ".//content-updates", "Software": ".//software",
    }
    def inventory_item(name: str, sources: list[ET.Element], path: str) -> dict:
        entries = [entry for source in sources for entry in source.findall(path + "//entry")]
        names = list(dict.fromkeys(entry.get("name", "") for entry in entries if entry.get("name")))
        return {"name": name, "present": any(source.find(path) is not None for source in sources), "entries": len(entries), "names": names[:250]}
    return {
        "network": (
            [inventory_item("Zones", network_root if snapshot.kind == "panorama" else [scope_root], ".//zone")]
            + [inventory_item(name, network_root, path) for name, path in network_paths.items()]
        ),
        "device": [inventory_item(name, device_inventory_root, path) for name, path in device_paths.items()],
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
