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
