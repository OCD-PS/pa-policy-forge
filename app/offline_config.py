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
    ("Objects", ["Addresses", "Address Groups", "Regions", "Dynamic User Groups", "Applications", "Application Groups", "Application Filters", "Services", "Service Groups", "Tags", "HIP Objects", "HIP Profiles", "External Dynamic Lists", "Custom URL Categories", "Security Profiles", "↳ Antivirus", "↳ Anti-Spyware", "↳ Vulnerability Protection", "↳ URL Filtering", "↳ File Blocking", "↳ WildFire Analysis", "↳ DoS Protection", "Security Profile Groups", "Log Forwarding", "Authentication", "Decryption", "Schedules"]),
    ("Network", ["Interfaces", "Zones", "VLANs", "Virtual Wires", "Virtual Routers", "Logical Routers", "Routing Profiles", "IPSec Tunnels", "GRE Tunnels", "GlobalProtect Portals", "GlobalProtect Gateways", "DHCP", "DNS Proxy", "QoS", "LLDP", "Network Profiles"]),
    ("Device", ["Setup", "Administrators", "Admin Roles", "Authentication Profile", "Authentication Sequence", "Certificates", "Certificate Management", "Local User Database", "Server Profiles", "Log Settings", "High Availability", "User Identification", "VM Information Sources"]),
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
    "log-forwarding": "log-settings/profiles", "authentication": "authentication-profile",
    "decryption-profiles": "profiles/decryption",
}


# New generic objects need a real PAN-OS-shaped entry before the field editor can
# render anything.  These seeds deliberately contain only safe, editable defaults;
# fields unknown to this application are still preserved when an existing entry is
# edited.  Structured object families are created by object_payload_xml instead.
OBJECT_CREATE_XML = {
    "regions": '<entry name=""><address><member></member></address><description /></entry>',
    "dynamic-user-groups": '<entry name=""><filter /></entry>',
    "applications": (
        '<entry name=""><category>business-systems</category><subcategory>general-business</subcategory>'
        '<technology>client-server</technology><risk>1</risk><description />'
        '<default><port><member></member></port></default></entry>'
    ),
    "application-filters": (
        '<entry name=""><category><member></member></category><subcategory><member></member></subcategory>'
        '<technology><member></member></technology><risk><member></member></risk>'
        '<evasive>no</evasive><excessive-bandwidth-use>no</excessive-bandwidth-use>'
        '<has-known-vulnerabilities>no</has-known-vulnerabilities><is-saas>no</is-saas>'
        '<new-appid>no</new-appid><pervasive>no</pervasive><prone-to-misuse>no</prone-to-misuse>'
        '<transfers-files>no</transfers-files><tunnels-other-apps>no</tunnels-other-apps>'
        '<used-by-malware>no</used-by-malware></entry>'
    ),
    "external-dynamic-lists": (
        '<entry name=""><type><ip><description /><url />'
        '<certificate-profile>None</certificate-profile><recurring><five-minute /></recurring>'
        '<exception-list><member></member></exception-list></ip></type></entry>'
    ),
    "hip-objects": '<entry name=""><description /><host-info><criteria><os><contains><Microsoft>All</Microsoft></contains></os></criteria></host-info></entry>',
    "hip-profiles": '<entry name=""><description /><match>any</match></entry>',
    "custom-url-categories": '<entry name=""><description /><type>URL List</type><list><member></member></list></entry>',
    "antivirus": (
        '<entry name=""><description /><packet-capture>disable</packet-capture><decoder>'
        '<entry name="http"><action>default</action><wildfire-action>default</wildfire-action>'
        '<mlav-action>default</mlav-action></entry></decoder></entry>'
    ),
    "anti-spyware": (
        '<entry name=""><description /><rules><entry name="critical-high"><action><default /></action>'
        '<severity><member>critical</member><member>high</member></severity><threat-name>any</threat-name>'
        '<category>any</category><packet-capture>disable</packet-capture></entry></rules></entry>'
    ),
    "vulnerability-protection": (
        '<entry name=""><description /><rules><entry name="critical-high"><action><default /></action>'
        '<severity><member>critical</member><member>high</member></severity><cve><member>any</member></cve>'
        '<vendor-id><member>any</member></vendor-id><threat-name>any</threat-name>'
        '<host>any</host><category>any</category><packet-capture>disable</packet-capture></entry></rules></entry>'
    ),
    "url-filtering": (
        '<entry name=""><description /><allow><member></member></allow><alert><member></member></alert>'
        '<block><member></member></block><continue><member></member></continue>'
        '<override><member></member></override><redirect><member></member></redirect>'
        '<safe-search-enforcement>no</safe-search-enforcement><log-container-page-only>yes</log-container-page-only></entry>'
    ),
    "file-blocking": (
        '<entry name=""><description /><rules><entry name="rule-1"><application><member>any</member></application>'
        '<file-type><member>any</member></file-type><direction>both</direction><action>alert</action></entry></rules></entry>'
    ),
    "wildfire-analysis": (
        '<entry name=""><description /><rules><entry name="rule-1"><application><member>any</member></application>'
        '<file-type><member>any</member></file-type><direction>both</direction><analysis>public-cloud</analysis></entry></rules></entry>'
    ),
    "dos-protection": '<entry name=""><description /><type><aggregate><resources><sessions><enabled>yes</enabled></sessions></resources></aggregate></type></entry>',
    "schedules": '<entry name=""><schedule-type><recurring><weekly><monday><member></member></monday></weekly></recurring></schedule-type></entry>',
    "security-profile-groups": (
        '<entry name=""><virus><member></member></virus><spyware><member></member></spyware>'
        '<vulnerability><member></member></vulnerability><url-filtering><member></member></url-filtering>'
        '<file-blocking><member></member></file-blocking><wildfire-analysis><member></member></wildfire-analysis></entry>'
    ),
    "authentication": '<entry name=""><authentication-profile /><timeout>60</timeout></entry>',
    "decryption-profiles": (
        '<entry name=""><ssl-forward-proxy><auto-include-altname>yes</auto-include-altname>'
        '<block-expired-certificate>yes</block-expired-certificate><block-untrusted-issuer>yes</block-untrusted-issuer>'
        '<block-unknown-cert>yes</block-unknown-cert></ssl-forward-proxy></entry>'
    ),
}

SERVER_PROFILE_NODES = {
    "syslog-server-profiles": "syslog",
    "email-server-profiles": "email",
    "snmp-trap-server-profiles": "snmptrap",
    "http-server-profiles": "http",
}

# Network and Device are represented by the same generic XML record model.  The
# paths intentionally stop at the PAN-OS configuration container; records below
# that container are discovered dynamically so newer PAN-OS fields survive a
# round-trip without requiring an application release.
CONFIG_SECTION_PATHS = {
    "network": {
        "interfaces": (".//network/interface",),
        "zones": (".//zone",),
        "vlans": (".//network/vlan",),
        "virtual-wires": (".//network/virtual-wire",),
        "virtual-routers": (".//network/virtual-router", ".//virtual-router"),
        "logical-routers": (".//network/logical-router", ".//logical-router"),
        "ipsec-tunnels": (".//network/tunnel/ipsec", ".//tunnel/ipsec"),
        "routing-profiles": (".//network/routing-profile",),
        "gre-tunnels": (".//network/tunnel/gre", ".//tunnel/gre"),
        "globalprotect-portals": (".//global-protect/global-protect-portal",),
        "globalprotect-gateways": (".//global-protect/global-protect-gateway",),
        "dhcp": (".//network/dhcp",),
        "dns-proxy": (".//network/dns-proxy",),
        "qos": (".//network/qos",),
        "lldp": (".//network/lldp",),
        "network-profiles": (".//network/profiles",),
    },
    "device": {
        "setup": (".//deviceconfig",),
        "administrators": (".//mgt-config/users",),
        "admin-roles": (".//mgt-config/admin-roles",),
        "authentication-profile": (".//authentication-profile",),
        "authentication-sequence": (".//authentication-sequence",),
        "certificates": (".//certificate",),
        "certificate-management": (".//ssl-decrypt",),
        "local-user-database": (".//local-user-database",),
        "server-profiles": (".//server-profile",),
        "log-settings": (".//log-settings",),
        "high-availability": (".//high-availability",),
        "user-identification": (".//user-id-collector",),
        "vm-information-sources": (".//vm-info-source",),
        # Operational software and license pages are intentionally not mapped
        # to candidate XML writes.  They are not ordinary configuration nodes.
    },
}

PROTECTED_CONFIG_TAGS = {
    "phash", "password", "passwd", "private-key", "private-key-data",
    "secret", "auth-key", "authentication-key", "passphrase",
}

# Presentation metadata only.  The XML remains the source of truth and fields
# unknown to this map are kept in an "Other" tab, so a newer PAN-OS release
# can still round-trip without losing configuration.
PANOS_CONFIG_UI_TABS = {
    "interfaces": ("Ethernet Interface", "Config", "IPv4", "IPv6", "Advanced", "LLDP", "SD-WAN", "Other"),
    "zones": ("General", "Network", "User Identification", "Device Identification", "Other"),
    "vlans": ("General", "Interfaces", "Other"),
    "virtual-wires": ("General", "Interfaces", "Other"),
    "virtual-routers": ("Router Settings", "Static Routes", "Redistribution", "RIP", "OSPF", "OSPFv3", "BGP", "Multicast", "ECMP", "Other"),
    "logical-routers": ("General", "Interfaces", "Static Routes", "Routing Profiles", "RIPv2", "OSPF", "OSPFv3", "BGP", "Multicast", "BFD", "Other"),
    "ipsec-tunnels": ("General", "Proxy IDs", "Tunnel Monitor", "Other"),
    "gre-tunnels": ("General", "Tunnel Monitor", "Other"),
    "globalprotect-portals": ("General", "Authentication", "Agent", "Satellite", "Other"),
    "globalprotect-gateways": ("General", "Authentication", "Agent", "Client Settings", "Satellite", "Other"),
    "dhcp": ("General", "IPv4", "IPv6", "Other"),
    "dns-proxy": ("General", "Static Entries", "Cache", "Other"),
    "qos": ("General", "Clear Text", "Tunnel Traffic", "Other"),
    "lldp": ("General", "Other"),
    "network-profiles": ("General", "Other"),
    "setup": ("General", "Management", "Services", "Operations", "Session", "Content-ID", "WildFire", "Telemetry", "Other"),
    "administrators": ("General", "Authentication", "Administrator Type", "Other"),
    "admin-roles": ("General", "Web UI", "XML API", "Command Line", "Other"),
    "authentication-profile": ("Authentication", "Advanced", "Factors", "Other"),
    "authentication-sequence": ("General", "Authentication Profiles", "Other"),
    "certificates": ("General", "Certificate Attributes", "Other"),
    "certificate-management": ("General", "SSL/TLS", "Decryption", "Other"),
    "local-user-database": ("General", "Authentication", "Other"),
    "server-profiles": ("General", "Servers", "Authentication", "Other"),
    "log-settings": ("General", "Filter", "Forwarding", "Other"),
    "high-availability": ("General", "Election Settings", "Control Link", "Data Link", "Active/Active", "Monitoring", "Other"),
    "user-identification": ("General", "Server Monitoring", "Include/Exclude Networks", "Other"),
    "vm-information-sources": ("General", "Source", "Authentication", "Other"),
}


def _panos_ui_group(section: str, label: str, original: str) -> str:
    value = f"{label} {original}".lower()
    if section == "interfaces":
        if "ipv6" in value: return "IPv6"
        if any(token in value for token in ("layer3 / ip", "dhcp-client", "dhcp client", "arp /", "ip / entry")): return "IPv4"
        if "lldp" in value: return "LLDP"
        if "sdwan" in value or "sd-wan" in value: return "SD-WAN"
        if any(token in value for token in ("virtual-system", "virtual system", "security-zone", "security zone", "virtual-router", "virtual router", "vlan")): return "Config"
        if any(token in value for token in ("link-state", "link state", "link-speed", "link speed", "link-duplex", "link duplex", "mtu", "mss", "lacp", "poe", "ndp")): return "Advanced"
        return "Ethernet Interface"
    if section == "zones":
        if "user-identification" in value or "user identification" in value or "userid" in value: return "User Identification"
        if "device-identification" in value or "device identification" in value: return "Device Identification"
        if any(token in value for token in ("network", "layer3", "layer2", "tap", "virtual-wire", "external")): return "Network"
        return "General"
    if section in {"vlans", "virtual-wires"}:
        return "Interfaces" if "interface" in value else "General"
    if section in {"virtual-routers", "logical-routers"}:
        if "static-route" in value or "static route" in value: return "Static Routes"
        if "redistribution" in value: return "Redistribution"
        if "ospfv3" in value: return "OSPFv3"
        if "ospf" in value: return "OSPF"
        if "rip" in value: return "RIPv2" if section == "logical-routers" else "RIP"
        if "bgp" in value: return "BGP"
        if "multicast" in value: return "Multicast"
        if "ecmp" in value: return "ECMP"
        if "bfd" in value: return "BFD"
        if "routing-profile" in value or "routing profile" in value or "filter" in value: return "Routing Profiles"
        if "interface" in value: return "Interfaces"
        return "General" if section == "logical-routers" else "Router Settings"
    if section == "ipsec-tunnels":
        if "proxy-id" in value or "proxy id" in value: return "Proxy IDs"
        if "monitor" in value: return "Tunnel Monitor"
    if section == "gre-tunnels" and "monitor" in value: return "Tunnel Monitor"
    if section in {"globalprotect-portals", "globalprotect-gateways"}:
        if "authentication" in value: return "Authentication"
        if "client" in value: return "Client Settings"
        if "satellite" in value: return "Satellite"
        if "agent" in value: return "Agent"
    if section == "dhcp":
        if "ipv6" in value: return "IPv6"
        if "ipv4" in value or "server" in value or "relay" in value: return "IPv4"
    if section == "dns-proxy":
        if "static" in value: return "Static Entries"
        if "cache" in value: return "Cache"
    if section == "setup":
        if any(token in value for token in ("management", "hostname", "domain", "timezone", "locale", "geo-location")): return "Management"
        if any(token in value for token in ("service", "dns", "ntp", "proxy", "update-server", "server-verification")): return "Services"
        if any(token in value for token in ("operation", "config-lock", "shutdown", "reboot", "audit-comment")): return "Operations"
        if "session" in value or "timeout" in value or "tcp" in value: return "Session"
        if "content" in value or "application" in value: return "Content-ID"
        if "wildfire" in value: return "WildFire"
        if "telemetry" in value: return "Telemetry"
        return "General"
    if section == "administrators":
        if any(token in value for token in ("authentication", "password", "certificate", "public-key")): return "Authentication"
        if any(token in value for token in ("role", "superuser", "device-admin", "vsys")): return "Administrator Type"
    if section == "admin-roles":
        if "webui" in value or "web ui" in value: return "Web UI"
        if "xml" in value or "restapi" in value or "rest api" in value: return "XML API"
        if "cli" in value or "command" in value: return "Command Line"
    if section == "authentication-profile":
        if "factor" in value or "mfa" in value: return "Factors"
        if any(token in value for token in ("allow-list", "allow list", "username-modifier", "user-domain", "advanced")): return "Advanced"
        return "Authentication"
    if section == "authentication-sequence" and "profile" in value: return "Authentication Profiles"
    if section == "certificates" and any(token in value for token in ("issuer", "subject", "algorithm", "expiry", "common-name", "common name", "san")): return "Certificate Attributes"
    if section == "certificate-management":
        if "decrypt" in value: return "Decryption"
        if "ssl" in value or "tls" in value: return "SSL/TLS"
    if section == "local-user-database" and any(token in value for token in ("password", "authentication")): return "Authentication"
    if section == "server-profiles":
        if any(token in value for token in ("authentication", "username", "password", "certificate")): return "Authentication"
        if "server" in value or "address" in value or "port" in value: return "Servers"
    if section == "log-settings":
        if "filter" in value or "match-list" in value or "match list" in value: return "Filter"
        if any(token in value for token in ("forward", "syslog", "email", "snmp", "http")): return "Forwarding"
    if section == "high-availability":
        if "election" in value or "priority" in value: return "Election Settings"
        if any(token in value for token in ("control-link", "control link", "ha1")): return "Control Link"
        if any(token in value for token in ("data-link", "data link", "ha2", "ha3")): return "Data Link"
        if "active-active" in value or "active/active" in value: return "Active/Active"
        if "monitor" in value or "path-group" in value or "link-group" in value: return "Monitoring"
    if section == "user-identification":
        if "server-monitor" in value or "server monitor" in value: return "Server Monitoring"
        if any(token in value for token in ("include", "exclude", "network")): return "Include/Exclude Networks"
    if section == "vm-information-sources":
        if any(token in value for token in ("authentication", "username", "password")): return "Authentication"
        if any(token in value for token in ("host", "source", "port")): return "Source"
    return "General"


def panos_ui_decorate_record(record: dict, section: str) -> dict:
    """Add PAN-OS-like UI metadata without changing writable locators."""
    tabs = PANOS_CONFIG_UI_TABS.get(section, ("General", "Other"))
    used = []
    for field in record.get("edit_fields", []):
        group = _panos_ui_group(section, field.get("label", ""), field.get("group", ""))
        if group not in tabs: group = "Other"
        field["group"] = group
        field["technical_label"] = field.get("label", "")
        # PAN-OS labels show the leaf name; the full XML path remains available
        # as unobtrusive context below the control.
        field["label"] = field.get("label", "").split(" / ")[-1] or "Value"
        if group not in used: used.append(group)
        normalized = field["label"].lower()
        if normalized in {"link state", "link speed", "link duplex"}:
            field["options"] = {
                "link state": ["auto", "up", "down"],
                "link speed": ["auto", "10", "100", "1000", "10000", "25000", "40000", "100000"],
                "link duplex": ["auto", "full", "half"],
            }[normalized]
    primary = {
        "interfaces": "Ethernet Interface", "zones": "General", "vlans": "General",
        "virtual-wires": "General", "virtual-routers": "Router Settings",
        "logical-routers": "General",
    }.get(section, "General")
    record["ui_tabs"] = [tab for tab in tabs if tab in used or (record.get("is_entry") and tab == primary)]
    kind = str(record.get("kind", "")).strip()
    record["ui_family"] = (kind.split(" / ", 1)[0] if kind else section.replace("-", " ")).replace(" Interfaces", "")
    return record
POLICY_LIST_FIELDS = (
    "from", "to", "source", "destination", "source-user", "category",
    "application", "service", "tag", "destination-user", "source-hip", "destination-hip",
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
    if not children and node.tag in {"layer3", "layer2", "virtual-wire", "tap", "tunnel", "external"}:
        lines.append("set " + " ".join(shlex.quote(part) for part in current))
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


def _xml_payload(node: ET.Element | None):
    if node is None:
        return {}
    children = list(node)
    if not children:
        return (node.text or "").strip()
    if all(child.tag == "member" for child in children):
        return [(child.text or "").strip() for child in children if (child.text or "").strip()]
    payload = {}
    for child in children:
        value = _xml_payload(child)
        if child.tag in payload:
            existing = payload[child.tag]
            payload[child.tag] = existing + [value] if isinstance(existing, list) else [existing, value]
        else:
            payload[child.tag] = value
    return payload


def policy_record(entry: ET.Element, kind: str, owner: str, rulebase: str, editable: bool) -> dict:
    record = {
        "id": entry.get("name", ""), "name": entry.get("name", ""), "kind": kind, "owner": owner,
        "rulebase": rulebase, "editable": editable,
        "action": entry.findtext("./action", ""),
        "description": entry.findtext("./description", ""),
        "disabled": entry.findtext("./disabled", "no") == "yes",
        "log_setting": entry.findtext("./log-setting", ""),
        "profile_group": entry.findtext("./profile-setting/group/member", ""),
        "schedule": entry.findtext("./schedule", ""),
        "_policy_kind": kind,
        "_xml": ET.tostring(entry, encoding="unicode"),
    }
    for field in POLICY_LIST_FIELDS:
        record[field.replace("-", "_")] = _members(entry, field)
    if kind == "nat":
        source_translation = _xml_payload(entry.find("./source-translation"))
        destination_translation = _xml_payload(entry.find("./destination-translation"))
        source_mode_raw = next(iter(source_translation), "none") if isinstance(source_translation, dict) else "none"
        source_mode = source_mode_raw.replace("-", "_")
        source_details = source_translation.get(source_mode_raw, {}) if source_mode != "none" else {}
        if not isinstance(source_details, dict):
            source_details = {"translated-address": source_details}
        translated_address = source_details.get("translated-address", [])
        if not isinstance(translated_address, list):
            translated_address = [translated_address] if translated_address not in (None, "") else []
        interface_address = source_details.get("interface-address", {})
        if not isinstance(interface_address, dict):
            interface_address = {}
        source_address_text = ", ".join(str(value) for value in translated_address)
        source_interface_text = str(interface_address.get("interface", "") or "")
        destination_address_text = str(destination_translation.get("translated-address", "") or "") if isinstance(destination_translation, dict) else ""
        destination_port_text = str(destination_translation.get("translated-port", "") or "") if isinstance(destination_translation, dict) else ""
        service_node = entry.find("./service")
        service_value = (service_node.findtext("./member", "") if service_node is not None and service_node.find("./member") is not None else entry.findtext("./service", "any")).strip() or "any"
        record.update({
            "service": [service_value],
            "nat_type": entry.findtext("./nat-type", "ipv4") or "ipv4",
            "to_interface": entry.findtext("./to-interface", "any") or "any",
            "source_translation": source_translation if isinstance(source_translation, dict) else {},
            "destination_translation": destination_translation if isinstance(destination_translation, dict) else {},
            "source_translation_mode": source_mode,
            "source_translation_address": source_address_text,
            "source_translation_interface": source_interface_text,
            "destination_translation_address": destination_address_text,
            "destination_translation_port": destination_port_text,
            "source_translation_summary": " · ".join(value for value in (source_mode.replace("_", " "), source_address_text, source_interface_text) if value) if source_mode != "none" else "—",
            "destination_translation_summary": " · ".join(value for value in (destination_address_text, destination_port_text) if value) or "—",
        })
    return record


def policy_create_record(kind: str, owner: str, rulebase: str) -> dict:
    """Return a PAN-OS-shaped editable seed for every policy family."""
    if kind not in POLICY_NODES:
        raise OfflineConfigError(f"Onbekend policytype: {kind}")
    entry = ET.Element("entry", {"name": ""})

    def members(tag: str, values: list[str]) -> None:
        node = ET.SubElement(entry, tag)
        for value in values:
            ET.SubElement(node, "member").text = value

    for field in ("from", "to", "source", "destination"):
        members(field, ["any"])
    if kind in {"security", "qos", "pbf", "application-override"}:
        members("application", ["any"])
    if kind == "nat":
        ET.SubElement(entry, "service").text = "any"
        ET.SubElement(entry, "nat-type").text = "ipv4"
        ET.SubElement(entry, "to-interface").text = "any"
    elif kind in {"security", "qos", "pbf", "authentication"}:
        members("service", ["application-default"])
    if kind == "security":
        ET.SubElement(entry, "action").text = "allow"
    elif kind == "decryption":
        ET.SubElement(entry, "action").text = "no-decrypt"
    ET.SubElement(entry, "disabled").text = "no"
    record = policy_record(entry, kind, owner, rulebase, True)
    record["create_template"] = True
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
        if _protected_config_tag(child.tag):
            fields.append({"name": child.tag, "values": ["Protected value"]})
            continue
        values = [node.text or "" for node in child.findall(".//member") if node.text]
        text = (child.text or "").strip()
        if values:
            fields.append({"name": child.tag, "values": values})
        elif text:
            fields.append({"name": child.tag, "values": [text]})
        elif list(child):
            fields.append({"name": child.tag, "values": ["Structured configuration"]})
    return fields


def _object_edit_fields(entry: ET.Element, object_type: str = "") -> list[dict]:
    """Flatten an entry into safe form fields without exposing raw XML.

    Index based paths deliberately address the existing tree. The object
    fingerprint prevents applying them to a tree that changed meanwhile.
    Nested attributes and unsupported nodes remain untouched.
    """
    fields: list[dict] = []

    def walk(node: ET.Element, path: list[int], labels: list[str]) -> None:
        children = list(node)
        label = " / ".join(labels)
        group = labels[0] if labels else "General"
        if path and node.tag == "entry" and node.get("name") is not None:
            fields.append({
                "path": "/".join(str(index) for index in path),
                "label": f"{label} / Name", "group": group,
                "kind": "attribute", "value": node.get("name", ""),
            })
        if object_type == "url-filtering":
            top = labels[0].strip().lower() if labels else ""
            if top in {"allow", "alert", "block", "continue", "override", "redirect", "none"}:
                group = "Categories"
            elif top == "credential enforcement":
                group = "User Credential Detection"
            elif "inline" in top or top.startswith("mlav"):
                group = "Inline Categorization"
            elif top.startswith("log http") or "header" in top:
                group = "HTTP Header Insertion"
            else:
                group = "General"
        if _protected_config_tag(node.tag):
            fields.append({
                "path": "/".join(str(index) for index in path),
                "label": label, "group": group, "kind": "protected",
            })
            return
        if children and all(child.tag == "member" for child in children):
            fields.append({
                "path": "/".join(str(index) for index in path),
                "label": label, "group": group,
                "kind": "members",
                "values": [(child.text or "") for child in children],
            })
            return
        if not children:
            value = node.text or ""
            if len(value) > 8192:
                fields.append({
                    "path": "/".join(str(index) for index in path),
                    "label": label, "group": group, "kind": "protected",
                })
                return
            fields.append({
                "path": "/".join(str(index) for index in path),
                "label": label, "group": group,
                "kind": "boolean" if value.strip().lower() in {"yes", "no"} else "text",
                "value": value,
            })
            return
        for index, child in enumerate(children):
            walk(child, path + [index], labels + [child.tag.replace("-", " ").title()])

    for index, child in enumerate(list(entry)):
        walk(child, [index], [child.tag.replace("-", " ").title()])
    return fields


def object_create_record(object_type: str, owner: str = "") -> dict | None:
    """Return the PAN-OS-shaped seed used by the generic Add editor."""
    source = OBJECT_CREATE_XML.get(object_type)
    if not source:
        return None
    entry = SafeET.fromstring(source)
    record = object_record(entry, owner, True, object_type)
    record["generic"] = True
    record["create_template"] = True
    return record


def generic_object_xml(object_type: str, current_xml: str | None, name: str, updates: list[dict]) -> str:
    """Apply validated generic form updates to an existing entry or create seed."""
    source = current_xml or OBJECT_CREATE_XML.get(object_type)
    if not source:
        raise OfflineConfigError("Voor dit objecttype is geen veilig PAN-OS create-schema beschikbaar")
    entry = SafeET.fromstring(source)
    if entry.tag != "entry":
        raise OfflineConfigError("Ongeldig object-create-schema")
    clean_name = str(name).strip()
    if not clean_name:
        raise OfflineConfigError("Name is verplicht")
    entry.set("name", clean_name)
    allowed = {
        (field["path"], field["kind"])
        for field in _object_edit_fields(entry, object_type)
        if field.get("kind") != "protected"
    }
    if not isinstance(updates, list) or len(updates) > 10000:
        raise OfflineConfigError("Ongeldige objectvelden")
    for update in updates:
        key = (str(update.get("path", "")), str(update.get("kind", "")))
        if key not in allowed:
            raise OfflineConfigError("Een objectveld bestaat niet meer of is beschermd")
        try:
            target = entry
            for index in (int(part) for part in key[0].split("/") if part != ""):
                target = list(target)[index]
        except (ValueError, IndexError):
            raise OfflineConfigError("Een objectveld bestaat niet meer")
        if key[1] == "members":
            values = update.get("values", [])
            if not isinstance(values, list) or len(values) > 10000:
                raise OfflineConfigError("Ongeldige memberlijst")
            for child in list(target):
                target.remove(child)
            for value in values:
                clean = str(value).strip()
                if clean:
                    member = ET.SubElement(target, "member")
                    member.text = clean
        elif key[1] == "attribute":
            target.set("name", str(update.get("value", ""))[:63])
        else:
            target.text = str(update.get("value", ""))[:65535]
    return ET.tostring(entry, encoding="unicode")


def object_fingerprint(record: dict) -> str:
    return hashlib.sha256(record["_xml"].encode()).hexdigest()


def object_record(entry: ET.Element, owner: str, editable: bool, object_type: str) -> dict:
    record = {
        "id": entry.get("name", ""), "name": entry.get("name", ""),
        "owner": owner, "editable": editable, "description": entry.findtext("./description", ""),
        "comments": entry.findtext("./comments", ""), "tag": _members(entry, "tag"),
        "summary": _object_summary(entry), "values": _object_values(entry),
        "fields": _object_fields(entry), "edit_fields": _object_edit_fields(entry, object_type),
        "_xml": ET.tostring(entry, encoding="unicode"),
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
            port = str(details.get("port", "")).strip()
            source_port = str(details.get("source_port", "")).strip()
            rendered = f"{protocol.upper()}/{port}" if port else protocol.upper()
            if source_port:
                rendered += f" · source {source_port}"
            record["summary"] = rendered
            record["values"] = [rendered]
            break
    elif object_type == "log-forwarding":
        match_list = []
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
                        "tags": _members(tagging, "tags"),
                    })
                elif integration is not None:
                    actions.append({
                        "name": action.get("name", ""), "type": "integration",
                        "integration_action": integration.findtext("./action", ""),
                    })
            match_list.append({
                "name": match.get("name", ""),
                "action_desc": match.findtext("./action-desc", ""),
                "log_type": match.findtext("./log-type", "traffic") or "traffic",
                "filter": match.findtext("./filter", ""),
                "send_to_panorama": match.findtext("./send-to-panorama", "no") == "yes",
                "send_syslog": _members(match, "send-syslog"),
                "send_email": _members(match, "send-email"),
                "send_snmptrap": _members(match, "send-snmptrap"),
                "send_http": _members(match, "send-http"),
                "quarantine": match.findtext("./quarantine", "no") == "yes",
                "actions": actions,
            })
        record["match_list"] = match_list
        record["enhanced_application_logging"] = entry.findtext("./enhanced-application-logging", "no") == "yes"
        record["summary"] = f"{len(match_list)} match-list entr{'y' if len(match_list) == 1 else 'ies'}"
        record["values"] = [item["name"] for item in match_list if item["name"]]
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


def scoped_server_profiles(xml_bytes: bytes, scope: str, parsed=None) -> list[dict]:
    """Return server-profile names visible to a policy/log-forwarding scope."""
    root, snapshot = parsed if parsed is not None else parse_snapshot(xml_bytes)
    chain = _scope_chain(snapshot, scope) if snapshot.kind == "panorama" else (["Shared", scope] if root.find("./shared") is not None else [scope])
    records = []
    seen = set()
    for owner in chain:
        scope_root = _scope_root(root, snapshot, owner)
        if scope_root is None:
            continue
        for kind, node in SERVER_PROFILE_NODES.items():
            for entry in scope_root.findall(f"./server-profile/{node}/entry"):
                name = entry.get("name", "").strip()
                key = (kind, name)
                if name and key not in seen:
                    seen.add(key)
                    records.append({"name": name, "kind": kind, "owner": owner})
    return records


EDITABLE_OBJECT_TAGS = {
    "addresses": {"description", "tag", "ip-netmask", "ip-range", "ip-wildcard", "fqdn"},
    "address-groups": {"description", "tag", "static", "dynamic"},
    "application-groups": {"description", "tag", "members"},
    "services": {"description", "tag", "protocol"},
    "service-groups": {"description", "tag", "members"},
    "tags": {"comments", "color"},
    "log-forwarding": {"description", "enhanced-application-logging", "match-list"},
}


def apply_object_changes(xml_bytes: bytes, scope: str, object_type: str, changes: list[dict]) -> bytes:
    if object_type not in OBJECT_NODES:
        raise OfflineConfigError("Onbekend objecttype")
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
        if change.get("generic_updates") is not None:
            replacement = SafeET.fromstring(generic_object_xml(
                object_type,
                ET.tostring(current, encoding="unicode") if current is not None else None,
                change.get("name", original_name),
                change["generic_updates"],
            ))
        else:
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
        if object_type not in EDITABLE_OBJECT_TAGS:
            index = list(container).index(current)
            container.remove(current)
            container.insert(index, replacement)
            continue
        editable_tags = EDITABLE_OBJECT_TAGS[object_type]
        for child in list(current):
            if child.tag in editable_tags:
                current.remove(child)
        for child in list(replacement):
            current.append(copy.deepcopy(child))
    return normalized_config_xml(root)


def _config_roots(root: ET.Element, snapshot: ConfigSnapshot, scope: str, template: str) -> list[tuple[str, ET.Element]]:
    """Return concrete configuration owners for a Network/Device view."""
    if snapshot.kind != "panorama":
        return [(scope, root)]
    templates = {
        entry.get("name", ""): entry
        for entry in root.findall("./devices/entry/template/entry")
        if entry.get("name")
    }
    if template in templates:
        return [(template, templates[template])]
    stack = next((
        entry for entry in root.findall("./devices/entry/template-stack/entry")
        if entry.get("name") == template
    ), None)
    if stack is None:
        return []
    names = [member.text or "" for member in stack.findall("./templates/member")]
    return [(name, templates[name]) for name in names if name in templates]


def _indexed_element(root: ET.Element, locator: str) -> ET.Element:
    node = root
    if not locator:
        return node
    try:
        for part in locator.split("/"):
            node = list(node)[int(part)]
    except (ValueError, IndexError):
        raise OfflineConfigError("Het configuratie-item bestaat niet meer")
    return node


def _element_parents(root: ET.Element) -> dict[int, tuple[ET.Element, int]]:
    return {
        id(child): (parent, index)
        for parent in root.iter()
        for index, child in enumerate(list(parent))
    }


def _element_locator(root: ET.Element, target: ET.Element, parents: dict[int, tuple[ET.Element, int]]) -> str:
    indices: list[int] = []
    current = target
    while current is not root:
        parent_info = parents.get(id(current))
        if parent_info is None:
            raise OfflineConfigError("Het configuratie-item bevindt zich niet in de geladen configuratie")
        current, index = parent_info
        indices.append(index)
    return "/".join(str(index) for index in reversed(indices))


def _protected_config_tag(tag: str) -> bool:
    normalized = tag.lower()
    return (
        normalized in PROTECTED_CONFIG_TAGS
        or "password" in normalized
        or "private-key" in normalized
        or normalized.endswith("-secret")
    )


def _config_edit_fields(entry: ET.Element, skip_nested_entries: bool = False) -> list[dict]:
    fields: list[dict] = []

    def walk(node: ET.Element, path: list[int], labels: list[str]) -> None:
        children = list(node)
        label = " / ".join(labels)
        group = labels[0] if labels else "General"
        if node is not entry and node.tag == "entry" and "name" in node.attrib:
            fields.append({
                "path": "/".join(map(str, path)), "label": label or "Name",
                "group": group, "kind": "attribute", "attribute": "name",
                "value": node.get("name", ""),
            })
        if _protected_config_tag(node.tag):
            fields.append({"path": "/".join(map(str, path)), "label": label, "group": group, "kind": "protected"})
            return
        if children and all(child.tag == "member" for child in children):
            fields.append({
                "path": "/".join(map(str, path)), "label": label,
                "group": group, "kind": "members",
                "values": [(child.text or "") for child in children],
            })
            return
        if not children:
            value = node.text or ""
            # Certificate blobs and similar large opaque values remain preserved
            # but are not copied into the browser DOM.
            if len(value) > 8192:
                fields.append({"path": "/".join(map(str, path)), "label": label, "group": group, "kind": "protected"})
                return
            fields.append({
                "path": "/".join(map(str, path)), "label": label,
                "group": group,
                "kind": "boolean" if value.strip().lower() in {"yes", "no"} else "text",
                "value": value,
            })
            return
        for index, child in enumerate(children):
            if skip_nested_entries and child.tag == "entry":
                continue
            walk(child, path + [index], labels + [child.tag.replace("-", " ").title()])

    for index, child in enumerate(list(entry)):
        walk(child, [index], [child.tag.replace("-", " ").title()])
    return fields


def _top_level_entries(section: ET.Element) -> list[tuple[ET.Element, list[str]]]:
    records: list[tuple[ET.Element, list[str]]] = []

    def walk(node: ET.Element, labels: list[str], inside_entry: bool) -> None:
        for child in list(node):
            next_labels = labels + [child.tag.replace("-", " ").title()]
            if child.tag == "entry" and not inside_entry:
                records.append((child, labels))
                continue
            walk(child, next_labels, inside_entry or child.tag == "entry")

    walk(section, [], False)
    return records


def _has_nonentry_leaf(node: ET.Element) -> bool:
    for child in list(node):
        if child.tag == "entry":
            continue
        if not list(child) or _has_nonentry_leaf(child):
            return True
    return False


def configuration_records(
    xml_bytes: bytes, scope: str, template: str, view: str, section: str, parsed=None,
) -> tuple[ConfigSnapshot, list[dict]]:
    root, snapshot = parsed if parsed is not None else parse_snapshot(xml_bytes)
    paths = CONFIG_SECTION_PATHS.get(view, {}).get(section)
    if not paths:
        return snapshot, []
    parents = _element_parents(root)
    records: list[dict] = []
    seen_sections: set[int] = set()
    for owner, source in _config_roots(root, snapshot, scope, template):
        search_source = source
        if view == "network" and section == "zones" and snapshot.kind != "panorama":
            scoped_root = _scope_root(root, snapshot, scope)
            search_source = scoped_root if scoped_root is not None else source
        sections: list[ET.Element] = []
        for path in paths:
            for node in search_source.findall(path):
                if id(node) not in seen_sections:
                    seen_sections.add(id(node)); sections.append(node)
        for section_node in sections:
            entries = _top_level_entries(section_node)
            targets = list(entries)
            if _has_nonentry_leaf(section_node):
                targets.insert(0, (section_node, []))
            for entry, labels in targets:
                locator = _element_locator(root, entry, parents)
                xml = ET.tostring(entry, encoding="unicode")
                name = entry.get("name") or section.replace("-", " ").title()
                kind = " / ".join(labels) if labels else section_node.tag.replace("-", " ").title()
                fields = _config_edit_fields(entry, skip_nested_entries=entry is section_node and bool(entries))
                summary_values = []
                for field in fields:
                    if field["kind"] == "members":
                        summary_values.extend(field.get("values", [])[:3])
                    elif field["kind"] != "protected" and str(field.get("value", "")).strip():
                        summary_values.append(str(field["value"]).strip())
                    elif section == "zones" and field.get("label", "").startswith("Network / "):
                        summary_values.append(field["label"].rsplit(" / ", 1)[-1])
                    if len(summary_values) >= 3:
                        break
                record = {
                    "id": locator, "locator": locator, "name": name, "owner": owner,
                    "kind": kind, "is_entry": entry.tag == "entry", "editable": True,
                    "summary": " · ".join(summary_values[:3]), "edit_fields": fields,
                    "fingerprint": hashlib.sha256(xml.encode()).hexdigest(), "_xml": xml,
                }
                records.append(panos_ui_decorate_record(record, section))
    return snapshot, records


def apply_configuration_changes(xml_bytes: bytes, changes: list[dict]) -> bytes:
    root, _ = parse_snapshot(xml_bytes)
    # Delete descending index paths so removing one sibling cannot retarget the
    # locator of a later sibling. Updates/duplicates then use stable locators.
    deletes = sorted(
        (item for item in changes if item.get("operation") == "delete"),
        key=lambda item: [int(part) for part in item.get("locator", "").split("/") if part],
        reverse=True,
    )
    ordered = deletes + [item for item in changes if item.get("operation") != "delete"]
    for change in ordered:
        locator = change.get("locator", "")
        current = _indexed_element(root, locator)
        current_xml = ET.tostring(current, encoding="unicode")
        if hashlib.sha256(current_xml.encode()).hexdigest() != change.get("fingerprint"):
            raise OfflineConfigError("Het configuratie-item is intussen gewijzigd")
        if change.get("operation") == "delete":
            if current.tag != "entry" or not locator:
                raise OfflineConfigError("Alleen benoemde configuratie-items kunnen worden verwijderd")
            parent_locator = "/".join(locator.split("/")[:-1])
            _indexed_element(root, parent_locator).remove(current)
            continue
        replacement = copy.deepcopy(current)
        new_name = str(change.get("name", "")).strip()
        if replacement.tag == "entry":
            if not new_name:
                raise OfflineConfigError("Name is verplicht")
            parent_locator = "/".join(locator.split("/")[:-1])
            parent = _indexed_element(root, parent_locator)
            if any(sibling is not current and sibling.tag == "entry" and sibling.get("name") == new_name for sibling in list(parent)):
                raise OfflineConfigError(f"Configuratie-item {new_name} bestaat al")
            replacement.set("name", new_name)
        allowed = {(field["path"], field["kind"]) for field in _config_edit_fields(current) if field["kind"] != "protected"}
        updates = change.get("updates", [])
        if not isinstance(updates, list) or len(updates) > 10000:
            raise OfflineConfigError("Ongeldige configuratievelden")
        for update in updates:
            key = (str(update.get("path", "")), str(update.get("kind", "")))
            if key not in allowed:
                raise OfflineConfigError("Een configuratieveld bestaat niet meer of is beschermd")
            target = _indexed_element(replacement, key[0])
            if key[1] == "members":
                values = update.get("values", [])
                if not isinstance(values, list) or len(values) > 10000:
                    raise OfflineConfigError("Ongeldige memberlijst")
                for child in list(target):
                    target.remove(child)
                for value in values:
                    clean = str(value).strip()
                    if clean:
                        member = ET.SubElement(target, "member"); member.text = clean
            elif key[1] == "attribute":
                target.set("name", str(update.get("value", ""))[:65535])
            else:
                target.text = str(update.get("value", ""))[:65535]
        if change.get("operation") == "create":
            if current.tag != "entry" or not locator:
                raise OfflineConfigError("Alleen een benoemd configuratie-item kan als basis worden gebruikt")
            parent = _indexed_element(root, "/".join(locator.split("/")[:-1]))
            if any(sibling.tag == "entry" and sibling.get("name") == new_name for sibling in list(parent)):
                raise OfflineConfigError(f"Configuratie-item {new_name} bestaat al")
            index = list(parent).index(current)
            parent.insert(index + 1, replacement)
        elif locator:
            parent = _indexed_element(root, "/".join(locator.split("/")[:-1]))
            index = list(parent).index(current)
            parent.remove(current); parent.insert(index, replacement)
        else:
            root = replacement
    return normalized_config_xml(root)


def create_basic_network_entry(
    xml_bytes: bytes, scope: str, template: str, section: str, name: str,
    interface_type: str = "ethernet", zone_type: str = "layer3",
) -> bytes:
    """Create the first interface/zone when an imported config has no seed row.

    Existing entries continue to use the generic PAN-OS field editor.  This
    narrow bootstrap path exists because duplicating an existing XML entry is
    impossible when a third-party migration starts with an empty network tree.
    """
    clean_name = str(name or "").strip()
    if not clean_name or len(clean_name) > 127:
        raise OfflineConfigError("Name is verplicht en mag maximaal 127 tekens bevatten")
    root, snapshot = parse_snapshot(xml_bytes)

    def ensure(parent: ET.Element, *tags: str) -> ET.Element:
        current = parent
        for tag in tags:
            child = current.find(tag)
            if child is None:
                child = ET.SubElement(current, tag)
            current = child
        return current

    device = root.find("./devices/entry")
    if device is None:
        devices = ensure(root, "devices")
        device = ET.SubElement(devices, "entry", {"name": "localhost.localdomain"})
    template_device = device
    if snapshot.kind == "panorama":
        template_entry = next(
            (item for item in device.findall("./template/entry") if item.get("name") == template),
            None,
        )
        if template_entry is None:
            raise OfflineConfigError("Kies of maak eerst een Panorama-template")
        config = ensure(template_entry, "config", "devices")
        template_device = config.find("entry")
        if template_device is None:
            template_device = ET.SubElement(config, "entry", {"name": "localhost.localdomain"})

    if section == "interfaces":
        if interface_type not in {"ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan"}:
            raise OfflineConfigError("Ongeldig interfacetype")
        parent = ensure(template_device, "network", "interface", interface_type)
        if any(item.get("name") == clean_name for item in parent.findall("entry")):
            raise OfflineConfigError(f"Interface {clean_name} bestaat al")
        entry = ET.SubElement(parent, "entry", {"name": clean_name})
        if interface_type in {"ethernet", "aggregate-ethernet"}:
            ET.SubElement(entry, "layer3")
        ET.SubElement(entry, "comment")
    elif section == "zones":
        if zone_type not in {"layer3", "layer2", "virtual-wire", "tap", "tunnel"}:
            raise OfflineConfigError("Ongeldig zonetype")
        if snapshot.kind == "panorama":
            vsys_parent = ensure(template_device, "vsys")
            scope_entry = next((item for item in vsys_parent.findall("entry") if item.get("name") == scope), None)
            if scope_entry is None:
                scope_entry = ET.SubElement(vsys_parent, "entry", {"name": scope or "vsys1"})
        else:
            scope_entry = _scope_root(root, snapshot, scope)
            if scope_entry is None:
                raise OfflineConfigError("De gekozen VSYS bestaat niet")
        parent = ensure(scope_entry, "zone")
        if any(item.get("name") == clean_name for item in parent.findall("entry")):
            raise OfflineConfigError(f"Zone {clean_name} bestaat al")
        entry = ET.SubElement(parent, "entry", {"name": clean_name})
        network = ET.SubElement(entry, "network")
        ET.SubElement(network, zone_type)
        enabled = ET.SubElement(entry, "enable-user-identification")
        enabled.text = "no"
    else:
        raise OfflineConfigError("Bootstrap-aanmaak wordt alleen voor interfaces en zones ondersteund")
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
    if replacement.tag != "entry" or not replacement.get("name"):
        raise OfflineConfigError("Ongeldige vervangende policy")
    collision = next((entry for entry in rules.findall("./entry") if entry is not current and entry.get("name") == replacement.get("name")), None)
    if collision is not None:
        raise OfflineConfigError(f"Policy {replacement.get('name')} bestaat al in deze rulebase")
    index = list(rules).index(current)
    rules.remove(current)
    rules.insert(index, replacement)
    return normalized_config_xml(root)


def _policy_rules_root(root: ET.Element, snapshot: ConfigSnapshot, scope: str, kind: str, rulebase: str) -> ET.Element:
    if kind not in POLICY_NODES:
        raise OfflineConfigError(f"Onbekend policytype: {kind}")
    scope_root = _scope_root(root, snapshot, scope)
    if scope_root is None:
        raise OfflineConfigError("De gekozen scope bestaat niet meer")
    base_tag = f"{rulebase}-rulebase" if snapshot.kind == "panorama" else "rulebase"
    base = scope_root.find(f"./{base_tag}")
    if base is None:
        base = ET.SubElement(scope_root, base_tag)
    policy = base.find(f"./{POLICY_NODES[kind]}")
    if policy is None:
        policy = ET.SubElement(base, POLICY_NODES[kind])
    rules = policy.find("./rules")
    return rules if rules is not None else ET.SubElement(policy, "rules")


def insert_policy_in_snapshot(
    xml_bytes: bytes, scope: str, kind: str, rulebase: str,
    policy_xml: str, position: str = "bottom",
) -> bytes:
    root, snapshot = parse_snapshot(xml_bytes)
    rules = _policy_rules_root(root, snapshot, scope, kind, rulebase)
    entry = SafeET.fromstring(policy_xml)
    name = str(entry.get("name", "")).strip()
    if entry.tag != "entry" or not name:
        raise OfflineConfigError("Ongeldige nieuwe policy")
    if any(current.get("name") == name for current in rules.findall("./entry")):
        raise OfflineConfigError(f"Policy {name} bestaat al in deze rulebase")
    if position == "top":
        rules.insert(0, entry)
    elif position == "bottom":
        rules.append(entry)
    else:
        raise OfflineConfigError("Ongeldige insertpositie")
    return normalized_config_xml(root)


def delete_policies_from_snapshot(
    xml_bytes: bytes, scope: str, kind: str, rulebase: str, names: set[str],
) -> bytes:
    root, snapshot = parse_snapshot(xml_bytes)
    rules = _policy_rules_root(root, snapshot, scope, kind, rulebase)
    current = {entry.get("name", ""): entry for entry in rules.findall("./entry")}
    missing = sorted(names - set(current))
    if missing:
        raise OfflineConfigError("Policies bestaan niet meer: " + ", ".join(missing[:12]))
    for name in names:
        rules.remove(current[name])
    return normalized_config_xml(root)


def move_policies_in_snapshot(
    xml_bytes: bytes, scope: str, kind: str, rulebase: str,
    names: set[str], direction: str,
) -> bytes:
    root, snapshot = parse_snapshot(xml_bytes)
    rules = _policy_rules_root(root, snapshot, scope, kind, rulebase)
    entries = list(rules.findall("./entry"))
    available = {entry.get("name", "") for entry in entries}
    missing = sorted(names - available)
    if missing:
        raise OfflineConfigError("Policies bestaan niet meer: " + ", ".join(missing[:12]))
    if direction == "up":
        for index in range(1, len(entries)):
            if entries[index].get("name") in names and entries[index - 1].get("name") not in names:
                entries[index - 1], entries[index] = entries[index], entries[index - 1]
    elif direction == "down":
        for index in range(len(entries) - 2, -1, -1):
            if entries[index].get("name") in names and entries[index + 1].get("name") not in names:
                entries[index], entries[index + 1] = entries[index + 1], entries[index]
    else:
        raise OfflineConfigError("Ongeldige move-richting")
    for entry in list(rules):
        rules.remove(entry)
    for entry in entries:
        rules.append(entry)
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
