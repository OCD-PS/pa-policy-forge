from __future__ import annotations

import hashlib
import ipaddress
import json
import copy
import csv
import io
import re
import shlex
import tarfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath
from typing import Iterable

from defusedxml import ElementTree as SafeET


class MigrationError(ValueError):
    pass


def clean_name(value: str, fallback: str = "item") -> str:
    value = re.sub(r"[^A-Za-z0-9._ -]+", "-", str(value or "").strip())
    value = re.sub(r"\s+", "-", value).strip("-.")
    return (value or fallback)[:63]


def unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))


def cidr(value: str, mask: str | None = None) -> str:
    value = value.strip()
    if mask:
        return str(ipaddress.ip_network(f"{value}/{mask}", strict=False))
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return value


def valid_panos_fqdn(value: str) -> bool:
    """Return whether a value is an exact hostname accepted by PAN-OS.

    Check Point dns-domain objects can contain URL paths.  Those must remain
    review items instead of becoming syntactically invalid PAN-OS FQDNs.
    """
    candidate = str(value or "").strip().rstrip(".")
    if not candidate or len(candidate) > 253 or any(char in candidate for char in "/:@?#"):
        return False
    try:
        ascii_name = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    labels = ascii_name.split(".")
    return len(labels) >= 2 and all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    )


@dataclass
class Address:
    name: str
    value: str
    value_type: str = "ip_netmask"
    description: str = ""
    tags: list[str] = field(default_factory=list)
    source_ref: str = ""
    target_context: str = ""
    mapping_action: str = "create"


@dataclass
class AddressGroup:
    name: str
    members: list[str] = field(default_factory=list)
    description: str = ""
    tags: list[str] = field(default_factory=list)
    source_ref: str = ""
    target_context: str = ""
    mapping_action: str = "create"


@dataclass
class Service:
    name: str
    protocol: str
    port: str
    source_port: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)
    source_ref: str = ""
    target_context: str = ""
    mapping_action: str = "create"


@dataclass
class ServiceGroup:
    name: str
    members: list[str] = field(default_factory=list)
    description: str = ""
    tags: list[str] = field(default_factory=list)
    source_ref: str = ""
    target_context: str = ""
    mapping_action: str = "create"


@dataclass
class Policy:
    name: str
    policy_type: str = "security"
    from_zones: list[str] = field(default_factory=lambda: ["any"])
    to_zones: list[str] = field(default_factory=lambda: ["any"])
    source: list[str] = field(default_factory=lambda: ["any"])
    destination: list[str] = field(default_factory=lambda: ["any"])
    application: list[str] = field(default_factory=lambda: ["any"])
    service: list[str] = field(default_factory=lambda: ["application-default"])
    action: str = "allow"
    disabled: bool = True
    description: str = ""
    tags: list[str] = field(default_factory=list)
    source_translation: dict = field(default_factory=dict)
    destination_translation: dict = field(default_factory=dict)
    nat_type: str = "ipv4"
    to_interface: str = "any"
    source_ref: str = ""
    original: dict = field(default_factory=dict)
    target_context: str = ""
    mapping_action: str = "create"


def policy_state(rule: Policy) -> dict:
    """Normalized editable policy fields used to detect untouched raw PAN-OS rules."""
    return {
        "name": rule.name, "policy_type": rule.policy_type,
        "from_zones": rule.from_zones, "to_zones": rule.to_zones,
        "source": rule.source, "destination": rule.destination,
        "application": rule.application, "service": rule.service,
        "action": rule.action, "disabled": rule.disabled,
        "description": rule.description, "tags": rule.tags,
        "source_translation": rule.source_translation,
        "destination_translation": rule.destination_translation,
        "nat_type": rule.nat_type, "to_interface": rule.to_interface,
    }


@dataclass
class MigrationModel:
    vendor: str
    source_name: str
    addresses: list[Address] = field(default_factory=list)
    address_groups: list[AddressGroup] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    service_groups: list[ServiceGroup] = field(default_factory=list)
    security_rules: list[Policy] = field(default_factory=list)
    nat_rules: list[Policy] = field(default_factory=list)
    interfaces: list[dict] = field(default_factory=list)
    zones: list[dict] = field(default_factory=list)
    # Configuration families that do not fit the first-wave normalized model.
    # Each item keeps its original PAN-OS entry XML and destination path so a
    # full configuration import never silently discards supported PAN-OS data.
    extras: dict[str, list[dict]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict) -> "MigrationModel":
        return cls(
            vendor=value["vendor"], source_name=value["source_name"],
            addresses=[Address(**item) for item in value.get("addresses", [])],
            address_groups=[AddressGroup(**item) for item in value.get("address_groups", [])],
            services=[Service(**item) for item in value.get("services", [])],
            service_groups=[ServiceGroup(**item) for item in value.get("service_groups", [])],
            security_rules=[Policy(**item) for item in value.get("security_rules", [])],
            nat_rules=[Policy(**item) for item in value.get("nat_rules", [])],
            interfaces=list(value.get("interfaces", [])), zones=list(value.get("zones", [])),
            extras={str(key): list(items) for key, items in value.get("extras", {}).items()},
            warnings=list(value.get("warnings", [])), unsupported=list(value.get("unsupported", [])),
        )

    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def counts(self) -> dict[str, int]:
        counts = {
            "addresses": len(self.addresses), "address_groups": len(self.address_groups),
            "services": len(self.services), "service_groups": len(self.service_groups),
            "security_rules": len(self.security_rules), "nat_rules": len(self.nat_rules),
            "interfaces": len(self.interfaces), "zones": len(self.zones),
            "warnings": len(self.warnings), "unsupported": len(self.unsupported),
        }
        counts.update({key: len(items) for key, items in self.extras.items()})
        return counts


MIGRATION_KIND_LABELS = {
    "addresses": "Addresses", "address_groups": "Address Groups",
    "services": "Services", "service_groups": "Service Groups",
    "applications": "Applications", "application_groups": "Application Groups",
    "application_filters": "Application Filters", "tags": "Tags",
    "regions": "Regions", "schedules": "Schedules",
    "external_dynamic_lists": "External Dynamic Lists",
    "custom_url_categories": "Custom URL Categories",
    "security_profiles": "Security Profiles",
    "security_profile_groups": "Security Profile Groups",
    "log_forwarding_profiles": "Log Forwarding",
    "authentication_enforcement": "Authentication Enforcement",
    "security_rules": "Security policies", "nat_rules": "NAT policies",
    "qos_rules": "QoS policies", "pbf_rules": "Policy Based Forwarding",
    "decryption_rules": "Decryption policies",
    "application_override_rules": "Application Override",
    "authentication_rules": "Authentication policies",
    "dos_rules": "DoS policies", "tunnel_inspection_rules": "Tunnel Inspection",
    "interfaces": "Interfaces", "zones": "Zones", "vlans": "VLANs",
    "virtual_routers": "Virtual Routers", "logical_routers": "Logical Routers",
    "virtual_wires": "Virtual Wires", "ipsec_tunnels": "IPsec Tunnels",
    "ike_gateways": "IKE Gateways", "network_profiles": "Network Profiles",
    "globalprotect_portals": "GlobalProtect Portals",
    "globalprotect_gateways": "GlobalProtect Gateways",
    "device_configuration": "Device configuration",
}

MIGRATION_MAPPING_ACTIONS = {"map", "create", "ignore", "review"}
MIGRATION_TOPOLOGY_KINDS = {"interfaces", "zones", "vlans", "virtual_routers", "logical_routers"}
MIGRATION_FILTER_FIELDS = {"kind", "name", "value", "source_ref", "references", "disabled"}
MIGRATION_FILTER_OPERATORS = {"contains", "equals", "starts_with", "ends_with", "regex", "not_contains"}


PANOS_EXTRA_PATHS = {
    "applications": ("./application/entry", "application"),
    "application_groups": ("./application-group/entry", "application-group"),
    "application_filters": ("./application-filter/entry", "application-filter"),
    "tags": ("./tag/entry", "tag"), "regions": ("./region/entry", "region"),
    "schedules": ("./schedule/entry", "schedule"),
    "external_dynamic_lists": ("./external-list/entry", "external-list"),
    "custom_url_categories": ("./profiles/custom-url-category/entry", "profiles/custom-url-category"),
    "security_profile_groups": ("./profile-group/entry", "profile-group"),
    "log_forwarding_profiles": ("./log-settings/entry", "log-settings"),
    "authentication_enforcement": ("./authentication-enforcement/entry", "authentication-enforcement"),
}

PANOS_SECURITY_PROFILE_TYPES = (
    "virus", "spyware", "vulnerability", "url-filtering", "file-blocking",
    "wildfire-analysis", "data-objects", "dos-protection", "decryption",
)

PANOS_POLICY_PATHS = {
    "qos_rules": "qos", "pbf_rules": "pbf", "decryption_rules": "decryption",
    "application_override_rules": "application-override",
    "authentication_rules": "authentication", "dos_rules": "dos",
    "tunnel_inspection_rules": "tunnel-inspect",
}

# Intentionally outside migration parity. SD-WAN policies are Panorama-specific
# and are left in the target/base configuration instead of being transferred
# from a migration source.
PANOS_EXCLUDED_POLICY_PATHS = {"sdwan": "SD-WAN"}


class BaseParser:
    vendor = "generic"
    label = "Generic"
    extensions = (".conf", ".txt", ".cfg")

    def parse(self, text: str, source_name: str) -> MigrationModel:
        raise NotImplementedError

    @staticmethod
    def lines(text: str):
        for number, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if line and not line.startswith(("#", "!")):
                yield number, line


class CiscoAsaParser(BaseParser):
    vendor = "cisco-asa"
    label = "Cisco ASA"

    def parse(self, text: str, source_name: str) -> MigrationModel:
        model = MigrationModel(self.vendor, source_name)
        current_group = None
        for number, line in self.lines(text):
            tokens = line.split()
            if tokens[:2] == ["object", "network"] and len(tokens) >= 3:
                current_group = ("object", clean_name(tokens[2])); continue
            if tokens[:2] == ["object-group", "network"] and len(tokens) >= 3:
                current_group = ("group", clean_name(tokens[2])); model.address_groups.append(AddressGroup(current_group[1], source_ref=f"line {number}")); continue
            if tokens[:2] == ["object-group", "service"] and len(tokens) >= 3:
                current_group = ("service-group", clean_name(tokens[2])); model.service_groups.append(ServiceGroup(current_group[1], source_ref=f"line {number}")); continue
            if current_group and current_group[0] == "object" and tokens[0] in {"host", "subnet", "range", "fqdn"}:
                kind = "fqdn" if tokens[0] == "fqdn" else "ip_range" if tokens[0] == "range" else "ip_netmask"
                value = tokens[-1] if tokens[0] in {"host", "fqdn"} else f"{tokens[1]}-{tokens[2]}" if tokens[0] == "range" else cidr(tokens[1], tokens[2])
                model.addresses.append(Address(current_group[1], value, kind, source_ref=f"line {number}")); current_group = None; continue
            if current_group and current_group[0] == "group" and tokens[0] == "network-object":
                group = model.address_groups[-1]
                if tokens[1:2] == ["object"]: group.members.append(clean_name(tokens[2]))
                elif tokens[1:2] == ["host"]:
                    name = clean_name(f"host-{tokens[2]}"); model.addresses.append(Address(name, cidr(tokens[2] + "/32"), source_ref=f"line {number}")); group.members.append(name)
                elif len(tokens) >= 3:
                    name = clean_name(f"net-{tokens[1]}-{tokens[2]}"); model.addresses.append(Address(name, cidr(tokens[1], tokens[2]), source_ref=f"line {number}")); group.members.append(name)
                continue
            if current_group and current_group[0] == "service-group" and tokens[0] in {"service-object", "port-object"}:
                proto = tokens[1] if tokens[0] == "service-object" and len(tokens) > 1 else "tcp"
                port = tokens[-1]
                name = clean_name(f"{proto}-{port}"); model.services.append(Service(name, proto, port, source_ref=f"line {number}")); model.service_groups[-1].members.append(name); continue
            if tokens[0] == "access-list" and "extended" in tokens:
                try:
                    idx = tokens.index("extended"); action = "allow" if tokens[idx + 1] == "permit" else "deny"; proto = tokens[idx + 2]
                    src, pos = self._asa_endpoint(tokens, idx + 3); dst, pos = self._asa_endpoint(tokens, pos)
                    service = ["application-default"]
                    if pos < len(tokens) and tokens[pos] in {"eq", "range"}:
                        port = tokens[pos + 1] if tokens[pos] == "eq" else f"{tokens[pos+1]}-{tokens[pos+2]}"
                        svc = clean_name(f"{proto}-{port}"); model.services.append(Service(svc, proto if proto in {"tcp", "udp"} else "tcp", port, source_ref=f"line {number}")); service = [svc]
                    name = clean_name(f"{tokens[1]}-{number}")
                    model.security_rules.append(Policy(name, source=src, destination=dst, service=service, action=action, description=f"Imported ASA ACL {tokens[1]}", source_ref=f"line {number}", original={"line": line}))
                except (ValueError, IndexError) as exc: model.warnings.append(f"Line {number}: ACL niet volledig vertaald ({exc})")
            elif tokens[0] in {"interface", "nameif"}:
                model.interfaces.append({"source_ref": f"line {number}", "command": line})
            elif tokens[0] in {"nat", "global", "static"}:
                model.unsupported.append(f"Line {number}: legacy NAT vereist review: {line[:180]}")
        return deduplicate(model)

    @staticmethod
    def _asa_endpoint(tokens, pos):
        if tokens[pos] in {"any", "any4", "any6"}: return ["any"], pos + 1
        if tokens[pos] == "object": return [clean_name(tokens[pos + 1])], pos + 2
        if tokens[pos] == "object-group": return [clean_name(tokens[pos + 1])], pos + 2
        if tokens[pos] == "host": return [tokens[pos + 1]], pos + 2
        if pos + 1 < len(tokens) and re.match(r"^\d+\.\d+", tokens[pos]): return [cidr(tokens[pos], tokens[pos + 1])], pos + 2
        return [clean_name(tokens[pos])], pos + 1


class CiscoIosParser(CiscoAsaParser):
    vendor = "cisco-ios"
    label = "Cisco IOS / ACL"

    def parse(self, text: str, source_name: str) -> MigrationModel:
        model = MigrationModel(self.vendor, source_name)
        acl = "ACL"
        for number, line in self.lines(text):
            tokens = line.split()
            if tokens[:3] == ["ip", "access-list", "extended"]:
                acl = clean_name("-".join(tokens[3:])); continue
            if tokens[0] in {"permit", "deny"}:
                tokens = ["access-list", acl, "extended", *tokens]
            if tokens[0] == "access-list" and "extended" in tokens:
                fragment = CiscoAsaParser.parse(self, " ".join(tokens), source_name)
                for rule in fragment.security_rules:
                    rule.name = clean_name(f"{acl}-{number}"); rule.source_ref = f"line {number}"
                model.security_rules.extend(fragment.security_rules); model.services.extend(fragment.services); model.warnings.extend(fragment.warnings)
            elif tokens[:2] == ["object-group", "network"] or tokens[:2] == ["object-group", "service"]:
                model.warnings.append(f"Line {number}: IOS object-group wordt herkend maar vereist blokcontext: {line[:160]}")
            elif tokens[0] == "interface": model.interfaces.append({"name": clean_name(tokens[1]), "source_ref": f"line {number}"})
        return deduplicate(model)


class FortinetParser(BaseParser):
    vendor = "fortinet"
    label = "Fortinet FortiGate"

    # These sections can contain multiline encrypted certificates, private
    # keys and SSH keys.  They are deliberately treated as opaque input: a
    # migration must never try to parse, copy or decrypt them.  The target
    # administrator has to provision fresh key material after migration.
    OPAQUE_CRYPTO_SECTIONS = {
        "vpn certificate ca",
        "vpn certificate remote",
        "vpn certificate local",
        "firewall ssh local-key",
        "firewall ssh local-ca",
    }

    def parse(self, text: str, source_name: str) -> MigrationModel:
        model = MigrationModel(self.vendor, source_name); section = ""; current = None; values = {}
        skipped_crypto_entries: set[tuple[str, str]] = set()
        def flush():
            nonlocal current, values
            if current is None: return
            ref = values.get("_ref", "")
            if section.endswith("firewall address"):
                value = values.get("subnet", values.get("fqdn", values.get("start-ip", "")))
                kind = "fqdn" if "fqdn" in values else "ip_range" if "end-ip" in values else "ip_netmask"
                if "subnet" in values:
                    parts = values["subnet"].split(); value = cidr(parts[0], parts[1]) if len(parts)>1 else parts[0]
                elif "end-ip" in values: value = f"{value}-{values['end-ip']}"
                model.addresses.append(Address(clean_name(current), value, kind, values.get("comment", ""), source_ref=ref))
            elif section.endswith("firewall addrgrp"):
                model.address_groups.append(AddressGroup(clean_name(current), split_forti(values.get("member", "")), values.get("comment", ""), source_ref=ref))
            elif section.endswith("firewall service custom"):
                proto, ports = ("tcp", values.get("tcp-portrange", "")) if values.get("tcp-portrange") else ("udp", values.get("udp-portrange", ""))
                model.services.append(Service(clean_name(current), proto, ports or "1-65535", description=values.get("comment", ""), source_ref=ref))
            elif section.endswith("firewall service group"):
                model.service_groups.append(ServiceGroup(clean_name(current), split_forti(values.get("member", "")), source_ref=ref))
            elif section.endswith("firewall policy"):
                rule = Policy(clean_name(values.get("name", f"policy-{current}")), from_zones=split_forti(values.get("srcintf", "any")), to_zones=split_forti(values.get("dstintf", "any")), source=split_forti(values.get("srcaddr", "all"), any_alias="all"), destination=split_forti(values.get("dstaddr", "all"), any_alias="all"), service=split_forti(values.get("service", "ALL"), any_alias="ALL"), action="allow" if values.get("action", "accept") == "accept" else "deny", disabled=values.get("status", "enable") != "enable", description=values.get("comments", ""), source_ref=ref, original=dict(values))
                if values.get("nat") == "enable":
                    destination_interface = rule.to_zones[0] if rule.to_zones else ""
                    model.nat_rules.append(Policy(clean_name(f"NAT-{rule.name}"), policy_type="nat", from_zones=rule.from_zones, to_zones=rule.to_zones, source=rule.source, destination=rule.destination, service=rule.service, disabled=rule.disabled, source_translation={"dynamic_ip_and_port": {"interface_address": {"interface": destination_interface}}}, description=f"Source NAT for {rule.name}", source_ref=ref, original=dict(values)))
                model.security_rules.append(rule)
            elif section.endswith("firewall vip"):
                external = clean_name(f"{current}-external"); mapped = clean_name(f"{current}-mapped")
                external_value = split_forti(values.get("extip", "")); mapped_value = split_forti(values.get("mappedip", ""))
                if external_value != ["any"] and mapped_value != ["any"]:
                    model.addresses.extend([Address(external, cidr(external_value[0] + ("/32" if "/" not in external_value[0] else "")), source_ref=ref), Address(mapped, cidr(mapped_value[0] + ("/32" if "/" not in mapped_value[0] else "")), source_ref=ref)])
                    translation = {"translated_address": mapped}
                    if values.get("mappedport"): translation["translated_port"] = values["mappedport"]
                    model.nat_rules.append(Policy(clean_name(f"NAT-{current}"), policy_type="nat", from_zones=split_forti(values.get("extintf", "any"), any_alias="any"), destination=[external], service=["any"], destination_translation=translation, description=f"Imported Fortinet VIP {current}", source_ref=ref, original=dict(values)))
                else:
                    model.unsupported.append(f"{ref}: VIP {current} mist extip/mappedip en vereist review")
            current = None; values = {}
        for number, line in self.lines(text):
            if line.startswith("config "): flush(); section = line[7:].strip(); continue
            if line == "end": flush(); section = ""; continue
            if line.startswith("edit "):
                flush(); current = unquote(line[5:]); values = {"_ref": f"line {number}"}
                if section in self.OPAQUE_CRYPTO_SECTIONS:
                    skipped_crypto_entries.add((section, str(current)))
                continue
            if line == "next": flush(); continue
            if current is not None and line.startswith("set "):
                if section in self.OPAQUE_CRYPTO_SECTIONS:
                    continue
                try:
                    parts = shlex.split(line)
                except ValueError:
                    # Do not abort an otherwise usable import because an
                    # unknown vendor field contains multiline quoting.  The
                    # field name is safe to report; its value is never kept.
                    field_name = line[4:].split(None, 1)[0] if line[4:].strip() else "onbekend"
                    model.warnings.append(
                        f"Fortinet veld {field_name} in {section or 'onbekende sectie'} overgeslagen wegens ongeldige of multiline quoting"
                    )
                    continue
                if len(parts) >= 2:
                    values[parts[1]] = " ".join(parts[2:]) if len(parts)>2 else ""
        flush()
        if skipped_crypto_entries:
            model.warnings.append(
                "Fortinet cryptomateriaal overgeslagen: "
                f"{len(skipped_crypto_entries)} certificaat/private-key/SSH-key object(en) moeten opnieuw op het target worden ingegeven"
            )
        return deduplicate(model)


class JuniperSrxParser(BaseParser):
    vendor = "juniper-srx"
    label = "Juniper SRX"

    def parse(self, text: str, source_name: str) -> MigrationModel:
        model = MigrationModel(self.vendor, source_name); policies = {}
        for number, line in self.lines(text):
            try: tokens = shlex.split(line)
            except ValueError: model.warnings.append(f"Line {number}: ongeldige quoting"); continue
            if tokens[:3] == ["set", "security", "address-book"] and "address" in tokens:
                idx=tokens.index("address"); name=clean_name(tokens[idx+1]); value=tokens[idx+2]
                if value == "range-address" and len(tokens)>idx+4: value=f"{tokens[idx+3]}-{tokens[idx+4]}"
                model.addresses.append(Address(name,value,"ip_range" if "-" in value else "ip_netmask",source_ref=f"line {number}")); continue
            if tokens[:3] == ["set", "security", "policies"] and "policy" in tokens:
                f=tokens[tokens.index("from-zone")+1]; t=tokens[tokens.index("to-zone")+1]; pidx=tokens.index("policy"); name=clean_name(tokens[pidx+1]); rule=policies.setdefault((f,t,name),Policy(name,from_zones=[f],to_zones=[t],source_ref=f"line {number}"))
                if "source-address" in tokens: rule.source=unique([*([] if rule.source==["any"] else rule.source),tokens[tokens.index("source-address")+1]])
                if "destination-address" in tokens: rule.destination=unique([*([] if rule.destination==["any"] else rule.destination),tokens[tokens.index("destination-address")+1]])
                if "application" in tokens: rule.service=unique([*([] if rule.service==["application-default"] else rule.service),clean_name(tokens[tokens.index("application")+1])])
                if "then" in tokens: rule.action="allow" if tokens[tokens.index("then")+1] in {"permit","accept"} else "deny"
            elif tokens[:4] == ["set","security","nat","source"] or tokens[:4] == ["set","security","nat","destination"]:
                model.unsupported.append(f"Line {number}: SRX NAT vereist review: {line[:180]}")
            elif tokens[:2] == ["set","interfaces"] and len(tokens)>2: model.interfaces.append({"name":clean_name(tokens[2]),"source_ref":f"line {number}","command":line})
        model.security_rules=list(policies.values()); return deduplicate(model)


class CheckPointParser(BaseParser):
    vendor = "checkpoint"
    label = "Check Point"
    extensions = (".json", ".xml", ".txt", ".tar")
    UNSUPPORTED_ACTION_TAG = "OCD-Review-Unsupported-Action"
    UNSUPPORTED_ACTION_TAG_COMMENT = "Automatisch gemarkeerd: Check Point-actie vereist handmatige PAN-OS-mapping."
    # Mappings verified against the PAN-OS 12.1 predefined application catalog.
    # Keep this deliberately small: an uncertain mapping must remain a review
    # item instead of silently broadening a Check Point rule.
    PANOS_APPLICATION_ALIASES = {
        "deliveryoptimazation": "ms-update-optimization-p2p",
        "dhcp-reply": "dhcp",
        "dhcp-request": "dhcp",
        "dropbox": "dropbox-base",
        "dropbox-web": "dropbox-base",
        "dropbox-web-download": "dropbox-downloading",
        "dropbox-web-upload": "dropbox-uploading",
        "echo-request": "ping",
        "filestack": "filestack-base",
        "gmail": "gmail-base",
        "hangouts-audio-video": "google-hangouts-audio-video",
        "icmp-proto": "icmp",
        "icmp-protocol": "icmp",
        "itunes": "itunes-base",
        "lastpass": "lastpass",
        "microsoft-remote-desktop-connection": "ms-rdp",
        "netflix": "netflix-base",
        "netflix-streaming": "netflix-streaming",
        "openvpn": "open-vpn",
        "psiphon": "psiphon",
        "rpc-over-http": "rpc-over-http",
        "sharepoint-online-upload": "sharepoint-online-uploading",
        "sharepoint-wiki": "sharepoint-wiki",
        "skype": "skype",
        "ssh": "ssh",
        "spotify": "spotify",
        "symantec-update": "symantec-av-update",
        "teamviewer": "teamviewer-base",
        "thunder-vpn": "thunder-vpn",
        "traceroute": "traceroute",
        "vrrp": "vrrp",
        "whatsapp-messenger": "whatsapp-base",
        "whatsapp-messenger-file-transfer": "whatsapp-file-transfer",
        "whatsapp-messenger-voice-call": "whatsapp-voice",
        "whatsapp-messenger-web-pc": "whatsapp-web",
        "windows-update": "ms-update",
        "zabbix": "zabbix",
    }

    @classmethod
    def _ensure_unsupported_action_tag(cls, model: MigrationModel) -> None:
        tags = model.extras.setdefault("tags", [])
        if any(str(item.get("name", "")) == cls.UNSUPPORTED_ACTION_TAG for item in tags):
            return
        entry = ET.Element("entry", {"name": cls.UNSUPPORTED_ACTION_TAG})
        ET.SubElement(entry, "comments").text = cls.UNSUPPORTED_ACTION_TAG_COMMENT
        tags.append({
            "name": cls.UNSUPPORTED_ACTION_TAG,
            "target_path": "tag",
            "xml": ET.tostring(entry, encoding="unicode"),
            "payload": {"comments": cls.UNSUPPORTED_ACTION_TAG_COMMENT},
            "source_ref": "generated:checkpoint-unsupported-action",
        })

    def parse_bytes(self, content: bytes, source_name: str) -> MigrationModel:
        """Parse a Check Point show-package, including a safely nested project archive."""
        documents: list[tuple[str, object]] = []
        total_size = 0
        member_count = 0

        def read_archive(payload: bytes, archive_name: str, depth: int = 0) -> None:
            nonlocal total_size, member_count
            if depth > 3:
                raise MigrationError("Check Point archief is te diep genest")
            try:
                archive = tarfile.open(fileobj=io.BytesIO(payload), mode="r:*")
            except tarfile.TarError as exc:
                raise MigrationError(f"Ongeldig Check Point archief {archive_name}: {exc}") from exc
            with archive:
                # Do not materialize/decompress the entire archive before
                # enforcing the limits. Count skipped payloads too: an ignored
                # file must not bypass the decompressed-byte budget.
                for member in archive:
                    member_count += 1
                    if member_count > 1000:
                        raise MigrationError("Check Point archief bevat te veel bestanden")
                    path = PurePosixPath(member.name)
                    qualified_name = f"{archive_name}!/{member.name}"
                    if path.is_absolute() or ".." in path.parts:
                        raise MigrationError(f"Onveilig pad in Check Point archief: {qualified_name}")
                    if member.issym() or member.islnk() or member.isdev():
                        raise MigrationError(f"Onveilig bestandstype in Check Point archief: {qualified_name}")
                    if member.size < 0:
                        raise MigrationError(f"Ongeldige bestandsgrootte in Check Point archief: {qualified_name}")
                    total_size += member.size
                    if total_size > 100 * 1024 * 1024:
                        raise MigrationError("Uitgepakte Check Point data is groter dan 100 MiB")
                    if not member.isfile():
                        continue
                    suffix = path.suffix.casefold()
                    if suffix not in {".json", ".tar"}:
                        continue
                    per_file_limit = 25 * 1024 * 1024 if suffix == ".json" else 100 * 1024 * 1024
                    if member.size > per_file_limit:
                        label = "JSON" if suffix == ".json" else "genest archief"
                        raise MigrationError(f"Check Point {label} is te groot: {qualified_name}")
                    stream = archive.extractfile(member)
                    if stream is None:
                        continue
                    raw = stream.read(per_file_limit + 1)
                    if len(raw) > per_file_limit:
                        raise MigrationError(f"Check Point bestand is te groot: {qualified_name}")
                    if suffix == ".tar":
                        read_archive(raw, qualified_name, depth + 1)
                        continue
                    try:
                        document = json.loads(raw.decode("utf-8-sig"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise MigrationError(f"Ongeldige JSON in {qualified_name}: {exc}") from exc
                    documents.append((qualified_name, document))

        read_archive(content, source_name)
        if not documents:
            raise MigrationError("Check Point archief bevat geen JSON-export")

        objects: list[dict] = []
        access_layers: list[object] = []
        nat_layers: list[object] = []

        def types_in(value) -> set[str]:
            found: set[str] = set()
            if isinstance(value, dict):
                if value.get("type"):
                    found.add(str(value["type"]).casefold())
                for child in value.values():
                    found.update(types_in(child))
            elif isinstance(value, list):
                for child in value:
                    found.update(types_in(child))
            return found

        def annotate(value, source_file: str):
            if isinstance(value, dict):
                result = {key: annotate(child, source_file) for key, child in value.items()}
                result["_source_file"] = source_file
                return result
            if isinstance(value, list):
                return [annotate(child, source_file) for child in value]
            return value

        for member_name, document in documents:
            document_types = types_in(document)
            annotated = annotate(document, member_name)
            if isinstance(annotated, dict):
                objects.extend(self._object_items(annotated))
            elif "access-rule" not in document_types and "nat-rule" not in document_types:
                objects.extend(item for item in annotated if isinstance(item, dict))
            if "nat-rule" in document_types:
                nat_layers.append(annotated)
            elif "access-rule" in document_types:
                access_layers.append(annotated)
        model = self._json({"objects": objects, "rulebase": access_layers, "nat-rulebase": nat_layers}, source_name)
        model.warnings.append(
            f"Check Point show-package: {len(documents)} JSON-bestanden gecombineerd met één globale UID-dictionary"
        )
        return model

    def parse(self, text: str, source_name: str) -> MigrationModel:
        stripped=text.lstrip()
        if stripped.startswith(("{","[")): return self._json(json.loads(text),source_name)
        if stripped.startswith("<"): return self._xml(text,source_name)
        model=MigrationModel(self.vendor,source_name); model.unsupported.append("Check Point text/dbedit-formaat vereist JSON/XML export voor betrouwbare mapping"); return model

    @staticmethod
    def _description(item: dict) -> str:
        return str(item.get("comments") or item.get("comment") or item.get("description") or "").strip()

    @staticmethod
    def _normalise_port(value) -> str:
        port = str(value or "1-65535").strip().replace(" ", "")
        match = re.fullmatch(r">(\d+)", port)
        if match:
            return f"{min(int(match.group(1)) + 1, 65535)}-65535"
        match = re.fullmatch(r"<(\d+)", port)
        if match:
            return f"1-{max(int(match.group(1)) - 1, 1)}"
        return port or "1-65535"

    @staticmethod
    def _object_items(data) -> list[dict]:
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if not isinstance(data, dict):
            return []
        result = []
        for key in ("objects", "items", "objects-dictionary"):
            value = data.get(key, [])
            if isinstance(value, dict):
                value = list(value.values())
            if isinstance(value, list):
                result.extend(item for item in value if isinstance(item, dict))
        return result

    @staticmethod
    def _name(value, lookup: dict[str, str]) -> str:
        if isinstance(value, dict):
            raw = value.get("name") or lookup.get(str(value.get("uid", ""))) or value.get("uid") or "any"
        else:
            raw = lookup.get(str(value), value)
        text = str(raw or "any").strip()
        if text.casefold() in {"any", "all"}:
            return "any"
        if text.casefold() in {"original", "= original"}:
            return "original"
        return clean_name(text)

    @classmethod
    def _names(cls, value, lookup: dict[str, str], default: list[str] | None = None) -> list[str]:
        if value is None:
            return list(default or ["any"])
        values = value if isinstance(value, list) else [value]
        return unique(cls._name(item, lookup) for item in values) or list(default or ["any"])

    @classmethod
    def _split_rule_services(
        cls,
        value,
        lookup: dict[str, str],
        type_lookup: dict[str, str],
    ) -> tuple[list[str], list[str]]:
        application_reference_types = {
            "application-site", "application-site-category", "application-site-group",
            "service-icmp", "service-icmp6", "service-other",
        }
        raw_values = value if isinstance(value, list) else [value]
        applications: list[str] = []
        services: list[str] = []
        for raw in raw_values:
            object_type = (
                str(raw.get("type", "")).lower()
                if isinstance(raw, dict)
                else type_lookup.get(str(raw), "")
            )
            name = cls._name(raw, lookup)
            if object_type in application_reference_types:
                applications.append(name)
            else:
                services.append(name)
        applications = unique(applications)
        services = unique(services)
        if applications and not services:
            services = ["application-default"]
        return applications or ["any"], services or ["application-default"]

    @staticmethod
    def _append_address_variants(model: MigrationModel, name: str, variants: list[tuple[str, str, str]], description: str, ref: str) -> None:
        variants = [(suffix, value, value_type) for suffix, value, value_type in variants if value]
        if len(variants) == 1:
            _, value, value_type = variants[0]
            model.addresses.append(Address(name, value, value_type, description, source_ref=ref))
            return
        if len(variants) > 1:
            members = []
            for suffix, value, value_type in variants:
                member = clean_name(f"{name}-{suffix}")
                members.append(member)
                model.addresses.append(Address(member, value, value_type, description, source_ref=ref))
            model.address_groups.append(AddressGroup(name, members, description, source_ref=ref))

    @staticmethod
    def _review_description(description: str, notes: list[str]) -> str:
        notes = unique(notes)
        if not notes:
            return description
        review = "MIGRATION-REVIEW: " + "; ".join(notes)
        return "; ".join(filter(None, [description, review]))[:1023]

    @classmethod
    def _collect_gateway_interfaces(cls, model: MigrationModel, items: list[dict]) -> None:
        """Retain Check Point interface topology without inventing PAN-OS zones.

        Check Point gateway exports describe interfaces, connected networks and
        whether an interface leads to the Internet.  They do not provide the
        PAN-OS zone design.  Store the source interfaces as review-only topology
        records; the migration project can map each one to a target interface
        and assign a PAN-OS zone.  Policy zones are inferred only after those
        assignments exist.
        """
        gateways = [
            item for item in items
            if isinstance(item, dict) and isinstance(item.get("interfaces"), list)
        ]
        if not gateways:
            return
        clusters = [
            item for item in gateways
            if "gatewaycluster" in str(item.get("type", "")).casefold()
        ]
        gateway = max(clusters or gateways, key=lambda item: len(item.get("interfaces", [])))
        collected = 0
        gateway_name = str(gateway.get("name") or gateway.get("uid") or "Check Point gateway")
        for interface in gateway.get("interfaces", []):
            if not isinstance(interface, dict):
                continue
            address = str(interface.get("ipv4-address") or "").strip()
            prefix = interface.get("ipv4-mask-length")
            interface_name = str(interface.get("interface-name") or "").strip()
            if not address or prefix is None or not interface_name:
                continue
            try:
                network = ipaddress.ip_interface(f"{address}/{prefix}").network
            except ValueError:
                continue
            if network.is_link_local:
                continue
            metadata = (
                interface.get("topology")
                if isinstance(interface.get("topology"), dict)
                else {}
            )
            entry = ET.Element("entry", {"name": interface_name})
            layer3 = ET.SubElement(entry, "layer3")
            addresses = ET.SubElement(layer3, "ip")
            ET.SubElement(addresses, "entry", {"name": f"{address}/{prefix}"})
            model.interfaces.append({
                "name": interface_name,
                "interface_type": "ethernet",
                "xml": ET.tostring(entry, encoding="unicode"),
                "source_ref": gateway_name,
                "source_vendor": "checkpoint",
                "source_networks": [str(network)],
                "source_addresses": [f"{address}/{prefix}"],
                "topology_role": "internet" if metadata.get("leads-to-internet") else "internal",
                "suggested_zone": "Untrust" if metadata.get("leads-to-internet") else "",
                "mapping_action": "review",
            })
            collected += 1
        if collected:
            model.warnings.append(
                f"Check Point gatewaytopologie: {collected} interfaces gevonden; "
                "wijs eerst PAN-OS zones toe om policyzones automatisch te berekenen"
            )

    @staticmethod
    def _is_address_reference(value: str, known: set[str]) -> bool:
        if value in {"any", "original"} or value in known:
            return True
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False

    def _conservative_panos_staging(self, model: MigrationModel) -> MigrationModel:
        """Remove invalid PAN-OS references and make Check Point output safe to stage.

        Check Point exports do not contain PAN-OS zones, interface placement,
        user-ID mappings or equivalent VPN semantics. The generated candidate
        retains representable data, records dropped semantics for review, and
        preserves the source enabled/disabled state. Rules with an unsupported
        action remain disabled independently of the import override.
        """
        mapped_names: dict[str, str] = {}
        remaining_unsupported: list[str] = []
        mapping_pattern = re.compile(
            r"Check Point (?:application-site(?:-category|-group)?|service-(?:icmp6?|other)) (.+?) vereist application/user mapping$"
        )
        for message in model.unsupported:
            match = mapping_pattern.search(message)
            source_name = match.group(1) if match else ""
            target_name = self.PANOS_APPLICATION_ALIASES.get(source_name.casefold())
            if target_name:
                mapped_names[source_name.casefold()] = target_name
                model.warnings.append(
                    f"Check Point application/service {source_name} gemapt naar PAN-OS App-ID {target_name}"
                )
            else:
                remaining_unsupported.append(message)
        model.unsupported = remaining_unsupported

        valid_addresses: list[Address] = []
        invalid_fqdns: list[dict] = []
        for item in model.addresses:
            if item.value_type == "fqdn" and not valid_panos_fqdn(item.value):
                invalid_fqdns.append({
                    "name": item.name,
                    "value": item.value,
                    "source_ref": item.source_ref,
                    "reason": "URL of ongeldige hostnaam kan niet als PAN-OS FQDN worden aangemaakt",
                    "mapping_action": "review",
                })
                model.warnings.append(
                    f"{item.source_ref}: FQDN {item.name} bevat geen geldige exacte hostnaam en is voor review uitgesloten"
                )
                continue
            valid_addresses.append(item)
        if invalid_fqdns:
            model.extras.setdefault("migration_review_items", []).extend(invalid_fqdns)
        model.addresses = valid_addresses

        address_names = {item.name for item in model.addresses}
        protocol_signature_apps = {
            "remote_desktop_protocol_udp-protocol-signature": "ms-rdp",
            "remote_desktop_protocol-protocol-signature": "ms-rdp",
            "ssh_version_2-protocol-signature": "ssh",
        }
        signature_service_names = {
            item.name: protocol_signature_apps[item.name.casefold()]
            for item in model.services if item.name.casefold() in protocol_signature_apps
        }
        if signature_service_names:
            model.services = [item for item in model.services if item.name not in signature_service_names]
            for source_name, app_id in signature_service_names.items():
                model.warnings.append(
                    f"Check Point protocol-signature {source_name} gemapt naar PAN-OS App-ID {app_id}"
                )
        service_names = {item.name for item in model.services}

        # Repeat because pruning an empty child group can invalidate a parent.
        while True:
            group_names = {item.name for item in model.address_groups}
            known = address_names | group_names
            changed = False
            kept_groups = []
            for group in model.address_groups:
                removed = [
                    value for value in group.members
                    if value == "any" or not self._is_address_reference(value, known)
                ]
                members = [
                    value for value in group.members
                    if value != "any" and self._is_address_reference(value, known)
                ]
                if removed:
                    changed = True
                    model.warnings.append(
                        f"{group.source_ref}: address-group {group.name} mist members: {', '.join(removed)}"
                    )
                    group.description = self._review_description(
                        group.description, ["ontbrekende members verwijderd: " + ", ".join(removed)]
                    )
                group.members = unique(members)
                if group.members:
                    kept_groups.append(group)
                else:
                    changed = True
                    model.unsupported.append(
                        f"{group.source_ref}: Check Point address-group {group.name} heeft geen geldige PAN-OS members"
                    )
            model.address_groups = kept_groups
            if not changed:
                break

        while True:
            service_group_names = {item.name for item in model.service_groups}
            known = service_names | service_group_names
            changed = False
            kept_groups = []
            for group in model.service_groups:
                removed = [value for value in group.members if value not in known]
                members = [value for value in group.members if value in known]
                if removed:
                    changed = True
                    model.warnings.append(
                        f"{group.source_ref}: service-group {group.name} mist members: {', '.join(removed)}"
                    )
                    group.description = self._review_description(
                        group.description, ["ontbrekende members verwijderd: " + ", ".join(removed)]
                    )
                group.members = unique(members)
                if group.members:
                    kept_groups.append(group)
                else:
                    changed = True
                    model.unsupported.append(
                        f"{group.source_ref}: Check Point service-group {group.name} heeft geen geldige PAN-OS members"
                    )
            model.service_groups = kept_groups
            if not changed:
                break

        known_addresses = address_names | {item.name for item in model.address_groups}
        known_services = service_names | {item.name for item in model.service_groups}

        def address_values(values: list[str]) -> tuple[list[str], list[str]]:
            kept = [value for value in values if self._is_address_reference(value, known_addresses)]
            removed = [value for value in values if not self._is_address_reference(value, known_addresses)]
            return unique(kept) or ["any"], unique(removed)

        def service_values(values: list[str], fallback: str) -> tuple[list[str], list[str]]:
            valid = {
                value for value in values
                if value in {"any", "application-default"}
                or value in known_services
                or re.match(r"^(?:tcp|udp)-\d+(?:-\d+)?$", value, re.I)
            }
            kept = [value for value in values if value in valid]
            removed = [value for value in values if value not in valid]
            return unique(kept) or [fallback], unique(removed)

        def sanitize_translation(translation: dict) -> tuple[dict, list[str]]:
            removed: list[str] = []

            def walk(value):
                if isinstance(value, dict):
                    result = {}
                    for key, child in value.items():
                        if str(key).replace("-", "_") == "translated_address":
                            candidates = child if isinstance(child, list) else [child]
                            invalid = [
                                str(item) for item in candidates
                                if not self._is_address_reference(str(item), known_addresses)
                            ]
                            if invalid:
                                removed.extend(invalid)
                                continue
                        cleaned = walk(child)
                        if cleaned not in ({}, [], None, ""):
                            result[key] = cleaned
                    return result
                if isinstance(value, list):
                    return [item for item in (walk(child) for child in value) if item not in ({}, [], None, "")]
                return value

            return walk(translation), unique(removed)

        for rule in model.security_rules:
            notes = ["Check Point policy requires review: map zones, identity, VPN and rule order before deployment"]
            rule.source, removed = address_values(rule.source)
            if removed:
                notes.append("source references not converted: " + ", ".join(removed))
            rule.destination, removed = address_values(rule.destination)
            if removed:
                notes.append("destination references not converted: " + ", ".join(removed))

            signature_applications = unique(
                signature_service_names[value]
                for value in rule.service if value in signature_service_names
            )
            if signature_applications:
                rule.service = [value for value in rule.service if value not in signature_service_names]
            applications: list[str] = []
            removed_applications: list[str] = []
            for application in rule.application:
                if application == "any":
                    applications.append("any")
                    continue
                mapped = mapped_names.get(application.casefold()) or self.PANOS_APPLICATION_ALIASES.get(application.casefold())
                if mapped:
                    applications.append(mapped)
                else:
                    removed_applications.append(application)
            applications.extend(signature_applications)
            if signature_applications:
                applications = [value for value in applications if value != "any"]
            rule.application = unique(applications) or ["any"]
            if removed_applications:
                notes.append("applications/categories not converted: " + ", ".join(unique(removed_applications)))

            service_fallback = "application-default" if rule.application != ["any"] else "any"
            rule.service, removed = service_values(rule.service, service_fallback)
            if removed:
                notes.append("service references not converted: " + ", ".join(removed))
            rule.description = self._review_description(rule.description, notes)

        for rule in model.nat_rules:
            notes = ["Check Point NAT requires review: validate order, zones, interfaces and translations before deployment"]
            rule.source, removed = address_values(rule.source)
            if removed:
                notes.append("source references not converted: " + ", ".join(removed))
            rule.destination, removed = address_values(rule.destination)
            if removed:
                notes.append("destination references not converted: " + ", ".join(removed))
            rule.service, removed = service_values(rule.service, "any")
            if removed:
                notes.append("service references not converted: " + ", ".join(removed))
            rule.source_translation, removed = sanitize_translation(rule.source_translation)
            if removed:
                notes.append("source translation not converted: " + ", ".join(removed))
            rule.destination_translation, removed = sanitize_translation(rule.destination_translation)
            if removed:
                notes.append("destination translation not converted: " + ", ".join(removed))
            rule.description = self._review_description(rule.description, notes)

        if model.security_rules or model.nat_rules:
            model.warnings.append(
                "Check Point policies behouden hun bronstatus: PAN-OS zones, identiteit, VPN, NAT-interfaces en rule order vereisen engineer review"
            )
        return model

    def _json(self, data, source_name):
        model = MigrationModel(self.vendor, source_name)
        items = self._object_items(data)
        lookup = {
            str(item.get("uid")): str(item.get("name") or item.get("uid"))
            for item in items if item.get("uid")
        }
        type_lookup = {
            str(item.get("uid")): str(item.get("type", "")).lower()
            for item in items if item.get("uid")
        }
        services_by_name: dict[str, Service] = {}
        exact_dns_domains: list[str] = []
        ignored_types = {
            "rulebaseaction", "track", "gateway",
            "package", "access-layer", "nat-section", "access-section", "threat-layer", "cpmianyobject",
        }

        for item in items:
            typ = str(item.get("type", "")).lower()
            name = clean_name(item.get("name", item.get("uid", "item")))
            ref = str(item.get("uid", name))
            description = self._description(item)
            if typ in {"host", "checkpoint-host", "simple-gateway", "simple-cluster"} or (
                not typ and item.get("ip-address")
            ):
                ipv4 = str(item.get("ipv4-address") or item.get("ip-address") or "")
                ipv6 = str(item.get("ipv6-address", ""))
                self._append_address_variants(model, name, [
                    ("ipv4", cidr(ipv4 + ("/32" if ipv4 and "/" not in ipv4 else "")), "ip_netmask"),
                    ("ipv6", cidr(ipv6 + ("/128" if ipv6 and "/" not in ipv6 else "")), "ip_netmask"),
                ], description, ref)
                if typ == "simple-cluster":
                    for member in item.get("cluster-members", []):
                        if not isinstance(member, dict):
                            continue
                        member_name = clean_name(member.get("name") or member.get("uid") or "cluster-member")
                        member_ref = str(member.get("uid") or member_name)
                        member_ipv4 = str(member.get("ip-address") or member.get("ipv4-address") or "")
                        member_ipv6 = str(member.get("ipv6-address") or "")
                        self._append_address_variants(model, member_name, [
                            ("ipv4", cidr(member_ipv4 + ("/32" if member_ipv4 and "/" not in member_ipv4 else "")), "ip_netmask"),
                            ("ipv6", cidr(member_ipv6 + ("/128" if member_ipv6 and "/" not in member_ipv6 else "")), "ip_netmask"),
                        ], self._description(member), member_ref)
            elif typ == "network":
                variants = []
                if item.get("subnet4"):
                    mask = item.get("mask-length4")
                    variants.append(("ipv4", cidr(f"{item['subnet4']}/{mask}" if mask is not None else str(item["subnet4"])), "ip_netmask"))
                if item.get("subnet6"):
                    mask = item.get("mask-length6")
                    variants.append(("ipv6", cidr(f"{item['subnet6']}/{mask}" if mask is not None else str(item["subnet6"])), "ip_netmask"))
                self._append_address_variants(model, name, variants, description, ref)
            elif typ == "address-range":
                variants = []
                if item.get("ipv4-address-first") and item.get("ipv4-address-last"):
                    variants.append(("ipv4", f"{item['ipv4-address-first']}-{item['ipv4-address-last']}", "ip_range"))
                if item.get("ipv6-address-first") and item.get("ipv6-address-last"):
                    variants.append(("ipv6", f"{item['ipv6-address-first']}-{item['ipv6-address-last']}", "ip_range"))
                self._append_address_variants(model, name, variants, description, ref)
            elif typ == "wildcard":
                address = str(item.get("ipv4-address", "")); mask = str(item.get("ipv4-mask-wildcard", ""))
                if address and mask:
                    model.addresses.append(Address(name, f"{address}/{mask}", "ip_wildcard", description, source_ref=ref))
            elif typ == "dns-domain":
                raw_domain = item.get("domain")
                if not isinstance(raw_domain, str) or not raw_domain.strip():
                    raw_domain = item.get("name") or ""
                domain = str(raw_domain).lstrip(".")
                if domain:
                    model.addresses.append(Address(name, domain, "fqdn", description, source_ref=ref))
                    if str(raw_domain).startswith("."):
                        exact_dns_domains.append(name)
            elif typ in {"group", "network-group"}:
                model.address_groups.append(AddressGroup(name, self._names(item.get("members", []), lookup, []), description, source_ref=ref))
            elif typ in {"service-tcp", "service-udp"}:
                service = Service(name, "tcp" if typ.endswith("tcp") else "udp", self._normalise_port(item.get("port")), description=description, source_ref=ref)
                model.services.append(service); services_by_name[name] = service
            elif typ == "service-group":
                model.service_groups.append(ServiceGroup(name, self._names(item.get("members", []), lookup, []), description, source_ref=ref))
            elif typ in {"service-icmp", "service-icmp6", "service-other", "application-site", "application-site-category", "application-site-group", "access-role"}:
                model.unsupported.append(f"{ref}: Check Point {typ} {name} vereist application/user mapping")
            elif typ and typ not in ignored_types:
                model.unsupported.append(f"{ref}: Check Point objecttype {typ} {name} wordt nog niet geconverteerd")

        if exact_dns_domains:
            samples = ", ".join(exact_dns_domains[:8])
            suffix = "" if len(exact_dns_domains) <= 8 else ", ..."
            model.warnings.append(
                f"{len(exact_dns_domains)} Check Point DNS-domain objecten zijn als exacte PAN-OS FQDN geïmporteerd; "
                f"controleer subdomeinsemantiek ({samples}{suffix})"
            )

        if isinstance(data, dict):
            access = data.get("rulebase", data.get("access-layers", []))
            nat = data.get("nat-rulebase", data.get("nat-rules", []))
        else:
            access, nat = data, []
        self._walk_rules(access, model, lookup, type_lookup)
        self._walk_nat_rules(nat, model, lookup, services_by_name)
        self._collect_gateway_interfaces(model, items)
        return self._conservative_panos_staging(deduplicate(model))

    @staticmethod
    def _unique_rule_name(rules: list[Policy], value: dict, source_file: str, fallback: str) -> str:
        raw_name = str(value.get("name") or "").strip()
        uuid_name = bool(re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            raw_name,
        ))
        if not raw_name or uuid_name:
            layer = PurePosixPath(source_file).stem.replace("-Management_server", "") if source_file else "rulebase"
            layer = clean_name(layer, "rulebase")
            ordinal = value.get("rule-number") or value.get("rule_number") or len(rules) + 1
            prefix = "NAT" if fallback.startswith("nat") else "Access"
            raw_name = f"{prefix}-{layer}-{ordinal}"
        base = clean_name(raw_name or value.get("uid") or fallback)
        existing = {rule.name for rule in rules}
        if base not in existing:
            return base
        layer = PurePosixPath(source_file).stem.replace("-Management_server", "") if source_file else "layer"
        candidate = clean_name(f"{base} [{layer}]")
        if candidate not in existing:
            return candidate
        number = 2
        while True:
            suffix = f"-{number}"
            numbered = f"{candidate[:63 - len(suffix)].rstrip('-.')}{suffix}"
            if numbered not in existing:
                return numbered
            number += 1

    def _walk_rules(self, value, model, lookup, type_lookup=None, source_file=""):
        type_lookup = type_lookup or {}
        if isinstance(value,list):
            for item in value: self._walk_rules(item,model,lookup,type_lookup,source_file)
        elif isinstance(value,dict):
            typ=str(value.get("type","")).lower()
            current_source = str(value.get("_source_file") or source_file)
            if typ == "access-rule":
                action = self._name(value.get("action", "Accept"), lookup)
                action_key = action.casefold()
                supported_allow = action_key in {"accept", "allow"}
                supported_deny = action_key in {"drop", "deny", "reject"}
                unsupported_action = not (supported_allow or supported_deny)
                description = self._description(value)
                track = self._names(value.get("track"), lookup, [])
                install_on = self._names(value.get("install-on"), lookup, [])
                metadata = []
                if track and track != ["none"]: metadata.append("Track: " + ", ".join(track))
                if install_on and install_on != ["policy-targets"]: metadata.append("Install On: " + ", ".join(install_on))
                if metadata: description = "; ".join(filter(None, [description, *metadata]))
                for field in ("content", "time", "vpn"):
                    values = self._names(value.get(field), lookup, [])
                    if values and values != ["any"]:
                        model.warnings.append(f"{value.get('uid','')}: access-rule {value.get('name','')} veld {field} vereist review: {', '.join(values)}")
                for field in ("source-negate", "destination-negate", "service-negate"):
                    if value.get(field): model.warnings.append(f"{value.get('uid','')}: access-rule {value.get('name','')} gebruikt {field}; handmatige review vereist")
                if unsupported_action:
                    self._ensure_unsupported_action_tag(model)
                    model.warnings.append(
                        f"{value.get('uid','')}: niet-ondersteunde Check Point actie {action or 'onbekend'}; regel is disabled en vereist handmatige mapping"
                    )
                    description = "; ".join(filter(None, [f"REVIEW: actie {action or 'onbekend'} niet gemapt", description]))
                applications, services = self._split_rule_services(value.get("service", []), lookup, type_lookup)
                model.security_rules.append(Policy(
                    self._unique_rule_name(model.security_rules, value, current_source, "rule"),
                    source=self._names(value.get("source"), lookup, ["any"]),
                    destination=self._names(value.get("destination"), lookup, ["any"]),
                    application=applications,
                    service=services,
                    action="allow" if supported_allow else "deny",
                    disabled=not bool(value.get("enabled",True)) or unsupported_action, description=description,
                    tags=[self.UNSUPPORTED_ACTION_TAG] if unsupported_action else [],
                    source_ref=f"{current_source}:{value.get('uid','')}".strip(":"), original=value,
                ))
            for child in value.values():
                if isinstance(child,(list,dict)): self._walk_rules(child,model,lookup,type_lookup,current_source)

    def _walk_nat_rules(self, value, model, lookup, services_by_name, source_file=""):
        if isinstance(value, list):
            for item in value: self._walk_nat_rules(item, model, lookup, services_by_name, source_file)
            return
        if not isinstance(value, dict):
            return
        typ = str(value.get("type", "")).lower()
        current_source = str(value.get("_source_file") or source_file)
        if typ == "nat-rule":
            translated_source = self._names(value.get("translated-source"), lookup, ["original"])
            translated_destination = self._names(value.get("translated-destination"), lookup, ["original"])
            translated_service = self._names(value.get("translated-service"), lookup, ["original"])
            method = str(value.get("method") or value.get("nat-method") or "static").casefold()
            source_translation = {}
            if translated_source and translated_source != ["original"]:
                if method == "hide":
                    source_translation = {"dynamic_ip_and_port": {"translated_address": translated_source}}
                else:
                    source_translation = {"static_ip": {"translated_address": translated_source[0]}}
            destination_translation = {}
            if translated_destination and translated_destination != ["original"]:
                destination_translation["translated_address"] = translated_destination[0]
            if translated_service and translated_service != ["original"]:
                service = services_by_name.get(translated_service[0])
                if service:
                    destination_translation["translated_port"] = service.port
                else:
                    model.warnings.append(f"{value.get('uid','')}: translated service {translated_service[0]} vereist handmatige port mapping")
            model.nat_rules.append(Policy(
                self._unique_rule_name(model.nat_rules, value, current_source, "nat-rule"), policy_type="nat",
                source=self._names(value.get("original-source"), lookup, ["any"]),
                destination=self._names(value.get("original-destination"), lookup, ["any"]),
                service=self._names(value.get("original-service"), lookup, ["any"]),
                disabled=not bool(value.get("enabled", True)), description=self._description(value),
                source_translation=source_translation, destination_translation=destination_translation,
                source_ref=f"{current_source}:{value.get('uid','')}".strip(":"), original=value,
            ))
        for child in value.values():
            if isinstance(child, (list, dict)):
                self._walk_nat_rules(child, model, lookup, services_by_name, current_source)

    def _xml(self,text,source_name):
        root=SafeET.fromstring(text); model=MigrationModel(self.vendor,source_name)
        for entry in root.findall(".//object")+root.findall(".//network_object"):
            name=clean_name(entry.get("name") or entry.findtext("name") or "object"); value=entry.findtext("ip") or entry.findtext("address") or entry.findtext("subnet")
            if value: model.addresses.append(Address(name,value,source_ref=entry.get("uid",name)))
        if not model.addresses: model.warnings.append("Check Point XML herkend, maar geen ondersteunde objectnodes gevonden")
        return deduplicate(model)


def _xml_members(entry: ET.Element, path: str, default: list[str] | None = None) -> list[str]:
    node = entry.find(path)
    if node is None:
        return list(default or [])
    values = [member.text or "" for member in node.findall("./member") if (member.text or "").strip()]
    if values:
        return unique(values)
    text = (node.text or "").strip()
    return [text] if text else list(default or [])


def _xml_payload(node: ET.Element | None):
    if node is None:
        return {}
    children = list(node)
    if not children:
        return node.text or ""
    if all(child.tag == "member" for child in children):
        return [child.text or "" for child in children]
    result = {}
    for child in children:
        key = child.tag.replace("-", "_")
        value = _xml_payload(child)
        if key in result:
            result[key] = result[key] if isinstance(result[key], list) else [result[key]]
            result[key].append(value)
        else:
            result[key] = value
    return result


def raw_item_payload(item: dict) -> dict:
    """Convert a preserved PAN-OS entry into a neutral REST-shaped payload."""
    if isinstance(item.get("payload"),dict):
        return {"name":str(item.get("name",item["payload"].get("name",""))),**copy.deepcopy(item["payload"])}
    try:
        entry=SafeET.fromstring(str(item.get("xml", "")))
    except Exception as exc:
        raise MigrationError(f"Ongeldige entry XML voor {item.get('name','')}: {exc}") from exc
    payload={"name":str(item.get("name",entry.get("name", "")))}
    for child in entry:
        payload[child.tag.replace("-","_")]=_xml_payload(child)
    return payload


class PanosConfigParser(BaseParser):
    vendor = "panos"
    label = "Palo Alto PAN-OS / Panorama XML"
    extensions = (".xml",)
    interface_types = ("ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan")

    def parse(self, text: str, source_name: str) -> MigrationModel:
        try:
            root = SafeET.fromstring(text)
        except Exception as exc:
            raise MigrationError(f"Ongeldige PAN-OS XML: {exc}") from exc
        if root.tag != "config":
            root = root.find(".//config")
        if root is None:
            raise MigrationError("Geen PAN-OS <config>-root gevonden")
        model = MigrationModel(self.vendor, source_name)
        locations: list[tuple[str, ET.Element]] = []
        shared = root.find("./shared")
        if shared is not None:
            locations.append(("Shared", shared))
        for entry in root.findall("./devices/entry/vsys/entry"):
            locations.append((f"VSYS {entry.get('name', '')}", entry))
        for entry in root.findall("./devices/entry/device-group/entry"):
            locations.append((f"Device Group {entry.get('name', '')}", entry))
        if not locations:
            raise MigrationError("Geen Shared, VSYS of Device Group in de PAN-OS-config gevonden")

        for owner, location in locations:
            self._objects(model, location, owner)
            self._policies(model, location, owner)
            self._extra_objects(model, location, owner)
            self._extra_policies(model, location, owner)
            for entry in location.findall("./zone/entry"):
                model.zones.append({"name": entry.get("name", ""), "xml": ET.tostring(entry, encoding="unicode"), "source_ref": owner})

        device = root.find("./devices/entry")
        if device is not None:
            for interface_type in self.interface_types:
                for entry in device.findall(f"./network/interface/{interface_type}/entry"):
                    model.interfaces.append({
                        "name": entry.get("name", ""), "interface_type": interface_type,
                        "xml": ET.tostring(entry, encoding="unicode"), "source_ref": "Device network",
                    })
            self._network(model, device.find("./network"), "Device network")
            self._device_configuration(model, device, "Device")
        for template in root.findall("./devices/entry/template/entry"):
            template_name = template.get("name", "")
            for interface_type in self.interface_types:
                for entry in template.findall(f"./config/devices/entry/network/interface/{interface_type}/entry"):
                    model.interfaces.append({
                        "name": entry.get("name", ""), "interface_type": interface_type,
                        "xml": ET.tostring(entry, encoding="unicode"), "source_ref": f"Template {template_name}",
                    })
            for entry in template.findall("./config/devices/entry/vsys/entry/zone/entry"):
                model.zones.append({"name": entry.get("name", ""), "xml": ET.tostring(entry, encoding="unicode"), "source_ref": f"Template {template_name}"})
            template_device = template.find("./config/devices/entry")
            if template_device is not None:
                self._network(model, template_device.find("./network"), f"Template {template_name}")
                self._device_configuration(model, template_device, f"Template {template_name}")
        return deduplicate(model)

    @staticmethod
    def _raw_item(entry: ET.Element, owner: str, target_path: str) -> dict:
        return {
            "name": entry.get("name", ""), "xml": ET.tostring(entry, encoding="unicode"),
            "source_ref": owner, "target_path": target_path,
        }

    @classmethod
    def _extra_objects(cls, model: MigrationModel, location: ET.Element, owner: str) -> None:
        for kind, (xpath, target_path) in PANOS_EXTRA_PATHS.items():
            for entry in location.findall(xpath):
                model.extras.setdefault(kind, []).append(cls._raw_item(entry, owner, target_path))
        for profile_type in PANOS_SECURITY_PROFILE_TYPES:
            for entry in location.findall(f"./profiles/{profile_type}/entry"):
                item = cls._raw_item(entry, owner, f"profiles/{profile_type}")
                item["profile_type"] = profile_type
                model.extras.setdefault("security_profiles", []).append(item)

    @classmethod
    def _extra_policies(cls, model: MigrationModel, location: ET.Element, owner: str) -> None:
        for rulebase in ("rulebase", "pre-rulebase", "post-rulebase"):
            for kind, policy_type in PANOS_POLICY_PATHS.items():
                for entry in location.findall(f"./{rulebase}/{policy_type}/rules/entry"):
                    item = cls._raw_item(entry, f"{owner} · {rulebase}", f"{rulebase}/{policy_type}/rules")
                    item.update({"rulebase": rulebase, "policy_type": policy_type})
                    model.extras.setdefault(kind, []).append(item)
            for policy_type, label in PANOS_EXCLUDED_POLICY_PATHS.items():
                for entry in location.findall(f"./{rulebase}/{policy_type}/rules/entry"):
                    model.unsupported.append(
                        f"{owner} · {rulebase}: {label} policy {entry.get('name', '')} wordt bewust niet gemigreerd"
                    )

    @classmethod
    def _network(cls, model: MigrationModel, network: ET.Element | None, owner: str) -> None:
        if network is None:
            return
        paths = {
            "vlans": ("./vlan/entry", "network/vlan"),
            "virtual_routers": ("./virtual-router/entry", "network/virtual-router"),
            "logical_routers": ("./logical-router/entry", "network/logical-router"),
            "virtual_wires": ("./virtual-wire/entry", "network/virtual-wire"),
            "ipsec_tunnels": ("./tunnel/ipsec/entry", "network/tunnel/ipsec"),
            "ike_gateways": ("./ike/gateway/entry", "network/ike/gateway"),
            "globalprotect_portals": ("./global-protect/global-protect-portal/entry", "network/global-protect/global-protect-portal"),
            "globalprotect_gateways": ("./global-protect/global-protect-gateway/entry", "network/global-protect/global-protect-gateway"),
        }
        for kind, (xpath, target_path) in paths.items():
            for entry in network.findall(xpath):
                model.extras.setdefault(kind, []).append(cls._raw_item(entry, owner, target_path))
        profile_roots = ("ike", "ipsec", "monitor-profile", "interface-management-profile", "qos-profile", "lldp")
        for root_name in profile_roots:
            root = network.find(f"./profiles/{root_name}")
            if root is None:
                continue
            for entry in root.findall(".//entry"):
                item = cls._raw_item(entry, owner, f"network/profiles/{root_name}")
                item["profile_type"] = root_name
                model.extras.setdefault("network_profiles", []).append(item)

    @classmethod
    def _device_configuration(cls, model: MigrationModel, device: ET.Element, owner: str) -> None:
        for child in device:
            if child.tag in {"network", "vsys", "device-group", "template", "template-stack"}:
                continue
            entries = child.findall("./entry")
            for entry in entries:
                item = cls._raw_item(entry, owner, child.tag)
                item["section"] = child.tag
                model.extras.setdefault("device_configuration", []).append(item)

    @staticmethod
    def _objects(model: MigrationModel, location: ET.Element, owner: str) -> None:
        for entry in location.findall("./address/entry"):
            for tag in ("ip-netmask", "ip-range", "ip-wildcard", "fqdn"):
                value = entry.findtext(f"./{tag}")
                if value is not None:
                    model.addresses.append(Address(entry.get("name", ""), value, tag.replace("-", "_"), entry.findtext("./description") or "", _xml_members(entry, "./tag"), owner))
                    break
        for entry in location.findall("./address-group/entry"):
            members = _xml_members(entry, "./static")
            if members:
                model.address_groups.append(AddressGroup(entry.get("name", ""), members, entry.findtext("./description") or "", _xml_members(entry, "./tag"), owner))
            elif entry.find("./dynamic") is not None:
                model.unsupported.append(f"{owner}: dynamic address group {entry.get('name', '')} vereist review")
        for entry in location.findall("./service/entry"):
            protocol_node = entry.find("./protocol")
            if protocol_node is None or not list(protocol_node):
                continue
            protocol = list(protocol_node)[0]
            model.services.append(Service(entry.get("name", ""), protocol.tag, protocol.findtext("./port") or "1-65535", protocol.findtext("./source-port") or "", entry.findtext("./description") or "", _xml_members(entry, "./tag"), owner))
        for entry in location.findall("./service-group/entry"):
            model.service_groups.append(ServiceGroup(entry.get("name", ""), _xml_members(entry, "./members"), entry.findtext("./description") or "", _xml_members(entry, "./tag"), owner))

    @staticmethod
    def _policies(model: MigrationModel, location: ET.Element, owner: str) -> None:
        for rulebase in ("rulebase", "pre-rulebase", "post-rulebase"):
            for kind, target in (("security", model.security_rules), ("nat", model.nat_rules)):
                for entry in location.findall(f"./{rulebase}/{kind}/rules/entry"):
                    rule = Policy(
                        name=entry.get("name", ""), policy_type=kind,
                        from_zones=_xml_members(entry, "./from", ["any"]), to_zones=_xml_members(entry, "./to", ["any"]),
                        source=_xml_members(entry, "./source", ["any"]), destination=_xml_members(entry, "./destination", ["any"]),
                        application=_xml_members(entry, "./application", ["any"]), service=_xml_members(entry, "./service", ["application-default" if kind == "security" else "any"]),
                        action=entry.findtext("./action") or "allow", disabled=(entry.findtext("./disabled") or "no").lower() == "yes",
                        description=entry.findtext("./description") or "", tags=_xml_members(entry, "./tag"),
                        source_translation=_xml_payload(entry.find("./source-translation")), destination_translation=_xml_payload(entry.find("./destination-translation")),
                        nat_type=entry.findtext("./nat-type") or "ipv4", to_interface=entry.findtext("./to-interface") or "any",
                        source_ref=f"{owner} · {rulebase}",
                    )
                    rule.original = {
                        "owner": owner, "rulebase": rulebase,
                        "xml": ET.tostring(entry, encoding="unicode"),
                        "normalized": policy_state(rule),
                    }
                    target.append(rule)


class GenericParser(BaseParser):
    vendor = "generic"
    label = "Overige / generiek"
    extensions = (".json", ".xml", ".csv", ".txt", ".conf", ".cfg")

    def parse(self,text,source_name):
        model=MigrationModel(self.vendor,source_name); stripped=text.lstrip()
        if stripped.startswith(("{","[")):
            data=json.loads(text); entries=data if isinstance(data,list) else data.get("objects",[])
            for item in entries if isinstance(entries,list) else []:
                if isinstance(item,dict) and item.get("name") and item.get("value"): model.addresses.append(Address(clean_name(item["name"]),str(item["value"]),str(item.get("value_type","ip_netmask")),source_ref=str(item.get("id",""))))
            if not model.addresses: model.unsupported.append("Generieke JSON bevat geen ondersteunde objects-lijst met name/value")
        elif stripped.startswith("<"):
            root=SafeET.fromstring(text)
            for entry in root.findall(".//entry"):
                name=entry.get("name"); child=next(iter(entry),None)
                if name and child is not None and child.tag in {"ip-netmask","ip-range","fqdn"}: model.addresses.append(Address(clean_name(name),child.text or "",child.tag.replace("-","_")))
            if not model.addresses: model.unsupported.append("Generieke XML bevat geen ondersteunde address entries")
        else: model.unsupported.append("Onbekend formaat; kies een specifieke vendorparser of lever een ondersteunde JSON/XML export")
        return deduplicate(model)


class PaloAltoCsvParser(BaseParser):
    vendor="panos-csv"; label="Palo Alto Networks CSV"; extensions=(".csv",)
    def parse(self,text,source_name):
        model=MigrationModel(self.vendor,source_name)
        reader=csv.DictReader(io.StringIO(text))
        for number,row in enumerate(reader,2):
            normalized={re.sub(r"[^a-z0-9]+","_",str(key).strip().lower()).strip("_"):str(value or "").strip() for key,value in row.items() if key is not None}
            name=normalized.get("name") or normalized.get("object_name") or normalized.get("rule_name")
            if not name: continue
            kind=(normalized.get("type") or normalized.get("object_type") or normalized.get("rule_type") or "").lower()
            value=normalized.get("value") or normalized.get("ip_netmask") or normalized.get("address")
            if value and kind not in {"service","security","nat","rule"}:
                try: ipaddress.ip_network(value,strict=False); value_type="ip_netmask"
                except ValueError: value_type="fqdn" if normalized.get("fqdn") or (re.search(r"[a-z]",value,re.I) and "/" not in value) else "ip_range" if "-" in value else "ip_netmask"
                model.addresses.append(Address(name,value,value_type,normalized.get("description",""),source_ref=f"row {number}")); continue
            if kind in {"service","tcp","udp"} or normalized.get("port") or normalized.get("destination_port"):
                model.services.append(Service(name,normalized.get("protocol") or (kind if kind in {"tcp","udp"} else "tcp"),normalized.get("port") or normalized.get("destination_port") or "1-65535",source_ref=f"row {number}")); continue
            if kind in {"security","nat","rule","policy"} or normalized.get("source_zone") or normalized.get("from"):
                target=model.nat_rules if kind=="nat" else model.security_rules
                target.append(Policy(name=name,policy_type="nat" if kind=="nat" else "security",from_zones=_csv_values(normalized.get("source_zone") or normalized.get("from"),["any"]),to_zones=_csv_values(normalized.get("destination_zone") or normalized.get("to"),["any"]),source=_csv_values(normalized.get("source"),["any"]),destination=_csv_values(normalized.get("destination"),["any"]),application=_csv_values(normalized.get("application"),["any"]),service=_csv_values(normalized.get("service"),["application-default"]),action=normalized.get("action") or "allow",disabled=(normalized.get("disabled","").lower() in {"yes","true","1"}),description=normalized.get("description",""),source_ref=f"row {number}"))
        return deduplicate(model)


def _csv_values(value: str, default: list[str]) -> list[str]:
    values=[part.strip() for part in re.split(r"[;,|]",value or "") if part.strip()]
    return values or list(default)


class AlgoSecParser(BaseParser):
    vendor="algosec"; label="AlgoSec"; extensions=(".xml",".csv",".json")
    def parse(self,text,source_name):
        if text.lstrip().startswith("{") or text.lstrip().startswith("["):
            model=GenericParser().parse(text,source_name); model.vendor=self.vendor; return model
        if not text.lstrip().startswith("<"):
            model=PaloAltoCsvParser().parse(text,source_name); model.vendor=self.vendor; return model
        root=SafeET.fromstring(text); model=MigrationModel(self.vendor,source_name)
        for node in root.iter():
            name=node.get("name") or node.findtext("./name"); value=node.get("ip") or node.get("address") or node.findtext("./ip") or node.findtext("./address")
            tag=node.tag.lower().replace("_","-")
            if name and value and any(token in tag for token in ("host","network","object")):
                model.addresses.append(Address(clean_name(name),cidr(value),source_ref=f"<{node.tag}>"))
            if name and any(token in tag for token in ("service","tcp","udp")):
                port=node.get("port") or node.findtext("./port")
                if port: model.services.append(Service(clean_name(name),"udp" if "udp" in tag else "tcp",port,source_ref=f"<{node.tag}>"))
        return deduplicate(model)


class StonesoftParser(AlgoSecParser):
    vendor="stonesoft"; label="Stonesoft / Forcepoint SMC"; extensions=(".xml",".txt")


PARSERS = {parser.vendor: parser for parser in (PanosConfigParser(), PaloAltoCsvParser(), CiscoAsaParser(), CiscoIosParser(), CheckPointParser(), FortinetParser(), JuniperSrxParser(), AlgoSecParser(), StonesoftParser(), GenericParser())}


def parse_vendor(vendor: str, content: bytes, source_name: str) -> MigrationModel:
    parser=PARSERS.get(vendor)
    if not parser: raise MigrationError("Onbekende vendorparser")
    if len(content)>100*1024*1024: raise MigrationError("Importbestand is groter dan 100 MiB")
    if hasattr(parser, "parse_bytes") and source_name.casefold().endswith(".tar"):
        model=parser.parse_bytes(content,source_name)
        if sum(value for key,value in model.counts().items() if key not in {"warnings","unsupported"})==0:
            model.warnings.append("Geen direct mergeerbare objecten of policies gevonden")
        return model
    try: text=content.decode("utf-8-sig")
    except UnicodeDecodeError: text=content.decode("latin-1")
    model=parser.parse(text,source_name)
    if sum(value for key,value in model.counts().items() if key not in {"warnings","unsupported"})==0:
        model.warnings.append("Geen direct mergeerbare objecten of policies gevonden")
    return model


def deduplicate(model: MigrationModel) -> MigrationModel:
    for attr in ("addresses","address_groups","services","service_groups","security_rules","nat_rules"):
        values=[]; seen={}
        for item in getattr(model,attr):
            item.name=str(item.name or "").strip() if model.vendor == "panos" else clean_name(item.name)
            if item.name in seen:
                if asdict(seen[item.name]) != asdict(item): model.warnings.append(f"Dubbele naam {item.name} in {attr}; eerste definitie behouden")
                continue
            seen[item.name]=item; values.append(item)
        setattr(model,attr,values)
    for attr in ("interfaces", "zones"):
        values=[]; seen={}
        for item in getattr(model, attr):
            original_name=str(item.get("name", "")).strip()
            name=original_name if model.vendor == "panos" else clean_name(original_name)
            if not name: continue
            item["name"]=name
            key=(item.get("interface_type", ""), name) if attr == "interfaces" else name
            if key in seen:
                if item.get("xml") != seen[key].get("xml"): model.warnings.append(f"Dubbele naam {name} in {attr}; eerste definitie behouden")
                continue
            seen[key]=item; values.append(item)
        setattr(model, attr, values)
    for kind, items in model.extras.items():
        values=[]; seen={}
        for item in items:
            name=str(item.get("name", "")).strip()
            if not name: continue
            item["name"]=name
            key=(item.get("profile_type", ""), item.get("target_path", ""), name)
            if key in seen:
                if generic_item_signature(item) != generic_item_signature(seen[key]):
                    model.warnings.append(f"Dubbele naam {name} in {kind}; eerste definitie behouden")
                continue
            seen[key]=item; values.append(item)
        model.extras[kind]=values
    return model


def generic_item_signature(item: dict) -> str:
    """Stable semantic signature for raw PAN-OS entries, excluding identity/source."""
    xml = str(item.get("xml", ""))
    if xml:
        try:
            entry = SafeET.fromstring(xml)
            entry.attrib.pop("name", None)
            xml = ET.tostring(entry, encoding="unicode")
        except Exception:
            pass
    return json.dumps({
        "xml": xml, "target_path": item.get("target_path", ""),
        "payload": item.get("payload"),
        "profile_type": item.get("profile_type", ""),
        "policy_type": item.get("policy_type", ""),
    }, sort_keys=True, separators=(",", ":"))


def model_collections(model: MigrationModel) -> dict[str, list]:
    collections = {
        "addresses": model.addresses, "address_groups": model.address_groups,
        "services": model.services, "service_groups": model.service_groups,
        "security_rules": model.security_rules, "nat_rules": model.nat_rules,
        "interfaces": model.interfaces, "zones": model.zones,
    }
    collections.update(model.extras)
    return collections


def item_selector(item: dict) -> str:
    return f"{item.get('name','')}|||{item.get('source_ref','')}"


def selector_item(collection: list, selector: str):
    """Resolve a saved selector after an import workspace changed provenance.

    Editing a vendor import through the PAN-OS workspace intentionally changes
    ``source_ref`` (for example from ``line 3`` to ``VSYS vsys1``).  The item
    name remains a safe fallback only when it is unique inside its collection.
    Ambiguous same-name collisions still require an explicit new choice.
    """
    exact = []
    for item in collection:
        raw = asdict(item) if hasattr(item, "__dataclass_fields__") else item
        if item_selector(raw) == selector:
            exact.append(item)
    if len(exact) == 1:
        return exact[0]
    name = selector.split("|||", 1)[0]
    matches = [
        item for item in collection
        if (item.name if hasattr(item, "name") else str(item.get("name", ""))) == name
    ]
    return matches[0] if len(matches) == 1 else None


def restore_migration_source_topology(original: MigrationModel, edited: MigrationModel) -> MigrationModel:
    """Keep source topology identity when the import editor round-trips PAN-OS.

    XML is the edited source of truth. Only unambiguous provenance is restored;
    addresses/networks are re-derived, never copied from an earlier subnet.
    Check Point staging interfaces remain map-only, including new/renamed ones.
    """
    result = MigrationModel.from_dict(edited.as_dict())
    metadata = ("source_ref", "source_vendor", "topology_role", "suggested_zone", "mapping_action",
                "gateway", "gateway_name", "gateway_uid", "source_gateway", "source_uid", "uid")
    def indexes(items):
        by_selector, by_name = {}, {}
        for item in items:
            by_selector.setdefault(item_selector(item), []).append(item)
            by_name.setdefault(str(item.get("name", "")), []).append(item)
        return by_selector, by_name
    original_selectors, original_names = indexes(original.interfaces)
    edited_selectors, edited_names = indexes(result.interfaces)
    for interface in result.interfaces:
        selector = item_selector(interface)
        exact = original_selectors.get(selector, [])
        edited_exact = edited_selectors.get(selector, [])
        name = str(interface.get("name", ""))
        matching = original_names.get(name, [])
        edited_matching = edited_names.get(name, [])
        previous = exact[0] if len(exact) == len(edited_exact) == 1 else (
            matching[0] if len(matching) == len(edited_matching) == 1 else None)
        if previous is not None:
            for key in metadata:
                if key in previous:
                    interface[key] = copy.deepcopy(previous[key])
        checkpoint = original.vendor == "checkpoint" or interface.get("source_vendor") == "checkpoint"
        if checkpoint:
            interface["source_vendor"] = "checkpoint"
            if previous is None:
                interface["mapping_action"] = "review"
        if not checkpoint and not (previous and "source_networks" in previous):
            continue
        try:
            entry = SafeET.fromstring(interface.get("xml", ""))
        except Exception as exc:
            raise MigrationError("Ongeldige interfaceconfiguratie in de importeditor") from exc
        addresses, networks = [], []
        # Do not take child subinterface addresses as networks of their parent.
        for path in (".", "./layer3"):
            layer3 = entry.find(path)
            if layer3 is None:
                continue
            dhcp = layer3.find("dhcp-client")
            address_nodes = list(layer3.findall("./ipv6/address/entry"))
            if dhcp is None or dhcp.findtext("enable", "yes") == "no":
                address_nodes.extend(layer3.findall("./ip/entry"))
            for node in address_nodes:
                value = str(node.get("name", ""))
                try:
                    parsed = ipaddress.ip_interface(value)
                except ValueError:
                    continue
                addresses.append(str(parsed))
                networks.append(str(parsed.network))
        interface["source_addresses"] = unique(addresses)
        interface["source_networks"] = unique(networks)
    return result


def migration_item_semantic(item) -> str:
    """Stable value comparison that deliberately ignores source provenance."""
    raw = asdict(item) if hasattr(item, "__dataclass_fields__") else dict(item)
    semantic = {
        key: value for key, value in raw.items()
        if key not in {"source_ref", "original", "selector", "target_context", "mapping_action"}
    }
    return json.dumps(semantic, sort_keys=True, separators=(",", ":"), default=str)


def migration_collision_report(left: MigrationModel, right: MigrationModel) -> dict:
    """Compare two sources by item name and semantic value for operator review."""
    result = {}
    for kind in sorted(set(model_collections(left)) | set(model_collections(right))):
        def named(items):
            values = {}
            for item in items:
                raw = asdict(item) if hasattr(item, "__dataclass_fields__") else dict(item)
                name = str(raw.get("name", ""))
                if name:
                    values.setdefault(name, item)
            return values
        left_items = named(model_collections(left).get(kind, []))
        right_items = named(model_collections(right).get(kind, []))
        shared = set(left_items) & set(right_items)
        conflicts = sorted(
            name for name in shared
            if migration_item_semantic(left_items[name]) != migration_item_semantic(right_items[name])
        )
        result[kind] = {
            "left": len(left_items), "right": len(right_items), "shared": len(shared),
            "identical": len(shared) - len(conflicts), "conflicts": len(conflicts),
            "conflict_names": conflicts,
            "left_only": len(set(left_items) - set(right_items)),
            "right_only": len(set(right_items) - set(left_items)),
        }
    return result


def set_panos_ha_mode(xml_bytes: bytes, topology: str) -> tuple[bytes, dict]:
    """Switch an existing HA pair between active/passive and active/active."""
    if topology not in {"active-passive", "active-active"}:
        raise MigrationError("Onbekende HA-topologie")
    root = SafeET.fromstring(xml_bytes)
    ha_nodes = root.findall(".//deviceconfig/high-availability")
    changed = 0
    target_tag = "active-passive" if topology == "active-passive" else "active-active"
    for ha in ha_nodes:
        group = ha.find("./group")
        if group is None:
            group = ET.SubElement(ha, "group")
        mode = group.find("./mode")
        if mode is None:
            mode = ET.SubElement(group, "mode")
        current = [child.tag for child in mode]
        if current == [target_tag]:
            continue
        for child in list(mode):
            mode.remove(child)
        ET.SubElement(mode, target_tag)
        changed += 1
    ET.indent(root, space="  ")
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8") + b"\n", {
        "topology": topology, "ha_nodes": len(ha_nodes), "changed": changed,
        "ha_missing": not bool(ha_nodes),
    }


def merge_inventory(model: MigrationModel, query: str = "") -> list[dict]:
    """Return Expedition-style duplicate/search inventory for every collection."""
    needle=query.casefold().strip(); result=[]
    for kind, items in model_collections(model).items():
        groups: dict[str, list[dict]] = {}
        for item in items:
            raw=asdict(item) if hasattr(item, "__dataclass_fields__") else dict(item)
            raw["selector"]=item_selector(raw)
            name=str(raw.get("name", "")); searchable=json.dumps(raw, sort_keys=True, default=str).casefold()
            if needle and needle not in name.casefold() and needle not in searchable: continue
            if kind in model.extras:
                signature=generic_item_signature(raw)
            else:
                semantic={key:value for key,value in raw.items() if key not in {"name","source_ref","original","selector"}}
                signature=json.dumps(semantic,sort_keys=True,separators=(",",":"),default=str)
            groups.setdefault(signature,[]).append(raw)
        names: dict[str,list[dict]]={}
        for item in items:
            raw=asdict(item) if hasattr(item, "__dataclass_fields__") else dict(item)
            raw["selector"]=item_selector(raw)
            names.setdefault(str(raw.get("name", "")).casefold(),[]).append(raw)
        duplicates={id(item) for values in groups.values() if len(values)>1 for item in values}
        for raw_items in names.values():
            if len(raw_items)>1: duplicates.update(id(item) for item in raw_items)
        for signature, values in groups.items():
            if len(values)>1:
                result.append({"kind":kind,"reason":"value","signature":signature,"items":values})
        for name, values in names.items():
            signatures={generic_item_signature(value) if kind in model.extras else json.dumps({k:v for k,v in value.items() if k not in {"name","source_ref","original","selector"}},sort_keys=True,default=str) for value in values}
            if len(values)>1 and len(signatures)>1:
                result.append({"kind":kind,"reason":"name","signature":name,"items":values})
    return result


def migration_search(model: MigrationModel, query: str) -> list[dict]:
    needle=query.casefold().strip()
    if not needle: return []
    results=[]
    for kind,items in model_collections(model).items():
        for item in items:
            raw=asdict(item) if hasattr(item,"__dataclass_fields__") else dict(item)
            if needle in json.dumps(raw,sort_keys=True,default=str).casefold():
                results.append({"kind":kind,"name":str(raw.get("name","")),"source_ref":str(raw.get("source_ref","")),"value":str(raw.get("value",raw.get("port","")))})
    return results[:250]


def migration_inventory_rows(model: MigrationModel) -> list[dict]:
    """Flatten every migration family for filters, dashboards and API staging."""
    rows = []
    for kind, items in model_collections(model).items():
        for item in items:
            raw = asdict(item) if hasattr(item, "__dataclass_fields__") else dict(item)
            references = []
            for key in (
                "members", "from_zones", "to_zones", "source", "destination",
                "application", "service", "tags",
            ):
                value = raw.get(key, [])
                references.extend(value if isinstance(value, list) else [value] if value else [])
            rows.append({
                "kind": kind,
                "name": str(raw.get("name", "")),
                "value": str(raw.get("value", raw.get("port", ""))),
                "source_ref": str(raw.get("source_ref", "")),
                "references": " ".join(str(value) for value in references),
                "disabled": bool(raw.get("disabled", False)),
                "selector": item_selector(raw),
                "raw": raw,
            })
    return rows


def migration_filter_inventory(
    model: MigrationModel,
    rules: list[dict],
    join_mode: str = "and",
) -> list[dict]:
    """Apply a small, deterministic Expedition-style AND/OR filter builder."""
    if join_mode not in {"and", "or"}:
        raise MigrationError("Onbekende filtercombinatie")
    normalized = []
    for rule in rules:
        field = str(rule.get("field", "name"))
        operator = str(rule.get("operator", "contains"))
        value = str(rule.get("value", ""))
        if field not in MIGRATION_FILTER_FIELDS or operator not in MIGRATION_FILTER_OPERATORS:
            raise MigrationError("Ongeldige migratiefilter")
        if field == "disabled":
            if operator != "equals" or value.casefold() not in {"yes", "no"}:
                raise MigrationError("Disabled gebruikt alleen Equals met Ja of Neen")
        if not value and field != "disabled":
            continue
        normalized.append((field, operator, value))
    if not normalized:
        return []

    def matches(row: dict, rule: tuple[str, str, str]) -> bool:
        field, operator, wanted = rule
        actual = "yes" if row[field] is True else "no" if row[field] is False else str(row.get(field, ""))
        actual_folded = actual.casefold()
        wanted_folded = wanted.casefold()
        if operator == "contains":
            return wanted_folded in actual_folded
        if operator == "not_contains":
            return wanted_folded not in actual_folded
        if operator == "equals":
            return actual_folded == wanted_folded
        if operator == "starts_with":
            return actual_folded.startswith(wanted_folded)
        if operator == "ends_with":
            return actual_folded.endswith(wanted_folded)
        try:
            return re.search(wanted, actual, re.IGNORECASE) is not None
        except re.error as exc:
            raise MigrationError(f"Ongeldige reguliere expressie: {exc}") from exc

    result = []
    for row in migration_inventory_rows(model):
        outcomes = [matches(row, rule) for rule in normalized]
        if (join_mode == "and" and all(outcomes)) or (join_mode == "or" and any(outcomes)):
            result.append(row)
    return result[:500]


def apply_family_mappings(model: MigrationModel, mappings: list[dict]) -> MigrationModel:
    """Apply and retain explicit per-family destination decisions.

    ``create`` allows missing items to be created in the selected target context.
    ``map`` only permits reuse of an equivalent item that already exists there.
    The merge adapters consume the retained metadata; it is not presentation-only.
    """
    result = MigrationModel.from_dict(model.as_dict())
    for mapping in mappings:
        kind = str(mapping.get("kind", ""))
        action = str(mapping.get("action", "map"))
        target_context = str(mapping.get("target_context", "")).strip()
        if kind not in model_collections(result) or action not in MIGRATION_MAPPING_ACTIONS:
            continue
        if action == "ignore":
            if kind in result.extras:
                result.extras[kind] = []
            else:
                setattr(result, kind, [])
        elif action == "review":
            result.warnings.append(
                f"Mapping voor {MIGRATION_KIND_LABELS.get(kind, kind)} vereist nog een beslissing"
            )
        else:
            if not target_context:
                raise MigrationError(
                    f"Doelcontext ontbreekt voor {MIGRATION_KIND_LABELS.get(kind, kind)}"
                )
            for item in model_collections(result)[kind]:
                if hasattr(item, "target_context"):
                    item.target_context = target_context
                    item.mapping_action = action
                elif isinstance(item, dict):
                    item["target_context"] = target_context
                    item["mapping_action"] = action
    return result


def apply_topology_mappings(model: MigrationModel, mappings: list[dict]) -> MigrationModel:
    """Map source topology names to existing targets without copying source definitions."""
    result = MigrationModel.from_dict(model.as_dict())
    replacements: dict[str, dict[str, str]] = {}
    for mapping in mappings:
        kind = str(mapping.get("kind", ""))
        source = str(mapping.get("source", "")).strip()
        action = str(mapping.get("action", "review"))
        target = str(mapping.get("target", "")).strip()
        if kind not in MIGRATION_TOPOLOGY_KINDS or not source or action not in MIGRATION_MAPPING_ACTIONS:
            continue
        collection = model_collections(result).get(kind, [])
        matching = [
            item for item in collection
            if (item.get("name", "") if isinstance(item, dict) else item.name) == source
        ]
        if action == "map" and target:
            replacements.setdefault(kind, {})[source] = target
            for item in matching:
                collection.remove(item)
        elif action == "ignore":
            for item in matching:
                collection.remove(item)
        elif action == "review":
            result.warnings.append(f"Topologiemapping vereist review: {kind} {source}")

    return _rewrite_typed_references(result, replacements) if replacements else result


def merge_member_names(model: MigrationModel, kind: str, master: str, mode: str, selected: list[str] | None = None) -> list[str]:
    items=model_collections(model).get(kind,[])
    raw=[asdict(item) if hasattr(item,"__dataclass_fields__") else dict(item) for item in items]
    master_item=next((item for item in raw if item_selector(item)==master),None)
    if master_item is None: return []
    if kind in model.extras: signature=lambda item:generic_item_signature(item)
    else: signature=lambda item:json.dumps({key:value for key,value in item.items() if key not in {"name","source_ref","original"}},sort_keys=True,separators=(",",":"),default=str)
    if mode=="selection": return unique(selected or [])
    master_name=str(master_item.get("name","")).casefold(); master_signature=signature(master_item); members=[]
    for item in raw:
        same_name=str(item.get("name","")).casefold()==master_name; same_value=signature(item)==master_signature
        if (mode=="name" and same_name) or (mode=="value" and same_value) or (mode=="name_value" and same_name and same_value): members.append(item_selector(item))
    return unique(members)


def _rewrite_typed_references(model: MigrationModel, replacements: dict[str, dict[str, str]]) -> MigrationModel:
    """Rewrite references in their own namespace, never unrelated free text."""
    def names(*kinds):
        values = dict(replacements.get("*", {}))
        for kind in kinds:
            values.update(replacements.get(kind, {}))
        return values

    addresses = names("addresses", "address_groups")
    services = names("services", "service_groups")
    applications = names("applications", "application_groups", "application_filters")
    tags, zones, interfaces = names("tags"), names("zones"), names("interfaces")
    for group in model.address_groups:
        group.members = unique(addresses.get(value, value) for value in group.members)
    for group in model.service_groups:
        group.members = unique(services.get(value, value) for value in group.members)
    for collection in (model.addresses, model.address_groups, model.services, model.service_groups):
        for item in collection:
            item.tags = unique(tags.get(value, value) for value in item.tags)

    def translation(value, key=""):
        if isinstance(value, dict):
            return {field: translation(child, field.replace("-", "_")) for field, child in value.items()}
        if isinstance(value, list):
            return [translation(child, key) for child in value]
        mapping = addresses if key in {"translated_address", "ip", "floating_ip"} else interfaces if key == "interface" else {}
        return mapping.get(value, value) if isinstance(value, str) else value

    for rule in [*model.security_rules, *model.nat_rules]:
        for field, mapping in (("source", addresses), ("destination", addresses), ("service", services),
                               ("application", applications), ("tags", tags), ("from_zones", zones), ("to_zones", zones)):
            setattr(rule, field, unique(mapping.get(value, value) for value in getattr(rule, field)))
        rule.to_interface = interfaces.get(rule.to_interface, rule.to_interface)
        rule.source_translation = translation(rule.source_translation)
        rule.destination_translation = translation(rule.destination_translation)

    xml_items = [(kind, item) for kind, items in model.extras.items() for item in items]
    xml_items.extend(("zones", item) for item in model.zones)
    xml_items.extend(("interfaces", item) for item in model.interfaces)
    for kind, item in xml_items:
        try:
            entry = SafeET.fromstring(str(item.get("xml", "")))
        except (ET.ParseError, ValueError):
            continue
        paths = [(".//tag/member", tags)]
        if kind.endswith("_rules"):
            paths.extend([
                ("./source/member", addresses), ("./destination/member", addresses),
                ("./service/member", services), ("./service", services),
                ("./application/member", applications), ("./from/member", zones), ("./to/member", zones),
                ("./to-interface", interfaces), (".//translated-address/member", addresses),
                (".//translated-address", addresses), (".//interface-address/interface", interfaces),
            ])
        if kind == "application_groups":
            paths.append(("./members/member", applications))
        if kind == "zones":
            paths.append(("./network/*/member", interfaces))
        if kind in {"virtual_routers", "logical_routers", "vlans", "virtual_wires"}:
            paths.extend([(".//interface/member", interfaces), (".//interface", interfaces),
                          ("./interface1", interfaces), ("./interface2", interfaces)])
        for path, mapping in paths:
            for node in entry.findall(path):
                if node.text in mapping:
                    node.text = mapping[node.text]
        item["xml"] = ET.tostring(entry, encoding="unicode")
    return model


def apply_merge_rules(model: MigrationModel, rules: list[dict]) -> MigrationModel:
    """Apply explicit master/member choices and rewrite object references globally."""
    result=MigrationModel.from_dict(model.as_dict()); rename={}
    for rule in rules:
        master_selector=str(rule.get("master", "")); members=unique(rule.get("members", [])); kind=str(rule.get("kind", ""))
        collection=model_collections(result).get(kind,[])
        master_item=selector_item(collection,master_selector)
        master=(master_item.name if hasattr(master_item,"name") else str(master_item.get("name",""))) if master_item is not None else ""
        if not master or not members or kind not in model_collections(result): continue
        member_items=[]
        for selector in members:
            resolved=selector_item(collection,selector)
            if resolved is not None and all(resolved is not item for item in member_items): member_items.append(resolved)
        member_ids={id(item) for item in member_items}
        for item in member_items:
            name=item.name if hasattr(item,"name") else str(item.get("name",""))
            if item is not master_item and name != master: rename.setdefault(kind, {})[name]=master
        filtered=[]; master_seen=False
        for item in collection:
            if item is master_item:
                if master_seen: continue
                master_seen=True; filtered.append(item)
            elif id(item) in member_ids: continue
            else: filtered.append(item)
        if kind in result.extras: result.extras[kind]=filtered
        else: setattr(result,kind,filtered)
    return _rewrite_typed_references(result, rename) if rename else result


def _address_network_resolver(model: MigrationModel):
    """Expand every member, failing closed on unknown, cyclic or conflicting names."""
    addresses: dict[str, list[Address]] = {}
    groups: dict[str, list[AddressGroup]] = {}
    for item in model.addresses:
        addresses.setdefault(item.name, []).append(item)
    for item in model.address_groups:
        groups.setdefault(item.name, []).append(item)

    def expand(values: list[str], seen: frozenset[str] = frozenset()):
        networks = []
        for value in values:
            if value in {"any", "original"} or value in seen:
                return None
            if value in groups:
                definitions = {tuple(item.members) for item in groups[value]}
                if value in addresses or len(definitions) != 1:
                    return None
                nested = expand(list(next(iter(definitions))), seen | {value})
                if not nested:
                    return None
                networks.extend(nested)
                continue
            if value in addresses:
                definitions = {(item.value_type, item.value) for item in addresses[value]}
                if len(definitions) != 1:
                    return None
                kind, candidate = next(iter(definitions))
                if kind != "ip_netmask":
                    return None
            else:
                candidate = value
            try:
                networks.append(ipaddress.ip_network(candidate, strict=False))
            except ValueError:
                return None
        return networks or None

    return expand


def _network_path(network, topology):
    """Resolve the entire address range, including more-specific exceptions.

    Empty paths represent known but unmapped interfaces/routes.  Keeping these
    in the table prevents an assigned aggregate/default from hiding them.
    """
    covering = [(target.prefixlen, path) for target, path in topology
                if target.version == network.version and network.subnet_of(target)]
    if not covering:
        return None
    longest = max(prefix for prefix, _ in covering)
    paths = {path for prefix, path in covering if prefix == longest}
    paths.update(path for target, path in topology
                 if target.version == network.version and target.subnet_of(network)
                 and target.prefixlen > longest)
    return next(iter(paths)) if len(paths) == 1 and None not in paths else None


def _apply_interface_zone_assignments(model: MigrationModel, rules: list[dict]) -> MigrationModel:
    """Create assigned PAN-OS zones and infer rule zones from source subnets.

    The imported interface remains a Check Point topology record until the
    operator maps it to a target interface.  Only address/group values fully
    contained by one longest-prefix interface network are mapped.  Ambiguous or
    unknown paths stay ``any`` for manual review.
    """
    result = MigrationModel.from_dict(model.as_dict())
    topology = {
        str(rule.get("selector", "")): (
            str(rule.get("operation", "")), str(rule.get("value", "")).strip()
        )
        for rule in rules
        if str(rule.get("kind", "")) == "interfaces"
        and str(rule.get("operation", "")).startswith("topology_")
    }
    assignments: dict[str, tuple[str, bool]] = {}
    for rule in rules:
        if str(rule.get("operation", "")) != "set_interface_zone" or str(rule.get("kind", "")) != "interfaces":
            continue
        selector = str(rule.get("selector", ""))
        try:
            payload = json.loads(str(rule.get("value", "")) or "{}")
        except json.JSONDecodeError:
            payload = {"zone": str(rule.get("value", "")), "create": True}
        zone = str(payload.get("zone", "")).strip() if isinstance(payload, dict) else ""
        if zone:
            assignments[selector] = (zone, bool(payload.get("create", True)))
    if not assignments:
        return result

    interface_zones = []
    new_zone_members: dict[str, list[str]] = {}
    for interface in result.interfaces:
        selector = item_selector(interface)
        zone, create_zone = assignments.get(selector, ("", False))
        decision, target = topology.get(selector, ("topology_review", ""))
        # A source topology label is not a valid PAN-OS target interface.  The
        # explicit mapping must exist before either export or inference uses it.
        effective_interface = target if decision == "topology_map" else ""
        if decision == "topology_create":
            effective_interface = target or str(interface.get("name", ""))
        assigned_zone = zone if effective_interface and zone else None
        for value in interface.get("source_networks", []):
            try:
                interface_zones.append((ipaddress.ip_network(str(value), strict=False), assigned_zone))
            except ValueError:
                continue
        if create_zone and effective_interface:
            new_zone_members.setdefault(zone, []).append(effective_interface)

    existing_zones = {str(item.get("name", "")) for item in result.zones}
    for zone, members in sorted(new_zone_members.items(), key=lambda item: item[0].casefold()):
        if zone in existing_zones:
            continue
        entry = ET.Element("entry", {"name": zone})
        layer3 = ET.SubElement(ET.SubElement(entry, "network"), "layer3")
        for member in unique(members):
            ET.SubElement(layer3, "member").text = member
        result.zones.append({
            "name": zone,
            "xml": ET.tostring(entry, encoding="unicode"),
            "source_ref": "Interface zone assignment",
            "auto_generated": True,
            "mapping_action": "create",
        })
        existing_zones.add(zone)

    expand = _address_network_resolver(result)

    def infer(values: list[str]) -> list[str] | None:
        networks = expand(values)
        if not networks:
            return None
        zones: list[str] = []
        for network in networks:
            zone = _network_path(network, interface_zones)
            if not zone:
                return None
            zones.append(zone)
        return unique(zones)

    mapped_sides = 0
    for policy in [*result.security_rules, *result.nat_rules]:
        source_zones = None if policy.original.get("source-negate") else infer(policy.source)
        destination_zones = None if policy.original.get("destination-negate") else infer(policy.destination)
        if policy.policy_type == "security" and any(
            rule.destination_translation and not rule.disabled for rule in result.nat_rules
        ):
            # Security uses post-NAT zones with pre-NAT addresses.  Source
            # connected networks alone cannot establish which DNAT rule wins.
            destination_zones = None
        if source_zones and policy.from_zones == ["any"]:
            policy.from_zones = source_zones
            mapped_sides += 1
        if destination_zones and policy.to_zones == ["any"]:
            policy.to_zones = destination_zones
            mapped_sides += 1
    if mapped_sides:
        result.warnings.append(
            f"Interfacezonemapping: {mapped_sides} policyzijden automatisch ingevuld via eenduidige longest-prefix matching"
        )
    return result


def apply_transform_rules(model: MigrationModel, rules: list[dict]) -> MigrationModel:
    result=_apply_interface_zone_assignments(model, rules); replacements={}
    for rule in rules:
        operation=str(rule.get("operation","")); kind=str(rule.get("kind","")); selector=str(rule.get("selector","")); value=str(rule.get("value",""))
        collection=model_collections(result).get(kind,[])
        if operation in {"rename","delete","disable","enable"}:
            item=selector_item(collection,selector)
            if item is not None:
                old=item.name if hasattr(item,"name") else str(item.get("name",""))
                if operation=="delete": collection.remove(item)
                elif operation=="rename" and value:
                    if hasattr(item,"name"): item.name=value
                    else:
                        item["name"]=value
                        try:
                            entry=SafeET.fromstring(item.get("xml","")); entry.set("name",value); item["xml"]=ET.tostring(entry,encoding="unicode")
                        except Exception: pass
                    replacements.setdefault(kind, {})[old]=value
                elif hasattr(item,"disabled"): item.disabled=operation=="disable"
        elif operation == "bulk_rename" and kind in model_collections(result):
            try:
                settings = json.loads(value or "{}")
            except json.JSONDecodeError:
                continue
            query = str(settings.get("query", "")).casefold()
            prefix = str(settings.get("prefix", ""))
            suffix = str(settings.get("suffix", ""))
            search = str(settings.get("search", ""))
            replace = str(settings.get("replace", ""))
            for item in list(collection):
                old = item.name if hasattr(item, "name") else str(item.get("name", ""))
                if query and query not in old.casefold():
                    continue
                middle = old.replace(search, replace) if search else old
                new = f"{prefix}{middle}{suffix}"[:63]
                if not new or new == old:
                    continue
                if hasattr(item, "name"):
                    item.name = new
                else:
                    item["name"] = new
                    try:
                        entry = SafeET.fromstring(item.get("xml", ""))
                        entry.set("name", new)
                        item["xml"] = ET.tostring(entry, encoding="unicode")
                    except Exception:
                        pass
                replacements.setdefault(kind, {})[old] = new
        elif operation == "set_interface_zone":
            continue
        elif operation in {"topology_map", "topology_create", "topology_ignore", "topology_review"}:
            item = selector_item(collection, selector)
            if item is None:
                continue
            old = item.name if hasattr(item, "name") else str(item.get("name", ""))
            if operation == "topology_map" and value:
                replacements.setdefault(kind, {})[old] = value
                collection.remove(item)
            elif operation == "topology_create" and kind == "interfaces" and value:
                item["name"] = value
                item["interface_type"] = "ethernet"
                try:
                    entry = SafeET.fromstring(item.get("xml", ""))
                    entry.set("name", value)
                    item["xml"] = ET.tostring(entry, encoding="unicode")
                except (ET.ParseError, ValueError) as exc:
                    raise MigrationError("Ongeldige broninterfaceconfiguratie") from exc
                replacements.setdefault(kind, {})[old] = value
            elif operation == "topology_ignore":
                collection.remove(item)
            elif operation == "topology_review":
                result.warnings.append(f"Topologiemapping vereist review: {kind} {old}")
        elif operation in {"set_from_zones", "set_to_zones"} and kind in {"security_rules", "nat_rules"}:
            item = selector_item(collection, selector)
            if item is None:
                continue
            try:
                zones = unique(str(zone).strip() for zone in json.loads(value or "[]") if str(zone).strip())
            except (json.JSONDecodeError, TypeError):
                zones = unique(zone.strip() for zone in value.split(",") if zone.strip())
            if zones:
                setattr(item, "from_zones" if operation == "set_from_zones" else "to_zones", zones)
        elif operation=="replace_reference" and selector and value:
            replacements.setdefault(kind or "*", {})[selector]=value
    return _rewrite_typed_references(result, replacements) if replacements else result


def migration_analysis(model: MigrationModel) -> dict:
    """Conservative project health analysis used by the Expedition-style toolbox."""
    address_names={item.name for item in model.addresses}; service_names={item.name for item in model.services}
    group_names={item.name for item in model.address_groups}; service_group_names={item.name for item in model.service_groups}
    used_addresses=set(); used_services=set(); used_applications=set(); unresolved=set(); duplicate_rules=[]; rule_signatures={}
    unsupported_applications = set()
    for message in model.unsupported:
        match = re.search(
            r"Check Point (?:application-site(?:-category|-group)?|service-(?:icmp6?|other)) (.+?) vereist application/user mapping$",
            message,
        )
        if match:
            unsupported_applications.add(match.group(1))

    def translation_addresses(value) -> list[str]:
        found=[]
        if not isinstance(value,dict): return found
        for key,child in value.items():
            normalized=str(key).replace("-","_")
            if normalized=="translated_address":
                if isinstance(child,list): found.extend(str(item) for item in child if str(item))
                elif child not in (None,""): found.append(str(child))
            elif isinstance(child,dict): found.extend(translation_addresses(child))
        return found

    for group in model.address_groups:
        used_addresses.update(value for value in group.members if value not in {"any", "original"})
    for group in model.service_groups:
        used_services.update(value for value in group.members if value not in {"any", "application-default"})
    for attr in ("security_rules","nat_rules"):
        for rule in getattr(model,attr):
            used_addresses.update(value for value in rule.source+rule.destination if value!="any")
            if attr=="nat_rules":
                used_addresses.update(value for value in translation_addresses(rule.source_translation) if value not in {"any", "original"})
                used_addresses.update(value for value in translation_addresses(rule.destination_translation) if value not in {"any", "original"})
            used_services.update(value for value in rule.service if value not in {"any","application-default"})
            used_applications.update(value for value in rule.application if value != "any")
            signature=json.dumps({
                "policy_type":rule.policy_type,"from":rule.from_zones,"to":rule.to_zones,
                "source":rule.source,"destination":rule.destination,"application":rule.application,
                "service":rule.service,"action":rule.action,"translation":[rule.source_translation,rule.destination_translation],
            },sort_keys=True,separators=(",",":"),default=str)
            if signature in rule_signatures: duplicate_rules.append({"kind":attr,"master":rule_signatures[signature],"duplicate":rule.name})
            else: rule_signatures[signature]=rule.name
    known_addresses=address_names|group_names
    for value in used_addresses:
        try: ipaddress.ip_network(value,strict=False); continue
        except ValueError: pass
        if value not in known_addresses: unresolved.add(value)
    known_services=service_names|service_group_names
    for value in used_services:
        if value not in known_services and not re.match(r"^(tcp|udp)-\d",value,re.I): unresolved.add(value)
    unresolved.update(value for value in used_applications if value in unsupported_applications)
    return {
        "unused_addresses":sorted(address_names-used_addresses),
        "unused_address_groups":sorted(group_names-used_addresses),
        "unused_services":sorted(service_names-used_services),
        "unused_service_groups":sorted(service_group_names-used_services),
        "unresolved_references":sorted(unresolved), "duplicate_rules":duplicate_rules,
    }


def migration_health_dashboard(model: MigrationModel) -> dict:
    """Project-wide health counters with stable filter anchors for the UI."""
    analysis = migration_analysis(model)
    duplicates = merge_inventory(model)
    unused = sum(
        len(analysis[key])
        for key in (
            "unused_addresses", "unused_address_groups",
            "unused_services", "unused_service_groups",
        )
    )
    disabled = sum(rule.disabled for rule in [*model.security_rules, *model.nat_rules])
    counters = {
        "duplicates": len(duplicates),
        "disabled": disabled,
        "unused": unused,
        "invalid": len(analysis["unresolved_references"]),
        "ghost": len(model.unsupported),
        "warnings": len(model.warnings),
    }
    return {
        "counters": counters,
        "total": sum(len(items) for items in model_collections(model).values()),
        "status": "blocked" if counters["invalid"] or counters["ghost"] else "review",
        "analysis": analysis,
    }


def migration_best_practices(model: MigrationModel) -> dict:
    """Conservative post-parse checks; these never claim the candidate is safe."""
    policies = [*model.security_rules, *model.nat_rules]
    checks = []

    def add(code: str, title: str, passed: bool, detail: str, count: int = 0, remediable: bool = False, informational: bool = False):
        checks.append({
            "code": code, "title": title, "passed": bool(passed),
            "detail": detail, "count": int(count), "remediable": bool(remediable),
            "informational": bool(informational),
        })

    enabled = sum(not rule.disabled for rule in policies)
    add(
        "policy-state-review", "Enabled/disabled-status",
        enabled == 0,
        f"{enabled} enabled en {len(policies) - enabled} disabled. De bronstatus behouden is toegestaan; "
        "controleer enabled regels vóór push. Alle security policies disabled maken is een optionele importoverride.",
        informational=True,
    )
    any_service = sum("any" in rule.service for rule in model.security_rules)
    add(
        "service-any", "Geen brede service any",
        any_service == 0, "Vervang brede services waar applicatie-default of een expliciete service mogelijk is.",
        any_service,
    )
    any_application = sum("any" in rule.application for rule in model.security_rules)
    add(
        "application-any", "App-ID beoordeeld",
        any_application == 0, "Rules met application any vereisen App-ID review of een bewuste uitzondering.",
        any_application,
    )
    any_zone = sum("any" in rule.from_zones or "any" in rule.to_zones for rule in policies)
    add(
        "zone-specific", "Zones expliciet gemapt",
        any_zone == 0, "Rules met zone any kunnen op ontbrekende vendorcontext wijzen.", any_zone,
    )
    unnamed = sum(not rule.description.strip() for rule in model.security_rules)
    add(
        "descriptions", "Security rules beschreven",
        unnamed == 0, "Een migratiebeschrijving maakt intentie en review achteraf traceerbaar.", unnamed,
    )
    analysis = migration_analysis(model)
    add(
        "references", "Alle referenties opgelost",
        not analysis["unresolved_references"], "Object-, service- en application-referenties moeten bestaan op het target.",
        len(analysis["unresolved_references"]),
    )
    return {
        "checks": checks,
        "passed": sum(item["passed"] and not item["informational"] for item in checks),
        "failed": sum(not item["passed"] and not item["informational"] for item in checks),
        "remediable": sum(item["remediable"] and not item["passed"] and not item["informational"] for item in checks),
    }


def migration_discovery(model: MigrationModel) -> dict:
    """Offline discovery hints from the imported configuration itself."""
    networks = set()
    fqdns = set()
    for item in model.addresses:
        try:
            network = ipaddress.ip_network(item.value, strict=False)
            networks.add(str(network))
        except ValueError:
            if item.value_type == "fqdn" or re.search(r"[A-Za-z]", item.value):
                fqdns.add(item.value)
    applications = sorted({value for rule in model.security_rules for value in rule.application if value != "any"})
    zones = sorted({value for rule in [*model.security_rules, *model.nat_rules] for value in [*rule.from_zones, *rule.to_zones] if value != "any"})
    return {
        "networks": sorted(networks, key=lambda value: (ipaddress.ip_network(value).version, ipaddress.ip_network(value).network_address, ipaddress.ip_network(value).prefixlen)),
        "fqdns": sorted(fqdns, key=str.casefold),
        "applications": applications,
        "zones": zones,
    }


def panos_candidate_analysis(
    content: bytes | str,
    predefined_applications: Iterable[str] | None = None,
) -> dict:
    """Validate references in the complete merged PAN-OS/Panorama candidate.

    Project analysis only covers selected migration sources. A target base can
    already contain broken references, so output sanity must inspect the final
    XML rather than assuming that the base is commit-valid.
    """
    raw = content.encode() if isinstance(content, str) else content
    model = parse_vendor("panos", raw, "candidate.xml")
    analysis = migration_analysis(model)
    try:
        root = SafeET.fromstring(raw)
    except Exception as exc:
        raise MigrationError(f"Ongeldige PAN-OS candidate XML: {exc}") from exc

    application_definitions = {
        "any", *CheckPointParser.PANOS_APPLICATION_ALIASES.values(),
        *(str(value) for value in (predefined_applications or []) if str(value)),
    }
    for path in (
        "./predefined/application/entry",
        "./predefined/application-container/entry",
        "./shared/application/entry",
        "./shared/application-group/entry",
        "./shared/application-filter/entry",
        "./devices/entry/vsys/entry/application/entry",
        "./devices/entry/vsys/entry/application-group/entry",
        "./devices/entry/vsys/entry/application-filter/entry",
        "./devices/entry/device-group/entry/application/entry",
        "./devices/entry/device-group/entry/application-group/entry",
        "./devices/entry/device-group/entry/application-filter/entry",
    ):
        application_definitions.update(
            entry.get("name", "") for entry in root.findall(path) if entry.get("name")
        )
    application_references = set()
    for rulebase in ("rulebase", "pre-rulebase", "post-rulebase"):
        application_references.update(
            (member.text or "").strip()
            for member in root.findall(f".//{rulebase}/*/rules/entry/application/member")
            if (member.text or "").strip()
        )
    unresolved_applications = sorted(application_references - application_definitions)
    # PAN-OS zone names are local to a VSYS. A zone that exists in vsys1 does
    # not make a policy reference in vsys2 valid; checking a device-wide union
    # would hide precisely the multi-VSYS error the candidate validator must
    # catch. Panorama rules are excluded here because their effective zones are
    # resolved through device-group/template relationships, not this XML node.
    unresolved_zones = []
    for device in root.findall("./devices/entry"):
        for vsys in device.findall("./vsys/entry"):
            vsys_name = str(vsys.get("name", "")).strip() or "<unnamed-vsys>"
            zone_names = {
                str(entry.get("name", "")).strip()
                for entry in vsys.findall("./zone/entry")
                if str(entry.get("name", "")).strip()
            }
            for rulebase_name in ("rulebase", "pre-rulebase", "post-rulebase"):
                for rule in vsys.findall(f"./{rulebase_name}/*/rules/entry"):
                    rule_name = str(rule.get("name", "")).strip() or "<unnamed-rule>"
                    for field in ("from", "to"):
                        for member in rule.findall(f"./{field}/member"):
                            zone = str(member.text or "").strip()
                            if zone and zone.casefold() != "any" and zone not in zone_names:
                                unresolved_zones.append(
                                    f"vsys {vsys_name}: {rule_name} -> {field} -> {zone}"
                                )
    analysis["unresolved_application_references"] = unresolved_applications
    analysis["unresolved_zone_references"] = sorted(set(unresolved_zones), key=str.casefold)
    analysis["unresolved_references"] = sorted(
        set(analysis["unresolved_references"])
        | set(unresolved_applications)
        | set(analysis["unresolved_zone_references"])
    )
    return analysis


def _migration_topology_owners(content, scope, panorama):
    """Return only the target's unambiguous Network and VSYS owners."""
    from app.offline_config import parse_snapshot, referenced_template, _config_roots
    raw = content.encode() if isinstance(content, str) else content
    root, snapshot = parse_snapshot(raw)
    if panorama:
        # A same-named interface in a different template is a different device.
        # Resolve only this DG's inherited reference, never all templates.
        template = referenced_template(snapshot, scope)
        owners = _config_roots(root, snapshot, scope, template) if template else []
        # Template-stack overrides require an effective-config merge.  Until
        # that is available, do not guess from one member or blend its peers.
        network_owners = owners[0][1].findall("./config/devices/entry") if len(owners) == 1 else []
        zone_owners = [vsys for owner in network_owners for vsys in owner.findall("./vsys/entry")]
        if len(zone_owners) != 1:
            zone_owners, network_owners = [], []
    else:
        network_owners = [owner for owner in root.findall("./devices/entry")
                          if any(vsys.get("name") == scope for vsys in owner.findall("./vsys/entry"))]
        zone_owners = [vsys for owner in network_owners for vsys in owner.findall("./vsys/entry")
                       if vsys.get("name") == scope]
    return network_owners, zone_owners


def migration_topology_targets(content: bytes | str, scope: str = "vsys1", panorama: bool = False) -> dict[str, list[str]]:
    """Existing topology names in exactly the selected target context."""
    network_owners, zone_owners = _migration_topology_owners(content, scope, panorama)
    targets = {"interfaces": [], "zones": [], "vlans": [], "virtual_routers": [], "logical_routers": []}
    for owner in network_owners:
        for entry in owner.findall("./network/interface/*/entry"):
            targets["interfaces"].append(entry.get("name", ""))
            targets["interfaces"].extend(unit.get("name", "") for unit in entry.findall(".//units/entry"))
        targets["interfaces"].extend(entry.get("name", "") for entry in owner.findall("./network/interface/*/units/entry"))
        for kind, path in (("vlans", "vlan"), ("virtual_routers", "virtual-router"), ("logical_routers", "logical-router")):
            targets[kind].extend(entry.get("name", "") for entry in owner.findall(f"./network/{path}/entry"))
    targets["zones"] = [entry.get("name", "") for owner in zone_owners for entry in owner.findall("./zone/entry")]
    return {kind: sorted(unique(names), key=str.casefold) for kind, names in targets.items()}


def migration_interface_zone_memberships(content: bytes | str, scope: str = "vsys1", panorama: bool = False) -> dict[str, list[str]]:
    """Actual zone attachments, for validating interface-zone assignments."""
    _, zone_owners = _migration_topology_owners(content, scope, panorama)
    memberships: dict[str, list[str]] = {}
    for owner in zone_owners:
        for zone in owner.findall("./zone/entry"):
            for member in zone.findall("./network/*/member"):
                name = (member.text or "").strip()
                if name and zone.get("name"):
                    memberships.setdefault(name, []).append(zone.get("name"))
    return {name: unique(zones) for name, zones in memberships.items()}


def auto_map_nat_topology(
    content: bytes | str,
    model: MigrationModel,
    scope: str = "vsys1",
    panorama: bool = False,
) -> dict[str, object]:
    """Infer NAT topology only if every address follows one target path.

    Unknown addresses, competing paths and unresolved scopes remain review-only.
    Explicitly selected zones and interfaces are preserved.
    """
    network_owners, zone_owners = _migration_topology_owners(content, scope, panorama)
    result = {"mapped": 0, "review": 0, "details": []}

    interface_zones: dict[str, set[str]] = {}
    for owner in zone_owners:
        for zone in owner.findall("./zone/entry"):
            zone_name = zone.get("name", "")
            for member in zone.findall("./network/*/member"):
                if zone_name and (member.text or "").strip():
                    interface_zones.setdefault((member.text or "").strip(), set()).add(zone_name)

    connected = []
    routes = []
    scoped_interfaces = set(interface_zones)

    def path_for(interface_name):
        zones = interface_zones.get(interface_name, set())
        return (next(iter(zones)), interface_name) if len(zones) == 1 else None

    for owner in network_owners:
        for entry in owner.findall("./network/interface/*/entry") + owner.findall("./network/interface/*/units/entry"):
            base_name = entry.get("name", "")
            candidates = [(base_name, entry)]
            candidates.extend((unit.get("name", ""), unit) for unit in entry.findall(".//units/entry"))
            for interface_name, node in candidates:
                for ip_entry in node.findall("./layer3/ip/entry") + node.findall("./ip/entry"):
                    value = ip_entry.get("name", "")
                    try:
                        connected.append((ipaddress.ip_interface(value).network, path_for(interface_name)))
                    except ValueError:
                        continue
        routers = owner.findall("./network/virtual-router/entry")
        eligible = [router for router in routers
                    if scoped_interfaces.intersection(member.text for member in router.findall("./interface/member"))]
        # Some imported minimal bases omit VR membership; one router is safe
        # to inspect, but several unidentified routing domains are not.
        if not eligible and len(routers) == 1:
            eligible = routers
        for router in eligible:
            route_entries = router.findall("./routing-table/ip/static-route/entry")
            route_entries += router.findall("./routing-table/ipv6/static-route/entry")
            for route in route_entries:
                candidate = route.findtext("destination") or ""
                try:
                    network = ipaddress.ip_network(candidate, strict=False)
                except ValueError:
                    continue
                routes.append((network, path_for(route.findtext("interface") or "")))

    expand = _address_network_resolver(model)

    def infer(values: list[str], destination: bool = False):
        networks = expand(values)
        if not networks:
            return None
        topology = connected + routes if destination else connected
        paths = set()
        for network in networks:
            path = _network_path(network, topology)
            if path is None:
                return None
            paths.add(path)
        return next(iter(paths)) if len(paths) == 1 else None

    for rule in model.nat_rules:
        # Do not turn a deliberately ignored/mapped rule back into a create.
        if rule.mapping_action in {"ignore", "map"}:
            continue
        source_target = None if rule.original.get("source-negate") else infer(rule.source)
        destination_target = None if rule.original.get("destination-negate") else infer(rule.destination, True)
        if source_target and rule.from_zones == ["any"]:
            rule.from_zones = [source_target[0]]
        if (destination_target and rule.to_zones == ["any"]
                and rule.to_interface in {"any", destination_target[1]}):
            rule.to_zones = [destination_target[0]]
            if rule.to_interface == "any":
                rule.to_interface = destination_target[1]
        if "any" in rule.to_zones:
            rule.mapping_action = "review"
            rule.description = CheckPointParser._review_description(
                rule.description,
                ["NAT destinationzone/interface kon niet eenduidig uit de targettopologie worden afgeleid"],
            )
            result["review"] += 1
            result["details"].append({"name": rule.name, "reason": "destination topology unresolved"})
        else:
            rule.mapping_action = "create"
            result["mapped"] += 1
    return result


def migration_review_findings(model: MigrationModel) -> dict:
    """Return the mandatory, conservative review gate for a migration model.

    This deliberately does not decide that a migration is safe.  It highlights
    what can be detected automatically and always requires a human engineer to
    acknowledge the complete candidate before it can be written.
    """
    analysis = migration_analysis(model)
    findings: list[dict[str, object]] = []

    def review_item(kind: str, item) -> dict[str, str]:
        raw = asdict(item) if hasattr(item, "__dataclass_fields__") else dict(item)
        return {
            "kind": kind,
            "name": str(raw.get("name", "")),
            "source_ref": str(raw.get("source_ref", "")),
            "selector": item_selector(raw),
        }

    def add(
        severity: str,
        code: str,
        title: str,
        detail: str,
        count: int = 0,
        affected: list[dict[str, str]] | None = None,
        anchor: str = "best-practices",
    ) -> None:
        findings.append({
            "severity": severity,
            "code": code,
            "title": title,
            "detail": detail,
            "count": int(count),
            "affected": (affected or [])[:100],
            "anchor": anchor,
        })

    unresolved = len(analysis["unresolved_references"])
    if unresolved:
        unresolved_names = set(analysis["unresolved_references"])
        affected = []
        for kind, groups in (("address_groups", model.address_groups), ("service_groups", model.service_groups)):
            affected.extend(review_item(kind, group) for group in groups if unresolved_names.intersection(group.members))
        for kind, rules in (("security_rules", model.security_rules), ("nat_rules", model.nat_rules)):
            affected.extend(
                review_item(kind, rule)
                for rule in rules
                if unresolved_names.intersection([*rule.source, *rule.destination, *rule.service, *rule.application])
            )
        add(
            "critical", "unresolved-references", "Onopgeloste referenties",
            "Objecten, services of groepen ontbreken nog op het doel en moeten worden gemapt.", unresolved,
            affected,
        )

    invalid_fqdns = model.extras.get("migration_review_items", [])
    if invalid_fqdns:
        add(
            "critical", "invalid-fqdn-review", "URL-achtige FQDN-objecten nakijken",
            "Deze bronwaarden bevatten een URL-pad of ongeldige hostnaam en zijn niet naar PAN-OS geschreven.",
            len(invalid_fqdns),
            [{
                "kind": "addresses", "name": str(item.get("name", "")),
                "source_ref": str(item.get("source_ref", "")),
                "selector": str(item.get("name", "")),
            } for item in invalid_fqdns],
        )

    if model.unsupported:
        add(
            "critical", "unsupported-items", "Niet automatisch geconverteerd",
            "Niet-ondersteunde configuratie is niet stilzwijgend meegenomen en vereist een handmatige beslissing.",
            len(model.unsupported),
        )

    unsupported_actions = sum(
        1 for message in model.warnings if "niet-ondersteunde Check Point actie" in message
    )
    if unsupported_actions:
        affected = [
            review_item("security_rules", rule)
            for rule in model.security_rules
            if "REVIEW: actie" in rule.description
        ]
        add(
            "critical", "unsupported-actions", "Policy-acties niet gemapt",
            "Deze regels zijn veiligheidshalve disabled; kies voor elke regel bewust de correcte actie.",
            unsupported_actions, affected,
        )

    unresolved_nat_topology = [
        rule for rule in model.nat_rules if rule.mapping_action == "review" or "any" in rule.to_zones
    ]
    if unresolved_nat_topology:
        add(
            "critical", "nat-topology-unresolved", "NAT-topologie niet eenduidig",
            "Deze NAT-regels zijn niet naar de candidate geschreven totdat destinationzone en interface gemapt zijn.",
            len(unresolved_nat_topology),
            [review_item("nat_rules", rule) for rule in unresolved_nat_topology],
            "topology-mapping",
        )

    policies = [*model.security_rules, *model.nat_rules]
    any_zone_rules = sum(
        1 for rule in policies
        if "any" in rule.from_zones or "any" in rule.to_zones
    )
    if any_zone_rules:
        severity = "critical" if policies and any_zone_rules == len(policies) else "warning"
        affected = [
            review_item(kind, rule)
            for kind, rules in (("security_rules", model.security_rules), ("nat_rules", model.nat_rules))
            for rule in rules
            if "any" in rule.from_zones or "any" in rule.to_zones
        ]
        add(
            severity, "zone-mapping", "Zone-mapping nakijken",
            "Policies met een bron- of doelzone 'any' kunnen uit ontbrekende vendorcontext komen.", any_zone_rules,
            affected, "topology-mapping",
        )

    if model.nat_rules:
        add(
            "warning", "nat-review", "NAT handmatig valideren",
            "Controleer volgorde, interfaces, vertaalmethode, adressen en poorten op het doel.", len(model.nat_rules),
        )
        known_interfaces = {
            str(item.get("name", "")).strip()
            for item in model.interfaces
            if str(item.get("name", "")).strip()
        }
        missing_nat_interfaces = []
        for rule in model.nat_rules:
            translation = rule.source_translation or {}
            mode = next(iter(translation), "")
            details = translation.get(mode, {}) if isinstance(translation, dict) else {}
            interface_address = details.get("interface_address") or details.get("interface-address") or {} if isinstance(details, dict) else {}
            interface_name = str(interface_address.get("interface", "") or "").strip() if isinstance(interface_address, dict) else ""
            if interface_name and interface_name not in known_interfaces:
                missing_nat_interfaces.append(f"{rule.name}: {interface_name}")
        if missing_nat_interfaces:
            analysis["unresolved_nat_interfaces"] = missing_nat_interfaces
            missing_rule_names = {item.split(":", 1)[0] for item in missing_nat_interfaces}
            add(
                "critical", "nat-interface-mapping", "NAT-interface ontbreekt",
                "Een source-NAT interface-address verwijst niet naar een gemigreerde PAN-OS-interface. Map eerst de doelinterface.",
                len(missing_nat_interfaces),
                [review_item("nat_rules", rule) for rule in model.nat_rules if rule.name in missing_rule_names],
                "topology-mapping",
            )

    duplicate_rules = len(analysis["duplicate_rules"])
    if duplicate_rules:
        duplicate_names = {item["duplicate"] for item in analysis["duplicate_rules"]}
        add(
            "warning", "duplicate-policies", "Mogelijk dubbele policies",
            "Exact gelijke signatures worden getoond, maar worden niet automatisch verwijderd.", duplicate_rules,
            [
                review_item(kind, rule)
                for kind, rules in (("security_rules", model.security_rules), ("nat_rules", model.nat_rules))
                for rule in rules if rule.name in duplicate_names
            ],
        )

    skipped_crypto = any("Fortinet cryptomateriaal overgeslagen" in message for message in model.warnings)
    if skipped_crypto:
        add(
            "warning", "fortinet-crypto-reentry", "Certificaten en sleutels opnieuw ingeven",
            "Fortinet certificaten, private keys en SSH keys zijn bewust niet gekopieerd of ontsleuteld.",
        )

    other_warnings = sum(
        1 for message in model.warnings
        if "niet-ondersteunde Check Point actie" not in message
        and "Fortinet cryptomateriaal overgeslagen" not in message
    )
    if other_warnings:
        add(
            "warning", "parser-warnings", "Parsermeldingen nakijken",
            "De bron bevat velden of context die niet volledig automatisch konden worden beoordeeld.", other_warnings,
        )

    disabled_rules = sum(1 for rule in policies if rule.disabled)
    if disabled_rules:
        add(
            "info", "disabled-policies", "Disabled policies",
            "Controleer of deze regels disabled moeten blijven op het doel.", disabled_rules,
            [
                review_item(kind, rule)
                for kind, rules in (("security_rules", model.security_rules), ("nat_rules", model.nat_rules))
                for rule in rules if rule.disabled
            ],
        )

    add(
        "required", "engineer-review", "Volledige engineer review verplicht",
        "Automatische checks zijn geen validatie van policy-intentie, rule order, routing, NAT of bereikbaarheid.",
    )
    return {
        "status": "review_required",
        "ready_for_push": False,
        "findings": findings,
        "critical": sum(1 for item in findings if item["severity"] == "critical"),
        "warnings": sum(1 for item in findings if item["severity"] == "warning"),
        "analysis": analysis,
    }


def migration_zone_names(model: MigrationModel) -> list[str]:
    """Return configured and policy-referenced zones in stable order."""
    return unique(
        [
            str(item.get("name", "")).strip()
            for item in model.zones
            if str(item.get("name", "")).strip()
        ]
        + [
            value
            for rule in [*model.security_rules, *model.nat_rules]
            for value in [*rule.from_zones, *rule.to_zones]
            if value and value != "any"
        ]
    )


def migration_base_xml(
    model: MigrationModel,
    scope: str,
    panorama: bool = False,
    version: str = "12.1.0",
) -> bytes:
    """Build a conservative full-config base for an offline migration.

    The generated base contains only the requested VSYS or Device Group and
    empty zones inferred from policy references.  Interfaces are deliberately
    not guessed: they can be mapped in the resulting workspace before push.
    """
    scope = str(scope or "").strip()
    if not scope:
        raise MigrationError("Doelscope ontbreekt")
    configured_zones = {
        str(item.get("name", "")).strip() for item in model.zones if str(item.get("name", "")).strip()
    }
    inferred_zones = [name for name in migration_zone_names(model) if name not in configured_zones]
    network_kinds = {
        "vlans", "virtual_routers", "logical_routers", "virtual_wires",
        "ipsec_tunnels", "ike_gateways", "network_profiles",
        "globalprotect_portals", "globalprotect_gateways", "device_configuration",
    }
    needs_template = bool(
        panorama and (
            inferred_zones or model.interfaces or model.zones
            or any(model.extras.get(kind) for kind in network_kinds)
        )
    )

    root = ET.Element("config", {"version": version})
    devices = ET.SubElement(root, "devices")
    device = ET.SubElement(devices, "entry", {"name": "localhost.localdomain"})
    if panorama:
        device_groups = ET.SubElement(device, "device-group")
        target = ET.SubElement(device_groups, "entry", {"name": scope})
        ET.SubElement(target, "pre-rulebase")
        ET.SubElement(target, "post-rulebase")
        if needs_template:
            template_name = "PPF-Migration-Template"
            ET.SubElement(target, "reference-template").text = template_name
            templates = ET.SubElement(device, "template")
            template = ET.SubElement(templates, "entry", {"name": template_name})
            config = ET.SubElement(template, "config")
            template_devices = ET.SubElement(config, "devices")
            template_device = ET.SubElement(template_devices, "entry", {"name": "localhost.localdomain"})
            network = ET.SubElement(template_device, "network")
            interface = ET.SubElement(network, "interface")
            ET.SubElement(interface, "ethernet")
            vsys = ET.SubElement(template_device, "vsys")
            zone_owner = ET.SubElement(vsys, "entry", {"name": "vsys1"})
            if inferred_zones:
                zones = ET.SubElement(zone_owner, "zone")
                for zone_name in inferred_zones:
                    zone = ET.SubElement(zones, "entry", {"name": zone_name})
                    zone_network = ET.SubElement(zone, "network")
                    ET.SubElement(zone_network, "layer3")
    else:
        network = ET.SubElement(device, "network")
        interface = ET.SubElement(network, "interface")
        ET.SubElement(interface, "ethernet")
        vsys = ET.SubElement(device, "vsys")
        target = ET.SubElement(vsys, "entry", {"name": scope})
        if inferred_zones:
            zones = ET.SubElement(target, "zone")
            for zone_name in inferred_zones:
                zone = ET.SubElement(zones, "entry", {"name": zone_name})
                zone_network = ET.SubElement(zone, "network")
                ET.SubElement(zone_network, "layer3")
        ET.SubElement(target, "rulebase")
    ET.indent(root, space="  ")
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8") + b"\n"


def split_forti(value: str, any_alias: str = "") -> list[str]:
    values=unique(shlex.split(value)) or ["any"]
    return ["any" if any_alias and item==any_alias else clean_name(item) for item in values]


def unquote(value: str) -> str:
    try: return shlex.split(value)[0]
    except (ValueError,IndexError): return value.strip('"')


def panos_fragment(model: MigrationModel, scope: str = "vsys1", panorama: bool = False, rulebase: str = "pre") -> bytes:
    config=ET.Element("config",{"version":"11.0.0"}); devices=ET.SubElement(config,"devices"); device=ET.SubElement(devices,"entry",{"name":"localhost.localdomain"})
    if panorama:
        if scope == "Shared":
            target=ET.SubElement(config,"shared")
        else:
            groups=ET.SubElement(device,"device-group"); target=ET.SubElement(groups,"entry",{"name":scope})
        rb=ET.SubElement(target,f"{rulebase}-rulebase")
    else:
        vsyses=ET.SubElement(device,"vsys"); target=ET.SubElement(vsyses,"entry",{"name":scope}); rb=ET.SubElement(target,"rulebase")
    def members(parent,values):
        for value in values: ET.SubElement(parent,"member").text=value
    addresses=ET.SubElement(target,"address")
    for item in model.addresses:
        if item.mapping_action in {"review", "ignore"}: continue
        e=ET.SubElement(addresses,"entry",{"name":item.name}); ET.SubElement(e,item.value_type.replace("_","-")).text=item.value
        if item.description: ET.SubElement(e,"description").text=item.description
        if item.tags: members(ET.SubElement(e,"tag"),item.tags)
    groups=ET.SubElement(target,"address-group")
    for item in model.address_groups:
        if item.mapping_action in {"review", "ignore"}: continue
        e=ET.SubElement(groups,"entry",{"name":item.name}); members(ET.SubElement(e,"static"),item.members)
        if item.description: ET.SubElement(e,"description").text=item.description
        if item.tags: members(ET.SubElement(e,"tag"),item.tags)
    services=ET.SubElement(target,"service")
    for item in model.services:
        if item.mapping_action in {"review", "ignore"}: continue
        e=ET.SubElement(services,"entry",{"name":item.name}); p=ET.SubElement(ET.SubElement(e,"protocol"),item.protocol); ET.SubElement(p,"port").text=item.port
        if item.source_port: ET.SubElement(p,"source-port").text=item.source_port
        if item.description: ET.SubElement(e,"description").text=item.description
        if item.tags: members(ET.SubElement(e,"tag"),item.tags)
    service_groups=ET.SubElement(target,"service-group")
    for item in model.service_groups:
        if item.mapping_action in {"review", "ignore"}: continue
        e=ET.SubElement(service_groups,"entry",{"name":item.name}); members(ET.SubElement(e,"members"),item.members)
        if item.description: ET.SubElement(e,"description").text=item.description
        if item.tags: members(ET.SubElement(e,"tag"),item.tags)
    tag_items=model.extras.get("tags",[])
    if tag_items:
        tags=ET.SubElement(target,"tag")
        for item in tag_items:
            try: entry=SafeET.fromstring(str(item.get("xml", "")))
            except Exception as exc: raise MigrationError(f"Ongeldige tag XML voor {item.get('name','')}: {exc}") from exc
            entry.set("name",str(item.get("name",entry.get("name",""))))
            tags.append(copy.deepcopy(entry))
    def replace_members(entry, tag, values):
        for child in list(entry.findall(f"./{tag}")): entry.remove(child)
        members(ET.SubElement(entry,tag),values)
    def replace_text(entry, tag, value):
        for child in list(entry.findall(f"./{tag}")): entry.remove(child)
        if value is not None: ET.SubElement(entry,tag).text=str(value)
    for kind,rules in (("security",model.security_rules),("nat",model.nat_rules)):
        root=ET.SubElement(ET.SubElement(rb,kind),"rules")
        for rule in rules:
            if rule.mapping_action in {"review", "ignore"}: continue
            raw_xml=str(rule.original.get("xml", "")) if isinstance(rule.original,dict) else ""
            try: e=SafeET.fromstring(raw_xml) if raw_xml else ET.Element("entry")
            except Exception: e=ET.Element("entry")
            e.set("name",rule.name)
            untouched=bool(raw_xml and rule.original.get("normalized")==policy_state(rule))
            if untouched:
                root.append(e)
                continue
            for tag,values in (("from",rule.from_zones),("to",rule.to_zones),("source",rule.source),("destination",rule.destination)): replace_members(e,tag,values)
            if kind=="security":
                replace_members(e,"application",rule.application); replace_members(e,"service",rule.service); replace_text(e,"action",rule.action)
            else:
                replace_text(e,"service",(rule.service or ["any"])[0])
                replace_text(e,"nat-type",rule.nat_type or "ipv4")
                replace_text(e,"to-interface",rule.to_interface or "any")
                for child in list(e.findall("./source-translation")): e.remove(child)
                for child in list(e.findall("./destination-translation")): e.remove(child)
                if rule.source_translation:
                    st=ET.SubElement(e,"source-translation"); _append_xml_dict(st,rule.source_translation)
                if rule.destination_translation:
                    dt=ET.SubElement(e,"destination-translation"); _append_xml_dict(dt,rule.destination_translation)
            for child in list(e.findall("./tag")): e.remove(child)
            if rule.tags: members(ET.SubElement(e,"tag"),rule.tags)
            replace_text(e,"disabled","yes" if rule.disabled else "no")
            replace_text(e,"description",rule.description if rule.description else None)
            root.append(e)
    return ET.tostring(config,encoding="utf-8",xml_declaration=True)


def _append_xml_dict(parent: ET.Element, value) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            node=ET.SubElement(parent,str(key).replace("_","-")); _append_xml_dict(node,child)
    elif isinstance(value, list):
        for child in value: ET.SubElement(parent,"member").text=str(child)
    elif value is not None:
        parent.text=str(value)


def scm_items(model: MigrationModel) -> list[dict]:
    items=[]
    def route(item) -> dict:
        return {
            "target_context": str(getattr(item, "target_context", "")),
            "mapping_action": str(getattr(item, "mapping_action", "create") or "create"),
        }
    def metadata(item):
        return {**({"description": item.description} if item.description else {}),
                **({"tag": list(item.tags)} if item.tags else {})}
    for item in model.addresses:
        if item.mapping_action not in {"review", "ignore"}: items.append({"kind":"addresses","name":item.name,"payload":{"name":item.name,item.value_type:item.value,**metadata(item)},**route(item)})
    for item in model.address_groups:
        if item.mapping_action not in {"review", "ignore"}: items.append({"kind":"address-groups","name":item.name,"payload":{"name":item.name,"static":item.members,**metadata(item)},**route(item)})
    for item in model.services:
        if item.mapping_action not in {"review", "ignore"}: items.append({"kind":"services","name":item.name,"payload":{"name":item.name,"protocol":{item.protocol:{"port":item.port,**({"source_port":item.source_port} if item.source_port else {})}},**metadata(item)},**route(item)})
    for item in model.service_groups:
        if item.mapping_action not in {"review", "ignore"}: items.append({"kind":"service-groups","name":item.name,"payload":{"name":item.name,"members":item.members,**metadata(item)},**route(item)})
    for kind,rules in (("security",model.security_rules),("nat",model.nat_rules)):
        for rule in rules:
            if rule.mapping_action in {"review", "ignore"}: continue
            payload={"name":rule.name,"from":rule.from_zones,"to":rule.to_zones,"source":rule.source,"destination":rule.destination,"service":rule.service if kind=="security" else (rule.service or ["any"])[0],"disabled":rule.disabled}
            if kind=="security": payload.update({"application":rule.application,"action":rule.action})
            else: payload.update({"nat_type":rule.nat_type,"to_interface":rule.to_interface})
            if rule.tags: payload["tag"]=rule.tags
            if kind=="nat" and rule.source_translation: payload["source_translation"]=rule.source_translation
            if kind=="nat" and rule.destination_translation: payload["destination_translation"]=rule.destination_translation
            if rule.description: payload["description"]=rule.description
            items.append({"kind":f"policy:{kind}","name":rule.name,"payload":payload,**route(rule)})
    return items


def migration_api_plan(model: MigrationModel, target_type: str, target_context: str = "") -> list[dict]:
    """Create a review-only output plan; it never performs a target write."""
    actions = []
    if target_type == "scm":
        for item in model.extras.get("tags", []):
            actions.append({
                "method": "POST", "kind": "tags", "name": str(item.get("name", "")),
                "target": str(item.get("target_context") or target_context), "payload": raw_item_payload(item), "status": "staged",
            })
        for item in scm_items(model):
            kind = item["kind"]
            actions.append({
                "method": "POST", "kind": kind, "name": item["name"],
                "target": str(item.get("target_context") or target_context), "payload": item["payload"], "status": "staged",
            })
        for kind, items in model.extras.items():
            if kind == "tags":
                continue
            for item in items:
                actions.append({
                    "method": "POST", "kind": kind, "name": str(item.get("name", "")),
                    "target": str(item.get("target_context") or target_context), "payload": raw_item_payload(item), "status": "staged",
                })
    else:
        for row in migration_inventory_rows(model):
            actions.append({
                "method": "SET", "kind": row["kind"], "name": row["name"],
                "target": str(row["raw"].get("target_context") or target_context), "status": "staged",
            })
    return actions


def reuse_decision_key(kind: str, imported: str, existing: str, semantic: str) -> str:
    return hashlib.sha256(
        json.dumps([kind, imported, existing, semantic], separators=(",", ":")).encode()
    ).hexdigest()


def reuse_value_summary(value) -> str:
    if isinstance(value, ET.Element):
        parts = [
            f"{node.tag}={node.text.strip()}"
            for node in value.iter()
            if len(node) == 0 and node.text and node.text.strip()
        ]
        return " · ".join(parts)[:500]
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)[:500]


def reconcile_model(
    model: MigrationModel,
    existing: dict[str, list[dict]],
    approved_reuses: set[str] | None = None,
) -> tuple[MigrationModel, dict]:
    """Reuse same-name matches and require approval for cross-name equivalence."""
    result = MigrationModel.from_dict(model.as_dict())
    approved_reuses = set(approved_reuses or set())
    plan = {
        "create": 0,
        "reuse": 0,
        "conflicts": [],
        "renamed_references": {},
        "suggested_reuses": [],
    }
    reference_map: dict[str, str] = {}

    def mapping_action(kind: str, name: str) -> str:
        for item in model_collections(model).get(kind, []):
            raw_name = item.name if hasattr(item, "name") else str(item.get("name", ""))
            if raw_name != name:
                continue
            action = getattr(item, "mapping_action", None)
            if action is None and isinstance(item, dict):
                action = item.get("mapping_action")
            return str(action or "create")
        return "create"
    object_fields = {
        "addresses": ("ip_netmask", "ip_range", "ip_wildcard", "fqdn"),
        "address-groups": ("static", "dynamic"),
        "services": ("protocol",),
        "service-groups": ("members",),
    }
    attr_for_kind = {
        "addresses": "addresses", "address-groups": "address_groups",
        "services": "services", "service-groups": "service_groups",
    }

    def signature(item: dict, fields: tuple[str, ...]) -> str:
        return json.dumps({field: item.get(field) for field in fields if item.get(field) is not None}, sort_keys=True, separators=(",", ":"))

    mapped = {kind: [] for kind in object_fields}
    for item in scm_items(result):
        kind = item["kind"]
        if kind not in {"addresses", "services"}:
            continue
        fields = object_fields[kind]
        target_items = existing.get(kind, [])
        by_name = {str(value.get("name", "")): value for value in target_items}
        by_signature = {signature(value, fields): value for value in target_items}
        name = item["name"]; payload = item["payload"]; wanted = signature(payload, fields)
        mapping_action = str(item.get("mapping_action") or "create")
        if name in by_name:
            if signature(by_name[name], fields) != wanted:
                plan["conflicts"].append(f"{kind}: {name}")
            else:
                plan["reuse"] += 1
            continue
        equivalent = by_signature.get(wanted)
        if equivalent:
            existing_name = str(equivalent["name"])
            if mapping_action == "map":
                reference_map[name] = existing_name
                plan["renamed_references"][name] = existing_name
                plan["reuse"] += 1
                continue
            decision_key = reuse_decision_key(kind, name, existing_name, wanted)
            suggestion = {
                "key": decision_key,
                "kind": kind,
                "imported": name,
                "existing": existing_name,
                "summary": reuse_value_summary({field: payload.get(field) for field in fields}),
            }
            plan["suggested_reuses"].append(suggestion)
            if decision_key in approved_reuses:
                reference_map[name] = existing_name
                plan["renamed_references"][name] = existing_name
                plan["reuse"] += 1
                continue
        if mapping_action == "map":
            plan["conflicts"].append(f"{kind} mapping target ontbreekt: {name}")
        else:
            mapped[kind].append(name); plan["create"] += 1

    for attr in ("address_groups", "service_groups"):
        for group in getattr(result, attr):
            group.members = [reference_map.get(member, member) for member in group.members]
    for attr in ("security_rules", "nat_rules"):
        for rule in getattr(result, attr):
            rule.source = [reference_map.get(value, value) for value in rule.source]
            rule.destination = [reference_map.get(value, value) for value in rule.destination]
            rule.service = [reference_map.get(value, value) for value in rule.service]

    for item in scm_items(result):
        kind = item["kind"]
        if kind not in {"address-groups", "service-groups"}:
            continue
        fields = object_fields[kind]
        target_items = existing.get(kind, [])
        by_name = {str(value.get("name", "")): value for value in target_items}
        by_signature = {signature(value, fields): value for value in target_items}
        name = item["name"]; payload = item["payload"]; wanted = signature(payload, fields)
        mapping_action = str(item.get("mapping_action") or "create")
        if name in by_name:
            if signature(by_name[name], fields) != wanted:
                plan["conflicts"].append(f"{kind}: {name}")
            else:
                plan["reuse"] += 1
            continue
        equivalent = by_signature.get(wanted)
        if equivalent:
            existing_name = str(equivalent["name"])
            if mapping_action == "map":
                reference_map[name] = existing_name
                plan["renamed_references"][name] = existing_name
                plan["reuse"] += 1
                continue
            decision_key = reuse_decision_key(kind, name, existing_name, wanted)
            suggestion = {
                "key": decision_key,
                "kind": kind,
                "imported": name,
                "existing": existing_name,
                "summary": reuse_value_summary({field: payload.get(field) for field in fields}),
            }
            plan["suggested_reuses"].append(suggestion)
            if decision_key in approved_reuses:
                reference_map[name] = existing_name
                plan["renamed_references"][name] = existing_name
                plan["reuse"] += 1
                continue
        if mapping_action == "map":
            plan["conflicts"].append(f"{kind} mapping target ontbreekt: {name}")
        else:
            mapped[kind].append(name); plan["create"] += 1

    for attr in ("security_rules", "nat_rules"):
        for rule in getattr(result, attr):
            rule.source = [reference_map.get(value, value) for value in rule.source]
            rule.destination = [reference_map.get(value, value) for value in rule.destination]
            rule.service = [reference_map.get(value, value) for value in rule.service]

    for kind, attr in attr_for_kind.items():
        keep = set(mapped.get(kind, []))
        setattr(result, attr, [item for item in getattr(result, attr) if item.name in keep])
    for kind, attr in (("security", "security_rules"), ("nat", "nat_rules")):
        target_items = existing.get(f"policy:{kind}", [])
        by_name = {str(value.get("name", "")): value for value in target_items}
        def policy_signature(value: dict) -> str:
            return json.dumps({
                key: value.get(key)
                for key in ("from", "to", "source", "destination", "application", "service", "action", "disabled")
            }, sort_keys=True, separators=(",", ":"))
        by_signature = {policy_signature(value): value for value in target_items}
        kept = []
        for rule in getattr(result, attr):
            if rule.name in by_name:
                payload = next(item["payload"] for item in scm_items(result) if item["kind"] == f"policy:{kind}" and item["name"] == rule.name)
                if policy_signature(by_name[rule.name]) == policy_signature(payload):
                    plan["reuse"] += 1
                else:
                    plan["conflicts"].append(f"{kind} policy: {rule.name}")
            elif rule.mapping_action == "map":
                payload = next(item["payload"] for item in scm_items(result) if item["kind"] == f"policy:{kind}" and item["name"] == rule.name)
                if policy_signature(payload) in by_signature:
                    plan["reuse"] += 1
                else:
                    plan["conflicts"].append(f"{kind} policy mapping target ontbreekt: {rule.name}")
            else:
                kept.append(rule); plan["create"] += 1
        setattr(result, attr, kept)
    if plan["conflicts"]:
        raise MigrationError("Mergeconflicten: " + ", ".join(plan["conflicts"][:12]))
    return result, plan


def _entry_signature(entry: ET.Element) -> str:
    clone = copy.deepcopy(entry)
    clone.attrib.pop("name", None)
    for node in clone.iter():
        node.tail = None
        if node.text is not None:
            node.text = node.text.strip() or None
    return ET.tostring(clone, encoding="unicode")


def _named_scope(root: ET.Element, path: str, name: str) -> ET.Element | None:
    return next((entry for entry in root.findall(path) if entry.get("name") == name), None)


def _merge_model_into_panos_xml_scope(
    xml_bytes: bytes,
    model: MigrationModel,
    scope: str,
    panorama: bool = False,
    rulebase: str = "pre",
    approved_reuses: set[str] | None = None,
) -> tuple[bytes, dict]:
    """Merge a neutral model into a full PAN-OS/Panorama config without a live write.

    Equal named entries are reused. Equivalent objects with another name are proposed
    for explicit engineer approval; incompatible name collisions stop the merge.
    """
    try:
        root = SafeET.fromstring(xml_bytes)
    except Exception as exc:
        raise MigrationError(f"Ongeldige PAN-OS XML-base: {exc}") from exc
    if root.tag != "config":
        root = root.find(".//config")
    if root is None:
        raise MigrationError("Geen PAN-OS <config>-root in de base gevonden")
    scope_path = "./devices/entry/device-group/entry" if panorama else "./devices/entry/vsys/entry"
    target = root.find("./shared") if panorama and scope == "Shared" else _named_scope(root, scope_path, scope)
    if target is None:
        raise MigrationError(f"Doelscope {scope} bestaat niet in de gekozen base-configuratie")

    fragment_root = SafeET.fromstring(panos_fragment(model, scope, panorama, rulebase))
    source = fragment_root.find("./shared") if panorama and scope == "Shared" else _named_scope(fragment_root, scope_path, scope)
    if source is None:
        raise MigrationError("Gegenereerde migratiescope ontbreekt")
    approved_reuses = set(approved_reuses or set())
    plan = {
        "create": 0,
        "reuse": 0,
        "conflicts": [],
        "renamed_references": {},
        "suggested_reuses": [],
    }
    reference_map: dict[str, str] = {}

    def container(parent: ET.Element, tag: str) -> ET.Element:
        node = parent.find(f"./{tag}")
        return node if node is not None else ET.SubElement(parent, tag)

    def mapping_action(kind: str, name: str) -> str:
        for item in model_collections(model).get(kind, []):
            raw_name = item.name if hasattr(item, "name") else str(item.get("name", ""))
            if raw_name != name:
                continue
            action = getattr(item, "mapping_action", None)
            if action is None and isinstance(item, dict):
                action = item.get("mapping_action")
            return str(action or "create")
        return "create"

    # A different object name may carry different intent even when its value matches.
    # Keep it separate unless the engineer explicitly approves the proposed reuse.
    for tag in ("address", "service"):
        kind = {"address": "addresses", "service": "services"}[tag]
        incoming = source.find(f"./{tag}")
        if incoming is None:
            continue
        destination = container(target, tag)
        existing = destination.findall("./entry")
        by_name = {entry.get("name", ""): entry for entry in existing}
        by_signature = {_entry_signature(entry): entry for entry in existing}
        for entry in incoming.findall("./entry"):
            name = entry.get("name", "")
            signature = _entry_signature(entry)
            if name in by_name:
                if _entry_signature(by_name[name]) != signature:
                    plan["conflicts"].append(f"{tag}: {name}")
                else:
                    plan["reuse"] += 1
                continue
            equivalent = by_signature.get(signature)
            if equivalent is not None:
                existing_name = equivalent.get("name", name)
                if mapping_action(kind, name) == "map":
                    reference_map[name] = existing_name
                    plan["renamed_references"][name] = existing_name
                    plan["reuse"] += 1
                    continue
                decision_key = reuse_decision_key(tag, name, existing_name, signature)
                plan["suggested_reuses"].append({
                    "key": decision_key,
                    "kind": tag,
                    "imported": name,
                    "existing": existing_name,
                    "summary": reuse_value_summary(entry),
                })
                if decision_key in approved_reuses:
                    reference_map[name] = existing_name
                    plan["renamed_references"][name] = existing_name
                    plan["reuse"] += 1
                    continue
            if mapping_action(kind, name) == "map":
                plan["conflicts"].append(f"{tag} mapping target ontbreekt: {name}")
                continue
            clone = copy.deepcopy(entry)
            destination.append(clone); by_name[name] = clone; by_signature[signature] = clone
            plan["create"] += 1

    # Rewrite references before groups and rules are compared or added.
    for node in source.findall(".//member"):
        if node.text in reference_map:
            node.text = reference_map[node.text]

    for tag in ("address-group", "service-group"):
        kind = {"address-group": "address_groups", "service-group": "service_groups"}[tag]
        incoming = source.find(f"./{tag}")
        if incoming is None:
            continue
        destination = container(target, tag)
        existing = destination.findall("./entry")
        by_name = {entry.get("name", ""): entry for entry in existing}
        by_signature = {_entry_signature(entry): entry for entry in existing}
        for entry in incoming.findall("./entry"):
            name = entry.get("name", "")
            signature = _entry_signature(entry)
            if name in by_name:
                if _entry_signature(by_name[name]) != signature:
                    plan["conflicts"].append(f"{tag}: {name}")
                else:
                    plan["reuse"] += 1
                continue
            equivalent = by_signature.get(signature)
            if equivalent is not None:
                existing_name = equivalent.get("name", name)
                if mapping_action(kind, name) == "map":
                    reference_map[name] = existing_name
                    plan["renamed_references"][name] = existing_name
                    plan["reuse"] += 1
                    continue
                decision_key = reuse_decision_key(tag, name, existing_name, signature)
                plan["suggested_reuses"].append({
                    "key": decision_key,
                    "kind": tag,
                    "imported": name,
                    "existing": existing_name,
                    "summary": reuse_value_summary(entry),
                })
                if decision_key in approved_reuses:
                    reference_map[name] = existing_name
                    plan["renamed_references"][name] = existing_name
                    plan["reuse"] += 1
                    continue
            if mapping_action(kind, name) == "map":
                plan["conflicts"].append(f"{tag} mapping target ontbreekt: {name}")
                continue
            clone = copy.deepcopy(entry)
            destination.append(clone); by_name[name] = clone; by_signature[signature] = clone
            plan["create"] += 1

    for node in source.findall(".//member"):
        if node.text in reference_map:
            node.text = reference_map[node.text]

    source_rb = source.find(f"./{rulebase}-rulebase") if panorama else source.find("./rulebase")
    target_rb = container(target, f"{rulebase}-rulebase" if panorama else "rulebase")
    if source_rb is not None:
        for policy_type in source_rb:
            policy_kind = f"{policy_type.tag}_rules"
            incoming_rules = policy_type.find("./rules")
            if incoming_rules is None:
                continue
            target_policy = container(target_rb, policy_type.tag)
            destination = container(target_policy, "rules")
            by_name = {entry.get("name", ""): entry for entry in destination.findall("./entry")}
            by_signature = {_entry_signature(entry): entry for entry in destination.findall("./entry")}
            for entry in incoming_rules.findall("./entry"):
                name = entry.get("name", "")
                if name in by_name:
                    if _entry_signature(by_name[name]) != _entry_signature(entry):
                        plan["conflicts"].append(f"{policy_type.tag} policy: {name}")
                    else:
                        plan["reuse"] += 1
                    continue
                if mapping_action(policy_kind, name) == "map":
                    equivalent = by_signature.get(_entry_signature(entry))
                    if equivalent is not None:
                        plan["reuse"] += 1
                    else:
                        plan["conflicts"].append(f"{policy_type.tag} policy mapping target ontbreekt: {name}")
                    continue
                destination.append(copy.deepcopy(entry)); plan["create"] += 1

    device = root.find("./devices/entry")
    if device is None:
        raise MigrationError("De doelconfiguratie bevat geen device-root")
    network_owner = device
    zone_owner = target
    network_extra_kinds = {"vlans","virtual_routers","logical_routers","virtual_wires","ipsec_tunnels","ike_gateways","network_profiles","globalprotect_portals","globalprotect_gateways","device_configuration"}
    network_needed = bool(model.interfaces or model.zones or any(model.extras.get(kind) for kind in network_extra_kinds))
    if panorama and network_needed:
        reference = target.findtext("./reference-template") or target.findtext("./reference-templates/member")
        if not reference:
            stack_name = target.findtext("./reference-template-stack") or target.findtext("./reference-template-stack/member")
            stack = next((entry for entry in root.findall("./devices/entry/template-stack/entry") if entry.get("name") == stack_name), None)
            reference = stack.findtext("./templates/member") if stack is not None else ""
        template = next((entry for entry in root.findall("./devices/entry/template/entry") if entry.get("name") == reference), None)
        if template is None:
            raise MigrationError("Interfaces/zones vereisen een bestaande referenced template in de gekozen Device Group")
        network_owner = template.find("./config/devices/entry")
        if network_owner is None:
            raise MigrationError(f"Template {reference} bevat geen device-config")
        zone_owner = network_owner.find("./vsys/entry")
        if model.zones and zone_owner is None:
            raise MigrationError(f"Template {reference} bevat geen VSYS voor zones")
        plan["network_target"] = reference

    if model.interfaces:
        network = container(network_owner, "network")
        interface_root = container(network, "interface")
        for item in model.interfaces:
            interface_type = str(item.get("interface_type", "ethernet"))
            destination = container(interface_root, interface_type)
            entry = SafeET.fromstring(item["xml"])
            name = str(item.get("name", entry.get("name", "")))
            entry.set("name", name)
            existing = {value.get("name", ""): value for value in destination.findall("./entry")}
            if name in existing:
                if _entry_signature(existing[name]) != _entry_signature(entry): plan["conflicts"].append(f"interface: {name}")
                else: plan["reuse"] += 1
            else:
                if mapping_action("interfaces", name) == "map":
                    plan["conflicts"].append(f"interface mapping target ontbreekt: {name}")
                    continue
                destination.append(copy.deepcopy(entry)); plan["create"] += 1

    if model.zones:
        if zone_owner is None:
            raise MigrationError("Geen doel-VSYS voor zones gevonden")
        destination = container(zone_owner, "zone")
        existing = {value.get("name", ""): value for value in destination.findall("./entry")}
        for item in model.zones:
            entry = SafeET.fromstring(item["xml"]); name = str(item.get("name", entry.get("name", ""))); entry.set("name", name)
            if name in existing:
                if item.get("auto_generated") and item.get("source_ref") == "Interface zone assignment":
                    incoming_network = entry.find("./network")
                    existing_network = existing[name].find("./network")
                    incoming_types = list(incoming_network) if incoming_network is not None else []
                    existing_types = list(existing_network) if existing_network is not None else []
                    if len(incoming_types) != 1 or (
                        existing_types and any(node.tag != incoming_types[0].tag for node in existing_types)
                    ):
                        plan["conflicts"].append(f"zone: {name}")
                    else:
                        if existing_network is None:
                            existing_network = ET.SubElement(existing[name], "network")
                        target_type = existing_network.find(f"./{incoming_types[0].tag}")
                        if target_type is None:
                            target_type = ET.SubElement(existing_network, incoming_types[0].tag)
                        current_members = {node.text for node in target_type.findall("./member")}
                        for member in incoming_types[0].findall("./member"):
                            if member.text and member.text not in current_members:
                                ET.SubElement(target_type, "member").text = member.text
                                current_members.add(member.text)
                        plan["reuse"] += 1
                elif _entry_signature(existing[name]) != _entry_signature(entry): plan["conflicts"].append(f"zone: {name}")
                else: plan["reuse"] += 1
            else:
                if mapping_action("zones", name) == "map":
                    plan["conflicts"].append(f"zone mapping target ontbreekt: {name}")
                    continue
                destination.append(copy.deepcopy(entry)); plan["create"] += 1

    def ensure_path(owner: ET.Element, path: str) -> ET.Element:
        current=owner
        for segment in (value for value in path.strip("/").split("/") if value):
            current=container(current,segment)
        return current

    # Preserve and merge every remaining PAN-OS family captured by the parser.
    # The original entry XML is retained, so fields unknown to Policy Forge are
    # not flattened or lost while still receiving collision protection.
    for kind, items in model.extras.items():
        for item in items:
            raw_path=str(item.get("target_path", "")).strip("/")
            if not raw_path: continue
            if kind in network_extra_kinds:
                owner=network_owner
            elif kind == "device_configuration":
                owner=network_owner
            else:
                owner=target
            if not panorama and raw_path.startswith(("pre-rulebase/","post-rulebase/")):
                raw_path="rulebase/"+raw_path.split("/",1)[1]
            destination=ensure_path(owner,raw_path)
            try: entry=SafeET.fromstring(str(item.get("xml", "")))
            except Exception as exc:
                plan["conflicts"].append(f"{kind}: ongeldige XML voor {item.get('name','')}: {exc}")
                continue
            name=str(item.get("name", entry.get("name", ""))); entry.set("name",name)
            existing={value.get("name", ""):value for value in destination.findall("./entry")}
            if name in existing:
                if _entry_signature(existing[name]) != _entry_signature(entry): plan["conflicts"].append(f"{kind}: {name}")
                else: plan["reuse"] += 1
            else:
                if mapping_action(kind, name) == "map":
                    plan["conflicts"].append(f"{kind} mapping target ontbreekt: {name}")
                    continue
                destination.append(copy.deepcopy(entry)); plan["create"] += 1
    if plan["conflicts"]:
        raise MigrationError("Mergeconflicten: " + ", ".join(plan["conflicts"][:12]))
    ET.indent(root, space="  ")
    merged = b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8") + b"\n"
    return merged, plan


def _routed_models(model: MigrationModel, default_scope: str) -> list[tuple[str, MigrationModel]]:
    """Split a neutral model by the target context retained on every item."""
    routed: dict[str, MigrationModel] = {}

    def bucket(context: str) -> MigrationModel:
        context = context.strip() or default_scope
        if not context:
            raise MigrationError("Doelscope ontbreekt")
        if context not in routed:
            routed[context] = MigrationModel(model.vendor, model.source_name)
        return routed[context]

    for attr in (
        "addresses", "address_groups", "services", "service_groups",
        "security_rules", "nat_rules", "interfaces", "zones",
    ):
        for item in getattr(model, attr):
            context = (
                str(getattr(item, "target_context", ""))
                if hasattr(item, "target_context")
                else str(item.get("target_context", ""))
            )
            getattr(bucket(context), attr).append(copy.deepcopy(item))
    for kind, items in model.extras.items():
        for item in items:
            context = str(item.get("target_context", ""))
            bucket(context).extras.setdefault(kind, []).append(copy.deepcopy(item))
    if not routed:
        routed[default_scope] = MigrationModel(model.vendor, model.source_name)
    return list(routed.items())


def _ensure_migration_scope(
    xml_bytes: bytes,
    scope: str,
    panorama: bool,
    routed_model: MigrationModel,
) -> bytes:
    """Create an explicitly selected context only for ``create`` mappings."""
    root = SafeET.fromstring(xml_bytes)
    if root.tag != "config":
        root = root.find(".//config")
    if root is None:
        raise MigrationError("Geen PAN-OS <config>-root in de base gevonden")
    if panorama and scope == "Shared":
        current = root.find("./shared")
    else:
        path = "./devices/entry/device-group/entry" if panorama else "./devices/entry/vsys/entry"
        current = _named_scope(root, path, scope)
    if current is not None:
        return xml_bytes
    actions = {
        str(getattr(item, "mapping_action", item.get("mapping_action", "create") if isinstance(item, dict) else "create") or "create")
        for items in model_collections(routed_model).values()
        for item in items
    }
    if "map" in actions:
        raise MigrationError(f"Doelcontext {scope} bestaat niet; gebruik Create of kies een bestaande context")
    if panorama and scope == "Shared":
        ET.SubElement(root, "shared")
    else:
        device = root.find("./devices/entry")
        if device is None:
            devices = root.find("./devices")
            if devices is None:
                devices = ET.SubElement(root, "devices")
            device = ET.SubElement(devices, "entry", {"name": "localhost.localdomain"})
        parent_tag = "device-group" if panorama else "vsys"
        parent = device.find(f"./{parent_tag}")
        if parent is None:
            parent = ET.SubElement(device, parent_tag)
        ET.SubElement(parent, "entry", {"name": scope})
    ET.indent(root, space="  ")
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8") + b"\n"


def merge_model_into_panos_xml(
    xml_bytes: bytes,
    model: MigrationModel,
    scope: str,
    panorama: bool = False,
    rulebase: str = "pre",
    approved_reuses: set[str] | None = None,
) -> tuple[bytes, dict]:
    """Merge every family into its persisted target context."""
    merged = xml_bytes
    combined = {
        "create": 0, "reuse": 0, "conflicts": [],
        "renamed_references": {}, "suggested_reuses": [],
        "target_contexts": [],
    }
    for target_context, routed_model in _routed_models(model, scope):
        merged = _ensure_migration_scope(merged, target_context, panorama, routed_model)
        merged, plan = _merge_model_into_panos_xml_scope(
            merged, routed_model, target_context, panorama, rulebase, approved_reuses,
        )
        combined["create"] += int(plan.get("create", 0))
        combined["reuse"] += int(plan.get("reuse", 0))
        combined["conflicts"].extend(plan.get("conflicts", []))
        combined["suggested_reuses"].extend(plan.get("suggested_reuses", []))
        combined["renamed_references"].update(plan.get("renamed_references", {}))
        combined["target_contexts"].append(target_context)
        if plan.get("network_target"):
            combined["network_target"] = plan["network_target"]
    combined["target_contexts"] = unique(combined["target_contexts"])
    return merged, combined
