from __future__ import annotations

import hashlib
import ipaddress
import json
import copy
import csv
import io
import re
import shlex
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
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


@dataclass
class Address:
    name: str
    value: str
    value_type: str = "ip_netmask"
    description: str = ""
    tags: list[str] = field(default_factory=list)
    source_ref: str = ""


@dataclass
class AddressGroup:
    name: str
    members: list[str] = field(default_factory=list)
    description: str = ""
    tags: list[str] = field(default_factory=list)
    source_ref: str = ""


@dataclass
class Service:
    name: str
    protocol: str
    port: str
    source_port: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)
    source_ref: str = ""


@dataclass
class ServiceGroup:
    name: str
    members: list[str] = field(default_factory=list)
    description: str = ""
    tags: list[str] = field(default_factory=list)
    source_ref: str = ""


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

    def parse(self, text: str, source_name: str) -> MigrationModel:
        model = MigrationModel(self.vendor, source_name); section = ""; current = None; values = {}
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
                    model.nat_rules.append(Policy(clean_name(f"NAT-{current}"), policy_type="nat", from_zones=split_forti(values.get("extintf", "any"), any_alias="any"), destination=[external], destination_translation=translation, description=f"Imported Fortinet VIP {current}", source_ref=ref, original=dict(values)))
                else:
                    model.unsupported.append(f"{ref}: VIP {current} mist extip/mappedip en vereist review")
            current = None; values = {}
        for number, line in self.lines(text):
            if line.startswith("config "): flush(); section = line[7:].strip(); continue
            if line == "end": flush(); section = ""; continue
            if line.startswith("edit "): flush(); current = unquote(line[5:]); values = {"_ref": f"line {number}"}; continue
            if line == "next": flush(); continue
            if current is not None and line.startswith("set "):
                parts = shlex.split(line); values[parts[1]] = " ".join(parts[2:]) if len(parts)>2 else ""
        flush(); return deduplicate(model)


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
    extensions = (".json", ".xml", ".txt")

    def parse(self, text: str, source_name: str) -> MigrationModel:
        stripped=text.lstrip()
        if stripped.startswith(("{","[")): return self._json(json.loads(text),source_name)
        if stripped.startswith("<"): return self._xml(text,source_name)
        model=MigrationModel(self.vendor,source_name); model.unsupported.append("Check Point text/dbedit-formaat vereist JSON/XML export voor betrouwbare mapping"); return model

    def _json(self,data,source_name):
        model=MigrationModel(self.vendor,source_name); items=data if isinstance(data,list) else data.get("objects",data.get("items",[]))
        if not isinstance(items,list): items=[]
        for item in items:
            if not isinstance(item,dict): continue
            typ=str(item.get("type","")).lower(); name=clean_name(item.get("name",item.get("uid","item"))); ref=str(item.get("uid",name))
            if typ in {"host","network","address-range","dns-domain"}:
                value=item.get("ipv4-address") or item.get("subnet4") or item.get("name","")
                if typ=="network" and item.get("mask-length4") is not None: value=f"{value}/{item['mask-length4']}"
                if typ=="address-range": value=f"{item.get('ipv4-address-first','')}-{item.get('ipv4-address-last','')}"
                model.addresses.append(Address(name,str(value),"ip_range" if typ=="address-range" else "fqdn" if typ=="dns-domain" else "ip_netmask",source_ref=ref))
            elif typ in {"group","network-group"}: model.address_groups.append(AddressGroup(name,[clean_name(m.get("name",m.get("uid","member"))) if isinstance(m,dict) else clean_name(m) for m in item.get("members",[])],source_ref=ref))
            elif typ in {"service-tcp","service-udp"}: model.services.append(Service(name,"tcp" if typ.endswith("tcp") else "udp",str(item.get("port","1-65535")),source_ref=ref))
            elif typ in {"service-group"}: model.service_groups.append(ServiceGroup(name,[clean_name(m.get("name",m.get("uid","member"))) if isinstance(m,dict) else clean_name(m) for m in item.get("members",[])],source_ref=ref))
        packages=data.get("rulebase",data.get("access-layers",[])) if isinstance(data,dict) else []
        self._walk_rules(packages,model); return deduplicate(model)

    def _walk_rules(self,value,model):
        if isinstance(value,list):
            for item in value: self._walk_rules(item,model)
        elif isinstance(value,dict):
            typ=str(value.get("type","")).lower()
            if typ in {"access-rule","rule"} or ("source" in value and "destination" in value and "action" in value):
                names=lambda v:[clean_name(x.get("name",x.get("uid","any"))) if isinstance(x,dict) else clean_name(x) for x in (v if isinstance(v,list) else [v])]
                action=value.get("action","Accept"); action=action.get("name",action) if isinstance(action,dict) else action
                model.security_rules.append(Policy(clean_name(value.get("name",value.get("uid","rule"))),source=names(value.get("source",["any"])),destination=names(value.get("destination",["any"])),service=names(value.get("service",["application-default"])),action="allow" if str(action).lower() in {"accept","allow"} else "deny",disabled=not bool(value.get("enabled",True)),source_ref=str(value.get("uid","")),original=value))
            for child in value.values():
                if isinstance(child,(list,dict)): self._walk_rules(child,model)

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
                        source_ref=f"{owner} · {rulebase}", original={"owner": owner, "rulebase": rulebase},
                    )
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
    return results[:1000]


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


def apply_merge_rules(model: MigrationModel, rules: list[dict]) -> MigrationModel:
    """Apply explicit master/member choices and rewrite object references globally."""
    result=MigrationModel.from_dict(model.as_dict()); rename={}
    for rule in rules:
        master_selector=str(rule.get("master", "")); members=unique(rule.get("members", [])); kind=str(rule.get("kind", ""))
        collection=model_collections(result).get(kind,[])
        master_item=next((item for item in collection if item_selector(asdict(item) if hasattr(item,"__dataclass_fields__") else item)==master_selector),None)
        master=(master_item.name if hasattr(master_item,"name") else str(master_item.get("name",""))) if master_item is not None else ""
        if not master or not members or kind not in model_collections(result): continue
        for selector in members:
            name=selector.split("|||",1)[0]
            if name != master: rename[name]=master
        filtered=[]; master_seen=False
        for item in collection:
            name=item.name if hasattr(item,"name") else str(item.get("name", ""))
            selector=item_selector(asdict(item) if hasattr(item,"__dataclass_fields__") else item)
            if selector == master_selector:
                if master_seen: continue
                master_seen=True; filtered.append(item)
            elif selector in members: continue
            else: filtered.append(item)
        if kind in result.extras: result.extras[kind]=filtered
        else: setattr(result,kind,filtered)
    if not rename: return result
    for group in result.address_groups: group.members=[rename.get(value,value) for value in group.members]
    for group in result.service_groups: group.members=[rename.get(value,value) for value in group.members]
    for attr in ("security_rules","nat_rules"):
        for policy in getattr(result,attr):
            for field_name in ("source","destination","service","application","tags"):
                setattr(policy,field_name,[rename.get(value,value) for value in getattr(policy,field_name)])
    for kind, items in result.extras.items():
        for item in items:
            try:
                entry=SafeET.fromstring(item.get("xml", ""))
                for node in entry.iter():
                    if node.text in rename: node.text=rename[node.text]
                item["xml"]=ET.tostring(entry,encoding="unicode")
            except Exception: continue
    return result


def apply_transform_rules(model: MigrationModel, rules: list[dict]) -> MigrationModel:
    result=MigrationModel.from_dict(model.as_dict()); replacements={}
    for rule in rules:
        operation=str(rule.get("operation","")); kind=str(rule.get("kind","")); selector=str(rule.get("selector","")); value=str(rule.get("value",""))
        collection=model_collections(result).get(kind,[])
        if operation in {"rename","delete","disable","enable"}:
            for item in list(collection):
                raw=asdict(item) if hasattr(item,"__dataclass_fields__") else item
                if item_selector(raw)!=selector: continue
                old=item.name if hasattr(item,"name") else str(item.get("name",""))
                if operation=="delete": collection.remove(item)
                elif operation=="rename" and value:
                    if hasattr(item,"name"): item.name=value
                    else:
                        item["name"]=value
                        try:
                            entry=SafeET.fromstring(item.get("xml","")); entry.set("name",value); item["xml"]=ET.tostring(entry,encoding="unicode")
                        except Exception: pass
                    replacements[old]=value
                elif hasattr(item,"disabled"): item.disabled=operation=="disable"
        elif operation=="replace_reference" and selector and value:
            replacements[selector]=value
    if replacements:
        for group in result.address_groups: group.members=[replacements.get(v,v) for v in group.members]
        for group in result.service_groups: group.members=[replacements.get(v,v) for v in group.members]
        for attr in ("security_rules","nat_rules"):
            for policy in getattr(result,attr):
                for field_name in ("from_zones","to_zones","source","destination","service","application","tags"):
                    setattr(policy,field_name,[replacements.get(v,v) for v in getattr(policy,field_name)])
        for items in result.extras.values():
            for item in items:
                try:
                    entry=SafeET.fromstring(item.get("xml",""))
                    for node in entry.iter():
                        if node.text in replacements: node.text=replacements[node.text]
                    item["xml"]=ET.tostring(entry,encoding="unicode")
                except Exception: continue
    return result


def migration_analysis(model: MigrationModel) -> dict:
    """Conservative project health analysis used by the Expedition-style toolbox."""
    address_names={item.name for item in model.addresses}; service_names={item.name for item in model.services}
    group_names={item.name for item in model.address_groups}; service_group_names={item.name for item in model.service_groups}
    used_addresses=set(); used_services=set(); unresolved=set(); duplicate_rules=[]; rule_signatures={}
    for group in model.address_groups: used_addresses.update(group.members)
    for group in model.service_groups: used_services.update(group.members)
    for attr in ("security_rules","nat_rules"):
        for rule in getattr(model,attr):
            used_addresses.update(value for value in rule.source+rule.destination if value!="any")
            used_services.update(value for value in rule.service if value not in {"any","application-default"})
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
    return {
        "unused_addresses":sorted(address_names-used_addresses),
        "unused_address_groups":sorted(group_names-used_addresses),
        "unused_services":sorted(service_names-used_services),
        "unused_service_groups":sorted(service_group_names-used_services),
        "unresolved_references":sorted(unresolved), "duplicate_rules":duplicate_rules,
    }


def split_forti(value: str, any_alias: str = "") -> list[str]:
    values=unique(shlex.split(value)) or ["any"]
    return ["any" if any_alias and item==any_alias else clean_name(item) for item in values]


def unquote(value: str) -> str:
    try: return shlex.split(value)[0]
    except (ValueError,IndexError): return value.strip('"')


def panos_fragment(model: MigrationModel, scope: str = "vsys1", panorama: bool = False, rulebase: str = "pre") -> bytes:
    config=ET.Element("config",{"version":"11.0.0"}); devices=ET.SubElement(config,"devices"); device=ET.SubElement(devices,"entry",{"name":"localhost.localdomain"})
    if panorama:
        groups=ET.SubElement(device,"device-group"); target=ET.SubElement(groups,"entry",{"name":scope}); rb=ET.SubElement(target,f"{rulebase}-rulebase")
    else:
        vsyses=ET.SubElement(device,"vsys"); target=ET.SubElement(vsyses,"entry",{"name":scope}); rb=ET.SubElement(target,"rulebase")
    def members(parent,values):
        for value in values: ET.SubElement(parent,"member").text=value
    addresses=ET.SubElement(target,"address")
    for item in model.addresses:
        e=ET.SubElement(addresses,"entry",{"name":item.name}); ET.SubElement(e,item.value_type.replace("_","-")).text=item.value
        if item.description: ET.SubElement(e,"description").text=item.description
        if item.tags: members(ET.SubElement(e,"tag"),item.tags)
    groups=ET.SubElement(target,"address-group")
    for item in model.address_groups:
        e=ET.SubElement(groups,"entry",{"name":item.name}); members(ET.SubElement(e,"static"),item.members)
        if item.description: ET.SubElement(e,"description").text=item.description
        if item.tags: members(ET.SubElement(e,"tag"),item.tags)
    services=ET.SubElement(target,"service")
    for item in model.services:
        e=ET.SubElement(services,"entry",{"name":item.name}); p=ET.SubElement(ET.SubElement(e,"protocol"),item.protocol); ET.SubElement(p,"port").text=item.port
        if item.source_port: ET.SubElement(p,"source-port").text=item.source_port
        if item.description: ET.SubElement(e,"description").text=item.description
        if item.tags: members(ET.SubElement(e,"tag"),item.tags)
    service_groups=ET.SubElement(target,"service-group")
    for item in model.service_groups:
        e=ET.SubElement(service_groups,"entry",{"name":item.name}); members(ET.SubElement(e,"members"),item.members)
        if item.description: ET.SubElement(e,"description").text=item.description
        if item.tags: members(ET.SubElement(e,"tag"),item.tags)
    for kind,rules in (("security",model.security_rules),("nat",model.nat_rules)):
        root=ET.SubElement(ET.SubElement(rb,kind),"rules")
        for rule in rules:
            e=ET.SubElement(root,"entry",{"name":rule.name})
            for tag,values in (("from",rule.from_zones),("to",rule.to_zones),("source",rule.source),("destination",rule.destination)): members(ET.SubElement(e,tag),values)
            if kind=="security":
                members(ET.SubElement(e,"application"),rule.application); members(ET.SubElement(e,"service"),rule.service); ET.SubElement(e,"action").text=rule.action
            else:
                ET.SubElement(e,"service").text=(rule.service or ["any"])[0]
                ET.SubElement(e,"nat-type").text=rule.nat_type or "ipv4"
                ET.SubElement(e,"to-interface").text=rule.to_interface or "any"
                if rule.source_translation:
                    st=ET.SubElement(e,"source-translation"); _append_xml_dict(st,rule.source_translation)
                if rule.destination_translation:
                    dt=ET.SubElement(e,"destination-translation"); _append_xml_dict(dt,rule.destination_translation)
            if rule.tags: members(ET.SubElement(e,"tag"),rule.tags)
            ET.SubElement(e,"disabled").text="yes" if rule.disabled else "no"
            if rule.description: ET.SubElement(e,"description").text=rule.description
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
    for item in model.addresses: items.append({"kind":"addresses","name":item.name,"payload":{"name":item.name,item.value_type:item.value,**({"description":item.description} if item.description else {})}})
    for item in model.address_groups: items.append({"kind":"address-groups","name":item.name,"payload":{"name":item.name,"static":item.members}})
    for item in model.services: items.append({"kind":"services","name":item.name,"payload":{"name":item.name,"protocol":{item.protocol:{"port":item.port}}}})
    for item in model.service_groups: items.append({"kind":"service-groups","name":item.name,"payload":{"name":item.name,"members":item.members}})
    for kind,rules in (("security",model.security_rules),("nat",model.nat_rules)):
        for rule in rules:
            payload={"name":rule.name,"from":rule.from_zones,"to":rule.to_zones,"source":rule.source,"destination":rule.destination,"service":rule.service if kind=="security" else (rule.service or ["any"])[0],"disabled":rule.disabled}
            if kind=="security": payload.update({"application":rule.application,"action":rule.action})
            else: payload.update({"nat_type":rule.nat_type,"to_interface":rule.to_interface})
            if kind=="nat" and rule.source_translation: payload["source_translation"]=rule.source_translation
            if kind=="nat" and rule.destination_translation: payload["destination_translation"]=rule.destination_translation
            if rule.description: payload["description"]=rule.description
            items.append({"kind":f"policy:{kind}","name":rule.name,"payload":payload})
    return items


def reconcile_model(model: MigrationModel, existing: dict[str, list[dict]]) -> tuple[MigrationModel, dict]:
    """Reuse exact/equivalent target objects and block incompatible name collisions."""
    result = MigrationModel.from_dict(model.as_dict())
    plan = {"create": 0, "reuse": 0, "conflicts": [], "renamed_references": {}}
    reference_map: dict[str, str] = {}
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
        if name in by_name:
            if signature(by_name[name], fields) != wanted:
                plan["conflicts"].append(f"{kind}: {name}")
            else:
                plan["reuse"] += 1
            continue
        equivalent = by_signature.get(wanted)
        if equivalent:
            reference_map[name] = str(equivalent["name"])
            plan["renamed_references"][name] = reference_map[name]
            plan["reuse"] += 1
            continue
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
        if name in by_name:
            if signature(by_name[name], fields) != wanted:
                plan["conflicts"].append(f"{kind}: {name}")
            else:
                plan["reuse"] += 1
            continue
        equivalent = by_signature.get(wanted)
        if equivalent:
            reference_map[name] = str(equivalent["name"])
            plan["renamed_references"][name] = reference_map[name]
            plan["reuse"] += 1
            continue
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
        kept = []
        for rule in getattr(result, attr):
            if rule.name in by_name:
                plan["conflicts"].append(f"{kind} policy: {rule.name}")
            else:
                kept.append(rule); plan["create"] += 1
        setattr(result, attr, kept)
    if plan["conflicts"]:
        raise MigrationError("Mergeconflicten: " + ", ".join(plan["conflicts"][:12]))
    return result, plan


def _entry_signature(entry: ET.Element) -> str:
    clone = copy.deepcopy(entry)
    clone.attrib.pop("name", None)
    return ET.tostring(clone, encoding="unicode")


def _named_scope(root: ET.Element, path: str, name: str) -> ET.Element | None:
    return next((entry for entry in root.findall(path) if entry.get("name") == name), None)


def merge_model_into_panos_xml(
    xml_bytes: bytes,
    model: MigrationModel,
    scope: str,
    panorama: bool = False,
    rulebase: str = "pre",
) -> tuple[bytes, dict]:
    """Merge a neutral model into a full PAN-OS/Panorama config without a live write.

    Equal named entries are reused, equivalent address/service objects are reused under
    their existing name, and incompatible name collisions stop the merge.
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
    target = _named_scope(root, scope_path, scope)
    if target is None:
        raise MigrationError(f"Doelscope {scope} bestaat niet in de gekozen base-configuratie")

    fragment_root = SafeET.fromstring(panos_fragment(model, scope, panorama, rulebase))
    source = _named_scope(fragment_root, scope_path, scope)
    if source is None:
        raise MigrationError("Gegenereerde migratiescope ontbreekt")
    plan = {"create": 0, "reuse": 0, "conflicts": [], "renamed_references": {}}
    reference_map: dict[str, str] = {}

    def container(parent: ET.Element, tag: str) -> ET.Element:
        node = parent.find(f"./{tag}")
        return node if node is not None else ET.SubElement(parent, tag)

    # Addresses and services can safely reuse an equivalent object with another name.
    for tag in ("address", "service"):
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
                reference_map[name] = equivalent.get("name", name)
                plan["renamed_references"][name] = reference_map[name]
                plan["reuse"] += 1
                continue
            clone = copy.deepcopy(entry)
            destination.append(clone); by_name[name] = clone; by_signature[signature] = clone
            plan["create"] += 1

    # Rewrite references before groups and rules are compared or added.
    for node in source.findall(".//member"):
        if node.text in reference_map:
            node.text = reference_map[node.text]

    for tag in ("address-group", "service-group"):
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
                reference_map[name] = equivalent.get("name", name)
                plan["renamed_references"][name] = reference_map[name]
                plan["reuse"] += 1
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
            incoming_rules = policy_type.find("./rules")
            if incoming_rules is None:
                continue
            target_policy = container(target_rb, policy_type.tag)
            destination = container(target_policy, "rules")
            by_name = {entry.get("name", ""): entry for entry in destination.findall("./entry")}
            for entry in incoming_rules.findall("./entry"):
                name = entry.get("name", "")
                if name in by_name:
                    if _entry_signature(by_name[name]) != _entry_signature(entry):
                        plan["conflicts"].append(f"{policy_type.tag} policy: {name}")
                    else:
                        plan["reuse"] += 1
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
                destination.append(copy.deepcopy(entry)); plan["create"] += 1

    if model.zones:
        if zone_owner is None:
            raise MigrationError("Geen doel-VSYS voor zones gevonden")
        destination = container(zone_owner, "zone")
        existing = {value.get("name", ""): value for value in destination.findall("./entry")}
        for item in model.zones:
            entry = SafeET.fromstring(item["xml"]); name = str(item.get("name", entry.get("name", ""))); entry.set("name", name)
            if name in existing:
                if _entry_signature(existing[name]) != _entry_signature(entry): plan["conflicts"].append(f"zone: {name}")
                else: plan["reuse"] += 1
            else:
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
                destination.append(copy.deepcopy(entry)); plan["create"] += 1
    if plan["conflicts"]:
        raise MigrationError("Mergeconflicten: " + ", ".join(plan["conflicts"][:12]))
    ET.indent(root, space="  ")
    merged = b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8") + b"\n"
    return merged, plan
