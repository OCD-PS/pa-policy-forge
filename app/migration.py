from __future__ import annotations

import hashlib
import ipaddress
import json
import copy
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
            warnings=list(value.get("warnings", [])), unsupported=list(value.get("unsupported", [])),
        )

    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def counts(self) -> dict[str, int]:
        return {
            "addresses": len(self.addresses), "address_groups": len(self.address_groups),
            "services": len(self.services), "service_groups": len(self.service_groups),
            "security_rules": len(self.security_rules), "nat_rules": len(self.nat_rules),
            "interfaces": len(self.interfaces), "zones": len(self.zones),
            "warnings": len(self.warnings), "unsupported": len(self.unsupported),
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


PARSERS = {parser.vendor: parser for parser in (CiscoAsaParser(), CiscoIosParser(), CheckPointParser(), FortinetParser(), JuniperSrxParser(), GenericParser())}


def parse_vendor(vendor: str, content: bytes, source_name: str) -> MigrationModel:
    parser=PARSERS.get(vendor)
    if not parser: raise MigrationError("Onbekende vendorparser")
    if len(content)>100*1024*1024: raise MigrationError("Importbestand is groter dan 100 MiB")
    try: text=content.decode("utf-8-sig")
    except UnicodeDecodeError: text=content.decode("latin-1")
    model=parser.parse(text,source_name)
    if sum(model.counts()[key] for key in ("addresses","address_groups","services","service_groups","security_rules","nat_rules"))==0:
        model.warnings.append("Geen direct mergeerbare objecten of policies gevonden")
    return model


def deduplicate(model: MigrationModel) -> MigrationModel:
    for attr in ("addresses","address_groups","services","service_groups","security_rules","nat_rules"):
        values=[]; seen={}
        for item in getattr(model,attr):
            item.name=clean_name(item.name)
            if item.name in seen:
                if asdict(seen[item.name]) != asdict(item): model.warnings.append(f"Dubbele naam {item.name} in {attr}; eerste definitie behouden")
                continue
            seen[item.name]=item; values.append(item)
        setattr(model,attr,values)
    return model


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
    groups=ET.SubElement(target,"address-group")
    for item in model.address_groups: e=ET.SubElement(groups,"entry",{"name":item.name}); members(ET.SubElement(e,"static"),item.members)
    services=ET.SubElement(target,"service")
    for item in model.services: e=ET.SubElement(services,"entry",{"name":item.name}); p=ET.SubElement(ET.SubElement(e,"protocol"),item.protocol); ET.SubElement(p,"port").text=item.port
    service_groups=ET.SubElement(target,"service-group")
    for item in model.service_groups: e=ET.SubElement(service_groups,"entry",{"name":item.name}); members(ET.SubElement(e,"members"),item.members)
    for kind,rules in (("security",model.security_rules),("nat",model.nat_rules)):
        root=ET.SubElement(ET.SubElement(rb,kind),"rules")
        for rule in rules:
            e=ET.SubElement(root,"entry",{"name":rule.name})
            for tag,values in (("from",rule.from_zones),("to",rule.to_zones),("source",rule.source),("destination",rule.destination),("application",rule.application),("service",rule.service)): members(ET.SubElement(e,tag),values)
            if kind=="security": ET.SubElement(e,"action").text=rule.action
            if kind=="nat" and rule.source_translation:
                st=ET.SubElement(e,"source-translation"); dip=rule.source_translation.get("dynamic_ip_and_port")
                if dip is not None:
                    ia=ET.SubElement(ET.SubElement(st,"dynamic-ip-and-port"),"interface-address")
                    if dip.get("interface_address",{}).get("interface"): ET.SubElement(ia,"interface").text=dip["interface_address"]["interface"]
            if kind=="nat" and rule.destination_translation:
                dt=ET.SubElement(e,"destination-translation"); ET.SubElement(dt,"translated-address").text=rule.destination_translation.get("translated_address","")
                if rule.destination_translation.get("translated_port"): ET.SubElement(dt,"translated-port").text=rule.destination_translation["translated_port"]
            ET.SubElement(e,"disabled").text="yes" if rule.disabled else "no"
            if rule.description: ET.SubElement(e,"description").text=rule.description
    return ET.tostring(config,encoding="utf-8",xml_declaration=True)


def scm_items(model: MigrationModel) -> list[dict]:
    items=[]
    for item in model.addresses: items.append({"kind":"addresses","name":item.name,"payload":{"name":item.name,item.value_type:item.value,**({"description":item.description} if item.description else {})}})
    for item in model.address_groups: items.append({"kind":"address-groups","name":item.name,"payload":{"name":item.name,"static":item.members}})
    for item in model.services: items.append({"kind":"services","name":item.name,"payload":{"name":item.name,"protocol":{item.protocol:{"port":item.port}}}})
    for item in model.service_groups: items.append({"kind":"service-groups","name":item.name,"payload":{"name":item.name,"members":item.members}})
    for kind,rules in (("security",model.security_rules),("nat",model.nat_rules)):
        for rule in rules:
            payload={"name":rule.name,"from":rule.from_zones,"to":rule.to_zones,"source":rule.source,"destination":rule.destination,"application":rule.application,"service":rule.service,"disabled":rule.disabled}
            if kind=="security": payload["action"]=rule.action
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
    if plan["conflicts"]:
        raise MigrationError("Mergeconflicten: " + ", ".join(plan["conflicts"][:12]))
    ET.indent(root, space="  ")
    merged = b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8") + b"\n"
    return merged, plan
