"""Conservative offline merge of standalone PAN-OS virtual systems.

PAN-OS policies and zones are VSYS-owned, while supported reusable objects
can be shared and network/routing configuration is device-owned. This module
keeps those ownership boundaries explicit and never calls a live firewall.
"""

from __future__ import annotations

import copy
import ipaddress
import re
import xml.etree.ElementTree as ET
from collections import defaultdict

from defusedxml import ElementTree as SafeET

from app.offline_config import (
    OBJECT_NODES,
    PANOS_SCOPE_MOVE_OBJECT_TYPES,
    normalized_config_xml,
    parse_snapshot,
)


class VsysMergeError(ValueError):
    """Raised when a VSYS merge needs an explicit decision or has a conflict."""


_RULEBASES = ("pre-rulebase", "rulebase", "post-rulebase")
_MAX_POLICY_NAME_LENGTH = 63
_SHARED_EXTRA_PATHS = (
    "log-settings/syslog",
    "log-settings/email",
    "log-settings/snmptrap",
    "log-settings/http",
)
_SERVER_PROFILE_TYPES = ("ldap", "radius", "tacacs-plus", "kerberos", "saml-idp")
_IMPORT_MEMBER_PATHS = frozenset({
    "import/network/interface",
    "import/network/virtual-router",
    "import/network/logical-router",
    "import/network/vlan",
    "import/network/virtual-wire",
})


def _config_signature(node: ET.Element) -> tuple:
    return (
        node.tag,
        tuple(sorted(node.attrib.items())),
        (node.text or "").strip(),
        tuple(_config_signature(child) for child in list(node)),
    )


def _find_path(root: ET.Element, path: str) -> ET.Element | None:
    current = root
    for part in (value for value in path.strip("/").split("/") if value):
        current = current.find(f"./{part}")
        if current is None:
            return None
    return current


def _ensure_path(root: ET.Element, path: str) -> ET.Element:
    current = root
    for part in (value for value in path.strip("/").split("/") if value):
        child = current.find(f"./{part}")
        if child is None:
            child = ET.SubElement(current, part)
        current = child
    return current


def _parse_standalone_config(
    xml_bytes: bytes, parsed_config: tuple[ET.Element, object] | None = None,
) -> tuple[ET.Element, list[ET.Element]]:
    try:
        root, snapshot = parsed_config if parsed_config is not None else parse_snapshot(xml_bytes)
    except Exception as exc:
        raise VsysMergeError(str(exc)) from exc
    if snapshot.kind != "panos":
        raise VsysMergeError(
            "VSYS samenvoegen is alleen beschikbaar voor standalone PAN-OS; "
            "Panorama device groups/templates en SCM hebben een ander scopemodel."
        )
    devices = root.findall("./devices/entry")
    if len(devices) != 1:
        raise VsysMergeError("De configuratie moet precies één standalone device bevatten")
    vsys_container = devices[0].find("./vsys")
    entries = vsys_container.findall("./entry") if vsys_container is not None else []
    names = [entry.get("name", "").strip() for entry in entries]
    if len(entries) < 2:
        raise VsysMergeError("De configuratie bevat geen meerdere VSYS om samen te voegen")
    if len(entries) > 255:
        raise VsysMergeError("De wizard ondersteunt maximaal 255 VSYS in één configuratie")
    if any(not name for name in names) or len(names) != len(set(names)):
        raise VsysMergeError("Elke VSYS moet een unieke, niet-lege naam hebben")
    vsys_ids = []
    for entry in entries:
        value = (entry.findtext("./vsys-id") or "").strip()
        if not value:
            continue
        if not value.isdecimal() or not 1 <= int(value) <= 255:
            raise VsysMergeError(f"Ongeldig VSYS-ID voor {entry.get('name', '')}; PAN-OS gebruikt IDs 1 tot en met 255")
        vsys_ids.append(value)
    if len(vsys_ids) != len(set(vsys_ids)):
        raise VsysMergeError("De configuratie bevat dubbele VSYS-ID's")
    if "vsys1" not in names:
        raise VsysMergeError("De configuratie bevat geen vsys1; PAN-OS vereist vsys1 als blijvende VSYS")
    return root, entries


def _zone_details(vsys: ET.Element) -> list[dict]:
    rows = []
    for zone in vsys.findall("./zone/entry"):
        name = str(zone.get("name", "")).strip()
        network = zone.find("./network")
        network_types = [child.tag for child in list(network)] if network is not None else []
        interfaces = [
            member.text.strip()
            for member in (network.iter("member") if network is not None else [])
            if member.text and member.text.strip()
        ]
        rows.append({
            "name": name,
            "network_type": ", ".join(network_types) or "geen",
            "external": "external" in network_types,
            "interfaces": list(dict.fromkeys(interfaces)),
        })
    return rows


def _policy_counts(vsys: ET.Element) -> tuple[dict[str, int], int]:
    counts: dict[str, int] = {}
    total = 0
    for rulebase in _RULEBASES:
        for policy_type in vsys.findall(f"./{rulebase}/*"):
            rules = policy_type.findall("./rules/entry")
            if rules:
                key = f"{rulebase} · {policy_type.tag}"
                counts[key] = len(rules)
                total += len(rules)
    return counts, total


def _interface_entries(device: ET.Element) -> dict[str, ET.Element]:
    result: dict[str, ET.Element] = {}
    for entry in device.findall("./network/interface/*/entry"):
        if entry.get("name"):
            result[entry.get("name", "")] = entry
        for unit in entry.findall(".//units/entry"):
            if unit.get("name"):
                result[unit.get("name", "")] = unit
    return result


def _possible_transit_subnets(device: ET.Element, vsyses: list[ET.Element]) -> list[dict]:
    """Find same connected L3 subnet assigned to interfaces in different VSYS.

    This is a review hint only. Identical addressing can be intentional and is
    never treated as proof that a subnet is a transit link.
    """
    interfaces = _interface_entries(device)
    owners_by_interface: dict[str, set[str]] = defaultdict(set)
    zone_by_interface: dict[tuple[str, str], set[str]] = defaultdict(set)
    for vsys in vsyses:
        owner = str(vsys.get("name", ""))
        for member in vsys.findall("./import/network/interface/member"):
            name = (member.text or "").strip()
            if name:
                owners_by_interface[name].add(owner)
        for zone in vsys.findall("./zone/entry"):
            zone_name = str(zone.get("name", ""))
            for member in zone.findall("./network/*/member"):
                if member.text and member.text.strip():
                    zone_by_interface[(owner, member.text.strip())].add(zone_name)

    by_network: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for interface_name, interface in interfaces.items():
        for owner in owners_by_interface.get(interface_name, set()):
            for ip_entry in interface.findall(".//ip/entry"):
                value = (ip_entry.get("name") or "").strip()
                try:
                    network = str(ipaddress.ip_interface(value).network)
                except ValueError:
                    continue
                by_network[network][owner].update(zone_by_interface.get((owner, interface_name), set()))

    return [
        {
            "subnet": network,
            "vsys": sorted(owners, key=str.casefold),
            "zones": sorted({zone for names in owners.values() for zone in names}, key=str.casefold),
        }
        for network, owners in sorted(by_network.items())
        if len(owners) > 1
    ]


def _device_network_inventory(device: ET.Element) -> list[dict]:
    """Summarize device-wide network objects that remain unchanged by flattening."""
    network = device.find("./network")
    if network is None:
        return []
    rows = []
    interface_root = network.find("./interface")
    if interface_root is not None:
        top_level = [entry for group in list(interface_root) for entry in group.findall("./entry")]
        interfaces = list(top_level)
        interfaces.extend(unit for entry in top_level for unit in entry.findall("./units/entry"))
        rows.append({"name": "Interfaces", "count": len(interfaces)})
    for label, path in (
        ("Virtual routers", "./virtual-router/entry"),
        ("Logical routers", "./logical-router/entry"),
        ("VLANs", "./vlan/entry"),
        ("Virtual wires", "./virtual-wire/entry"),
        ("IPsec tunnels", "./tunnel/ipsec/entry"),
        ("GRE tunnels", "./tunnel/gre/entry"),
    ):
        rows.append({"name": label, "count": len(network.findall(path))})
    routes = network.findall("./virtual-router/entry/routing-table/ip/static-route/entry")
    routes.extend(network.findall("./virtual-router/entry/routing-table/ipv6/static-route/entry"))
    rows.append({"name": "Static routes", "count": len(routes)})
    return rows


def analyze_panos_vsys_merge(
    xml_bytes: bytes, parsed_config: tuple[ET.Element, object] | None = None,
) -> dict:
    """Return the topology and family inventory shown before a merge decision."""
    root, vsyses = _parse_standalone_config(xml_bytes, parsed_config)
    device = root.find("./devices/entry")
    rows = []
    for vsys in vsyses:
        name = str(vsys.get("name", ""))
        counts, total = _policy_counts(vsys)
        rows.append({
            "name": name,
            "zones": _zone_details(vsys),
            "policy_counts": counts,
            "policy_total": total,
            "interfaces": [
                member.text.strip()
                for member in vsys.findall("./import/network/interface/member")
                if member.text and member.text.strip()
            ],
        })
    all_zones = [
        {"vsys": row["name"], **zone}
        for row in rows for zone in row["zones"]
    ]
    return {
        "vsys": rows,
        "vsys_count": len(rows),
        "zone_mappings": all_zones,
        "possible_transit_subnets": _possible_transit_subnets(device, vsyses),
        "network_inventory": _device_network_inventory(device),
        "policy_total": sum(row["policy_total"] for row in rows),
        "warnings": [
            "Policies blijven policies: de wizard herschrijft alleen de gekozen zone-namen en voegt de VSYS-rulebases in de gekozen volgorde samen.",
            "Er worden geen rules automatisch samengevoegd of verwijderd; rule-volgorde kan de verkeersuitkomst veranderen.",
            "Routes, interfaces, VPN's en overige apparaatbrede netwerkconfiguratie blijven behouden; mogelijke transitnetwerken worden niet automatisch verwijderd.",
            "De transitnetwerkdetectie is een beperkte subnet-hint en kan niet elke routeringsafhankelijkheid vinden; controleer het volledige netwerkoverzicht handmatig.",
            "Alleen PAN-OS-objecttypen die naar Shared kunnen, gaan naar Shared. Policies en zones blijven in vsys1.",
        ],
    }


def _object_collection(scope: ET.Element, path: str, create: bool = False) -> ET.Element | None:
    return _ensure_path(scope, path) if create else _find_path(scope, path)


def _merge_named_items_to_shared(
    shared: ET.Element,
    vsyses: list[ET.Element],
    collection_paths: list[tuple[str, str]],
) -> tuple[int, int]:
    moved = 0
    reused = 0
    for path, label in collection_paths:
        existing_shared = _object_collection(shared, path)
        by_name = {
            entry.get("name", ""): entry
            for entry in (existing_shared.findall("./entry") if existing_shared is not None else [])
            if entry.get("name")
        }
        candidates: list[tuple[ET.Element, ET.Element]] = []
        for vsys in vsyses:
            collection = _object_collection(vsys, path)
            if collection is None:
                continue
            for entry in collection.findall("./entry"):
                name = str(entry.get("name", "")).strip()
                if not name:
                    raise VsysMergeError(f"{label}: er staat een item zonder naam in {vsys.get('name')}")
                current = by_name.get(name)
                if current is not None and _config_signature(current) != _config_signature(entry):
                    raise VsysMergeError(
                        f"{label} '{name}' bestaat met verschillende inhoud in meerdere scopes; "
                        "hernoem of los dit eerst op in de bronworkspace."
                    )
                if current is None:
                    if existing_shared is None:
                        existing_shared = _object_collection(shared, path, create=True)
                    clone = copy.deepcopy(entry)
                    existing_shared.append(clone)
                    by_name[name] = clone
                    moved += 1
                else:
                    reused += 1
                candidates.append((collection, entry))
        for collection, entry in candidates:
            collection.remove(entry)
    return moved, reused


def _move_shareable_objects(root: ET.Element, vsyses: list[ET.Element]) -> tuple[int, int]:
    shared = root.find("./shared")
    if shared is None:
        # Create Shared only if at least one eligible object actually exists.
        has_objects = any(
            _object_collection(vsys, OBJECT_NODES[kind]) is not None
            and _object_collection(vsys, OBJECT_NODES[kind]).find("./entry") is not None
            for vsys in vsyses
            for kind in PANOS_SCOPE_MOVE_OBJECT_TYPES
            if kind in OBJECT_NODES
        )
        has_server_profiles = any(
            _object_collection(vsys, path) is not None
            and _object_collection(vsys, path).find("./entry") is not None
            for vsys in vsyses
            for path in (*_SHARED_EXTRA_PATHS, *(f"server-profile/{kind}" for kind in _SERVER_PROFILE_TYPES))
        )
        if not has_objects and not has_server_profiles:
            return 0, 0
        shared = ET.SubElement(root, "shared")

    paths = [
        (OBJECT_NODES[kind], kind)
        for kind in sorted(PANOS_SCOPE_MOVE_OBJECT_TYPES)
        if kind in OBJECT_NODES
    ]
    paths.extend((path, path.rsplit("/", 1)[-1]) for path in _SHARED_EXTRA_PATHS)
    paths.extend((f"server-profile/{kind}", f"server-profile/{kind}") for kind in _SERVER_PROFILE_TYPES)
    return _merge_named_items_to_shared(shared, vsyses, paths)


def _merge_config_node(
    target: ET.Element,
    source: ET.Element,
    path: str,
    union_member_paths: frozenset[str] = frozenset(),
) -> None:
    if target.tag != source.tag:
        raise VsysMergeError(f"Onverwachte XML-structuur bij {path}")
    for key, value in source.attrib.items():
        current = target.attrib.get(key)
        if current is not None and current != value:
            raise VsysMergeError(f"Conflicterend attribuut bij {path}/@{key}")
        target.set(key, value)
    source_text = (source.text or "").strip()
    target_text = (target.text or "").strip()
    if source_text:
        if target_text and target_text != source_text:
            raise VsysMergeError(f"Conflicterende instellingen bij {path}")
        target.text = source.text

    for child in list(source):
        child_path = f"{path}/{child.tag}"
        if child.tag == "member" and path in union_member_paths:
            value = (child.text or "").strip()
            if not any((candidate.text or "").strip() == value for candidate in target.findall("./member")):
                target.append(copy.deepcopy(child))
            continue
        if child.tag == "entry" and child.get("name"):
            matches = [
                item for item in target.findall("./entry")
                if item.get("name") == child.get("name")
            ]
            if not matches:
                target.append(copy.deepcopy(child))
            elif len(matches) > 1:
                raise VsysMergeError(f"Dubbel item '{child.get('name')}' bij {child_path}")
            else:
                _merge_config_node(matches[0], child, f"{child_path}[@name={child.get('name')}]")
            continue
        matches = [item for item in target.findall("./*") if item.tag == child.tag]
        if not matches:
            target.append(copy.deepcopy(child))
        elif len(matches) == 1:
            _merge_config_node(matches[0], child, child_path, union_member_paths)
        elif _config_signature(child) not in {_config_signature(item) for item in matches}:
            raise VsysMergeError(f"Meerdere conflicterende waarden bij {child_path}")


def _mapped_zone_name(zone_mappings: dict[tuple[str, str], str], vsys_name: str, zone_name: str) -> str:
    result = str(zone_mappings.get((vsys_name, zone_name), "")).strip()
    if not result:
        raise VsysMergeError(f"Kies een doelzone voor {vsys_name} · {zone_name}")
    if len(result) > 31 or re.search(r"[\x00-\x1f\\/]", result):
        raise VsysMergeError(f"Ongeldige PAN-OS-zone naam: {result}")
    return result


def _merge_zone(target: ET.Element, incoming: ET.Element, path: str) -> None:
    for key, value in incoming.attrib.items():
        current = target.attrib.get(key)
        if current is not None and current != value:
            raise VsysMergeError(f"Conflicterende zone-instelling bij {path}/@{key}")
        target.set(key, value)
    for child in list(incoming):
        if child.tag == "network":
            incoming_network = copy.deepcopy(child)
            for external in list(incoming_network.findall("./external")):
                incoming_network.remove(external)
            if not list(incoming_network):
                continue
            current_network = target.find("./network")
            if current_network is None:
                target.append(incoming_network)
                continue
            current_types = {item.tag for item in list(current_network)}
            incoming_types = {item.tag for item in list(incoming_network)}
            if current_types and incoming_types and current_types != incoming_types:
                raise VsysMergeError(f"Zone {path} combineert incompatibele netwerktypen")
            for network_type in list(incoming_network):
                current_type = current_network.find(f"./{network_type.tag}")
                if current_type is None:
                    current_network.append(copy.deepcopy(network_type))
                    continue
                _merge_config_node(
                    current_type, network_type, f"{path}/network/{network_type.tag}",
                    frozenset({f"network/{network_type.tag}"}),
                )
            continue
        existing = target.find(f"./{child.tag}")
        if existing is None:
            target.append(copy.deepcopy(child))
        else:
            _merge_config_node(existing, child, f"{path}/{child.tag}")


def _merge_zones(
    vsyses: list[ET.Element],
    ordered_names: list[str],
    target_vsys: str,
    zone_mappings: dict[tuple[str, str], str],
) -> tuple[int, int]:
    by_name = {str(vsys.get("name", "")): vsys for vsys in vsyses}
    local_zone_targets: set[str] = set()
    prepared: list[tuple[str, str, ET.Element, bool]] = []
    for vsys_name in ordered_names:
        vsys = by_name[vsys_name]
        for zone in vsys.findall("./zone/entry"):
            source_name = str(zone.get("name", "")).strip()
            destination = _mapped_zone_name(zone_mappings, vsys_name, source_name)
            network = zone.find("./network")
            is_external = network is not None and network.find("./external") is not None
            if not is_external:
                local_zone_targets.add(destination)
            prepared.append((vsys_name, destination, zone, is_external))

    for vsys_name, destination, _zone, is_external in prepared:
        if is_external and destination not in local_zone_targets:
            raise VsysMergeError(
                f"Externe zone {vsys_name} · {_zone.get('name', '')} moet aan een bestaande of gemapte lokale zone worden gekoppeld."
            )

    target_scope = by_name[target_vsys]
    target_container = target_scope.find("./zone")
    if target_container is None:
        target_container = ET.SubElement(target_scope, "zone")
    for existing in list(target_container):
        target_container.remove(existing)
    merged_names: set[str] = set()
    for vsys_name, destination, zone, _is_external in prepared:
        incoming = copy.deepcopy(zone)
        incoming.set("name", destination)
        existing = next((item for item in target_container.findall("./entry") if item.get("name") == destination), None)
        if existing is None:
            # External zones have no local interface binding and cannot stand
            # alone after flattening. They must be mapped onto a local zone.
            if incoming.find("./network/external") is not None:
                continue
            target_container.append(incoming)
        else:
            _merge_zone(existing, incoming, f"{target_vsys} · {destination}")
        merged_names.add(destination)
    interface_zone_owners: dict[str, set[str]] = defaultdict(set)
    for zone in target_container.findall("./entry"):
        zone_name = str(zone.get("name", ""))
        for member in zone.findall("./network/*/member"):
            value = (member.text or "").strip()
            if value:
                interface_zone_owners[value].add(zone_name)
    duplicate_zone_interfaces = [
        f"{interface} ({', '.join(sorted(zones, key=str.casefold))})"
        for interface, zones in interface_zone_owners.items() if len(zones) > 1
    ]
    if duplicate_zone_interfaces:
        raise VsysMergeError(
            "Een interface zou na de zonekoppeling in meerdere zones zitten; pas de zonekeuzes aan: "
            + ", ".join(duplicate_zone_interfaces[:12])
        )
    return len(prepared), len(merged_names)


def _rewrite_policy_zones(rule: ET.Element, source_vsys: str, mappings: dict[tuple[str, str], str]) -> None:
    for field in ("from", "to"):
        for member in rule.findall(f"./{field}/member"):
            value = (member.text or "").strip()
            if not value or value.casefold() == "any":
                continue
            mapped = mappings.get((source_vsys, value))
            if mapped:
                member.text = mapped


def _policy_vsys_numbers(vsyses: list[ET.Element]) -> dict[str, int]:
    """Resolve stable numeric prefixes from PAN-OS IDs, names, or source order."""
    numbers: dict[str, int] = {}
    used: set[int] = set()
    unresolved: list[tuple[str, int]] = []

    for index, vsys in enumerate(vsyses, start=1):
        name = str(vsys.get("name", ""))
        raw_id = (vsys.findtext("./vsys-id") or "").strip()
        match = re.fullmatch(r"vsys([1-9][0-9]*)", name, flags=re.IGNORECASE)
        if raw_id.isdecimal():
            number = int(raw_id)
        elif match and int(match.group(1)) <= 255:
            number = int(match.group(1))
        else:
            unresolved.append((name, index))
            continue
        numbers[name] = number
        used.add(number)

    for name, preferred in unresolved:
        number = preferred
        while number in used and number <= 255:
            number += 1
        if number > 255:
            raise VsysMergeError("Kan geen uniek VSYS-nummer bepalen voor automatisch hernoemde policies")
        numbers[name] = number
        used.add(number)

    return numbers


def _policy_name_assignments(
    source_bases: list[tuple[str, ET.Element]],
    vsys_numbers: dict[str, int],
    base_name: str,
) -> tuple[dict[tuple[str, str, str], str], list[dict[str, str]]]:
    """Plan unique, length-limited names for policies duplicated across VSYS."""
    names_by_category: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    names_by_scope_category: dict[tuple[str, str], set[str]] = defaultdict(set)
    for scope, source_base in source_bases:
        for category in list(source_base):
            rules = category.find("./rules")
            if rules is None:
                continue
            for rule in rules.findall("./entry"):
                name = str(rule.get("name", "")).strip()
                if not name:
                    raise VsysMergeError(f"Policy zonder naam bij {base_name}/{category.tag}")
                scope_names = names_by_scope_category[(scope, category.tag)]
                if name in scope_names:
                    raise VsysMergeError(
                        f"Dubbele policynaam '{name}' binnen {scope}/{base_name}/{category.tag}; "
                        "controleer de bronconfiguratie."
                    )
                scope_names.add(name)
                names_by_category[category.tag][name].append(scope)

    assignments: dict[tuple[str, str, str], str] = {}
    renamed: list[dict[str, str]] = []
    for category_name, names in names_by_category.items():
        # Reserve original names so generated prefixes cannot shadow a rule
        # that already exists in one of the VSYS.
        used_names = set(names)
        pending = []
        for name, scopes in names.items():
            if len(scopes) <= 1:
                continue
            if len({vsys_numbers[scope] for scope in scopes}) != len(scopes):
                raise VsysMergeError("VSYS-ID's leveren geen eenduidige prefix op voor dubbele policynamen")
            ordered_scopes = sorted(scopes, key=lambda scope: vsys_numbers[scope])
            for scope in ordered_scopes[1:]:
                pending.append((vsys_numbers[scope], scope, name))

        for number, scope, name in sorted(pending):
            prefix = f"{number}_"
            suffix_number = 1
            while True:
                suffix = "" if suffix_number == 1 else f"_{suffix_number}"
                available = _MAX_POLICY_NAME_LENGTH - len(prefix) - len(suffix)
                if available < 1:
                    raise VsysMergeError("Kan geen unieke policynaam binnen de PAN-OS-limiet van 63 tekens maken")
                candidate = f"{prefix}{name[:available]}{suffix}"
                if candidate not in used_names:
                    break
                suffix_number += 1

            used_names.add(candidate)
            assignments[(scope, category_name, name)] = candidate
            renamed.append({
                "rulebase": base_name,
                "policy_type": category_name,
                "vsys": scope,
                "old_name": name,
                "new_name": candidate,
            })
    return assignments, renamed


def _merge_rulebases(
    vsyses: list[ET.Element],
    ordered_names: list[str],
    target_vsys: str,
    default_rule_source: str,
    zone_mappings: dict[tuple[str, str], str],
    vsys_numbers: dict[str, int],
) -> tuple[int, list[dict[str, str]]]:
    by_name = {str(vsys.get("name", "")): vsys for vsys in vsyses}
    target = by_name[target_vsys]
    policy_total = 0
    renamed_policies: list[dict[str, str]] = []
    for base_name in _RULEBASES:
        source_bases = [
            (scope, by_name[scope].find(f"./{base_name}"))
            for scope in ordered_names
            if by_name[scope].find(f"./{base_name}") is not None
        ]
        if not source_bases:
            continue
        name_assignments, base_renames = _policy_name_assignments(
            source_bases, vsys_numbers, base_name,
        )
        renamed_policies.extend(base_renames)
        original = target.find(f"./{base_name}")
        insert_at = list(target).index(original) if original is not None else len(list(target))
        if original is not None:
            target.remove(original)
        merged_base = ET.Element(base_name)
        categories: dict[str, ET.Element] = {}
        rule_entries: dict[str, list[ET.Element]] = defaultdict(list)
        selected_default_rules: dict[tuple[str, str], ET.Element] = {}
        default_rule_sources: dict[tuple[str, str], set[str]] = defaultdict(set)

        for scope, source_base in source_bases:
            for source_category in list(source_base):
                category = categories.get(source_category.tag)
                if category is None:
                    category = ET.Element(source_category.tag, dict(source_category.attrib))
                    categories[source_category.tag] = category
                    merged_base.append(category)
                elif dict(category.attrib) != dict(source_category.attrib):
                    raise VsysMergeError(f"Conflicterende rulebase-instellingen bij {base_name}/{source_category.tag}")

                for child in list(source_category):
                    if child.tag == "default-rule":
                        key = (source_category.tag, "category")
                        default_rule_sources[key].add(scope)
                        if scope == default_rule_source:
                            selected_default_rules[key] = copy.deepcopy(child)
                        continue
                    if child.tag != "rules":
                        current = category.find(f"./{child.tag}")
                        if current is None:
                            category.append(copy.deepcopy(child))
                        else:
                            _merge_config_node(current, child, f"{base_name}/{source_category.tag}/{child.tag}")
                        continue

                    if category.find("./rules") is None:
                        category.append(ET.Element("rules"))
                    for rule_item in list(child):
                        if rule_item.tag == "entry":
                            name = str(rule_item.get("name", "")).strip()
                            if not name:
                                raise VsysMergeError(f"Policy zonder naam bij {base_name}/{source_category.tag}")
                            clone = copy.deepcopy(rule_item)
                            renamed_name = name_assignments.get((scope, source_category.tag, name))
                            if renamed_name:
                                clone.set("name", renamed_name)
                            _rewrite_policy_zones(clone, scope, zone_mappings)
                            rule_entries[source_category.tag].append(clone)
                            policy_total += 1
                        elif rule_item.tag == "default-rule":
                            key = (source_category.tag, "rules")
                            default_rule_sources[key].add(scope)
                            if scope == default_rule_source:
                                selected_default_rules[key] = copy.deepcopy(rule_item)
                        else:
                            current_rules = category.find("./rules")
                            existing = next((item for item in current_rules if item.tag == rule_item.tag), None)
                            if existing is None:
                                current_rules.append(copy.deepcopy(rule_item))
                            else:
                                _merge_config_node(
                                    existing, rule_item,
                                    f"{base_name}/{source_category.tag}/rules/{rule_item.tag}",
                                )

        for category_name, category in categories.items():
            for location in ("category", "rules"):
                key = (category_name, location)
                if default_rule_sources.get(key) and key not in selected_default_rules:
                    raise VsysMergeError(
                        f"De gekozen default-rulebron {default_rule_source} heeft geen default rules voor {base_name}/{category_name}; "
                        "kies een bron die deze rulebase bevat."
                    )
            rules = category.find("./rules")
            if rules is None:
                rules = ET.SubElement(category, "rules")
            default_rule = selected_default_rules.get((category_name, "rules"))
            other_children = [copy.deepcopy(item) for item in list(rules) if item.tag != "default-rule"]
            for item in list(rules):
                rules.remove(item)
            for item in rule_entries.get(category_name, []):
                rules.append(item)
            for item in other_children:
                rules.append(item)
            if default_rule is not None:
                rules.append(default_rule)
            category_default = selected_default_rules.get((category_name, "category"))
            if category_default is not None:
                category.append(category_default)

        target.insert(min(insert_at, len(list(target))), merged_base)
    return policy_total, renamed_policies


def _merge_vsys_settings(
    vsyses: list[ET.Element],
    ordered_names: list[str],
    target_vsys: str,
) -> None:
    by_name = {str(vsys.get("name", "")): vsys for vsys in vsyses}
    target = by_name[target_vsys]
    shareable_root_tags = {
        OBJECT_NODES[kind].split("/", 1)[0]
        for kind in PANOS_SCOPE_MOVE_OBJECT_TYPES
        if kind in OBJECT_NODES and "/" not in OBJECT_NODES[kind]
    }
    scope_managed = {"zone", *_RULEBASES, "vsys-id", *shareable_root_tags}
    for source_name in ordered_names:
        if source_name == target_vsys:
            continue
        source = by_name[source_name]
        for child in list(source):
            if child.tag in scope_managed:
                continue
            existing = target.find(f"./{child.tag}")
            if existing is None:
                target.append(copy.deepcopy(child))
            else:
                _merge_config_node(existing, child, child.tag, _IMPORT_MEMBER_PATHS)


def _check_duplicate_interface_assignments(vsyses: list[ET.Element]) -> None:
    owners: dict[str, set[str]] = defaultdict(set)
    for vsys in vsyses:
        scope = str(vsys.get("name", ""))
        for member in vsys.findall("./import/network/interface/member"):
            value = (member.text or "").strip()
            if value:
                owners[value].add(scope)
    duplicates = [
        f"{interface} ({', '.join(sorted(scopes, key=str.casefold))})"
        for interface, scopes in owners.items() if len(scopes) > 1
    ]
    if duplicates:
        raise VsysMergeError(
            "Interfaces kunnen niet tegelijk aan meerdere VSYS gekoppeld zijn; los de dubbele toewijzing eerst op: "
            + ", ".join(duplicates[:12])
        )


def merge_panos_vsys_config(
    xml_bytes: bytes,
    *,
    target_vsys: str,
    vsys_order: list[str],
    default_rule_source: str,
    zone_mappings: dict[tuple[str, str], str],
    parsed_config: tuple[ET.Element, object] | None = None,
) -> tuple[bytes, dict]:
    """Flatten a multi-VSYS workspace into a new single-VSYS PAN-OS snapshot.

    The caller stores the returned XML in a new workspace. This function only
    transforms an in-memory copy and fails closed on conflicting definitions.
    """
    original_root, original_vsys = _parse_standalone_config(xml_bytes, parsed_config)
    original_names = [str(item.get("name", "")) for item in original_vsys]
    if target_vsys != "vsys1" or target_vsys not in original_names:
        raise VsysMergeError("PAN-OS vereist vsys1 als blijvende doel-VSYS")
    if len(vsys_order) != len(original_names) or set(vsys_order) != set(original_names):
        raise VsysMergeError("Kies elke VSYS precies één keer in de gewenste rule-volgorde")
    if default_rule_source not in original_names:
        raise VsysMergeError("Kies een bestaande VSYS als bron voor de default rules")

    zone_keys = {
        (str(vsys.get("name", "")), str(zone.get("name", "")))
        for vsys in original_vsys for zone in vsys.findall("./zone/entry")
    }
    if set(zone_mappings) != zone_keys:
        raise VsysMergeError("Geef voor elke bestaande zone precies één doelzone op")
    for key, value in zone_mappings.items():
        _mapped_zone_name(zone_mappings, key[0], key[1])

    # Work only on a deep copy: validation failures never alter the source XML.
    root = copy.deepcopy(original_root)
    device = root.find("./devices/entry")
    vsys_container = device.find("./vsys")
    vsyses = vsys_container.findall("./entry")
    _check_duplicate_interface_assignments(vsyses)
    shared_moved, shared_reused = _move_shareable_objects(root, vsyses)
    zone_total, merged_zone_total = _merge_zones(vsyses, vsys_order, target_vsys, zone_mappings)
    policy_total, renamed_policies = _merge_rulebases(
        vsyses, vsys_order, target_vsys, default_rule_source, zone_mappings,
        _policy_vsys_numbers(vsyses),
    )
    _merge_vsys_settings(vsyses, vsys_order, target_vsys)

    for item in list(vsys_container.findall("./entry")):
        if item.get("name") != target_vsys:
            vsys_container.remove(item)

    try:
        merged_root, snapshot = parse_snapshot(normalized_config_xml(root))
    except Exception as exc:
        raise VsysMergeError(f"Samengevoegde XML is niet parsebaar: {exc}") from exc
    if snapshot.kind != "panos" or snapshot.vsys != [target_vsys]:
        raise VsysMergeError("De output heeft niet precies één verwachte VSYS")
    output = normalized_config_xml(merged_root)
    source_analysis = analyze_panos_vsys_merge(xml_bytes, parsed_config)
    return output, {
        "target_vsys": target_vsys,
        "source_order": list(vsys_order),
        "removed_vsys": [name for name in original_names if name != target_vsys],
        "policy_total": policy_total,
        "renamed_policies": renamed_policies,
        "zones_in_sources": zone_total,
        "zones_in_target": merged_zone_total,
        "shareable_objects_moved": shared_moved,
        "shared_objects_reused": shared_reused,
        "possible_transit_subnets": source_analysis["possible_transit_subnets"],
        "warnings": source_analysis["warnings"],
    }
