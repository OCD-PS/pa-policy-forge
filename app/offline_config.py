from __future__ import annotations

import hashlib
import hmac
import copy
import shlex
import re
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable
import xml.etree.ElementTree as ET

from defusedxml import ElementTree as SafeET


class OfflineConfigError(ValueError):
    pass


def merge_config_xml(
    base_xml: bytes, desired_xml: bytes, current_xml: bytes,
    ignored_attributes: Iterable[str] = (),
    root_normalizer: Callable[[ET.Element], None] | None = None,
) -> tuple[bytes, list[str]]:
    """Merge independent edits from a workspace onto a newer PAN-OS XML candidate.

    XML child collections that represent member lists are treated as unordered
    multisets. Named ``entry`` collections merge by name; policy ``rules`` order
    is preserved and concurrent order changes fail closed.
    """
    base = SafeET.fromstring(base_xml)
    desired = SafeET.fromstring(desired_xml)
    current = SafeET.fromstring(current_xml)
    for root in (base, desired, current):
        for node in root.iter():
            for attribute in ignored_attributes:
                node.attrib.pop(attribute, None)
        if root_normalizer is not None:
            root_normalizer(root)
    conflicts: list[str] = []
    signature_cache: dict[ET.Element, tuple] = {}

    def signature(node):
        cached = signature_cache.get(node)
        if cached is not None:
            return cached
        value = (
            node.tag,
            tuple(sorted(node.attrib.items())),
            (node.text or "").strip(),
            tuple(signature(child) for child in list(node)),
        )
        signature_cache[node] = value
        return value

    def conflict(path):
        if path not in conflicts and len(conflicts) < 20:
            conflicts.append(path[:240])

    def merge_scalar(base_value, desired_value, current_value, path):
        if desired_value == base_value:
            return current_value
        if current_value == base_value or desired_value == current_value:
            return desired_value
        conflict(path)
        return current_value

    def merge_node(base_node, desired_node, current_node, path):
        if base_node is None:
            if desired_node is None:
                return copy.deepcopy(current_node) if current_node is not None else None
            if current_node is None or signature(desired_node) == signature(current_node):
                return copy.deepcopy(desired_node)
            conflict(path)
            return copy.deepcopy(current_node)
        if desired_node is None:
            if current_node is None or signature(current_node) == signature(base_node):
                return None
            conflict(path)
            return copy.deepcopy(current_node)
        if current_node is None:
            if signature(desired_node) == signature(base_node):
                return None
            conflict(path)
            return None

        merged = ET.Element(base_node.tag)
        attr_keys = set(base_node.attrib) | set(desired_node.attrib) | set(current_node.attrib)
        for key in sorted(attr_keys):
            value = merge_scalar(
                base_node.attrib.get(key), desired_node.attrib.get(key),
                current_node.attrib.get(key), f"{path}/@{key}",
            )
            if value is not None:
                merged.set(key, value)
        merged.text = merge_scalar(
            (base_node.text or "").strip(), (desired_node.text or "").strip(),
            (current_node.text or "").strip(), path,
        ) or None

        base_children, desired_children, current_children = (
            list(base_node), list(desired_node), list(current_node)
        )
        all_children = (*base_children, *desired_children, *current_children)
        if all_children and all(
            child.tag == "member" and not child.attrib and not list(child) for child in all_children
        ):
            def member_values(children):
                return [(child.text or "").strip() for child in children]

            b_values = member_values(base_children)
            d_values = member_values(desired_children)
            c_values = member_values(current_children)
            if d_values == b_values:
                chosen = current_children
            elif c_values == b_values or d_values == c_values:
                chosen = desired_children
            else:
                # PAN-OS member lists commonly mean OR alternatives. Combining
                # two distinct edits could widen a security rule unexpectedly.
                conflict(f"{path}/member-list")
                chosen = current_children
            for child in chosen:
                merged.append(copy.deepcopy(child))
            return merged

        if all_children and all(child.tag == "entry" and child.get("name") for child in all_children):
            def named_map(children):
                return {child.get("name"): child for child in children}

            b_map, d_map, c_map = map(named_map, (base_children, desired_children, current_children))
            merged_map = {}
            for name in dict.fromkeys((*b_map, *d_map, *c_map)):
                item = merge_node(
                    b_map.get(name), d_map.get(name), c_map.get(name),
                    f"{path}/entry[@name={name}]",
                )
                if item is not None:
                    merged_map[name] = item
            b_order = [child.get("name") for child in base_children]
            d_order = [child.get("name") for child in desired_children]
            c_order = [child.get("name") for child in current_children]
            if base_node.tag == "rules":
                order = merge_scalar(b_order, d_order, c_order, f"{path}/order")
            else:
                order = c_order + [name for name in d_order if name not in c_map]
            emitted_names = set()
            for name in order:
                if name in merged_map and name not in emitted_names:
                    merged.append(merged_map[name])
                    emitted_names.add(name)
            for name, child in merged_map.items():
                if name not in emitted_names:
                    merged.append(child)
            return merged

        # Singleton child tags (description, action, source, etc.) can merge
        # recursively. Ambiguous repeated schemas are replaced only when one
        # side is unchanged; competing edits are surfaced as conflicts.
        def unique_tag_map(children):
            tags = [child.tag for child in children]
            return len(tags) == len(set(tags))

        if all(unique_tag_map(children) for children in (base_children, desired_children, current_children)):
            b_map = {child.tag: child for child in base_children}
            d_map = {child.tag: child for child in desired_children}
            c_map = {child.tag: child for child in current_children}
            merged_map = {}
            for tag in dict.fromkeys((*b_map, *d_map, *c_map)):
                item = merge_node(b_map.get(tag), d_map.get(tag), c_map.get(tag), f"{path}/{tag}")
                if item is not None:
                    merged_map[tag] = item
            tags = [child.tag for child in current_children]
            tags.extend(tag for tag in merged_map if tag not in tags)
            for tag in tags:
                if tag in merged_map:
                    merged.append(merged_map.pop(tag))
            for child in merged_map.values():
                merged.append(child)
            return merged

        if signature(desired_node) == signature(base_node):
            return copy.deepcopy(current_node)
        if signature(current_node) == signature(base_node) or signature(desired_node) == signature(current_node):
            return copy.deepcopy(desired_node)
        conflict(path)
        return copy.deepcopy(current_node)

    merged_root = merge_node(base, desired, current, "/config")
    if conflicts:
        return b"", conflicts
    if merged_root is None:
        raise OfflineConfigError("De volledige configuratieroot kan niet worden verwijderd")
    return normalized_config_xml(merged_root), []


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


UNUSED_OBJECT_TYPES = frozenset({
    "addresses", "address-groups", "application-groups", "services",
    "service-groups", "tags",
})
REFERENCE_CHECK_OBJECT_TYPES = UNUSED_OBJECT_TYPES | frozenset({
    "regions", "applications", "application-filters", "schedules",
    "security-profile-groups", "log-forwarding", "custom-url-categories",
    "hip-profiles", "dynamic-user-groups",
})

MERGEABLE_OBJECT_TYPES = REFERENCE_CHECK_OBJECT_TYPES


def object_reference_index(
    xml_bytes: bytes, object_type: str, names: Iterable[str], *, parsed_root: ET.Element | None = None,
) -> dict[str, list[str]]:
    """Find conservative typed references to named PAN-OS objects."""
    return object_reference_indexes(
        xml_bytes, {object_type: names}, parsed_root=parsed_root,
    )[object_type]


def object_reference_indexes(
    xml_bytes: bytes, names_by_type: dict[str, Iterable[str]], *, parsed_root: ET.Element | None = None,
) -> dict[str, dict[str, list[str]]]:
    """Index several object types in one full-config walk.

    Incremental pushes can delete many object types at once. Building XML
    paths and ancestor chains separately for every type made dependency checks
    scale poorly with large PAN-OS/Panorama configurations. This keeps the
    complete, fail-closed reference inventory while sharing that work.
    """
    supported_types = REFERENCE_CHECK_OBJECT_TYPES | {"certificates"}
    if any(object_type not in supported_types for object_type in names_by_type):
        raise OfflineConfigError("Voor dit configuratietype is geen referentiecontrole beschikbaar")
    wanted_by_type = {
        object_type: {str(name): [] for name in names if str(name)}
        for object_type, names in names_by_type.items()
    }
    if not any(wanted_by_type.values()):
        return wanted_by_type

    root = parsed_root if parsed_root is not None else SafeET.fromstring(xml_bytes)
    parent = {child: node for node in root.iter() for child in node}
    paths: dict[ET.Element, str] = {root: "/" + root.tag}

    def path_for(node: ET.Element) -> str:
        pending = []
        current = node
        while current not in paths:
            pending.append(current)
            current = parent.get(current)
            if current is None:
                break
        path = paths.get(current, "")
        for item in reversed(pending):
            suffix = f"[@name={item.get('name')}]" if item.tag == "entry" and item.get("name") else ""
            path = f"{path}/{item.tag}{suffix}"
            paths[item] = path
        return paths.get(node, path)

    def add(object_type: str, value: str, node: ET.Element, suffix: str = "") -> None:
        value = value.strip()
        wanted = wanted_by_type[object_type]
        if value in wanted:
            path = path_for(node) + suffix
            if path not in wanted[value]:
                wanted[value].append(path[:240])

    policy_kinds = set(POLICY_NODES.values())
    rulebase_scopes = {"rulebase", "pre-rulebase", "post-rulebase"}
    certificate_value_tags = {
        "certificate", "certificate-name", "ca-certificate", "ca-certificates",
        "forward-trust-certificate", "forward-untrust-certificate", "root-ca",
        "ssl-tls-service-profile", "server-certificate",
    }
    candidate_tags = {
        "member", "translated-address", "translated-port", "schedule", "log-setting", "filter",
    }
    if "certificates" in wanted_by_type:
        candidate_tags.update({"rsa", "entry", *certificate_value_tags})

    for node in root.iter():
        if node.tag not in candidate_tags:
            continue
        parent_node = parent.get(node)
        owner_tag = parent_node.tag if parent_node is not None else ""
        chain_set: set[str] | None = None

        def ancestors() -> set[str]:
            nonlocal chain_set
            if chain_set is None:
                chain_set = set()
                current = node
                while current is not None:
                    chain_set.add(current.tag)
                    current = parent.get(current)
            return chain_set

        for object_type, wanted in wanted_by_type.items():
            if not wanted:
                continue
            if object_type == "certificates":
                if node.tag in certificate_value_tags:
                    add(object_type, node.text or "", node)
                if node.tag == "rsa" and ancestors() & {"forward-trust-certificate", "forward-untrust-certificate"}:
                    add(object_type, node.text or "", node)
                if node.tag == "member" and ancestors() & {"ca", "certificate", "ca-certificates", "trusted-root-CA", "trusted-root-ca"}:
                    add(object_type, node.text or "", node)
                if node.tag == "entry" and str(node.findtext("./usage", "")).casefold() in {
                    "forward-trust", "forward-untrust", "forward trust", "forward untrust",
                    "forward-trust-certificate", "forward-untrust-certificate",
                }:
                    add(object_type, node.get("name", ""), node, "/usage")
            elif object_type in {"addresses", "address-groups", "regions"}:
                if node.tag == "member" and owner_tag in {"source", "destination"}:
                    if ancestors() & rulebase_scopes and ancestors() & policy_kinds:
                        add(object_type, node.text or "", node)
                if node.tag == "member" and owner_tag == "static" and "address-group" in ancestors():
                    add(object_type, node.text or "", node)
                if node.tag in {"translated-address", "translated-port", "member"} and node.text:
                    if ancestors() & {"source-translation", "destination-translation"}:
                        add(object_type, node.text, node)
            elif object_type in {"services", "service-groups"}:
                if node.tag == "member" and owner_tag == "service":
                    if ancestors() & rulebase_scopes and ancestors() & policy_kinds:
                        add(object_type, node.text or "", node)
                if node.tag == "member" and owner_tag == "members" and "service-group" in ancestors():
                    add(object_type, node.text or "", node)
            elif object_type == "application-groups":
                if node.tag == "member" and owner_tag == "application":
                    if ancestors() & rulebase_scopes and ancestors() & policy_kinds:
                        add(object_type, node.text or "", node)
                if node.tag == "member" and owner_tag == "members" and "application-group" in ancestors():
                    add(object_type, node.text or "", node)
            elif object_type in {"applications", "application-filters"}:
                if node.tag == "member" and owner_tag in {"application", "application-filter"}:
                    if ancestors() & rulebase_scopes and ancestors() & policy_kinds:
                        add(object_type, node.text or "", node)
                if node.tag == "member" and owner_tag == "members" and "application-group" in ancestors():
                    add(object_type, node.text or "", node)
            elif object_type == "schedules":
                if node.tag == "schedule" and ancestors() & rulebase_scopes and ancestors() & policy_kinds:
                    add(object_type, node.text or "", node)
            elif object_type == "security-profile-groups":
                if node.tag == "member" and owner_tag == "group" and "profile-setting" in ancestors():
                    add(object_type, node.text or "", node)
            elif object_type == "log-forwarding":
                if node.tag == "log-setting" and ancestors() & rulebase_scopes and ancestors() & policy_kinds:
                    add(object_type, node.text or "", node)
            elif object_type == "custom-url-categories":
                if node.tag == "member" and owner_tag == "category" and ancestors() & rulebase_scopes:
                    add(object_type, node.text or "", node)
            elif object_type == "hip-profiles":
                if node.tag == "member" and owner_tag in {"source-hip", "destination-hip"}:
                    add(object_type, node.text or "", node)
            elif object_type == "dynamic-user-groups":
                if node.tag == "member" and owner_tag in {"source-user", "destination-user"}:
                    add(object_type, node.text or "", node)
            elif object_type == "tags":
                if node.tag == "member" and owner_tag in {"tag", "tags"}:
                    add(object_type, node.text or "", node)
                if node.tag == "filter" and node.text and ancestors() & {"address-group", "dynamic-user-group"}:
                    expression = node.text
                    for name in wanted:
                        if re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w.-])", expression):
                            add(object_type, name, node)

    return wanted_by_type


def unresolved_object_reference_index(
    xml_bytes: bytes, object_type: str, names: Iterable[str], *, original_xml_bytes: bytes | None = None,
    parsed: tuple[ET.Element, ConfigSnapshot] | None = None,
    original_parsed: tuple[ET.Element, ConfigSnapshot] | None = None,
) -> dict[str, list[str]]:
    """Return references whose effective object is missing or changed.

    ``object_reference_index`` intentionally reports every typed name match,
    which is useful for conservative deletion workflows. Incremental pushes
    need one extra distinction: a VSYS reference remains valid after its local
    definition is moved to Shared, because PAN-OS resolves that same reference
    through inheritance. Compare against the original target too, so a
    same-name but behaviorally different Shared object cannot silently change
    policy semantics. Keep untyped/unknown references fail-closed.
    """
    root = parsed[0] if parsed is not None else None
    all_references = object_reference_index(xml_bytes, object_type, names, parsed_root=root)
    wanted = {name for name, paths in all_references.items() if paths}
    if not wanted:
        return all_references
    root, snapshot = parsed if parsed is not None else parse_snapshot(xml_bytes)
    original_root, original_snapshot = (
        original_parsed if original_parsed is not None else (
            parse_snapshot(original_xml_bytes) if original_xml_bytes is not None else (root, snapshot)
        )
    )
    references, _ = _typed_object_reference_nodes(root, object_type)
    parent = {child: node for node in root.iter() for child in node}
    paths: dict[ET.Element, str] = {root: "/" + root.tag}

    def reference_paths(source_root: ET.Element, source_references: list[ET.Element]) -> set[tuple[str, str]]:
        source_parent = {child: node for node in source_root.iter() for child in node}
        source_paths: dict[ET.Element, str] = {source_root: "/" + source_root.tag}

        def path_for(node: ET.Element) -> str:
            if node in source_paths:
                return source_paths[node]
            owner = source_parent.get(node)
            if owner is None:
                source_paths[node] = "/" + node.tag
            else:
                suffix = f"[@name={node.get('name')}]" if node.tag == "entry" and node.get("name") else ""
                source_paths[node] = path_for(owner) + "/" + node.tag + suffix
            return source_paths[node]

        return {
            (path_for(node), (node.text or "").strip())
            for node in source_references
            if (node.text or "").strip() in wanted
        }

    original_references, _ = _typed_object_reference_nodes(original_root, object_type)
    original_reference_paths = reference_paths(original_root, original_references)

    for node in root.iter():
        if node in paths:
            continue
        owner = parent.get(node)
        if owner is None:
            paths[node] = "/" + node.tag
        else:
            suffix = f"[@name={node.get('name')}]" if node.tag == "entry" and node.get("name") else ""
            paths[node] = paths[owner] + "/" + node.tag + suffix

    resolved_paths: dict[str, set[str]] = {name: set() for name in wanted}
    for node in references:
        name = (node.text or "").strip()
        if name not in wanted:
            continue
        scope = _reference_scope(node, parent, snapshot)
        if scope is None:
            continue
        try:
            resolved = _resolve_scoped_object_entry(root, snapshot, scope, object_type, name)
            # A newly-added policy reference has no prior object resolution to
            # compare. Validate that its desired Shared/VSYS object resolves,
            # then compare behavior only when this same reference existed before.
            had_original_reference = (paths[node], name) in original_reference_paths
            original_resolved = (
                _resolve_scoped_object_entry(original_root, original_snapshot, scope, object_type, name)
                if had_original_reference else None
            )
        except OfflineConfigError:
            # Duplicate/ambiguous ownership is not proof of safety.
            continue
        if resolved is not None and (
            not had_original_reference
            or (
                original_resolved is not None
                and _merge_object_signature(resolved, object_type)
                == _merge_object_signature(original_resolved, object_type)
            )
        ):
            resolved_paths[name].add(paths[node][:240])

    return {
        name: [path for path in paths if path not in resolved_paths.get(name, set())]
        for name, paths in all_references.items()
    }


def _merge_object_signature(entry: ET.Element, object_type: str) -> tuple:
    """Compare behavior-bearing XML; service tags are preserved as metadata."""
    ignored_nodes = {"description", "comments"}
    if object_type in {"services", "service-groups"}:
        ignored_nodes.update({"tag", "tags"})

    def canonical(node: ET.Element, *, root: bool = False, parent_tag: str = "") -> tuple | None:
        if (
            object_type == "services" and node.tag == "source-port"
            and parent_tag in {"tcp", "udp"} and (node.text or "").strip() == "0-65535"
        ):
            # PAN-OS documents source-port as optional and accepts 0-65535;
            # this explicit range is the same unrestricted source-port value.
            return None
        children = tuple(
            value for child in node if child.tag not in ignored_nodes
            if (value := canonical(child, parent_tag=node.tag)) is not None
        )
        attributes = tuple(sorted(
            (key, value) for key, value in node.attrib.items()
            if key != "uuid" and not (root and key == "name")
        ))
        return node.tag, attributes, (node.text or "").strip(), children

    return canonical(entry, root=True)


def duplicate_object_groups(xml_bytes: bytes, scope: str, object_type: str, parsed=None) -> list[dict]:
    """Return exact functional duplicate groups in one editable object scope."""
    if object_type not in MERGEABLE_OBJECT_TYPES:
        raise OfflineConfigError("Dubbele objecten samenvoegen is niet veilig ondersteund voor dit type")
    root, snapshot = parsed if parsed is not None else parse_snapshot(xml_bytes)
    _, records = scoped_objects(xml_bytes, scope, object_type, parsed=(root, snapshot))
    candidates = [record for record in records if record.get("editable")]
    by_signature: dict[tuple, list[dict]] = {}
    for record in candidates:
        entry = _find_scoped_object_entry(root, snapshot, scope, object_type, record["name"])
        if entry is None:
            raise OfflineConfigError("De objectinventaris wijzigde tijdens het zoeken; vernieuw de workspace")
        by_signature.setdefault(_merge_object_signature(entry, object_type), []).append({
            "name": record["name"],
            "owner": record["owner"],
            "description": record.get("description") or record.get("comments", ""),
            "tags": list(record.get("tag", []) or []),
            "summary": record.get("summary", ""),
            "fingerprint": hashlib.sha256(ET.tostring(entry, encoding="utf-8")).hexdigest(),
        })
    groups = []
    for signature, items in by_signature.items():
        if len(items) < 2:
            continue
        names = sorted(item["name"] for item in items)
        group_id = hashlib.sha256((object_type + "\0" + scope + "\0" + "\0".join(names)).encode()).hexdigest()[:20]
        groups.append({
            "id": group_id,
            "objects": sorted(items, key=lambda item: item["name"].casefold()),
            "metadata_differs": len({item["description"] for item in items}) > 1,
            "tags_differ": len({tuple(sorted(item["tags"])) for item in items}) > 1,
        })
    return sorted(groups, key=lambda group: group["objects"][0]["name"].casefold())


def duplicate_object_groups_across_panos_scopes(xml_bytes: bytes, object_type: str, parsed=None) -> list[dict]:
    """Find functional duplicates defined in Shared and multiple standalone VSYS scopes."""
    if object_type not in MERGEABLE_OBJECT_TYPES:
        raise OfflineConfigError("Dubbele objecten samenvoegen is niet veilig ondersteund voor dit objecttype")
    root, snapshot = parsed if parsed is not None else parse_snapshot(xml_bytes)
    if snapshot.kind != "panos" or len(snapshot.vsys) < 2:
        raise OfflineConfigError("Scope-overstijgend samenvoegen vereist standalone PAN-OS met meerdere VSYS")

    by_signature: dict[tuple, list[dict]] = {}
    for scope in ["Shared", *snapshot.vsys]:
        scope_root = _scope_root(root, snapshot, scope)
        if scope_root is None:
            continue
        collection = scope_root
        for part in OBJECT_NODES[object_type].split("/"):
            collection = collection.find(f"./{part}")
            if collection is None:
                break
        if collection is None:
            continue
        for entry in collection.findall("./entry"):
            record = object_record(entry, scope, True, object_type)
            fingerprint = hashlib.sha256(ET.tostring(entry, encoding="utf-8")).hexdigest()
            candidate_id = hashlib.sha256(
                f"{object_type}\0{scope}\0{entry.get('name', '')}\0{fingerprint}".encode()
            ).hexdigest()[:24]
            by_signature.setdefault(_merge_object_signature(entry, object_type), []).append({
                "name": entry.get("name", ""),
                "owner": scope,
                "scope": scope,
                "description": record.get("description") or record.get("comments", ""),
                "tags": list(record.get("tag", []) or []),
                "summary": record.get("summary", ""),
                "fingerprint": fingerprint,
                "candidate_id": candidate_id,
            })

    groups = []
    scope_order = {scope: index for index, scope in enumerate(["Shared", *snapshot.vsys])}
    for signature, items in by_signature.items():
        if len(items) < 2 or len({item["scope"] for item in items}) < 2:
            continue
        sorted_items = sorted(items, key=lambda item: (scope_order[item["scope"]], item["name"].casefold()))
        group_id = hashlib.sha256("\0".join(item["candidate_id"] for item in sorted_items).encode()).hexdigest()[:20]
        groups.append({
            "id": group_id,
            "objects": sorted_items,
            "metadata_differs": len({item["description"] for item in items}) > 1,
            "tags_differ": len({tuple(sorted(item["tags"])) for item in items}) > 1,
        })
    return sorted(groups, key=lambda group: (group["objects"][0]["name"].casefold(), group["id"]))


def _find_scoped_object_entry(root: ET.Element, snapshot: ConfigSnapshot, scope: str, object_type: str, name: str) -> ET.Element | None:
    scope_root = _scope_root(root, snapshot, scope)
    if scope_root is None:
        return None
    collection = scope_root
    for part in OBJECT_NODES[object_type].split("/"):
        collection = collection.find(f"./{part}")
        if collection is None:
            return None
    matches = [entry for entry in collection.findall("./entry") if entry.get("name") == name]
    return matches[0] if len(matches) == 1 else None


def _reference_scope(node: ET.Element, parent: dict[ET.Element, ET.Element], snapshot: ConfigSnapshot) -> str | None:
    """Return the VSYS/device-group that owns a reference, or Shared."""
    current = node
    while current is not None:
        owner = parent.get(current)
        if current.tag == "shared":
            return "Shared"
        if current.tag == "entry" and owner is not None and owner.tag in {"vsys", "device-group"}:
            return current.get("name")
        current = owner
    return None


def _object_resolution_chain(snapshot: ConfigSnapshot, scope: str) -> list[str]:
    if scope == "Shared":
        return ["Shared"]
    if snapshot.kind == "panorama":
        return _scope_chain(snapshot, scope)
    return ["Shared", scope]


def _resolve_scoped_object_entry(
    root: ET.Element, snapshot: ConfigSnapshot, scope: str, object_type: str, name: str,
) -> ET.Element | None:
    """Resolve a name using Shared/VSYS or Panorama device-group inheritance."""
    for candidate_scope in reversed(_object_resolution_chain(snapshot, scope)):
        scope_root = _scope_root(root, snapshot, candidate_scope)
        if scope_root is None:
            continue
        collection = scope_root
        for part in OBJECT_NODES[object_type].split("/"):
            collection = collection.find(f"./{part}")
            if collection is None:
                break
        if collection is None:
            continue
        matches = [entry for entry in collection.findall("./entry") if entry.get("name") == name]
        if len(matches) > 1:
            raise OfflineConfigError(f"Object {name} komt dubbel voor in scope {candidate_scope}")
        if matches:
            return matches[0]
    return None


def _typed_object_reference_nodes(root: ET.Element, object_type: str) -> tuple[list[ET.Element], list[ET.Element]]:
    """Return recognized reference nodes and tag-filter expressions for a type."""
    if object_type not in MERGEABLE_OBJECT_TYPES:
        raise OfflineConfigError("Referenties herschrijven is niet veilig ondersteund voor dit objecttype")
    parent = {child: node for node in root.iter() for child in node}
    policy_kinds = set(POLICY_NODES.values())
    rulebase_scopes = {"rulebase", "pre-rulebase", "post-rulebase"}
    members: list[ET.Element] = []
    expressions: list[ET.Element] = []
    for node in root.iter():
        owner = parent.get(node)
        if node.tag != "member" and not (object_type == "schedules" and node.tag == "schedule") and not (
            object_type in {"addresses", "address-groups", "regions"}
            and node.tag in {"translated-address", "translated-port"}
        ):
            if object_type == "tags" and node.tag == "filter" and node.text:
                chain = set()
                current = node
                while current is not None:
                    chain.add(current.tag)
                    current = parent.get(current)
                if chain & {"address-group", "dynamic-user-group"}:
                    expressions.append(node)
            continue
        chain = set()
        current = node
        while current is not None:
            chain.add(current.tag)
            current = parent.get(current)
        is_reference = False
        if object_type in {"addresses", "address-groups", "regions"}:
            is_reference = (
                node.tag == "member" and owner is not None
                and ((owner.tag in {"source", "destination"} and chain & rulebase_scopes and bool(chain & policy_kinds))
                     or (owner.tag == "static" and "address-group" in chain)
                     or ("source-translation" in chain or "destination-translation" in chain))
            )
            if node.tag in {"translated-address", "translated-port"} and node.text and chain & {"source-translation", "destination-translation"}:
                members.append(node)
        elif object_type in {"services", "service-groups"}:
            is_reference = node.tag == "member" and owner is not None and (
                (owner.tag == "service" and chain & rulebase_scopes and bool(chain & policy_kinds))
                or (owner.tag == "members" and "service-group" in chain)
            )
        elif object_type == "application-groups":
            is_reference = node.tag == "member" and owner is not None and (
                (owner.tag == "application" and chain & rulebase_scopes and bool(chain & policy_kinds))
                or (owner.tag == "members" and "application-group" in chain)
            )
        elif object_type in {"applications", "application-filters"}:
            is_reference = node.tag == "member" and owner is not None and (
                (owner.tag in {"application", "application-filter"} and chain & rulebase_scopes and bool(chain & policy_kinds))
                or (owner.tag == "members" and "application-group" in chain)
            )
        elif object_type == "schedules":
            is_reference = node.tag == "schedule" and chain & rulebase_scopes and bool(chain & policy_kinds)
        elif object_type == "security-profile-groups":
            is_reference = node.tag == "member" and owner is not None and owner.tag == "group" and "profile-setting" in chain
        elif object_type == "log-forwarding":
            is_reference = node.tag == "log-setting" and chain & rulebase_scopes and bool(chain & policy_kinds)
        elif object_type == "custom-url-categories":
            is_reference = node.tag == "member" and owner is not None and owner.tag == "category" and chain & rulebase_scopes
        elif object_type == "hip-profiles":
            is_reference = node.tag == "member" and owner is not None and owner.tag in {"source-hip", "destination-hip"}
        elif object_type == "dynamic-user-groups":
            is_reference = node.tag == "member" and owner is not None and owner.tag in {"source-user", "destination-user"}
        elif object_type == "tags":
            is_reference = node.tag == "member" and owner is not None and owner.tag in {"tag", "tags"}
        if is_reference:
            members.append(node)
    return members, expressions


def merge_duplicate_objects(
    xml_bytes: bytes, scope: str, object_type: str, selections: list[dict],
) -> tuple[bytes, dict[str, int]]:
    """Merge selected duplicate groups from one typed object collection."""
    return merge_duplicate_object_groups(xml_bytes, scope, [
        {**selection, "object_type": object_type} for selection in selections
    ])


def merge_duplicate_object_groups(
    xml_bytes: bytes, scope: str, selections: list[dict],
) -> tuple[bytes, dict[str, int]]:
    """Apply duplicate groups from multiple object types in one validated edit."""
    root, snapshot = parse_snapshot(xml_bytes)
    scope_root = _scope_root(root, snapshot, scope)
    if scope_root is None:
        raise OfflineConfigError("De geselecteerde scope bestaat niet meer")

    duplicates_by_type: dict[str, dict[str, str]] = {}
    selected_entries: dict[tuple[str, str], tuple[ET.Element, ET.Element]] = {}
    selected_entry_by_name: dict[tuple[str, str], ET.Element] = {}
    selected_master_entries: dict[tuple[str, str], ET.Element] = {}
    selected_names_by_type: dict[str, set[str]] = {}
    collections: dict[str, ET.Element] = {}

    for selection in selections:
        object_type = str(selection.get("object_type", ""))
        if object_type not in MERGEABLE_OBJECT_TYPES:
            raise OfflineConfigError("Dubbele objecten samenvoegen is niet veilig ondersteund voor dit type")
        collection = collections.get(object_type)
        if collection is None:
            collection = scope_root
            for part in OBJECT_NODES[object_type].split("/"):
                collection = collection.find(f"./{part}")
                if collection is None:
                    raise OfflineConfigError("De objectcollectie bestaat niet meer")
            collections[object_type] = collection

        names = list(dict.fromkeys(str(value) for value in selection.get("names", []) if str(value)))
        master_name = str(selection.get("master", ""))
        if len(names) < 2 or master_name not in names:
            raise OfflineConfigError("Kies precies één masterobject per duplicaatgroep")
        selected_names_seen = selected_names_by_type.setdefault(object_type, set())
        if selected_names_seen.intersection(names):
            raise OfflineConfigError("Duplicaatgroepen overlappen; maak een nieuwe preview")
        selected_names_seen.update(names)
        entries = {}
        for name in names:
            matches = [entry for entry in collection.findall("./entry") if entry.get("name") == name]
            if len(matches) != 1:
                raise OfflineConfigError(f"Object {name} is intussen gewijzigd of bestaat niet meer")
            entries[name] = matches[0]
            expected_fingerprint = (selection.get("fingerprints") or {}).get(name)
            actual_fingerprint = hashlib.sha256(ET.tostring(matches[0], encoding="utf-8")).hexdigest()
            if not isinstance(expected_fingerprint, str) or not hmac.compare_digest(expected_fingerprint, actual_fingerprint):
                raise OfflineConfigError(f"Object {name} is intussen gewijzigd; maak een nieuwe merge-preview")
        signatures = {_merge_object_signature(entry, object_type) for entry in entries.values()}
        if len(signatures) != 1:
            raise OfflineConfigError("De objecten zijn niet langer functioneel identiek; niets samengevoegd")
        duplicates = duplicates_by_type.setdefault(object_type, {})
        for name, entry in entries.items():
            if name == master_name:
                continue
            if name in duplicates or master_name in duplicates:
                raise OfflineConfigError("Duplicaatgroepen overlappen; maak een nieuwe preview")
            duplicates[name] = master_name
            selected_entries[(object_type, name)] = (collection, entry)
            selected_entry_by_name[(object_type, name)] = entry
        selected_master_entries[(object_type, master_name)] = entries[master_name]
        if object_type in {"services", "service-groups"}:
            # Tags on services are organizational metadata. Retain the union
            # instead of dropping tags when aliases are removed.
            master = entries[master_name]
            master_tag = master.find("./tag")
            seen_tags = {
                (item.text or "").strip()
                for item in (master_tag.findall("./member") if master_tag is not None else [])
            }
            for entry in entries.values():
                if entry is master:
                    continue
                for tag in entry.findall("./tag/member"):
                    value = (tag.text or "").strip()
                    if value and value not in seen_tags:
                        if master_tag is None:
                            master_tag = ET.SubElement(master, "tag")
                        ET.SubElement(master_tag, "member").text = value
                        seen_tags.add(value)
        if master_name in duplicates:
            raise OfflineConfigError("Een gekozen master staat ook als duplicaat in een andere groep")
    if not selected_entries:
        raise OfflineConfigError("Er zijn geen duplicaten geselecteerd")

    parent_map = {child: parent for parent in root.iter() for child in parent}
    resolution_cache: dict[tuple[str, str, str], ET.Element | None] = {}

    def resolve_reference(scope_name: str, object_type: str, name: str) -> ET.Element | None:
        key = (scope_name, object_type, name)
        if key not in resolution_cache:
            resolution_cache[key] = _resolve_scoped_object_entry(root, snapshot, scope_name, object_type, name)
        return resolution_cache[key]

    for object_type, duplicates in duplicates_by_type.items():
        # Resolve each reference in its own VSYS/device-group chain. Identical
        # names in other scopes can refer to different objects and must survive.
        refs, expressions = _typed_object_reference_nodes(root, object_type)
        replaced_by_parent: dict[ET.Element, set[str]] = {}
        for node in refs:
            value = (node.text or "").strip()
            selected_entry = selected_entry_by_name.get((object_type, value))
            if selected_entry is None:
                continue
            reference_scope = _reference_scope(node, parent_map, snapshot)
            if reference_scope is None:
                raise OfflineConfigError(
                    f"Referentie naar object {value} heeft geen herkenbare scope; niets opgeslagen",
                )
            if resolve_reference(reference_scope, object_type, value) is not selected_entry:
                continue
            master_name = duplicates[value]
            expected_master = selected_master_entries[(object_type, master_name)]
            if resolve_reference(reference_scope, object_type, master_name) is not expected_master:
                raise OfflineConfigError(
                    f"Object {master_name} wordt in scope {reference_scope} overschaduwd; "
                    "de verwijzing kan niet veilig worden omgezet",
                )
            node.text = master_name
            if node in parent_map:
                replaced_by_parent.setdefault(parent_map[node], set()).add(master_name)
        for node in expressions:
            expression = node.text or ""
            reference_scope = _reference_scope(node, parent_map, snapshot)
            if reference_scope is None:
                if any(
                    re.search(rf"(?<![\w.-]){re.escape(old_name)}(?![\w.-])", expression)
                    for old_name in duplicates
                ):
                    raise OfflineConfigError(
                        "Tagfilter met een geselecteerd object heeft geen herkenbare scope; niets opgeslagen",
                    )
                continue
            for old_name, new_name in duplicates.items():
                selected_entry = selected_entry_by_name[(object_type, old_name)]
                if resolve_reference(reference_scope, object_type, old_name) is not selected_entry:
                    continue
                expected_master = selected_master_entries[(object_type, new_name)]
                if resolve_reference(reference_scope, object_type, new_name) is not expected_master:
                    raise OfflineConfigError(
                        f"Object {new_name} wordt in scope {reference_scope} overschaduwd; "
                        "de verwijzing kan niet veilig worden omgezet",
                    )
                expression = re.sub(
                    rf"(?<![\w.-]){re.escape(old_name)}(?![\w.-])",
                    lambda _: new_name,
                    expression,
                )
            node.text = expression

        # Replacements can duplicate members when both names were referenced.
        for parent, merged_names in replaced_by_parent.items():
            children = list(parent)
            if not children or any(child.tag != "member" for child in children):
                continue
            seen = set()
            for child in children:
                value = (child.text or "").strip()
                if value in merged_names and value in seen:
                    parent.remove(child)
                elif value in merged_names:
                    seen.add(value)

    for object_type, duplicates in duplicates_by_type.items():
        refs, expressions = _typed_object_reference_nodes(root, object_type)
        for node in refs:
            value = (node.text or "").strip()
            selected_entry = selected_entry_by_name.get((object_type, value))
            reference_scope = _reference_scope(node, parent_map, snapshot)
            if selected_entry is not None:
                if reference_scope is None:
                    raise OfflineConfigError("Een objectreferentie heeft geen herkenbare scope; niets opgeslagen")
                if resolve_reference(reference_scope, object_type, value) is selected_entry:
                    raise OfflineConfigError("Niet alle scopegebonden referenties konden veilig worden bijgewerkt; niets opgeslagen")
        for node in expressions:
            expression = node.text or ""
            reference_scope = _reference_scope(node, parent_map, snapshot)
            if reference_scope is None:
                if any(
                    re.search(rf"(?<![\w.-]){re.escape(old_name)}(?![\w.-])", expression)
                    for old_name in duplicates
                ):
                    raise OfflineConfigError("Een tagfilter heeft geen herkenbare scope; niets opgeslagen")
                continue
            if any(
                re.search(rf"(?<![\w.-]){re.escape(old_name)}(?![\w.-])", expression)
                and resolve_reference(reference_scope, object_type, old_name)
                is selected_entry_by_name[(object_type, old_name)]
                for old_name in duplicates
            ):
                raise OfflineConfigError("Niet alle scopegebonden referenties konden veilig worden bijgewerkt; niets opgeslagen")

    for collection, entry in selected_entries.values():
        collection.remove(entry)
    return normalized_config_xml(root), {"merged": len(selected_entries), "groups": len(selections)}


def merge_duplicate_object_groups_to_shared(
    xml_bytes: bytes, selections: list[dict],
) -> tuple[bytes, dict[str, int]]:
    """Merge identical local/Shared PAN-OS objects into one Shared definition."""
    root, snapshot = parse_snapshot(xml_bytes)
    if snapshot.kind != "panos" or len(snapshot.vsys) < 2:
        raise OfflineConfigError("Scope-overstijgend samenvoegen vereist standalone PAN-OS met meerdere VSYS")
    if not isinstance(selections, list) or not selections:
        raise OfflineConfigError("Selecteer minstens één scope-overstijgende duplicaatgroep")

    valid_scopes = {"Shared", *snapshot.vsys}
    selected_by_key: dict[tuple[str, str, str], tuple[ET.Element, ET.Element]] = {}
    selected_by_entry: dict[ET.Element, tuple[str, str, str]] = {}
    merged_groups: list[dict] = []
    target_signatures: dict[tuple[str, str], tuple] = {}

    def collection_for(scope_name: str, object_type: str, *, create: bool = False) -> ET.Element | None:
        scope_root = _scope_root(root, snapshot, scope_name)
        if scope_root is None and create and scope_name == "Shared":
            scope_root = ET.SubElement(root, "shared")
        if scope_root is None:
            return None
        collection = scope_root
        for part in OBJECT_NODES[object_type].split("/"):
            child = collection.find(f"./{part}")
            if child is None:
                if not create:
                    return None
                child = ET.SubElement(collection, part)
            collection = child
        return collection

    for selection in selections:
        object_type = str(selection.get("object_type", ""))
        if object_type not in MERGEABLE_OBJECT_TYPES:
            raise OfflineConfigError("Scope-overstijgend samenvoegen is niet veilig ondersteund voor dit type")
        raw_objects = selection.get("objects")
        master = selection.get("master")
        if not isinstance(raw_objects, list) or len(raw_objects) < 2 or not isinstance(master, dict):
            raise OfflineConfigError("Een duplicaatgroep bevat geen geldige scope/objectselectie")

        entries: list[tuple[tuple[str, str, str], ET.Element, ET.Element]] = []
        signatures = set()
        for item in raw_objects:
            if not isinstance(item, dict):
                raise OfflineConfigError("Een duplicaatgroep bevat een ongeldige objectselectie")
            owner = str(item.get("scope", ""))
            name = str(item.get("name", ""))
            key = (object_type, owner, name)
            if owner not in valid_scopes or not name or key in selected_by_key:
                raise OfflineConfigError("Duplicaatgroepen overlappen of bevatten een onbekende scope")
            collection = collection_for(owner, object_type)
            matches = [entry for entry in collection.findall("./entry") if entry.get("name") == name] if collection is not None else []
            if len(matches) != 1:
                raise OfflineConfigError(f"Object {name} in {owner} is intussen gewijzigd of bestaat niet meer")
            entry = matches[0]
            fingerprint = hashlib.sha256(ET.tostring(entry, encoding="utf-8")).hexdigest()
            if not isinstance(item.get("fingerprint"), str) or not hmac.compare_digest(item["fingerprint"], fingerprint):
                raise OfflineConfigError(f"Object {name} in {owner} is intussen gewijzigd; maak een nieuwe merge-preview")
            entries.append((key, collection, entry))
            signatures.add(_merge_object_signature(entry, object_type))
        if len(signatures) != 1 or len({key[1] for key, _, _ in entries}) < 2:
            raise OfflineConfigError("De objecten zijn niet langer gelijk of komen niet uit meerdere scopes")

        master_scope = str(master.get("scope", ""))
        master_name = str(master.get("name", ""))
        master_key = (object_type, master_scope, master_name)
        if master_key not in {key for key, _, _ in entries}:
            raise OfflineConfigError("De gekozen Shared-master hoort niet bij deze duplicaatgroep")
        target_key = (object_type, master_name)
        signature = next(iter(signatures))
        if target_key in target_signatures and target_signatures[target_key] != signature:
            raise OfflineConfigError(f"Naam {master_name} zou verschillende objecten in Shared samenvoegen")
        target_signatures[target_key] = signature

        for key, collection, entry in entries:
            selected_by_key[key] = (collection, entry)
            selected_by_entry[entry] = key
        merged_groups.append({
            "object_type": object_type,
            "entries": entries,
            "master_key": master_key,
            "master_name": master_name,
            "signature": signature,
        })

    if not selected_by_key:
        raise OfflineConfigError("Er zijn geen scope-overstijgende duplicaten geselecteerd")

    # A Shared master cannot be shadowed by a different local definition in any VSYS.
    for group in merged_groups:
        object_type, master_name = group["master_key"][0], group["master_name"]
        for owner in ["Shared", *snapshot.vsys]:
            collection = collection_for(owner, object_type)
            matches = [entry for entry in collection.findall("./entry") if entry.get("name") == master_name] if collection is not None else []
            for entry in matches:
                key = (object_type, owner, master_name)
                if key not in selected_by_key:
                    raise OfflineConfigError(
                        f"Shared-master {master_name} wordt overschaduwd door een ander object in {owner}; "
                        "los die naamconflict eerst op",
                    )

    duplicates_by_entry: dict[ET.Element, tuple[str, str]] = {}
    for group in merged_groups:
        object_type = group["object_type"]
        master_key = group["master_key"]
        master_entry = selected_by_key[master_key][1]
        for key, _, entry in group["entries"]:
            duplicates_by_entry[entry] = (object_type, group["master_name"])
        if object_type in {"services", "service-groups"}:
            master_tag = master_entry.find("./tag")
            seen_tags = {
                (item.text or "").strip()
                for item in (master_tag.findall("./member") if master_tag is not None else [])
            }
            for _, _, entry in group["entries"]:
                for tag in entry.findall("./tag/member"):
                    value = (tag.text or "").strip()
                    if value and value not in seen_tags:
                        if master_tag is None:
                            master_tag = ET.SubElement(master_entry, "tag")
                        ET.SubElement(master_tag, "member").text = value
                        seen_tags.add(value)

    parent_map = {child: parent for parent in root.iter() for child in parent}
    resolution_cache: dict[tuple[str, str, str], ET.Element | None] = {}

    def resolve(scope_name: str, object_type: str, name: str) -> ET.Element | None:
        cache_key = (scope_name, object_type, name)
        if cache_key not in resolution_cache:
            resolution_cache[cache_key] = _resolve_scoped_object_entry(root, snapshot, scope_name, object_type, name)
        return resolution_cache[cache_key]

    replacements_to_verify: list[tuple[ET.Element, str, str, str]] = []
    for object_type in {key[0] for key in selected_by_key}:
        refs, expressions = _typed_object_reference_nodes(root, object_type)
        replaced_by_parent: dict[ET.Element, set[str]] = {}
        for node in refs:
            reference_scope = _reference_scope(node, parent_map, snapshot)
            value = (node.text or "").strip()
            if reference_scope is None:
                if any(key[0] == object_type and key[2] == value for key in selected_by_key):
                    raise OfflineConfigError(f"Referentie naar object {value} heeft geen herkenbare scope; niets opgeslagen")
                continue
            entry = resolve(reference_scope, object_type, value)
            selected_key = selected_by_entry.get(entry) if entry is not None else None
            if selected_key is None:
                continue
            master_name = duplicates_by_entry[entry][1]
            node.text = master_name
            replacements_to_verify.append((node, reference_scope, object_type, master_name))
            if node in parent_map:
                replaced_by_parent.setdefault(parent_map[node], set()).add(master_name)

        for node in expressions:
            reference_scope = _reference_scope(node, parent_map, snapshot)
            expression = node.text or ""
            relevant_names = {
                key[2] for key in selected_by_key if key[0] == object_type
                and re.search(rf"(?<![\w.-]){re.escape(key[2])}(?![\w.-])", expression)
            }
            if reference_scope is None:
                if relevant_names:
                    raise OfflineConfigError("Tagfilter met een geselecteerd object heeft geen herkenbare scope; niets opgeslagen")
                continue
            for old_name in relevant_names:
                entry = resolve(reference_scope, object_type, old_name)
                selected_key = selected_by_entry.get(entry) if entry is not None else None
                if selected_key is None:
                    continue
                master_name = duplicates_by_entry[entry][1]
                expression = re.sub(
                    rf"(?<![\w.-]){re.escape(old_name)}(?![\w.-])",
                    lambda _: master_name,
                    expression,
                )
                # Each expression can mention multiple merged names. Keep the
                # specific token so verification resolves an object name, not
                # the complete filter expression.
                replacements_to_verify.append((node, reference_scope, object_type, master_name))
            node.text = expression

        for parent, merged_names in replaced_by_parent.items():
            children = list(parent)
            if not children or any(child.tag != "member" for child in children):
                continue
            seen = set()
            for child in children:
                value = (child.text or "").strip()
                if value in merged_names and value in seen:
                    parent.remove(child)
                elif value in merged_names:
                    seen.add(value)

    # Copy masters only after rewriting references in the source tree. This is
    # important for nested objects: a copied Shared address-group must inherit
    # any member rewrites made while merging its referenced address objects.
    shared_entries: dict[tuple[str, str], ET.Element] = {}
    for index, group in enumerate(merged_groups):
        object_type = group["object_type"]
        master_name = group["master_name"]
        target_key = (object_type, master_name)
        master_entry = selected_by_key[group["master_key"]][1]
        target_entry = copy.deepcopy(master_entry)
        prior = shared_entries.get(target_key)
        if prior is not None:
            if _merge_object_signature(prior, object_type) != group["signature"]:
                raise OfflineConfigError(f"Naam {master_name} zou verschillende objecten in Shared samenvoegen")
            # Identical groups with a common target name retain metadata from the
            # first selected master while unioning service tags.
            if object_type in {"services", "service-groups"}:
                tag = prior.find("./tag")
                seen = {(item.text or "").strip() for item in (tag.findall("./member") if tag is not None else [])}
                for member in target_entry.findall("./tag/member"):
                    value = (member.text or "").strip()
                    if value and value not in seen:
                        if tag is None:
                            tag = ET.SubElement(prior, "tag")
                        ET.SubElement(tag, "member").text = value
                        seen.add(value)
        else:
            shared_entries[target_key] = target_entry

    for collection, entry in selected_by_key.values():
        collection.remove(entry)
    for (object_type, _), entry in shared_entries.items():
        collection = collection_for("Shared", object_type, create=True)
        if any(item.get("name") == entry.get("name") for item in collection.findall("./entry")):
            raise OfflineConfigError(f"Object {entry.get('name')} bestaat al in Shared")
        collection.append(entry)

    for node, reference_scope, object_type, master_name in replacements_to_verify:
        resolved = _resolve_scoped_object_entry(root, snapshot, reference_scope, object_type, master_name)
        expected_entry = shared_entries.get((object_type, master_name))
        if expected_entry is None or resolved is not expected_entry:
            raise OfflineConfigError("Een verwijzing naar de nieuwe Shared-master wordt lokaal overschaduwd; niets opgeslagen")

    return normalized_config_xml(root), {"merged": len(selected_by_key) - len(merged_groups), "groups": len(merged_groups)}


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
        "server-profiles": (".//server-profile", ".//log-settings/syslog", ".//log-settings/email", ".//log-settings/snmptrap", ".//log-settings/http"),
        "log-settings": (".//log-settings",),
        "high-availability": (".//high-availability",),
        "user-identification": (".//user-id-collector",),
        "vm-information-sources": (".//vm-info-source",),
        # Operational software and license pages are intentionally not mapped
        # to candidate XML writes.  They are not ordinary configuration nodes.
    },
}

# PAN-OS permits these device configuration objects in Shared or a VSYS.
# Keep this selector narrow because other Device pages have different owners.
PANOS_LOCATION_SECTIONS = {
    "device": {"authentication-profile", "authentication-sequence", "local-user-database", "server-profiles"},
}

# Immutable bootstrap schemas for empty sections.  These are candidate editor
# seeds, not claims of full device validation; required references must be filled
# before save.  Secret/account/certificate operations are deliberately excluded.
# XML paths follow the PaloAltoNetworks/pan-os-python Network and Device models.
CONFIG_CREATE_SCHEMAS = {
    "ethernet-layer3": ("network", "interfaces", "device", "network/interface/ethernet", "Ethernet Interface",
             '<entry name=""><layer3><ip><entry name="" /></ip><mtu>1500</mtu></layer3><comment /><link-state>auto</link-state></entry>', ()),
    "aggregate-layer3": ("network", "interfaces", "device", "network/interface/aggregate-ethernet", "Aggregate Interface",
             '<entry name=""><layer3><ip><entry name="" /></ip><mtu>1500</mtu></layer3><comment /></entry>', ()),
    "ethernet-subinterface": ("network", "interfaces", "device", "network/interface/ethernet", "Ethernet Subinterface",
             '<entry name=""><tag /><ip><entry name="" /></ip><comment /></entry>', ()),
    "loopback-interface": ("network", "interfaces", "device", "network/interface/loopback/units", "Loopback Interface",
             '<entry name=""><ip><entry name="" /></ip><comment /></entry>', ()),
    "tunnel-interface": ("network", "interfaces", "device", "network/interface/tunnel/units", "Tunnel Interface",
             '<entry name=""><ip><entry name="" /></ip><comment /></entry>', ()),
    "vlan-interface": ("network", "interfaces", "device", "network/interface/vlan/units", "VLAN Interface",
             '<entry name=""><ip><entry name="" /></ip><comment /></entry>', ()),
    "zone-layer3": ("network", "zones", "vsys", "zone", "Layer 3 Zone",
             '<entry name=""><network><layer3><member /></layer3></network><enable-user-identification>no</enable-user-identification></entry>', ()),
    "zone-layer2": ("network", "zones", "vsys", "zone", "Layer 2 Zone",
             '<entry name=""><network><layer2><member /></layer2></network><enable-user-identification>no</enable-user-identification></entry>', ()),
    "zone-virtual-wire": ("network", "zones", "vsys", "zone", "Virtual Wire Zone",
             '<entry name=""><network><virtual-wire><member /></virtual-wire></network><enable-user-identification>no</enable-user-identification></entry>', ()),
    "zone-tap": ("network", "zones", "vsys", "zone", "Tap Zone",
             '<entry name=""><network><tap><member /></tap></network></entry>', ()),
    "vlan": ("network", "vlans", "device", "network/vlan", "VLAN",
             '<entry name=""><interface><member /></interface><virtual-interface><interface /></virtual-interface></entry>', ()),
    "virtual-wire": ("network", "virtual-wires", "device", "network/virtual-wire", "Virtual Wire",
             '<entry name=""><interface1 /><interface2 /><tag-allowed>0-4094</tag-allowed><multicast-firewalling><enable>no</enable></multicast-firewalling><link-state-pass-through><enable>yes</enable></link-state-pass-through></entry>', ("interface1", "interface2")),
    "virtual-router": ("network", "virtual-routers", "device", "network/virtual-router", "Virtual Router",
             '<entry name=""><interface><member /></interface><admin-dists><static>10</static><static-ipv6>10</static-ipv6></admin-dists></entry>', ()),
    "logical-router": ("network", "logical-routers", "device", "network/logical-router", "Logical Router",
             '<entry name=""><vrf><entry name="default"><interface><member /></interface></entry></vrf></entry>', ()),
    "interface-management-profile": ("network", "network-profiles", "device", "network/profiles/interface-management-profile", "Interface Management Profile",
             '<entry name=""><ping>no</ping><https>no</https><ssh>no</ssh><http>no</http><telnet>no</telnet><snmp>no</snmp><permitted-ip><entry name="" /></permitted-ip></entry>', ()),
    "tunnel-monitor-profile": ("network", "network-profiles", "device", "network/profiles/monitor-profile", "Tunnel Monitor Profile",
             '<entry name=""><interval>3</interval><threshold>5</threshold><action>wait-recover</action></entry>', ()),
    "lldp": ("network", "lldp", "device", "network", "LLDP",
             '<lldp><enable>no</enable></lldp>', ()),
    "authentication-local": ("device", "authentication-profile", "location", "authentication-profile", "Local Database Authentication",
             '<entry name=""><method><local-database /></method><allow-list><member /></allow-list><user-domain /><username-modifier>%USERINPUT%</username-modifier></entry>', ("allow-list",)),
    "authentication-ldap": ("device", "authentication-profile", "location", "authentication-profile", "LDAP Authentication",
             '<entry name=""><method><ldap><server-profile /><login-attribute>sAMAccountName</login-attribute></ldap></method><allow-list><member /></allow-list><user-domain /><username-modifier>%USERINPUT%</username-modifier></entry>', ("method/ldap/server-profile", "allow-list")),
    "authentication-sequence": ("device", "authentication-sequence", "location", "authentication-sequence", "Authentication Sequence",
             '<entry name=""><authentication-profiles><member /></authentication-profiles><use-domain-find-profile>yes</use-domain-find-profile></entry>', ("authentication-profiles",)),
    "local-user-group": ("device", "local-user-database", "location", "local-user-database/user-group", "Local User Group",
             '<entry name=""><user><member /></user></entry>', ("user",)),
    "syslog-server-profile": ("device", "server-profiles", "location", "log-settings/syslog", "Syslog Server Profile",
             '<entry name=""><server><entry name="server-1"><server /><transport>UDP</transport><port>514</port><format>BSD</format><facility>LOG_USER</facility></entry></server></entry>', ("server/entry/server",)),
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


def _ensure_scope_root(root: ET.Element, snapshot: ConfigSnapshot, scope: str) -> ET.Element:
    existing = _scope_root(root, snapshot, scope)
    if existing is not None:
        return existing
    if scope == "Shared":
        return ET.SubElement(root, "shared")
    raise OfflineConfigError("De gekozen scope bestaat niet meer")


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
    chain = _scope_chain(snapshot, scope) if snapshot.kind == "panorama" else (["Shared"] if scope == "Shared" else (["Shared", scope] if root.find("./shared") is not None else [scope]))
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
    chain = _scope_chain(snapshot, scope) if snapshot.kind == "panorama" else (["Shared"] if scope == "Shared" else (["Shared", scope] if root.find("./shared") is not None else [scope]))
    records = []
    for owner in chain:
        scope_root = _scope_root(root, snapshot, owner)
        if scope_root is None:
            continue
        for entry in scope_root.findall(f"./{node}/entry"):
            records.append(object_record(entry, owner, owner == scope, object_type))
    return snapshot, records


def scoped_object_names(xml_bytes: bytes, scope: str, object_type: str, parsed=None) -> tuple[ConfigSnapshot, list[str]]:
    """Return scoped object names without building full editor records.

    Reference pickers only need names. Avoid flattening descriptions, nested
    members, and editable fields for every object when rendering a policy page.
    """
    root, snapshot = parsed if parsed is not None else parse_snapshot(xml_bytes)
    node = OBJECT_NODES.get(object_type)
    if not node:
        raise OfflineConfigError(f"Onbekend objecttype: {object_type}")
    chain = _scope_chain(snapshot, scope) if snapshot.kind == "panorama" else (
        ["Shared"] if scope == "Shared" else (["Shared", scope] if root.find("./shared") is not None else [scope])
    )
    names = []
    for owner in chain:
        scope_root = _scope_root(root, snapshot, owner)
        if scope_root is None:
            continue
        names.extend(
            entry.get("name", "")
            for entry in scope_root.findall(f"./{node}/entry")
            if entry.get("name")
        )
    return snapshot, names


def scoped_object_page(
    xml_bytes: bytes,
    scope: str,
    object_type: str,
    requested_page: int,
    page_size: int,
    *,
    parsed=None,
    editable_first: bool = False,
    selected_name: str = "",
) -> tuple[ConfigSnapshot, int, int, int, list[dict]]:
    """Build editor records only for the requested page of an unfiltered list."""
    root, snapshot = parsed if parsed is not None else parse_snapshot(xml_bytes)
    node = OBJECT_NODES.get(object_type)
    if not node:
        raise OfflineConfigError(f"Onbekend objecttype: {object_type}")
    chain = _scope_chain(snapshot, scope) if snapshot.kind == "panorama" else (
        ["Shared"] if scope == "Shared" else (["Shared", scope] if root.find("./shared") is not None else [scope])
    )
    entries = []
    for owner in chain:
        scope_root = _scope_root(root, snapshot, owner)
        if scope_root is None:
            continue
        entries.extend(
            (entry, owner, owner == scope)
            for entry in scope_root.findall(f"./{node}/entry")
        )
    if editable_first:
        entries.sort(key=lambda item: not item[2])

    total = len(entries)
    page_count = max(1, (total + page_size - 1) // page_size)
    selected_index = next(
        (index for index, (entry, _, _) in enumerate(entries) if entry.get("name") == selected_name),
        None,
    ) if selected_name else None
    page = selected_index // page_size + 1 if selected_index is not None else requested_page
    page = min(max(1, page), page_count)
    offset = (page - 1) * page_size
    records = [
        object_record(entry, owner, editable, object_type)
        for entry, owner, editable in entries[offset:offset + page_size]
    ]
    return snapshot, total, page_count, page, records


PANOS_SCOPE_MOVE_OBJECT_TYPES = frozenset({
    "addresses", "address-groups", "regions", "dynamic-user-groups",
    "applications", "application-groups", "application-filters",
    "services", "service-groups", "tags", "external-dynamic-lists",
    "hip-objects", "hip-profiles", "custom-url-categories",
    "antivirus", "anti-spyware", "vulnerability-protection",
    "url-filtering", "file-blocking", "wildfire-analysis", "dos-protection",
    "schedules", "security-profile-groups", "log-forwarding",
    "authentication", "decryption-profiles",
})
_PANOS_MOVE_BUILTINS = {"any", "application-default", "none", "unknown", "known-user", "auto"}
# ISO 3166-1 alpha-2 codes used by PAN-OS predefined regions. Keep this list
# explicit: a two-letter token alone is not enough to treat a policy value as
# a built-in region.
PANOS_GEO_REGION_CODES = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO
FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE
JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN
MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS
PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ
TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
""".split())
# PAN-DB names from Palo Alto Networks' predefined URL category inventory.
# Custom categories are still resolved by exact name against the configuration.
# Source: https://docs.paloaltonetworks.com/advanced-url-filtering/administration/url-filtering-basics/url-categories
_PANOS_PREDEFINED_URL_CATEGORIES = frozenset("""
abortion abused-drugs adult alcohol-and-tobacco artificial-intelligence auctions
ai-code-assistant ai-conversational-assistant ai-data-and-workflow-optimizer ai-meeting-assistant
ai-media-service ai-platform-service ai-website-generator ai-writing-assistant browser-runtime-attack
business-and-economy command-and-control compromised-website computer-and-internet-info
content-delivery-networks copyright-infringement cryptocurrency dating dynamic-dns
educational-institutions encrypted-dns entertainment-and-arts extremism file-converter
financial-services gambling games government grayware hacking health-and-medicine home-and-garden
hunting-and-fishing insufficient-content internet-communications-and-telephony internet-portals
job-search legal malware marijuana military motor-vehicles music newly-registered-domain news
not-resolved nudity online-storage-and-backup parked peer-to-peer personal-sites-and-blogs
philosophy-and-political-advocacy phishing private-ip-addresses proxy-avoidance-and-anonymizers
questionable ransomware real-estate real-time-detection recreation-and-hobbies reference-and-research
religion remote-access scanning-activity search-engines sex-education shareware-and-freeware shopping
social-networking society sports stock-advice-and-tools streaming-media swimsuits-and-intimate-apparel
training-and-tools translation travel unknown weapons web-advertisements web-based-email web-hosting
high-risk medium-risk low-risk
""".split())
_PANOS_PROFILE_GROUP_NODES = {
    "virus": "antivirus", "spyware": "anti-spyware",
    "vulnerability": "vulnerability-protection", "url-filtering": "url-filtering",
    "file-blocking": "file-blocking", "wildfire-analysis": "wildfire-analysis",
    "dos-protection": "dos-protection",
}


def _panos_scope_root(root: ET.Element, scope: str) -> ET.Element | None:
    if scope == "Shared":
        return root.find("./shared")
    return next((entry for entry in root.findall("./devices/entry/vsys/entry") if entry.get("name") == scope), None)


def _panos_scope_collection(scope_root: ET.Element, item_kind: str, item_type: str) -> ET.Element | None:
    if item_kind == "object":
        collection = scope_root
        for part in OBJECT_NODES[item_type].split("/"):
            collection = collection.find(f"./{part}")
            if collection is None:
                return None
        return collection
    rules = scope_root.find(f"./rulebase/{POLICY_NODES[item_type]}/rules")
    return rules


def _panos_visible_object_names(root: ET.Element, scope: str, object_types: Iterable[str]) -> set[str]:
    names: set[str] = set()
    for owner in (["Shared"] if scope == "Shared" else ["Shared", scope]):
        owner_root = _panos_scope_root(root, owner)
        if owner_root is None:
            continue
        for object_type in object_types:
            collection = _panos_scope_collection(owner_root, "object", object_type)
            if collection is not None:
                names.update(entry.get("name", "") for entry in collection.findall("./entry") if entry.get("name"))
    return names


def _panos_move_refs_for_policy(entry: ET.Element, kind: str) -> tuple[list[tuple[str, str]], str | None]:
    references: list[tuple[str, str]] = []

    def add(path: str, dependency: str) -> None:
        references.extend((dependency, member.text.strip()) for member in entry.findall(path) if member.text and member.text.strip())

    add("./from/member", "zones")
    add("./to/member", "zones")
    add("./source/member", "addresses")
    add("./destination/member", "addresses")
    add("./application/member", "applications")
    add("./application-filter/member", "applications")
    add("./service/member", "services")
    add("./tag/member", "tags")
    add("./category/member", "url-categories")
    add("./source-hip/member", "hip-profiles")
    add("./destination-hip/member", "hip-profiles")
    add("./schedule", "schedules")
    add("./log-setting", "log-forwarding")
    add("./profile-setting/group/member", "security-profile-groups")
    for profile_type in entry.findall("./profile-setting/profiles"):
        for profile in profile_type:
            dependency = _PANOS_PROFILE_GROUP_NODES.get(profile.tag)
            members = [member.text.strip() for member in profile.findall("./member") if member.text and member.text.strip()]
            if dependency is None and members:
                return references, f"Onbekende directe security-profile-afhankelijkheid: {profile.tag}"
            if dependency:
                references.extend((dependency, name) for name in members)
    # User-ID selectors are runtime usernames/groups, not PAN-OS XML objects.
    # Their directory mappings are not represented in this candidate snapshot.
    if kind == "nat":
        add("./to-interface", "interfaces")
        add(".//source-translation//interface-address/interface", "interfaces")
    if kind == "pbf":
        add(".//egress-interface", "interfaces")
        add(".//next-hop/interface", "interfaces")
        add(".//next-vr", "virtual-routers")
    if kind == "nat":
        service = entry.findtext("./service", "").strip()
        if service:
            references.append(("services", service))
        for node in entry.findall(".//source-translation//translated-address") + entry.findall(".//destination-translation//translated-address"):
            if node.text and node.text.strip():
                references.append(("addresses", node.text.strip()))
            references.extend(("addresses", member.text.strip()) for member in node.findall(".//member") if member.text and member.text.strip())
    return references, None


def _panos_move_refs_for_object(entry: ET.Element, object_type: str) -> tuple[list[tuple[str, str]], str | None]:
    references: list[tuple[str, str]] = []
    references.extend(("tags", member.text.strip()) for member in entry.findall("./tag/member") if member.text and member.text.strip())
    if object_type == "address-groups":
        references.extend(("addresses", member.text.strip()) for member in entry.findall("./static/member") if member.text and member.text.strip())
        if entry.find("./dynamic") is not None:
            return references, "Dynamische address groups kunnen niet veilig scope-verplaatst worden"
    elif object_type == "service-groups":
        references.extend(("services", member.text.strip()) for member in entry.findall("./members/member") if member.text and member.text.strip())
    elif object_type == "application-groups":
        references.extend(("applications", member.text.strip()) for member in entry.findall("./members/member") if member.text and member.text.strip())
    elif object_type == "security-profile-groups":
        for child in entry:
            dependency_type = _PANOS_PROFILE_GROUP_NODES.get(child.tag)
            if dependency_type is None:
                if child.find("./member") is not None:
                    return references, f"Onbekende profile-group-afhankelijkheid: {child.tag}"
                continue
            references.extend((dependency_type, member.text.strip()) for member in child.findall("./member") if member.text and member.text.strip())
    elif object_type in {
        "dynamic-user-groups", "external-dynamic-lists", "hip-objects", "hip-profiles",
        "log-forwarding", "antivirus", "anti-spyware", "vulnerability-protection",
        "url-filtering", "file-blocking", "wildfire-analysis", "dos-protection",
        "authentication", "decryption-profiles",
    }:
        return references, f"Voor {object_type} is dependency-validatie niet volledig ondersteund"
    return references, None


def _panos_move_dependency_exists(
    root: ET.Element, scope: str, dependency: str, name: str,
    selected_entries: set[tuple[str, str]], selected_type: str,
    predefined_applications: set[str], predefined_regions: set[str],
) -> bool:
    if name.casefold() in _PANOS_MOVE_BUILTINS:
        return True
    if dependency == "addresses":
        try:
            ipaddress.ip_network(name, strict=False)
            return True
        except ValueError:
            if name in predefined_regions:
                return True
    if dependency == "zones":
        if name.casefold() == "any":
            return True
        owner = _panos_scope_root(root, scope)
        return owner is not None and scope != "Shared" and any(entry.get("name") == name for entry in owner.findall("./zone/entry"))
    if dependency == "interfaces":
        if name.casefold() in {"any", "auto"}:
            return True
        if scope == "Shared":
            return False
        configured = any(entry.get("name") == name for entry in root.findall("./devices/entry/network/interface//entry"))
        owner = _panos_scope_root(root, scope)
        if owner is None:
            return False
        assigned = any(
            member.text and member.text.strip() == name
            for zone in owner.findall("./zone/entry")
            for network_type in ("layer3", "layer2", "virtual-wire", "tap", "tunnel")
            for member in zone.findall(f"./network/{network_type}/member")
        )
        return configured and assigned
    if dependency == "virtual-routers":
        if scope == "Shared":
            return False
        owner = _panos_scope_root(root, scope)
        if owner is None:
            return False
        routers = [entry for entry in root.findall("./devices/entry/network/virtual-router/entry") if entry.get("name") == name]
        if len(routers) != 1:
            return False
        imported_routers = {
            member.text.strip() for member in owner.findall("./import/network/virtual-router/member")
            if member.text and member.text.strip()
        }
        return name in imported_routers
    if dependency == "url-categories":
        custom_names = _panos_visible_object_names(root, scope, ("custom-url-categories",))
        if name in custom_names:
            return True
        if name in _PANOS_PREDEFINED_URL_CATEGORIES:
            return True
        # A same-name custom category in another VSYS shadows the predefined
        # category for that scope; moving the policy there must require the
        # custom definition to be visible in the target scope.
        scopes = ["Shared", *(entry.get("name", "") for entry in root.findall("./devices/entry/vsys/entry"))]
        for owner in scopes:
            owner_root = _panos_scope_root(root, owner)
            collection = _panos_scope_collection(owner_root, "object", "custom-url-categories") if owner_root is not None else None
            if collection is not None and any(entry.get("name") == name for entry in collection.findall("./entry")):
                return False
        return False
    candidate_types = {
        "addresses": ("addresses", "address-groups", "regions"),
        "applications": ("applications", "application-groups", "application-filters"),
        "services": ("services", "service-groups"),
        "tags": ("tags",),
        "custom-url-categories": ("custom-url-categories",),
        "schedules": ("schedules",),
        "security-profile-groups": ("security-profile-groups",),
        "log-forwarding": ("log-forwarding",),
        "hip-profiles": ("hip-profiles",),
        "dynamic-user-groups": ("dynamic-user-groups",),
        "antivirus": ("antivirus",), "anti-spyware": ("anti-spyware",),
        "vulnerability-protection": ("vulnerability-protection",),
        "url-filtering": ("url-filtering",), "file-blocking": ("file-blocking",),
        "wildfire-analysis": ("wildfire-analysis",), "dos-protection": ("dos-protection",),
    }.get(dependency, ())
    if selected_type in candidate_types and (selected_type, name) in selected_entries:
        return True
    if name in _panos_visible_object_names(root, scope, candidate_types):
        return True
    # Predefined applications are not included in the candidate configuration.
    return dependency == "applications" and name in predefined_applications


def _panos_scope_path(root: ET.Element, scope: str) -> str:
    if scope == "Shared":
        return "/config/shared"
    device = next((entry for entry in root.findall("./devices/entry") if entry.find("./vsys") is not None), None)
    device_name = device.get("name", "localhost.localdomain") if device is not None else "localhost.localdomain"
    return f"/config/devices/entry[@name={device_name}]/vsys/entry[@name={scope}]"


def move_panos_scope_entries(
    xml_bytes: bytes, *, item_kind: str, item_type: str, names: Iterable[str],
    source_scope: str, target_scope: str, predefined_applications: Iterable[str] = (),
    predefined_regions: Iterable[str] = PANOS_GEO_REGION_CODES,
    insertion_position: str = "top",
) -> tuple[bytes, list[dict], list[dict]]:
    """Move selected entries between a standalone PAN-OS VSYS and Shared.

    The operation is per-item: failures stay at their source and successful
    entries are moved in one normalized snapshot. Panorama and SCM ownership
    models are intentionally excluded.
    """
    root, snapshot = parse_snapshot(xml_bytes)
    if snapshot.kind != "panos":
        raise OfflineConfigError("Scope-verplaatsen is alleen beschikbaar voor standalone PAN-OS")
    if item_kind not in {"policy", "object"}:
        raise OfflineConfigError("Ongeldig type configuratie-item")
    if item_kind == "policy" and item_type not in POLICY_NODES:
        raise OfflineConfigError("Onbekend policytype")
    if item_kind == "object" and item_type not in PANOS_SCOPE_MOVE_OBJECT_TYPES:
        raise OfflineConfigError("Voor dit objecttype is scope-verplaatsen niet veilig ondersteund")
    if insertion_position not in {"top", "bottom"}:
        raise OfflineConfigError("Ongeldige invoegpositie; kies top of bottom")
    valid_scopes = {"Shared", *snapshot.vsys}
    if source_scope not in valid_scopes or target_scope not in valid_scopes:
        raise OfflineConfigError("Bron- of doelscope bestaat niet in deze PAN-OS-configuratie")
    if source_scope == target_scope:
        raise OfflineConfigError("Bron- en doelscope moeten verschillend zijn")
    predefined_application_names = {str(name).strip() for name in predefined_applications if str(name).strip()}
    predefined_region_names = {str(name).strip().upper() for name in predefined_regions if str(name).strip()}
    requested = list(dict.fromkeys(str(name).strip() for name in names if str(name).strip()))
    if not requested or len(requested) > 5000:
        raise OfflineConfigError("Selecteer één tot 5000 configuratie-items")

    candidates: list[tuple[str, ET.Element, ET.Element]] = []
    failures: list[dict] = []
    target_root = _panos_scope_root(root, target_scope)
    for name in requested:
        source_root = _panos_scope_root(root, source_scope)
        source_collection = _panos_scope_collection(source_root, item_kind, item_type) if source_root is not None else None
        matches = [entry for entry in source_collection.findall("./entry") if entry.get("name") == name] if source_collection is not None else []
        if len(matches) != 1:
            failures.append({"name": name, "reason": "Niet gevonden of dubbel in de bronscope"})
            continue
        if target_root is None and target_scope != "Shared":
            failures.append({"name": name, "reason": "Doelscope ontbreekt"})
            continue
        target_collection = _panos_scope_collection(target_root, item_kind, item_type) if target_root is not None else None
        if target_collection is not None and any(entry.get("name") == name for entry in target_collection.findall("./entry")):
            failures.append({"name": name, "reason": "In de doelscope bestaat al een item met deze naam"})
            continue
        if target_scope != "Shared" and source_scope != "Shared":
            shared_root = _panos_scope_root(root, "Shared")
            shared_collection = _panos_scope_collection(shared_root, item_kind, item_type) if shared_root is not None else None
            if shared_collection is not None and any(entry.get("name") == name for entry in shared_collection.findall("./entry")):
                failures.append({"name": name, "reason": "In Shared bestaat al een item met deze naam"})
                continue
        candidates.append((name, matches[0], source_collection))

    selected_entries = {(item_type, name) for name, _, _ in candidates} if item_kind == "object" else set()
    reference_index: dict[str, list[str]] = {}
    reference_index_error: OfflineConfigError | None = None
    if item_kind == "object" and target_scope != "Shared" and candidates:
        try:
            reference_index = object_reference_index(xml_bytes, item_type, (name for name, _, _ in candidates))
        except OfflineConfigError as exc:
            reference_index_error = exc
    accepted: list[tuple[str, ET.Element, ET.Element]] = []
    for name, entry, source_collection in candidates:
        if item_kind == "policy":
            references, unsupported = _panos_move_refs_for_policy(entry, item_type)
        else:
            references, unsupported = _panos_move_refs_for_object(entry, item_type)
        if unsupported:
            failures.append({"name": name, "reason": unsupported})
            selected_entries.discard((item_type, name))
            continue
        missing = [
            f"{dependency}: {reference}" for dependency, reference in references
            if not _panos_move_dependency_exists(
                root, target_scope, dependency, reference, selected_entries,
                item_type if item_kind == "object" else "",
                predefined_application_names, predefined_region_names,
            )
        ]
        if missing:
            failures.append({"name": name, "reason": "Ontbrekende afhankelijkheden in doelscope: " + ", ".join(dict.fromkeys(missing[:8]))})
            selected_entries.discard((item_type, name))
            continue
        if item_kind == "object" and target_scope != "Shared":
            if reference_index_error is not None:
                failures.append({"name": name, "reason": f"Referentiecontrole faalde: {reference_index_error}"})
                selected_entries.discard((item_type, name))
                continue
            references_to_item = reference_index.get(name, [])
            target_path = _panos_scope_path(root, target_scope)
            if any(not path.startswith(target_path + "/") for path in references_to_item):
                failures.append({"name": name, "reason": "Wordt nog gebruikt buiten de doelscope"})
                selected_entries.discard((item_type, name))
                continue
        if item_kind == "object" and target_scope == "Shared":
            collision = False
            for other_scope in snapshot.vsys:
                if other_scope == source_scope:
                    continue
                other_root = _panos_scope_root(root, other_scope)
                other_collection = _panos_scope_collection(other_root, "object", item_type) if other_root is not None else None
                if other_collection is not None and any(item.get("name") == name for item in other_collection.findall("./entry")):
                    collision = True
                    break
            if collision:
                failures.append({"name": name, "reason": "Een andere VSYS heeft al een lokaal item met deze naam"})
                selected_entries.discard((item_type, name))
                continue
        accepted.append((name, entry, source_collection))

    # A selected group cannot move if another selected dependency failed.
    # Resolve selected-item dependencies to a fixed point. If C is rejected,
    # B (which needs C) is rejected on one pass, then A (which needs B) on the
    # next. A single pass can incorrectly leave A pointing at B in its source.
    final = list(accepted)
    while True:
        remaining_names = {(item_type, name) for name, _, _ in final} if item_kind == "object" else set()
        rejected: list[tuple[str, ET.Element, ET.Element, list[str]]] = []
        for name, entry, source_collection in final:
            references, _ = (
                _panos_move_refs_for_policy(entry, item_type)
                if item_kind == "policy" else _panos_move_refs_for_object(entry, item_type)
            )
            missing = [
                reference for dependency, reference in references
                if not _panos_move_dependency_exists(
                    root, target_scope, dependency, reference, remaining_names,
                    item_type if item_kind == "object" else "",
                    predefined_application_names, predefined_region_names,
                )
            ]
            if missing:
                rejected.append((name, entry, source_collection, list(dict.fromkeys(missing[:8]))))
        if not rejected:
            break
        rejected_names = {name for name, _, _, _ in rejected}
        for name, _, _, missing in rejected:
            failures.append({"name": name, "reason": "Afhankelijkheid is niet mee verplaatst: " + ", ".join(missing)})
        final = [candidate for candidate in final if candidate[0] not in rejected_names]

    # Policy rule order is meaningful. Keep the original source ordering for
    # the moved block, then insert that block at the requested edge.
    if item_kind == "policy":
        source_collection = candidates[0][2] if candidates else None
        if source_collection is not None:
            source_order = {entry.get("name", ""): index for index, entry in enumerate(source_collection.findall("./entry"))}
            final.sort(key=lambda candidate: source_order.get(candidate[0], len(source_order)))

    moved = []
    if final and target_root is None:
        target_root = ET.SubElement(root, "shared")
    for name, entry, source_collection in (reversed(final) if insertion_position == "top" else final):
        source_collection.remove(entry)
        target_collection = _panos_scope_collection(target_root, item_kind, item_type)
        if target_collection is None:
            if item_kind == "object":
                target_collection = target_root
                for part in OBJECT_NODES[item_type].split("/"):
                    child = target_collection.find(f"./{part}")
                    if child is None:
                        child = ET.SubElement(target_collection, part)
                    target_collection = child
            else:
                rulebase = target_root.find("./rulebase")
                if rulebase is None:
                    rulebase = ET.SubElement(target_root, "rulebase")
                policy = rulebase.find(f"./{POLICY_NODES[item_type]}")
                if policy is None:
                    policy = ET.SubElement(rulebase, POLICY_NODES[item_type])
                target_collection = policy.find("./rules")
                if target_collection is None:
                    target_collection = ET.SubElement(policy, "rules")
        if insertion_position == "top":
            target_collection.insert(0, entry)
        else:
            target_collection.append(entry)
        moved.append({"name": name, "item_kind": item_kind, "item_type": item_type, "source_scope": source_scope, "target_scope": target_scope})
    return (normalized_config_xml(root), moved, failures) if moved else (xml_bytes, moved, failures)


def scoped_server_profiles(xml_bytes: bytes, scope: str, parsed=None) -> list[dict]:
    """Return server-profile names visible to a policy/log-forwarding scope."""
    root, snapshot = parsed if parsed is not None else parse_snapshot(xml_bytes)
    chain = _scope_chain(snapshot, scope) if snapshot.kind == "panorama" else (["Shared"] if scope == "Shared" else (["Shared", scope] if root.find("./shared") is not None else [scope]))
    records = []
    seen = set()
    for owner in chain:
        scope_root = _scope_root(root, snapshot, owner)
        if scope_root is None:
            continue
        for kind, node in SERVER_PROFILE_NODES.items():
            for entry in scope_root.findall(f"./log-settings/{node}/entry"):
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
    scope_root = _ensure_scope_root(root, snapshot, scope)
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


def _configuration_edit_seed(root: ET.Element, current: ET.Element, parents=None):
    """Match a server schema to its actual XML owner, retaining union choices."""
    if parents is None:
        parents = _element_parents(root)
    chain = []
    node = current
    while id(node) in parents:
        node = parents[id(node)][0]
        chain.append(node.tag)
    ancestry = list(reversed(chain))
    for variant, spec in CONFIG_CREATE_SCHEMAS.items():
        _, section, _, parent_path, _, xml, _ = spec
        suffix = parent_path.split("/")
        if variant == "ethernet-subinterface":
            suffix = ["network", "interface", "ethernet", "entry", "layer3", "units"]
        if ancestry[-len(suffix):] != suffix:
            continue
        seed = SafeET.fromstring(xml)
        if current.tag != seed.tag:
            continue
        if variant in {"ethernet-layer3", "aggregate-layer3"}:
            if any(current.find(tag) is not None for tag in ("layer2", "virtual-wire", "tap", "ha", "aggregate-group")):
                continue
        if section == "zones":
            zone_kind = variant.removeprefix("zone-")
            network = current.find("network")
            if network is None or network.find(zone_kind) is None:
                continue
        if section == "authentication-profile":
            method = "local-database" if variant == "authentication-local" else "ldap"
            if current.find(f"./method/{method}") is None:
                continue
        if section == "interfaces":
            # A DHCP client and static IPv4 address are alternative choices.
            # Do not offer a synthetic static address beneath an active client.
            for path in (".", "./layer3"):
                configured, offered = current.find(path), seed.find(path)
                if configured is not None and offered is not None:
                    dhcp = configured.find("dhcp-client")
                    ip = offered.find("ip")
                    if dhcp is not None and dhcp.findtext("enable", "yes") != "no" and ip is not None:
                        offered.remove(ip)
        return seed, section
    return None, ""


def _augmented_configuration_edit(root: ET.Element, current: ET.Element, skip_nested_entries: bool = False, parents=None):
    """Build a virtual edit tree without putting optional placeholders on disk.

    Existing child order remains stable. Missing schema fields are appended in
    deterministic order on read and apply, so numeric field paths are identical.
    Fingerprints always remain tied to the unmodified source entry.
    """
    replacement = copy.deepcopy(current)
    if parents is None:
        parents = _element_parents(root)
    seed, section = _configuration_edit_seed(root, current, parents)
    synthetic = set()
    hints = {}
    schemas = [(replacement, seed, section)] if seed is not None else []
    if not skip_nested_entries:
        # Physical interfaces contain subinterfaces in the same editor. Apply
        # the latter's own schema too, while retaining the original index paths.
        for nested in current.iter("entry"):
            if nested is current:
                continue
            nested_seed, nested_section = _configuration_edit_seed(root, nested, parents)
            if nested_seed is not None:
                path = _element_locator(current, nested, parents)
                schemas.append((_indexed_element(replacement, path), nested_seed, nested_section))
    for target_entry, seed, section in schemas:
        schema_fields = _configuration_creation_fields(seed, section)["edit_fields"]
        seed_hints = {id(_indexed_element(seed, field["path"])): field for field in schema_fields}

        def attach(target, source, created=False):
            if created:
                synthetic.add(id(target))
                target.text = None
                if target.tag == "entry":
                    target.set("name", "")
            if id(source) in seed_hints:
                hints[id(target)] = seed_hints[id(source)]
            for child in list(source):
                if _protected_config_tag(child.tag):
                    continue
                matches = target.findall(child.tag)
                if not matches:
                    added = ET.Element(child.tag, child.attrib)
                    target.append(added)
                    attach(added, child, True)
                else:
                    # An entry seed describes fields for existing members, not
                    # permission to invent another server/VRF with its example name.
                    for match in matches:
                        attach(match, child)
        attach(target_entry, seed)
    fields = []
    for field in _config_edit_fields(replacement, skip_nested_entries):
        node = _indexed_element(replacement, field["path"])
        if schemas and field["kind"] == "text" and node.tag in {"entry", "local-database"}:
            continue
        hint = hints.get(id(node), {})
        if hint.get("options"):
            field["options"] = list(hint["options"])
            existing = str(field.get("value", ""))
            if id(node) not in synthetic and existing and existing not in field["options"]:
                # A newer PAN-OS enum may be unknown to this schema. Preserve
                # that existing choice without allowing arbitrary new values.
                field["options"].append(existing)
        if field["kind"] == "members":
            field["values"] = [value for value in field.get("values", []) if value]
        if id(node) in synthetic:
            field["optional"] = True
            if field["kind"] == "members":
                field["values"] = []
            else:
                field["value"] = ""
                if hint.get("kind") == "boolean":
                    field["kind"] = "boolean"
            if field.get("options"):
                field["options"] = ["", *field["options"]]
        fields.append(field)
    return replacement, fields, synthetic


def _prune_virtual_configuration_fields(node: ET.Element, synthetic: set[int]) -> None:
    """Materialize only filled virtual fields; leave original unknown XML alone."""
    for child in list(node):
        _prune_virtual_configuration_fields(child, synthetic)
        if id(child) not in synthetic:
            continue
        populated = bool(list(child)) or bool((child.text or "").strip())
        if child.tag == "entry":
            if child.get("name"):
                continue
            if populated:
                raise OfflineConfigError("Geef een naam op voor het nieuwe geneste configuratie-item")
        elif child.attrib:
            continue
        if not populated:
            node.remove(child)


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
    config_roots = _config_roots(root, snapshot, scope, template)
    if snapshot.kind == "panos" and section in PANOS_LOCATION_SECTIONS.get(view, set()):
        selected_root = _scope_root(root, snapshot, scope)
        config_roots = [(scope, selected_root)] if selected_root is not None else []
    for owner, source in config_roots:
        search_source = source
        if view == "network" and section == "zones" and snapshot.kind != "panorama":
            scoped_root = _scope_root(root, snapshot, scope)
            search_source = scoped_root if scoped_root is not None else source
        sections: list[ET.Element] = []
        for path in paths:
            for node in search_source.findall(path):
                ancestor = node
                imported = False
                while id(ancestor) in parents:
                    ancestor = parents[id(ancestor)][0]
                    if ancestor.tag == "import":
                        imported = True
                        break
                if imported:
                    continue
                if id(node) not in seen_sections:
                    seen_sections.add(id(node)); sections.append(node)
        for section_node in sections:
            entries = _top_level_entries(section_node)
            targets = list(entries)
            singleton_seed, _ = _configuration_edit_seed(root, section_node, parents)
            if _has_nonentry_leaf(section_node) or singleton_seed is not None:
                targets.insert(0, (section_node, []))
            for entry, labels in targets:
                locator = _element_locator(root, entry, parents)
                xml = ET.tostring(entry, encoding="unicode")
                name = entry.get("name") or section.replace("-", " ").title()
                kind = " / ".join(labels) if labels else section_node.tag.replace("-", " ").title()
                _, fields, _ = _augmented_configuration_edit(
                    root, entry, skip_nested_entries=entry is section_node and bool(entries), parents=parents
                )
                if entry is section_node and singleton_seed is None and not any(
                    field.get("kind") == "protected"
                    or (field.get("kind") == "members" and field.get("values"))
                    or str(field.get("value", "")).strip()
                    for field in fields
                ):
                    continue
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
                if section == "zones" and not summary_values:
                    network = entry.find("network")
                    if network is not None:
                        summary_values.extend(child.tag.replace("-", " ").title() for child in network)
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
        replacement, editable_fields, synthetic = _augmented_configuration_edit(root, current)
        new_name = str(change.get("name", "")).strip()
        if replacement.tag == "entry":
            if not new_name:
                raise OfflineConfigError("Name is verplicht")
            parent_locator = "/".join(locator.split("/")[:-1])
            parent = _indexed_element(root, parent_locator)
            if any(sibling is not current and sibling.tag == "entry" and sibling.get("name") == new_name for sibling in list(parent)):
                raise OfflineConfigError(f"Configuratie-item {new_name} bestaat al")
            replacement.set("name", new_name)
        allowed = {(field["path"], field["kind"]): field for field in editable_fields if field["kind"] != "protected"}
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
                value = str(update.get("value", ""))[:65535]
                field = allowed[key]
                if key[1] == "boolean" and value not in ({"", "yes", "no"} if field.get("optional") else {"yes", "no"}):
                    raise OfflineConfigError("Ongeldige booleanwaarde")
                if field.get("options") and value not in field["options"]:
                    raise OfflineConfigError("Kies een waarde uit de beschikbare opties")
                target.text = value
        _prune_virtual_configuration_fields(replacement, synthetic)
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


def _configuration_creation_owner(root, snapshot, scope, template, owner_kind):
    if snapshot.kind == "panorama":
        selected = next((item for item in root.findall("./devices/entry/template/entry") if item.get("name") == template), None)
        if selected is None:
            raise OfflineConfigError("Kies een concrete Panorama-template voor aanmaak")
        device = selected.find("./config/devices/entry")
    else:
        device = root.find("./devices/entry")
    if device is None:
        raise OfflineConfigError("De configuratie bevat geen doel-device")
    if owner_kind == "device":
        return device
    if owner_kind == "location" and snapshot.kind == "panos":
        return _ensure_scope_root(root, snapshot, scope)
    vsyses = device.findall("./vsys/entry")
    owner = next((item for item in vsyses if item.get("name") == scope), None)
    if owner is None and snapshot.kind == "panorama" and len(vsyses) == 1:
        owner = vsyses[0]
    if owner is None:
        raise OfflineConfigError("Kies een bestaande, eenduidige VSYS in de doelconfiguratie")
    return owner


def _configuration_creation_fields(entry, section):
    fields = []
    options = {"transport": ["UDP", "TCP", "SSL"], "format": ["BSD", "IETF"],
               "facility": ["LOG_USER"] + [f"LOG_LOCAL{number}" for number in range(8)],
               "action": ["wait-recover", "fail-over"], "link-state": ["auto", "up", "down"]}
    for field in _config_edit_fields(entry):
        if field["kind"] == "protected":
            continue
        node = _indexed_element(entry, field["path"])
        # Choice nodes and named entries have no editable inner text.
        if field["kind"] == "text" and node.tag in {"local-database", "entry"}:
            continue
        if field["kind"] == "members":
            field["values"] = [value for value in field["values"] if value]
        if node.tag in options:
            field["options"] = options[node.tag]
        fields.append(field)
    return panos_ui_decorate_record({"is_entry": entry.tag == "entry", "edit_fields": fields}, section)


def configuration_create_templates(xml_bytes: bytes, scope: str, template: str, view: str, section: str) -> list[dict]:
    """Offer typed Add forms even when no existing record can act as a seed."""
    root, snapshot = parse_snapshot(xml_bytes)
    templates = []
    for variant, spec in CONFIG_CREATE_SCHEMAS.items():
        spec_view, spec_section, owner_kind, parent_path, label, xml, _ = spec
        if (view, section) != (spec_view, spec_section):
            continue
        try:
            owner = _configuration_creation_owner(root, snapshot, scope, template, owner_kind)
        except OfflineConfigError:
            continue
        entry = SafeET.fromstring(xml)
        parent = owner.find(parent_path)
        if entry.tag != "entry" and parent is not None and parent.find(entry.tag) is not None:
            continue
        record = _configuration_creation_fields(entry, section)
        record.update({"create_variant": variant, "name": "", "kind": label, "label": label,
                       "owner": template if snapshot.kind == "panorama" else scope, "ui_family": label})
        templates.append(record)
    return templates


def create_configuration_entry(xml_bytes: bytes, scope: str, template: str, view: str, section: str,
                               variant: str, name: str, updates: list[dict] | None = None) -> bytes:
    """Create a typed candidate item using only a server-owned XML schema."""
    spec = CONFIG_CREATE_SCHEMAS.get(variant)
    if spec is None or (view, section) != spec[:2]:
        raise OfflineConfigError("Ongeldig configuratietype voor deze pagina")
    _, _, owner_kind, parent_path, _, xml, required = spec
    root, snapshot = parse_snapshot(xml_bytes)
    owner = _configuration_creation_owner(root, snapshot, scope, template, owner_kind)
    entry = SafeET.fromstring(xml)
    clean_name = str(name or "").strip()
    if entry.tag == "entry":
        invalid_name = re.search(r"[\x00-\x1f\\]", clean_name) or ("/" in clean_name and section != "interfaces")
        if not clean_name or len(clean_name) > 127 or invalid_name:
            raise OfflineConfigError("Name is verplicht, maximaal 127 tekens en zonder slashes of controltekens")
        entry.set("name", clean_name)
    if section == "interfaces":
        patterns = {"ethernet-layer3": r"ethernet\d+/\d+", "aggregate-layer3": r"ae\d+",
                    "ethernet-subinterface": r"ethernet\d+/\d+\.\d+", "loopback-interface": r"loopback\.\d+",
                    "tunnel-interface": r"tunnel\.\d+", "vlan-interface": r"vlan\.\d+"}
        if not re.fullmatch(patterns.get(variant, r"(?!)"), clean_name):
            raise OfflineConfigError("Ongeldige PAN-OS interfacenaam voor dit type")
    offered = _configuration_creation_fields(entry, section)["edit_fields"]
    allowed = {(field["path"], field["kind"]): field for field in offered if field["kind"] != "protected"}
    if not isinstance(updates, (list, type(None))) or len(updates or []) > 10000:
        raise OfflineConfigError("Ongeldige configuratievelden")
    for update in updates or []:
        if not isinstance(update, dict):
            raise OfflineConfigError("Ongeldig configuratieveld")
        key = (str(update.get("path", "")), str(update.get("kind", "")))
        field = allowed.get(key)
        if field is None:
            raise OfflineConfigError("Het veld behoort niet tot dit configuratietype")
        node = _indexed_element(entry, key[0])
        if key[1] == "members":
            values = update.get("values", [])
            if not isinstance(values, list) or len(values) > 10000:
                raise OfflineConfigError("Ongeldige memberlijst")
            for child in list(node):
                node.remove(child)
            for value in dict.fromkeys(str(value).strip() for value in values):
                if value:
                    ET.SubElement(node, "member").text = value
        else:
            value = str(update.get("value", "")).strip()
            if len(value) > 65535 or (key[1] == "boolean" and value not in {"yes", "no"}):
                raise OfflineConfigError("Ongeldige configuratiewaarde")
            if field.get("options") and value not in field["options"]:
                raise OfflineConfigError("Kies een waarde uit de beschikbare opties")
            if key[1] == "attribute":
                if field.get("value") and not value:
                    raise OfflineConfigError("De naam van een genest configuratie-item mag niet leeg zijn")
                if len(value) > 255 or re.search(r"[\x00-\x1f]", value):
                    raise OfflineConfigError("Ongeldige naam voor het geneste configuratie-item")
                node.set("name", value)
            else:
                node.text = value
    for path in required:
        node = entry.find(path)
        if node is None or not any(str(value or "").strip() for value in node.itertext()):
            raise OfflineConfigError(f"Verplicht veld ontbreekt: {path.replace('/', ' / ')}")
    if variant == "ethernet-subinterface":
        physical_name, suffix = clean_name.rsplit(".", 1)
        physical = next((item for item in owner.findall("./network/interface/ethernet/entry") if item.get("name") == physical_name), None)
        if physical is None or physical.find("layer3") is None:
            raise OfflineConfigError("Maak eerst de bijbehorende Layer 3 Ethernet-interface")
        if not entry.findtext("tag"):
            entry.find("tag").text = suffix
        if not entry.findtext("tag").isdigit() or not 1 <= int(entry.findtext("tag")) <= 4094:
            raise OfflineConfigError("De subinterface VLAN-tag moet tussen 1 en 4094 liggen")
    if variant == "virtual-wire" and entry.findtext("interface1") == entry.findtext("interface2"):
        raise OfflineConfigError("Een Virtual Wire vereist twee verschillende interfaces")
    for ip_entry in entry.findall(".//ip/entry") + entry.findall("./permitted-ip/entry"):
        value = ip_entry.get("name", "")
        if value:
            try:
                ipaddress.ip_interface(value)
            except ValueError as exc:
                raise OfflineConfigError("Voer een geldig interface-IP/netmask in") from exc
    device = _configuration_creation_owner(root, snapshot, scope, template, "device")
    interface_names = {item.get("name") for item in device.findall("./network/interface/*/entry")}
    interface_names.update(item.get("name") for item in device.findall("./network/interface/*/units/entry"))
    interface_names.update(item.get("name") for item in device.findall("./network/interface/*/entry/layer3/units/entry"))
    interface_paths = {
        "vlan": ("./interface/member", "./virtual-interface/interface"),
        "virtual-router": ("./interface/member",), "logical-router": ("./vrf/entry/interface/member",),
        "virtual-wire": ("./interface1", "./interface2"),
    }.get(variant, ("./network/*/member",) if section == "zones" else ())
    for path in interface_paths:
        for node in entry.findall(path):
            if (node.text or "").strip() and node.text not in interface_names:
                raise OfflineConfigError(f"Interface {node.text} bestaat niet; maak ze eerst aan")
    reference_paths = {
        "authentication-sequence": ("authentication-profiles/member", "authentication-profile"),
        "authentication-ldap": ("method/ldap/server-profile", "server-profile/ldap"),
        "local-user-group": ("user/member", "local-user-database/user"),
    }
    if variant in reference_paths:
        field_path, collection_path = reference_paths[variant]
        existing = {item.get("name") for item in owner.findall(f"./{collection_path}/entry")}
        existing.update(item.get("name") for item in root.findall(f"./shared/{collection_path}/entry"))
        for node in entry.findall(field_path):
            if (node.text or "").strip() and node.text not in existing:
                raise OfflineConfigError(f"Referentie {node.text} bestaat niet; maak het object eerst aan")
    for field in offered:
        node = _indexed_element(entry, field["path"])
        limits = {"interval": (1, 60), "threshold": (2, 100), "port": (1, 65535),
                  "static": (1, 255), "static-ipv6": (1, 255), "mtu": (576, 9216)}
        if node.tag in limits and node.text:
            low, high = limits[node.tag]
            if not node.text.isdigit() or not low <= int(node.text) <= high:
                raise OfflineConfigError(f"{node.tag} moet tussen {low} en {high} liggen")

    # Remove optional blank placeholders; keep union-choice nodes such as
    # <local-database/> and the named root. Never export <member/> as a value.
    def prune(node):
        for child in list(node):
            had_children = bool(list(child))
            prune(child)
            empty = not list(child) and not (child.text or "").strip()
            if (child.tag == "entry" and not child.get("name")) or (
                empty and child.tag != "entry" and child.tag not in {"local-database", "layer3", "layer2", "virtual-wire", "network"}
                and (had_children or child.tag == "member" or not child.attrib)
            ):
                node.remove(child)
    prune(entry)
    parent = owner
    for tag in parent_path.split("/"):
        current = parent.find(tag)
        if current is None:
            current = ET.SubElement(parent, tag)
        parent = current
    if variant == "ethernet-subinterface":
        parent = physical.find("layer3")
        units = parent.find("units")
        if units is None:
            units = ET.SubElement(parent, "units")
        parent = units
    if entry.tag == "entry":
        if any(child.get("name") == clean_name for child in parent.findall("entry")):
            raise OfflineConfigError(f"Configuratie-item {clean_name} bestaat al")
    elif parent.find(entry.tag) is not None:
        raise OfflineConfigError("Deze instelling bestaat al; open ze om te bewerken")
    parent.append(entry)
    if section == "interfaces":
        vsys = _configuration_creation_owner(root, snapshot, scope, template, "vsys")
        imported = vsys
        for tag in ("import", "network", "interface"):
            child = imported.find(tag)
            if child is None:
                child = ET.SubElement(imported, tag)
            imported = child
        if clean_name not in [member.text for member in imported.findall("member")]:
            ET.SubElement(imported, "member").text = clean_name
    return normalized_config_xml(root)


def create_basic_network_entry(
    xml_bytes: bytes, scope: str, template: str, section: str, name: str,
    interface_type: str = "ethernet", zone_type: str = "layer3",
) -> bytes:
    """Backward-compatible quick Add, backed by the same validated schemas."""
    if section == "interfaces":
        variant = {"ethernet": "ethernet-subinterface" if "." in name else "ethernet-layer3",
                   "aggregate-ethernet": "aggregate-layer3", "loopback": "loopback-interface",
                   "tunnel": "tunnel-interface", "vlan": "vlan-interface"}.get(interface_type, "")
    elif section == "zones":
        variant = f"zone-{zone_type}"
    else:
        raise OfflineConfigError("Gebruik de getypeerde aanmaak voor deze configuratiesectie")
    return create_configuration_entry(xml_bytes, scope, template, "network", section, variant, name)


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


def replace_policies_in_snapshot(
    xml_bytes: bytes, scope: str, kind: str, rulebase: str,
    replacements: list[dict[str, str]],
) -> bytes:
    """Replace several policies in one parse/serialization pass."""
    if not replacements:
        return xml_bytes
    root, snapshot = parse_snapshot(xml_bytes)
    scope_root = _scope_root(root, snapshot, scope)
    if scope_root is None:
        raise OfflineConfigError("De gekozen scope bestaat niet meer")
    base = f"./{rulebase}-rulebase" if snapshot.kind == "panorama" else "./rulebase"
    rules = scope_root.find(f"{base}/{POLICY_NODES[kind]}/rules")
    if rules is None:
        raise OfflineConfigError("De gekozen rulebase bestaat niet")
    entries = list(rules.findall("./entry"))
    current_by_name = {entry.get("name", ""): entry for entry in entries}
    requested = [item.get("name", "") for item in replacements]
    if len(requested) != len(set(requested)):
        raise OfflineConfigError("Dezelfde policy is meer dan één keer geselecteerd")
    replacement_by_name = {}
    for item in replacements:
        name = item.get("name", "")
        current = current_by_name.get(name)
        if current is None:
            raise OfflineConfigError(f"Policy {name or '(zonder naam)'} bestaat niet meer")
        current_record = policy_record(current, kind, scope, rulebase, True)
        if policy_fingerprint(current_record) != item.get("expected_fingerprint", ""):
            raise OfflineConfigError(f"Policy {name} is intussen gewijzigd; pas de wijziging opnieuw toe")
        replacement = SafeET.fromstring(item.get("replacement_xml", ""))
        replacement_name = replacement.get("name", "")
        if replacement.tag != "entry" or not replacement_name:
            raise OfflineConfigError("Ongeldige vervangende policy")
        if replacement_name != name and replacement_name in current_by_name:
            raise OfflineConfigError(f"Policy {replacement_name} bestaat al in deze rulebase")
        replacement_by_name[name] = replacement
    for index, current in enumerate(entries):
        replacement = replacement_by_name.get(current.get("name", ""))
        if replacement is not None:
            rules.remove(current)
            rules.insert(index, replacement)
    return normalized_config_xml(root)


def replace_policy_in_snapshot(xml_bytes: bytes, scope: str, kind: str, rulebase: str, name: str, expected_fingerprint: str, replacement_xml: str) -> bytes:
    return replace_policies_in_snapshot(
        xml_bytes, scope, kind, rulebase,
        [{"name": name, "expected_fingerprint": expected_fingerprint, "replacement_xml": replacement_xml}],
    )


def _policy_rules_root(root: ET.Element, snapshot: ConfigSnapshot, scope: str, kind: str, rulebase: str) -> ET.Element:
    if kind not in POLICY_NODES:
        raise OfflineConfigError(f"Onbekend policytype: {kind}")
    scope_root = _ensure_scope_root(root, snapshot, scope)
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
