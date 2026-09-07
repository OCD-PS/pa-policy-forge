import unittest
import xml.etree.ElementTree as ET

from app import migration as m


class MigrationReferenceAuditTests(unittest.TestCase):
    @staticmethod
    def model():
        return m.MigrationModel("generic", "test",
            addresses=[m.Address("same", "192.0.2.8", tags=["same"])],
            address_groups=[m.AddressGroup("hosts", ["same"], tags=["same"])],
            services=[m.Service("same", "tcp", "443", tags=["same"])],
            service_groups=[m.ServiceGroup("services", ["same"], tags=["same"])],
            security_rules=[m.Policy("same", source=["same"], destination=["same"], service=["same"], application=["same"], tags=["same"], from_zones=["same"], to_zones=["same"])],
            nat_rules=[m.Policy("nat", policy_type="nat", destination=["same"],
                                source_translation={"dynamic_ip_and_port": {"translated_address": ["same"]}},
                                destination_translation={"translated_address": "same", "translated_port": "same"})],
            extras={"tags": [{"name": "same", "xml": '<entry name="same"><color>color1</color></entry>'}],
                    "qos_rules": [{"name": "qos", "xml": '<entry name="qos"><source><member>same</member></source><service><member>same</member></service><description>same</description><tag><member>same</member></tag></entry>'}]})

    def test_address_rename_keeps_other_namespaces_and_descriptions(self):
        model = m.apply_transform_rules(self.model(), [{"kind": "addresses", "operation": "rename", "selector": "same|||", "value": "new-address"}])
        rule = model.security_rules[0]
        self.assertEqual(rule.source, ["new-address"])
        self.assertEqual(rule.service, ["same"])
        self.assertEqual(rule.application, ["same"])
        self.assertEqual(rule.from_zones, ["same"])
        self.assertEqual(rule.tags, ["same"])
        self.assertEqual(model.service_groups[0].members, ["same"])
        raw = ET.fromstring(model.extras["qos_rules"][0]["xml"])
        self.assertEqual(raw.findtext("source/member"), "new-address")
        self.assertEqual(raw.findtext("service/member"), "same")
        self.assertEqual(raw.findtext("description"), "same")

    def test_address_rename_updates_nat_translations(self):
        model = m.apply_transform_rules(self.model(), [{"kind": "addresses", "operation": "rename", "selector": "same|||", "value": "new-address"}])
        rule = model.nat_rules[0]
        self.assertEqual(rule.source_translation["dynamic_ip_and_port"]["translated_address"], ["new-address"])
        self.assertEqual(rule.destination_translation["translated_address"], "new-address")
        self.assertEqual(rule.destination_translation["translated_port"], "same")

    def test_service_rename_does_not_change_address_or_application(self):
        model = m.apply_transform_rules(self.model(), [{"kind": "services", "operation": "rename", "selector": "same|||", "value": "new-service"}])
        rule = model.security_rules[0]
        self.assertEqual(rule.service, ["new-service"])
        self.assertEqual(rule.source, ["same"])
        self.assertEqual(rule.application, ["same"])
        self.assertEqual(model.address_groups[0].members, ["same"])

    def test_policy_rename_does_not_rename_any_object_reference(self):
        model = m.apply_transform_rules(self.model(), [{"kind": "security_rules", "operation": "rename", "selector": "same|||", "value": "new-rule"}])
        self.assertEqual(model.security_rules[0].name, "new-rule")
        self.assertEqual(model.security_rules[0].source, ["same"])

    def test_tag_rename_updates_object_tags_without_changing_members(self):
        model = m.apply_transform_rules(self.model(), [{"kind": "tags", "operation": "rename", "selector": "same|||", "value": "new-tag"}])
        for item in [*model.addresses, *model.address_groups, *model.services, *model.service_groups]:
            self.assertEqual(item.tags, ["new-tag"])
        self.assertEqual(model.address_groups[0].members, ["same"])
        self.assertEqual(model.security_rules[0].tags, ["new-tag"])

    def test_merge_address_rewrites_nat_without_corrupting_service(self):
        model = self.model()
        model.addresses.append(m.Address("master", "192.0.2.8"))
        merged = m.apply_merge_rules(model, [{"kind": "addresses", "master": "master|||", "members": ["master|||", "same|||"]}])
        self.assertEqual(merged.security_rules[0].source, ["master"])
        self.assertEqual(merged.security_rules[0].service, ["same"])
        self.assertEqual(merged.nat_rules[0].destination_translation["translated_address"], "master")

    def test_interface_mapping_rewrites_nat_interface_address_and_zone_members(self):
        model = self.model()
        model.interfaces = [{"name": "same", "xml": '<entry name="same"><layer3/></entry>'}]
        model.zones = [{"name": "zone", "xml": '<entry name="zone"><network><layer3><member>same</member></layer3></network></entry>'}]
        model.nat_rules[0].to_interface = "same"
        model.nat_rules[0].source_translation = {"dynamic_ip_and_port": {"interface_address": {"interface": "same"}}}
        mapped = m.apply_transform_rules(model, [{"kind": "interfaces", "selector": "same|||", "operation": "topology_map", "value": "ethernet1/1"}])
        self.assertEqual(mapped.nat_rules[0].to_interface, "ethernet1/1")
        self.assertEqual(mapped.nat_rules[0].source_translation["dynamic_ip_and_port"]["interface_address"]["interface"], "ethernet1/1")
        self.assertEqual(ET.fromstring(mapped.zones[0]["xml"]).findtext("network/layer3/member"), "ethernet1/1")
        self.assertEqual(mapped.security_rules[0].source, ["same"])

    def test_scm_payload_preserves_object_metadata_and_source_port(self):
        model = self.model()
        model.services[0].source_port = "1024-65535"
        for item in [*model.addresses, *model.address_groups, *model.services, *model.service_groups]:
            item.description = "Keep this description"
        payloads = {item["kind"]: item["payload"] for item in m.scm_items(model)}
        for kind in ("addresses", "address-groups", "services", "service-groups"):
            self.assertEqual(payloads[kind]["tag"], ["same"])
            self.assertEqual(payloads[kind]["description"], "Keep this description")
        self.assertEqual(payloads["services"]["protocol"]["tcp"]["source_port"], "1024-65535")


if __name__ == "__main__":
    unittest.main()
