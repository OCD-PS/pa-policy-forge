import unittest
import xml.etree.ElementTree as ET

from app.offline_config import move_panos_scope_entries, normalized_config_xml, parse_snapshot


def multi_vsys_xml(shared: str = "", vsys1: str = "", vsys2: str = "") -> bytes:
    xml = (
        '<config><shared>' + shared + '</shared><devices><entry name="localhost.localdomain"><vsys>'
        '<entry name="vsys1">' + vsys1 + '</entry>'
        '<entry name="vsys2">' + vsys2 + '</entry>'
        '</vsys></entry></devices></config>'
    )
    return normalized_config_xml(ET.fromstring(xml))


class ScopeMoveTests(unittest.TestCase):
    def move_addresses(self, xml: bytes, *, parsed_config=None):
        return move_panos_scope_entries(
            xml,
            item_kind="object",
            item_type="addresses",
            names=["shared-duplicate"],
            source_scope="vsys1",
            target_scope="Shared",
            parsed_config=parsed_config,
        )

    def test_identical_shared_address_reuses_existing_definition_and_normalizes_host_prefix(self):
        xml = multi_vsys_xml(
            shared=(
                '<tag><entry name="approved-tag"><color>color1</color></entry></tag>'
                '<address><entry name="shared-duplicate"><description>same</description>'
                '<tag><member>approved-tag</member></tag><ip-netmask>192.0.2.10/32</ip-netmask>'
                '</entry></address>'
            ),
            vsys1=(
                '<address><entry name="shared-duplicate"><description>same</description>'
                '<tag><member>approved-tag</member></tag><ip-netmask>192.0.2.10</ip-netmask>'
                '</entry></address>'
            ),
        )
        cached_root, snapshot = parse_snapshot(xml)

        updated, moved, reused, failed = self.move_addresses(xml, parsed_config=(cached_root, snapshot))

        result_root, result_snapshot = parse_snapshot(updated)
        self.assertEqual(result_snapshot.kind, "panos")
        self.assertEqual(moved, [])
        self.assertEqual([item["name"] for item in reused], ["shared-duplicate"])
        self.assertEqual(failed, [])
        self.assertIsNotNone(result_root.find('./shared/address/entry[@name="shared-duplicate"]'))
        self.assertIsNone(result_root.find('./devices/entry/vsys/entry[@name="vsys1"]/address/entry[@name="shared-duplicate"]'))
        # The cached parsed tree is reused for other read paths and must stay immutable.
        self.assertIsNotNone(cached_root.find('./devices/entry/vsys/entry[@name="vsys1"]/address/entry[@name="shared-duplicate"]'))

    def test_same_name_with_different_shared_behavior_stays_in_source(self):
        xml = multi_vsys_xml(
            shared='<address><entry name="shared-duplicate"><ip-netmask>192.0.2.10/32</ip-netmask></entry></address>',
            vsys1='<address><entry name="shared-duplicate"><ip-netmask>198.51.100.20/32</ip-netmask></entry></address>',
        )

        updated, moved, reused, failed = self.move_addresses(xml)

        self.assertEqual(updated, xml)
        self.assertEqual(moved, [])
        self.assertEqual(reused, [])
        self.assertEqual(len(failed), 1)
        self.assertIn("niet veilig gelijk bevonden", failed[0]["reason"])

    def test_same_name_local_object_in_other_vsys_remains_shadowed(self):
        xml = multi_vsys_xml(
            vsys1='<address><entry name="shared-duplicate"><ip-netmask>192.0.2.10/32</ip-netmask></entry></address>',
            vsys2='<address><entry name="shared-duplicate"><ip-netmask>198.51.100.20/32</ip-netmask></entry></address>',
        )

        updated, moved, reused, failed = self.move_addresses(xml)

        root, _ = parse_snapshot(updated)
        self.assertEqual([item["name"] for item in moved], ["shared-duplicate"])
        self.assertEqual(reused, [])
        self.assertEqual(failed, [])
        self.assertIsNotNone(root.find('./shared/address/entry[@name="shared-duplicate"]'))
        self.assertIsNone(root.find('./devices/entry/vsys/entry[@name="vsys1"]/address/entry[@name="shared-duplicate"]'))
        self.assertIsNotNone(root.find('./devices/entry/vsys/entry[@name="vsys2"]/address/entry[@name="shared-duplicate"]'))

    def test_same_name_shared_group_is_not_reused_without_dependency_resolution(self):
        xml = multi_vsys_xml(
            shared=(
                '<address><entry name="member"><ip-netmask>192.0.2.10/32</ip-netmask></entry></address>'
                '<address-group><entry name="shared-duplicate"><static><member>member</member></static></entry></address-group>'
            ),
            vsys1=(
                '<address><entry name="member"><ip-netmask>192.0.2.10/32</ip-netmask></entry></address>'
                '<address-group><entry name="shared-duplicate"><static><member>member</member></static></entry></address-group>'
            ),
        )

        updated, moved, reused, failed = move_panos_scope_entries(
            xml,
            item_kind="object",
            item_type="address-groups",
            names=["shared-duplicate"],
            source_scope="vsys1",
            target_scope="Shared",
        )

        self.assertEqual(updated, xml)
        self.assertEqual(moved, [])
        self.assertEqual(reused, [])
        self.assertEqual(len(failed), 1)
        self.assertIn("niet veilig gelijk bevonden", failed[0]["reason"])


if __name__ == "__main__":
    unittest.main()
