import unittest

from app.offline_config import (
    OfflineConfigError,
    apply_virtual_router_static_route_change,
    virtual_router_static_route_records,
)


PANOS_CONFIG = b'''<config><shared><address>
  <entry name="GatewayV4"><ip-netmask>192.0.2.1/32</ip-netmask></entry>
  <entry name="GatewayV6"><ip-netmask>2001:db8::1/128</ip-netmask></entry>
</address></shared><devices><entry name="localhost.localdomain"><network>
  <virtual-router>
    <entry name="default"><interface><member>ethernet1/1</member></interface><routing-table><ip><static-route>
      <entry name="default-route"><destination>0.0.0.0/0</destination><nexthop><ip-address>192.0.2.1</ip-address></nexthop><interface>ethernet1/1</interface><admin-dist>10</admin-dist><metric>10</metric><route-table><unicast/></route-table><path-monitor><enable>yes</enable><hold-time>2</hold-time></path-monitor><bfd><profile>None</profile></bfd></entry>
    </static-route></ip></routing-table></entry>
    <entry name="inside"><interface><member>ethernet1/2</member></interface></entry>
  </virtual-router>
</network></entry><vsys><entry name="vsys1"><import><network><virtual-router><member>default</member></virtual-router></network></import></entry></vsys></devices></config>'''


class VirtualRouterStaticRouteTests(unittest.TestCase):
    def test_records_expose_route_fields_and_interface_and_next_vr_choices(self):
        _snapshot, routes, interfaces, next_vrs = virtual_router_static_route_records(
            PANOS_CONFIG, "default",
        )
        self.assertEqual(interfaces, ["ethernet1/1"])
        self.assertEqual(next_vrs, ["inside"])
        self.assertEqual(routes[0]["name"], "default-route")
        self.assertEqual(routes[0]["next_hop_type"], "ip-address")
        self.assertTrue(routes[0]["path_monitor"])
        self.assertFalse(routes[0]["bfd"])

    def test_create_adds_ipv4_route_with_gui_fields(self):
        updated = apply_virtual_router_static_route_change(
            PANOS_CONFIG, "default", "ip", "create", {
                "name": "Office-Route", "destination": "198.51.100.0/24",
                "interface": "ethernet1/1", "next_hop_type": "ip-address",
                "next_hop_value": "192.0.2.1", "admin_distance": "20",
                "metric": "15", "route_table": "both",
            },
        )
        _snapshot, routes, _interfaces, _next_vrs = virtual_router_static_route_records(updated, "default")
        route = next(item for item in routes if item["name"] == "Office-Route")
        self.assertEqual(route["destination"], "198.51.100.0/24")
        self.assertEqual(route["admin_distance"], "20")
        self.assertEqual(route["metric"], "15")
        self.assertEqual(route["route_table"], "both")

    def test_create_ipv6_uses_ipv6_next_hop_and_supported_route_table(self):
        updated = apply_virtual_router_static_route_change(
            PANOS_CONFIG, "default", "ipv6", "create", {
                "name": "IPv6-Default", "destination": "::/0",
                "interface": "ethernet1/1", "next_hop_type": "ipv6-address",
                "next_hop_value": "2001:db8::1", "admin_distance": "10",
                "metric": "10", "route_table": "unicast",
            },
        )
        from xml.etree import ElementTree as ET
        route = ET.fromstring(updated).find(".//ipv6/static-route/entry[@name='IPv6-Default']")
        self.assertEqual(route.findtext("./nexthop/ipv6-address"), "2001:db8::1")
        self.assertIsNotNone(route.find("./route-table/unicast"))

    def test_edit_preserves_path_monitor_and_bfd_configuration(self):
        _snapshot, routes, _interfaces, _next_vrs = virtual_router_static_route_records(PANOS_CONFIG, "default")
        updated = apply_virtual_router_static_route_change(
            PANOS_CONFIG, "default", "ip", "update", {
                "name": "default-route", "new_name": "renamed-default",
                "destination": "0.0.0.0/0", "interface": "ethernet1/1",
                "next_hop_type": "ip-address", "next_hop_value": "192.0.2.2",
                "admin_distance": "10", "metric": "10", "route_table": "unicast",
            }, fingerprint=routes[0]["fingerprint"],
        )
        _snapshot, changed, _interfaces, _next_vrs = virtual_router_static_route_records(updated, "default")
        self.assertEqual(changed[0]["name"], "renamed-default")
        self.assertTrue(changed[0]["path_monitor"])
        self.assertFalse(changed[0]["bfd"])

    def test_delete_requires_current_fingerprint_and_removes_only_selected_route(self):
        _snapshot, routes, _interfaces, _next_vrs = virtual_router_static_route_records(PANOS_CONFIG, "default")
        with self.assertRaisesRegex(OfflineConfigError, "intussen gewijzigd"):
            apply_virtual_router_static_route_change(
                PANOS_CONFIG, "default", "ip", "delete", {"name": "default-route"}, fingerprint="stale",
            )
        updated = apply_virtual_router_static_route_change(
            PANOS_CONFIG, "default", "ip", "delete", {"name": "default-route"},
            fingerprint=routes[0]["fingerprint"],
        )
        _snapshot, changed, _interfaces, _next_vrs = virtual_router_static_route_records(updated, "default")
        self.assertEqual(changed, [])

    def test_invalid_family_interface_next_vr_and_metric_are_rejected(self):
        base = {
            "name": "bad-route", "destination": "2001:db8::/32",
            "interface": "ethernet1/1", "next_hop_type": "next-vr",
            "next_hop_value": "default", "admin_distance": "10",
            "metric": "0", "route_table": "unicast",
        }
        with self.assertRaisesRegex(OfflineConfigError, "adresfamilie"):
            apply_virtual_router_static_route_change(PANOS_CONFIG, "default", "ip", "create", base)
        base["destination"] = "198.51.100.0/24"
        with self.assertRaisesRegex(OfflineConfigError, "andere virtual router"):
            apply_virtual_router_static_route_change(PANOS_CONFIG, "default", "ip", "create", base)
        base["next_hop_value"] = "inside"
        with self.assertRaisesRegex(OfflineConfigError, "Metric"):
            apply_virtual_router_static_route_change(PANOS_CONFIG, "default", "ip", "create", base)

    def test_edit_fails_closed_for_an_unknown_existing_next_hop_type(self):
        unsupported = PANOS_CONFIG.replace(b"<ip-address>192.0.2.1</ip-address>", b"<future-hop>edge</future-hop>")
        _snapshot, routes, _interfaces, _next_vrs = virtual_router_static_route_records(unsupported, "default")
        self.assertFalse(routes[0]["editable"])
        with self.assertRaisesRegex(OfflineConfigError, "niet ondersteund"):
            apply_virtual_router_static_route_change(
                unsupported, "default", "ip", "update", {
                    "name": "default-route", "new_name": "default-route",
                    "destination": "0.0.0.0/0", "interface": "ethernet1/1",
                    "next_hop_type": "none", "admin_distance": "10",
                    "metric": "10", "route_table": "unicast",
                }, fingerprint=routes[0]["fingerprint"],
            )

    def test_edit_fails_closed_for_unknown_route_table_without_changing_xml(self):
        unsupported = PANOS_CONFIG.replace(b"<route-table><unicast/></route-table>", b"<route-table><future-table/></route-table>")
        _snapshot, routes, _interfaces, _next_vrs = virtual_router_static_route_records(unsupported, "default")
        self.assertFalse(routes[0]["editable"])
        self.assertIn("route-tableconfiguratie", routes[0]["edit_error"])
        with self.assertRaisesRegex(OfflineConfigError, "route-tableconfiguratie"):
            apply_virtual_router_static_route_change(
                unsupported, "default", "ip", "update", {
                    "name": "default-route", "new_name": "default-route",
                    "destination": "0.0.0.0/0", "interface": "ethernet1/1",
                    "next_hop_type": "ip-address", "next_hop_value": "192.0.2.1",
                    "admin_distance": "10", "metric": "10", "route_table": "unicast",
                }, fingerprint=routes[0]["fingerprint"],
            )

    def test_edit_fails_closed_for_duplicate_route_table_values(self):
        malformed = PANOS_CONFIG.replace(
            b"<route-table><unicast/></route-table>",
            b"<route-table><unicast/><unicast/></route-table>",
        )
        _snapshot, routes, _interfaces, _next_vrs = virtual_router_static_route_records(malformed, "default")
        self.assertFalse(routes[0]["editable"])
        self.assertIn("dubbele waarden", routes[0]["edit_error"])
        with self.assertRaisesRegex(OfflineConfigError, "dubbele route-tablewaarden"):
            apply_virtual_router_static_route_change(
                malformed, "default", "ip", "update", {
                    "name": "default-route", "new_name": "default-route",
                    "destination": "0.0.0.0/0", "interface": "ethernet1/1",
                    "next_hop_type": "ip-address", "next_hop_value": "192.0.2.1",
                    "admin_distance": "10", "metric": "10", "route_table": "unicast",
                }, fingerprint=routes[0]["fingerprint"],
            )

    def test_active_bfd_cannot_be_kept_with_a_non_ip_next_hop(self):
        active_bfd = PANOS_CONFIG.replace(b"<profile>None</profile>", b"<profile>edge-bfd</profile>")
        _snapshot, routes, _interfaces, _next_vrs = virtual_router_static_route_records(active_bfd, "default")
        self.assertTrue(routes[0]["bfd"])
        with self.assertRaisesRegex(OfflineConfigError, "BFD vereist"):
            apply_virtual_router_static_route_change(
                active_bfd, "default", "ip", "update", {
                    "name": "default-route", "new_name": "default-route",
                    "destination": "0.0.0.0/0", "interface": "ethernet1/1",
                    "next_hop_type": "discard", "admin_distance": "10",
                    "metric": "10", "route_table": "unicast",
                }, fingerprint=routes[0]["fingerprint"],
            )

    def test_path_monitor_requires_interface_when_editing_next_hop(self):
        _snapshot, routes, _interfaces, _next_vrs = virtual_router_static_route_records(PANOS_CONFIG, "default")
        with self.assertRaisesRegex(OfflineConfigError, "Path monitoring vereist een interface"):
            apply_virtual_router_static_route_change(
                PANOS_CONFIG, "default", "ip", "update", {
                    "name": "default-route", "new_name": "default-route",
                    "destination": "0.0.0.0/0", "interface": "",
                    "next_hop_type": "next-vr", "next_hop_value": "inside",
                    "admin_distance": "10", "metric": "10", "route_table": "unicast",
                }, fingerprint=routes[0]["fingerprint"],
            )


if __name__ == "__main__":
    unittest.main()
