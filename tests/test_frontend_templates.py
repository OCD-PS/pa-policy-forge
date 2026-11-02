"""UI contracts rendered without importing the application or starting workers."""
import unittest
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlencode, parse_qs, urlsplit

from jinja2 import Environment, FileSystemLoader


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.anchors = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get("id"):
            self.ids.append(attrs["id"])
        if tag == "a" and attrs.get("href", "").startswith("#"):
            self.anchors.append(attrs["href"][1:])


class FrontendTemplateTests(unittest.TestCase):
    def environment(self):
        env = Environment(loader=FileSystemLoader(Path(__file__).parents[1] / "app" / "templates"), autoescape=True)
        env.globals.update(url_for=lambda endpoint, **kwargs: "/" + endpoint,
                           csrf_token=lambda: "test-only", get_flashed_messages=lambda **kwargs: [])
        return env

    def migration_context(self):
        return dict(
            project=dict(id=1, name="Test", profile_name="Offline", target_type="panos", topology="active-passive"),
            current_project_role="owner", profiles=[], sources=[], outputs=[], workspaces=[], parsers={},
            merge_inventory=[], merge_inventory_total=0, merge_rules=[], transform_rules=[], transform_candidates=[], transform_candidate_total=0, available_kinds={},
            migration_analysis={key: [] for key in ("duplicate_rules", "unresolved_references", "unused_addresses", "unused_address_groups", "unused_services", "unused_service_groups")},
            migration_review=dict(critical=1, warnings=0, findings=[dict(code="review", severity="critical", title="Review", detail="Inspect", anchor="best-practices", affected=[])]),
            best_practices=dict(checks=[dict(passed=False, title="Inspect references", detail="Resolve missing members", count=1)]),
            show_topology_mapping=True, topology_items=[], topology_targets={}, target_zones=[],
            policy_zone_items=[], migration_kind_labels={}, topology_rules=[], interface_zone_rules={},
        )

    def test_all_templates_parse(self):
        environment = self.environment()
        for name in environment.list_templates():
            with self.subTest(template=name):
                environment.parse(environment.loader.get_source(environment, name)[0])

    def test_vsys_merge_form_serializes_large_scope_choices_into_bounded_fields(self):
        environment = self.environment()
        source = environment.loader.get_source(environment, "workspace_vsys_merge.html")[0]
        environment.parse(source)
        self.assertIn('name="vsys_order_json"', source)
        self.assertIn('name="zone_mappings_json"', source)
        self.assertIn('name="preview_token"', source)
        self.assertIn("preview_plan.renamed_policies", source)
        self.assertIn("maximaal 63 tekens", source)
        self.assertIn("app.js", source)
        script = (Path(__file__).parents[1] / "app" / "static" / "app.js").read_text()
        self.assertIn("JSON.stringify(order)", script)
        self.assertIn("JSON.stringify(zones)", script)
        self.assertNotIn('name="vsys_order_name"', source)
        self.assertNotIn('name="vsys_order_rank"', source)
        self.assertNotIn('name="zone_source_vsys"', source)
        self.assertNotIn('name="zone_source_name"', source)

    def test_object_page_jump_submits_context_as_get_fields(self):
        environment = self.environment()
        source = environment.loader.get_source(environment, "workspace_editor.html")[0]
        form_source = next(form for form in re.findall(r'<form class="workspace-page-jump".*?</form>', source, re.S)
                           if 'id="object-page-jump"' in form)
        environment.globals["url_for"] = lambda endpoint, **values: "/edit?" + urlencode(values)
        context = dict(workspace={"id": 1}, scope="vsys2", template="Branch & West", object_type="services",
                       object_query="web & proxy", object_page=3, object_page_count=5, workspace_object_page_size=100)
        markup = environment.from_string(form_source).render(**context)

        class Form(HTMLParser):
            def __init__(self):
                super().__init__()
                self.fields = {}
                self.action = ""

            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == "form":
                    self.action = attrs["action"]
                if tag == "input" and attrs.get("name"):
                    self.fields[attrs["name"]] = attrs.get("value", "")

        form = Form()
        form.feed(markup)
        # Browser GET submission replaces, rather than extends, action's query.
        destination = urlsplit(form.action)._replace(query=urlencode(form.fields)).geturl()
        self.assertEqual(parse_qs(urlsplit(destination).query), {
            "scope": ["vsys2"], "template": ["Branch & West"], "workspace_view": ["objects"],
            "object_type": ["services"], "object_query": ["web & proxy"], "object_page": ["3"],
        })
        policy_source = next(form for form in re.findall(r'<form class="workspace-page-jump".*?</form>', source, re.S)
                             if 'id="policy-page-jump"' in form)
        form = Form()
        form.feed(environment.from_string(policy_source).render(
            **context, policy_kind="nat", rulebase="post", policy_query="NAT & HTTPS",
            policy_page=2, policy_page_count=4, workspace_policy_page_size=100,
        ))
        self.assertEqual(form.fields, {
            "scope": "vsys2", "template": "Branch & West", "workspace_view": "policies",
            "policy_kind": "nat", "rulebase": "post", "policy_query": "NAT & HTTPS", "policy_page": "2",
        })

    def test_policy_member_macro_keeps_long_rules_compact(self):
        macro = self.environment().get_template("_policy_members.html").module.compact_members
        short = str(macro(["one", "two", "three"]))
        long = str(macro(["one", "two", "three", "four", "five"]))
        self.assertNotIn("<details", short)
        self.assertIn('class="policy-members"', long)
        self.assertIn("+3 meer", long)
        self.assertIn("five", long)

    def test_workspace_editor_omits_multi_vsys_explainer_but_keeps_policy_guidance(self):
        source = self.environment().loader.get_source(self.environment(), "workspace_editor.html")[0]
        self.assertNotIn("Multi-VSYS-configuratie", source)
        self.assertNotIn("PAN-OS valideert elke policy tegen de zones", source)
        self.assertIn("Klik op een policy om ze te bewerken. Inherited regels openen in hun owning scope.", source)

    def test_device_workspace_owns_zone_mapping_and_push_flow(self):
        source = self.environment().loader.get_source(self.environment(), "app.html")[0]
        self.assertIn("Firewall toevoegen", source)
        self.assertIn("Open device", source)
        self.assertIn("Actuele zones en rollen", source)
        self.assertIn('name="zone_role"', source)
        self.assertIn("Zones opnieuw ophalen", source)
        self.assertIn("Flow voor {{ep.name}}", source)
        self.assertNotIn("Selecteer een target", source)

    def test_running_policy_page_auto_refreshes_with_concise_status(self):
        source = self.environment().loader.get_source(self.environment(), "run.html")[0]
        self.assertIn('run.status==\'running\'', source)
        self.assertIn('http-equiv="refresh"', source)
        self.assertNotIn("gatewayverbinding hoeft niet te blijven wachten", source)
        self.assertIn("SCM-candidate geschreven en de deployment is uitgevoerd", source)

    def test_migration_review_and_step_links_have_real_targets(self):
        html = self.environment().get_template("migration.html").render(**self.migration_context())
        links = Links(); links.feed(html)
        self.assertIn("best-practices", links.ids)
        self.assertIn("best-practices", links.anchors)
        self.assertNotIn("migration-outputs", links.anchors)
        self.assertEqual(set(links.anchors) - set(links.ids), set())
        self.assertEqual(len(links.ids), len(set(links.ids)), "No duplicate ids across collapsed tools")
        self.assertIn("/migration_analysis_run", html)
        self.assertIn("Security en NAT disabled zetten", html)
        self.assertIn('data-confirm="Alle geïmporteerde Security- en NAT-regels disabled zetten?"', html)

    def test_interface_picker_uses_scoped_targets_instead_of_global_union(self):
        context = self.migration_context()
        context["topology_targets"] = {"interfaces": ["ethernet1/1", "ethernet1/99"]}
        context["topology_items"] = [dict(kind="interfaces", name="eth0", selector="eth0|||source", targets=["ethernet1/1"], source_vendor="checkpoint")]
        context["can_edit"] = True
        html = self.environment().get_template("_migration_topology_mapping.html").render(**context)
        self.assertIn('value="ethernet1/1"', html)
        self.assertNotIn('value="ethernet1/99"', html)


if __name__ == "__main__":
    unittest.main()
