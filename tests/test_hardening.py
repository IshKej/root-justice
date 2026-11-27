"""Tests for artex_antidote.hardening — endpoint/wireless hardening baselines.

Pure, offline, deterministic. The one host-external read (``_read_host_facts``)
is exercised via the injectable seam, so no real platform call is required and
nothing on the machine is touched.
"""

from __future__ import annotations

import json
import unittest

from artex_antidote import hardening
from artex_antidote.hardening import (
    endpoint_baseline,
    local_quickcheck,
    render_markdown,
    wifi_baseline,
)

_REQUIRED_KEYS = {"id", "control", "rationale", "how"}


class BaselineShapeTests(unittest.TestCase):
    def test_endpoint_baseline_non_empty_with_required_keys(self):
        baseline = endpoint_baseline()
        self.assertIsInstance(baseline, list)
        self.assertTrue(baseline, "endpoint baseline must be non-empty")
        for item in baseline:
            self.assertIsInstance(item, dict)
            self.assertTrue(_REQUIRED_KEYS.issubset(item.keys()))
            for key in _REQUIRED_KEYS:
                self.assertIsInstance(item[key], str)
                self.assertTrue(item[key].strip(), f"{key} must be non-empty")

    def test_wifi_baseline_non_empty_with_required_keys(self):
        baseline = wifi_baseline()
        self.assertIsInstance(baseline, list)
        self.assertTrue(baseline, "wifi baseline must be non-empty")
        for item in baseline:
            self.assertIsInstance(item, dict)
            self.assertTrue(_REQUIRED_KEYS.issubset(item.keys()))
            for key in _REQUIRED_KEYS:
                self.assertIsInstance(item[key], str)
                self.assertTrue(item[key].strip(), f"{key} must be non-empty")

    def test_control_ids_are_unique_per_baseline(self):
        for baseline in (endpoint_baseline(), wifi_baseline()):
            ids = [c["id"] for c in baseline]
            self.assertEqual(len(ids), len(set(ids)), "control ids must be unique")

    def test_endpoint_covers_required_topics(self):
        blob = json.dumps(endpoint_baseline()).lower()
        for needle in ("badusb", "autorun", "screen", "edr", "least", "allowlist"):
            self.assertIn(needle, blob, f"endpoint baseline should mention {needle}")

    def test_wifi_covers_required_topics(self):
        blob = json.dumps(wifi_baseline()).lower()
        for needle in ("wpa", "passphrase", "wps", "management-frame", "guest", "rogue"):
            self.assertIn(needle, blob, f"wifi baseline should mention {needle}")

    def test_baselines_are_deterministic(self):
        self.assertEqual(endpoint_baseline(), endpoint_baseline())
        self.assertEqual(wifi_baseline(), wifi_baseline())

    def test_baselines_are_json_serialisable(self):
        both = {"endpoint": endpoint_baseline(), "wifi": wifi_baseline()}
        self.assertEqual(json.loads(json.dumps(both)), both)


class RenderMarkdownTests(unittest.TestCase):
    def setUp(self):
        self.baselines = {"endpoint": endpoint_baseline(), "wifi": wifi_baseline()}
        self.md = render_markdown(self.baselines)

    def test_returns_str(self):
        self.assertIsInstance(self.md, str)
        self.assertTrue(self.md.strip())

    def test_markdown_contains_wps_and_badusb(self):
        self.assertIn("WPS", self.md)
        self.assertIn("BadUSB", self.md)

    def test_markdown_has_section_headings(self):
        self.assertIn("# Root Justice", self.md)
        self.assertIn("## Endpoint hardening", self.md)
        self.assertIn("## Wireless (Wi-Fi) hardening", self.md)

    def test_markdown_lists_every_control_id(self):
        for baseline in self.baselines.values():
            for ctrl in baseline:
                self.assertIn(ctrl["id"], self.md)

    def test_empty_section_does_not_raise(self):
        md = render_markdown({"endpoint": []})
        self.assertIsInstance(md, str)
        self.assertIn("No controls defined", md)

    def test_unknown_section_name_rendered(self):
        md = render_markdown({"weird_domain": endpoint_baseline()})
        self.assertIn("Weird Domain", md)


class LocalQuickcheckTests(unittest.TestCase):
    def test_returns_dict_and_does_not_raise(self):
        result = local_quickcheck()
        self.assertIsInstance(result, dict)
        self.assertIn("host", result)
        self.assertIn("endpoint", result)
        self.assertIn("wifi", result)

    def test_uses_injected_facts_seam(self):
        fake = {
            "system": "Windows",
            "release": "11",
            "machine": "AMD64",
            "node": "test-host",
            "user": "operator",
        }
        result = local_quickcheck(read_facts=lambda: fake)
        self.assertEqual(result["host"]["system"], "Windows")
        self.assertEqual(result["host"]["release"], "11")
        # The detected-OS info row should reflect the injected facts.
        info = [i for i in result["endpoint"] if i["status"] == "info"]
        self.assertTrue(info)
        self.assertIn("Windows", info[0]["detail"])

    def test_controls_labelled_manual(self):
        result = local_quickcheck(read_facts=lambda: {})
        manual = [i for i in result["endpoint"] if i["status"] == "manual"]
        self.assertTrue(manual, "unverifiable controls must be labelled manual")
        for item in result["wifi"]:
            self.assertEqual(item["status"], "manual")

    def test_item_count_matches_baselines(self):
        result = local_quickcheck(read_facts=lambda: {})
        # endpoint = 1 info row + one item per endpoint control
        self.assertEqual(len(result["endpoint"]), len(endpoint_baseline()) + 1)
        self.assertEqual(len(result["wifi"]), len(wifi_baseline()))

    def test_tolerates_failing_facts_reader(self):
        def boom():
            raise RuntimeError("no host access")

        result = local_quickcheck(read_facts=boom)  # must not raise
        self.assertIsInstance(result, dict)
        self.assertIsInstance(result["host"], dict)

    def test_tolerates_non_dict_facts(self):
        result = local_quickcheck(read_facts=lambda: "not-a-dict")  # type: ignore[arg-type,return-value]
        self.assertIsInstance(result, dict)
        self.assertIsInstance(result["host"], dict)

    def test_result_is_json_serialisable(self):
        result = local_quickcheck(read_facts=lambda: {"system": "Linux"})
        self.assertEqual(json.loads(json.dumps(result)), result)

    def test_default_reader_runs_against_real_platform(self):
        # The default seam reads only inert platform identity; must not raise.
        result = local_quickcheck()
        self.assertIsInstance(result["host"].get("system"), (str, type(None)))

    def test_read_host_facts_seam_is_safe_and_returns_dict(self):
        facts = hardening._read_host_facts()
        self.assertIsInstance(facts, dict)
        for key in ("system", "release", "machine", "node", "user"):
            self.assertIn(key, facts)


if __name__ == "__main__":
    unittest.main()
