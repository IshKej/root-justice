"""Tests for artex_antidote.domainwatch -- offline, deterministic, no network."""

import unittest

from artex_antidote import domainwatch


class PermutationsTests(unittest.TestCase):
    def test_excludes_original(self):
        variants = domainwatch.permutations("example.com")
        self.assertNotIn("example.com", variants)

    def test_deduplicated(self):
        variants = domainwatch.permutations("example.com")
        self.assertEqual(len(variants), len(set(variants)))

    def test_includes_a_homoglyph_variant(self):
        # 'o' -> '0' in "example" has no 'o'; but example has none... use the l/1
        # swap on the 'l' in example -> "examp1e.com". And 'e'->'3'.
        variants = domainwatch.permutations("example.com")
        self.assertIn("examp1e.com", variants)  # l -> 1 homoglyph
        self.assertIn("exampl3.com", variants)  # e -> 3 homoglyph

    def test_includes_rn_m_homoglyph(self):
        # "corn.com": rn -> m gives "com.com"
        variants = domainwatch.permutations("corn.com")
        self.assertIn("com.com", variants)

    def test_includes_tld_swap_variant(self):
        variants = domainwatch.permutations("example.com")
        self.assertIn("example.net", variants)
        self.assertIn("example.org", variants)

    def test_includes_char_omission(self):
        variants = domainwatch.permutations("example.com")
        self.assertIn("exmple.com", variants)  # dropped 'a'

    def test_includes_hyphen_insertion(self):
        variants = domainwatch.permutations("example.com")
        self.assertIn("ex-ample.com", variants)

    def test_empty_input(self):
        self.assertEqual(domainwatch.permutations(""), [])
        self.assertEqual(domainwatch.permutations("."), [])

    def test_bare_label_no_tld(self):
        variants = domainwatch.permutations("example")
        self.assertNotIn("example", variants)
        self.assertIn("exmple", variants)


class CheckRegisteredTests(unittest.TestCase):
    def test_marks_only_resolving_names(self):
        resolving = {"evil.com": ["203.0.113.5"], "good.net": ["198.51.100.9"]}

        def fake_resolve(name):
            return resolving.get(name)

        domains = ["evil.com", "unregistered.org", "good.net"]
        results = domainwatch.check_registered(domains, resolve=fake_resolve)

        by_name = {r["domain"]: r for r in results}
        self.assertTrue(by_name["evil.com"]["registered"])
        self.assertEqual(by_name["evil.com"]["addresses"], ["203.0.113.5"])
        self.assertFalse(by_name["unregistered.org"]["registered"])
        self.assertEqual(by_name["unregistered.org"]["addresses"], [])
        self.assertTrue(by_name["good.net"]["registered"])

        registered_names = {r["domain"] for r in results if r["registered"]}
        self.assertEqual(registered_names, {"evil.com", "good.net"})

    def test_preserves_input_order(self):
        results = domainwatch.check_registered(
            ["a.com", "b.com", "c.com"], resolve=lambda n: None
        )
        self.assertEqual([r["domain"] for r in results], ["a.com", "b.com", "c.com"])

    def test_flaky_resolver_does_not_crash(self):
        def boom(name):
            raise RuntimeError("DNS down")

        results = domainwatch.check_registered(["x.com"], resolve=boom)
        self.assertFalse(results[0]["registered"])

    def test_empty_address_list_is_unregistered(self):
        results = domainwatch.check_registered(["x.com"], resolve=lambda n: [])
        self.assertFalse(results[0]["registered"])

    def test_default_resolver_is_module_seam(self):
        # Monkeypatch the module-level seam; no network should be touched.
        orig = domainwatch._resolve
        try:
            domainwatch._resolve = lambda name: ["192.0.2.1"] if name == "hit.com" else None
            results = domainwatch.check_registered(["hit.com", "miss.com"])
        finally:
            domainwatch._resolve = orig
        by_name = {r["domain"]: r["registered"] for r in results}
        self.assertTrue(by_name["hit.com"])
        self.assertFalse(by_name["miss.com"])


class EmailAuthAdviceTests(unittest.TestCase):
    def test_contains_p_reject_and_hard_fail(self):
        advice = domainwatch.email_auth_advice()
        self.assertIn("p=reject", advice["dmarc"]["record"])
        self.assertIn("-all", advice["spf"]["record"])

    def test_has_dkim_guidance(self):
        advice = domainwatch.email_auth_advice()
        self.assertIn("DKIM1", advice["dkim"]["record"])


class ScanTests(unittest.TestCase):
    def test_scan_ties_it_together(self):
        candidates = domainwatch.permutations("example.com")
        target = candidates[0]

        def fake_resolve(name):
            return ["203.0.113.1"] if name == target else None

        result = domainwatch.scan("example.com", resolve=fake_resolve)
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["candidates"], candidates)
        self.assertEqual(len(result["registered"]), 1)
        self.assertEqual(result["registered"][0]["domain"], target)
        self.assertIn("p=reject", result["email_auth"]["dmarc"]["record"])


if __name__ == "__main__":
    unittest.main()
