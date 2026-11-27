"""Parity + unit tests for the shared signature source of truth (signatures.py).

These lock in the de-duplication fix: the SQLi/XSS/traversal payload regexes and
the scanner-UA regexes now live once in :mod:`artex_antidote.signatures`, imported
by BOTH the edge shield and the attribution/patch-synthesis path. The parity test
asserts the two paths agree on which exploit families a shared corpus contains, so
a future edit that reintroduces a divergent copy (the ``benchmark(`` drift that
originally motivated this) fails CI.
"""

from __future__ import annotations

import unittest

from artex_antidote import shield as shield_mod
from artex_antidote import signatures
from artex_antidote.attribution import reverse_engineer_request
from artex_antidote.shield import ArtexShield, RequestEvent, VirtualPatchRegistry

# (path_or_payload, user_agent). Mixes clean, exploit, and scanner traffic; the
# third row is the historical drift case: ``benchmark(`` is a SQLi primitive the
# shield caught but the attribution path used to miss.
CORPUS = [
    ("/login?id=1 UNION SELECT 1,2", "sqlmap/1.8"),
    ("/x?q=1 OR 1=1", "curl/8.4.0"),
    ("/s?d=1;benchmark(1000000,md5(1))", "python-requests/2.31"),
    ("/p?x=<script>alert(1)</script>", "nuclei"),
    ("/f?path=../../etc/passwd", "ffuf"),
    ("/home", "Mozilla/5.0"),
    ("/api?u=1 sleep(5)", "Go-http-client/1.1"),
    ("/status", "httpx/0.27"),
]

_EXPLOIT_LABELS = {"sqli", "xss", "path_traversal_or_rce"}


def _event(path: str, user_agent: str) -> RequestEvent:
    return RequestEvent(
        timestamp_utc="2026-11-26T20:00:00.000Z",
        remote_ip="198.51.100.25",
        forwarded_for=[],
        method="GET",
        path=path,
        user_agent=user_agent,
        headers={},
        body_sha256="",
        body_size=0,
    )


class TestSignatureSingleSourceOfTruth(unittest.TestCase):
    def test_shield_imports_the_same_pattern_objects(self) -> None:
        # Not merely equal values: the very same compiled objects, so the two
        # modules physically cannot drift.
        self.assertIs(shield_mod.EXPLOIT_PATTERNS, signatures.EXPLOIT_PATTERNS)
        self.assertIs(
            shield_mod.OFFENSIVE_TOOL_UA_PATTERNS, signatures.OFFENSIVE_TOOL_UA_PATTERNS
        )
        self.assertIs(
            shield_mod.GENERIC_AUTOMATION_UA_PATTERNS,
            signatures.GENERIC_AUTOMATION_UA_PATTERNS,
        )

    def test_dead_aliases_removed(self) -> None:
        # The spoofable XFF helper and the back-compat UA alias were deleted.
        self.assertFalse(hasattr(ArtexShield, "extract_origin_ips"))
        self.assertFalse(hasattr(shield_mod, "SCANNER_UA_PATTERNS"))

    def test_benchmark_sqli_now_classified(self) -> None:
        # The drift that this refactor fixes, pinned directly.
        self.assertIn("sqli", signatures.classify_vectors("x benchmark(1000000)", ""))
        atk = reverse_engineer_request("GET", "/s?d=benchmark(1000000,md5(1))", "curl/8")
        self.assertIn("sqli", atk.vectors)


class TestShieldAttributionParity(unittest.TestCase):
    """Both real code paths must agree on the exploit families in the corpus."""

    def test_exploit_family_parity(self) -> None:
        for path, ua in CORPUS:
            with self.subTest(path=path, ua=ua):
                # Attribution path (real call).
                atk = reverse_engineer_request("GET", path, ua)
                attribution_exploits = set(atk.vectors) & _EXPLOIT_LABELS

                # Shared classifier on the same combined text.
                combined = f"GET {path} {ua} "
                classifier_exploits = set(signatures.classify_vectors(combined, ua)) & _EXPLOIT_LABELS

                # Shield path (real inspect): it emits a single
                # "exploit_probe_pattern" reason iff any exploit family matched.
                det = ArtexShield(patches=VirtualPatchRegistry()).inspect(_event(path, ua))
                shield_saw_exploit = any(r == "exploit_probe_pattern" for r in det.reasons)

                self.assertEqual(attribution_exploits, classifier_exploits)
                self.assertEqual(
                    shield_saw_exploit,
                    bool(classifier_exploits),
                    msg="shield exploit detection diverged from the shared classifier",
                )

    def test_scanner_label_parity_for_offensive_tools(self) -> None:
        # An offensive-tool UA is recognized as automation by both paths.
        for ua in ("sqlmap/1.8", "nuclei", "ffuf", "nmap"):
            with self.subTest(ua=ua):
                self.assertIn("automated_scanner", signatures.classify_vectors("", ua))
                atk = reverse_engineer_request("GET", "/home", ua)
                self.assertIn("automated_scanner", atk.vectors)


if __name__ == "__main__":
    unittest.main()
