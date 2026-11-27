"""Unit tests for the decoy / canary-response module.

Verifies that known honeypot canary paths produce non-empty, synthetic,
traceable bodies, that benign application paths are never treated as decoys,
and that the loot is deterministic and obviously fake (no routable secrets).

All tests pass offline with no network and no admin: the module is pure stdlib
and performs no I/O.
"""

import unittest

from artex_antidote.decoy import (
    CANARY_MARKER,
    DECOY_PATHS,
    decoy_headers,
    decoy_response,
    is_decoy_path,
)


# Benign paths that MUST NOT be treated as decoys (real traffic).
BENIGN_PATHS = (
    "/",
    "/home",
    "/api/status",
    "/login",
    "/static/app.js",
    "/environment-report",       # near-miss on /.env, different prefix
    "/server-status-dashboard",  # near-miss on /server-status
    "/wp-content/themes/x.css",  # not an admin/login canary
    "",
)


class TestIsDecoyPath(unittest.TestCase):
    def test_all_declared_canary_paths_match(self) -> None:
        for p in DECOY_PATHS:
            self.assertTrue(is_decoy_path(p), f"canary path should match: {p}")

    def test_case_insensitive_and_querystring_tolerant(self) -> None:
        self.assertTrue(is_decoy_path("/.ENV"))
        self.assertTrue(is_decoy_path("/.git/config?ref=main"))
        self.assertTrue(is_decoy_path("/.env#frag"))
        self.assertTrue(is_decoy_path("/.env.local"))

    def test_benign_paths_are_not_decoys(self) -> None:
        for p in BENIGN_PATHS:
            self.assertFalse(is_decoy_path(p), f"benign path must not be a decoy: {p!r}")

    def test_near_miss_prefix_boundary(self) -> None:
        # "/.environment" shares leading chars with "/.env" but is a different path.
        self.assertFalse(is_decoy_path("/.environment"))


class TestDecoyResponse(unittest.TestCase):
    def test_known_canary_paths_produce_nonempty_synthetic_bodies(self) -> None:
        for p in DECOY_PATHS:
            body = decoy_response(p)
            self.assertIsInstance(body, bytes)
            self.assertGreater(len(body), 0, f"empty decoy body for {p}")
            # Every body is a traceable canary.
            self.assertIn(CANARY_MARKER.encode("utf-8"), body,
                          f"decoy for {p} is missing the canary marker")

    def test_benign_path_raises_not_a_decoy(self) -> None:
        for p in ("/home", "/api/status", "/"):
            with self.assertRaises(ValueError):
                decoy_response(p)

    def test_env_decoy_looks_real_but_is_fake(self) -> None:
        body = decoy_response("/.env").decode("utf-8")
        # Looks like a real secrets file...
        self.assertIn("DB_PASSWORD", body)
        self.assertIn("AWS_SECRET_ACCESS_KEY", body)
        self.assertIn("STRIPE_SECRET", body)
        # ...but every sink is non-routable / clearly synthetic.
        self.assertIn("sinkhole.invalid", body)
        self.assertIn(CANARY_MARKER, body)
        self.assertIn("not a real secret", body.lower())

    def test_git_config_decoy(self) -> None:
        body = decoy_response("/.git/config").decode("utf-8")
        self.assertIn("[remote \"origin\"]", body)
        self.assertIn("sinkhole.invalid", body)
        self.assertIn(CANARY_MARKER, body)

    def test_deterministic_for_same_path_and_token(self) -> None:
        a = decoy_response("/.env", token="artex-stream-abc")
        b = decoy_response("/.env", token="artex-stream-abc")
        self.assertEqual(a, b)

    def test_token_changes_the_canary_but_not_the_shape(self) -> None:
        a = decoy_response("/.env", token="stream-1")
        b = decoy_response("/.env", token="stream-2")
        self.assertNotEqual(a, b)  # per-stream tracer differs
        self.assertIn(b"DB_PASSWORD", a)
        self.assertIn(b"DB_PASSWORD", b)

    def test_renderer_longest_prefix_wins(self) -> None:
        # "/.git/config" and "/.git/HEAD" must use their specific renderers,
        # not the generic "/.git" fallback.
        head = decoy_response("/.git/HEAD").decode("utf-8")
        self.assertIn("ref: refs/heads/main", head)
        cfg = decoy_response("/.git/config").decode("utf-8")
        self.assertIn("[core]", cfg)

    def test_no_decoy_contains_an_aws_key_without_trap_marker(self) -> None:
        # Guard against accidentally emitting a plausibly-real AKIA key: every
        # AKIA token we produce carries the TRAP suffix.
        for p in ("/.env", "/.aws/credentials"):
            body = decoy_response(p).decode("utf-8")
            if "AKIA" in body:
                for chunk in body.split():
                    if chunk.startswith("AKIA"):
                        self.assertIn("TRAP", chunk)


class TestDecoyHeaders(unittest.TestCase):
    def test_headers_carry_canary_and_content_type(self) -> None:
        h = decoy_headers("/config.json")
        self.assertEqual(h["X-Canary"], CANARY_MARKER)
        self.assertEqual(h["Content-Type"], "application/json")
        self.assertEqual(decoy_headers("/phpinfo.php")["Content-Type"],
                         "text/html; charset=UTF-8")
        self.assertEqual(decoy_headers("/backup.sql")["Content-Type"],
                         "application/sql")


if __name__ == "__main__":
    unittest.main()
