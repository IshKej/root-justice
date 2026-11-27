"""Unit tests for artex_antidote.tlsconf (design #2 TLS termination).

These tests run fully offline with no admin rights and no real certificates.
They exercise the validation / error paths, the minimum-version flooring, and
the server-socket wrapping wiring. A live key-pair load is only attempted when a
real cert/key is supplied via the ARTEX_TEST_CERT / ARTEX_TEST_KEY environment
variables (skipped otherwise), because generating a throwaway cert needs tooling
that is not guaranteed in this stdlib-only environment.
"""

from __future__ import annotations

import os
import ssl
import tempfile
import unittest
from pathlib import Path

from artex_antidote import tlsconf


class RequireReadableFileTests(unittest.TestCase):
    def test_empty_path_raises(self):
        with self.assertRaises(tlsconf.TLSConfigError):
            tlsconf._require_readable_file("", "certificate")

    def test_missing_file_raises_with_role_and_path(self):
        missing = str(Path(tempfile.gettempdir()) / "definitely-not-here-xyz.pem")
        with self.assertRaises(tlsconf.TLSConfigError) as cm:
            tlsconf._require_readable_file(missing, "private key")
        msg = str(cm.exception)
        self.assertIn("private key", msg)
        self.assertIn("definitely-not-here-xyz.pem", msg)

    def test_directory_is_not_a_regular_file(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(tlsconf.TLSConfigError):
                tlsconf._require_readable_file(d, "certificate")

    def test_existing_file_returns_path(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"x")
            name = f.name
        try:
            result = tlsconf._require_readable_file(name, "certificate")
            self.assertEqual(result, Path(name))
        finally:
            os.unlink(name)


class BuildSSLContextErrorPathTests(unittest.TestCase):
    def setUp(self):
        # A real file that exists but is not a valid PEM, so we can reach the
        # load_cert_chain failure branch deterministically.
        self._tmp = tempfile.NamedTemporaryFile(delete=False)
        self._tmp.write(b"-----BEGIN NONSENSE-----\nnot a real key\n-----END NONSENSE-----\n")
        self._tmp.close()
        self.bogus = self._tmp.name

    def tearDown(self):
        os.unlink(self.bogus)

    def test_missing_certfile_raises(self):
        with self.assertRaises(tlsconf.TLSConfigError) as cm:
            tlsconf.build_ssl_context("/no/such/cert.pem", self.bogus)
        self.assertIn("certificate", str(cm.exception))

    def test_missing_keyfile_raises(self):
        with self.assertRaises(tlsconf.TLSConfigError) as cm:
            tlsconf.build_ssl_context(self.bogus, "/no/such/key.pem")
        self.assertIn("private key", str(cm.exception))

    def test_min_version_below_tls12_rejected(self):
        with self.assertRaises(tlsconf.TLSConfigError) as cm:
            tlsconf.build_ssl_context(
                self.bogus, self.bogus, min_version=ssl.TLSVersion.TLSv1
            )
        self.assertIn("TLS 1.2", str(cm.exception))

    def test_min_version_wrong_type_rejected(self):
        with self.assertRaises(tlsconf.TLSConfigError):
            tlsconf.build_ssl_context(self.bogus, self.bogus, min_version="TLSv1_2")

    def test_bogus_pem_load_failure_wrapped(self):
        # Files exist and min_version is fine, so we reach load_cert_chain, which
        # must fail on the garbage PEM and be re-raised as a TLSConfigError.
        with self.assertRaises(tlsconf.TLSConfigError) as cm:
            tlsconf.build_ssl_context(self.bogus, self.bogus)
        self.assertIn("key pair", str(cm.exception))

    def test_self_signed_context_shares_validation(self):
        # The convenience wrapper must enforce the same checks.
        with self.assertRaises(tlsconf.TLSConfigError):
            tlsconf.self_signed_context("/no/such/cert.pem", self.bogus)


class MinVersionFlooringTests(unittest.TestCase):
    """Verify min_version is actually applied to the context object.

    We monkeypatch load_cert_chain so no real certificate is needed; this lets
    us assert on the configured minimum_version and hardening options without a
    live key pair.
    """

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(delete=False)
        self._tmp.write(b"placeholder")
        self._tmp.close()
        self.path = self._tmp.name
        self._orig_load = ssl.SSLContext.load_cert_chain
        ssl.SSLContext.load_cert_chain = lambda self, *a, **k: None  # type: ignore[assignment]

    def tearDown(self):
        ssl.SSLContext.load_cert_chain = self._orig_load  # type: ignore[assignment]
        os.unlink(self.path)

    def test_default_min_version_is_tls12(self):
        ctx = tlsconf.build_ssl_context(self.path, self.path)
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_explicit_tls13_floor_applied(self):
        ctx = tlsconf.build_ssl_context(
            self.path, self.path, min_version=ssl.TLSVersion.TLSv1_3
        )
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_3)

    def test_compression_disabled(self):
        ctx = tlsconf.build_ssl_context(self.path, self.path)
        self.assertTrue(ctx.options & ssl.OP_NO_COMPRESSION)

    def test_returns_server_side_context(self):
        ctx = tlsconf.build_ssl_context(self.path, self.path)
        self.assertIsInstance(ctx, ssl.SSLContext)


class WrapServerSocketTests(unittest.TestCase):
    class _FakeHTTPD:
        def __init__(self, sock):
            self.socket = sock

    def test_non_context_rejected(self):
        httpd = self._FakeHTTPD(sock=object())
        with self.assertRaises(tlsconf.TLSConfigError):
            tlsconf.wrap_server_socket(httpd, "not-a-context")

    def test_missing_socket_attribute_rejected(self):
        class NoSocket:
            pass

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with self.assertRaises(tlsconf.TLSConfigError):
            tlsconf.wrap_server_socket(NoSocket(), ctx)

    def test_wraps_socket_with_server_side_flags(self):
        sentinel = object()
        captured = {}

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        def fake_wrap(sock, **kwargs):
            captured["sock"] = sock
            captured["kwargs"] = kwargs
            return sentinel

        ctx.wrap_socket = fake_wrap  # type: ignore[assignment]

        original_sock = object()
        httpd = self._FakeHTTPD(sock=original_sock)
        returned = tlsconf.wrap_server_socket(httpd, ctx)

        self.assertIs(httpd.socket, sentinel)
        self.assertIs(captured["sock"], original_sock)
        self.assertTrue(captured["kwargs"]["server_side"])
        self.assertFalse(captured["kwargs"]["do_handshake_on_connect"])
        self.assertIs(returned, ctx)


class LiveCertTests(unittest.TestCase):
    def test_live_cert_load_if_available(self):
        cert = os.environ.get("ARTEX_TEST_CERT")
        key = os.environ.get("ARTEX_TEST_KEY")
        if not cert or not key:
            self.skipTest("no ARTEX_TEST_CERT/ARTEX_TEST_KEY provided")
        ctx = tlsconf.build_ssl_context(cert, key)
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)


if __name__ == "__main__":
    unittest.main()
