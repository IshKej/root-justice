"""Offline tests for the defensive reverse proxy (artex_antidote.proxy).

No network, no admin, no live upstream: every test monkeypatches the module's
``_open_conn`` seam with a fake connection that records what the proxy sent and
replays a canned response (or raises to simulate an unreachable origin).
"""

from __future__ import annotations

import unittest

from artex_antidote import proxy
from artex_antidote.proxy import HOP_BY_HOP_HEADERS, ProxyResult, UpstreamProxy


class _FakeResponse:
    def __init__(self, status=200, headers=None, body=b"hello"):
        self.status = status
        self._headers = list((headers or {}).items())
        self._body = body

    def getheaders(self):
        return self._headers

    def read(self, _n=None):
        return self._body


class _FakeConn:
    """Records the outbound request and returns a canned response."""

    def __init__(self, response=None, raise_on=None):
        self.response = response or _FakeResponse()
        self.raise_on = raise_on  # "request" | "getresponse" | None
        self.closed = False
        self.sent = None  # (method, path, body, headers)

    def request(self, method, path, body=None, headers=None):
        if self.raise_on == "request":
            raise ConnectionRefusedError("upstream down")
        self.sent = {
            "method": method,
            "path": path,
            "body": body,
            "headers": dict(headers or {}),
        }

    def getresponse(self):
        if self.raise_on == "getresponse":
            raise TimeoutError("upstream timed out")
        return self.response

    def close(self):
        self.closed = True


def _patch_conn(test, conn, record=None):
    """Install a fake _open_conn that yields `conn` and records its args."""

    def fake_open(host, port, use_https, timeout):
        if record is not None:
            record.update(
                host=host, port=port, use_https=use_https, timeout=timeout
            )
        return conn

    original = proxy._open_conn
    proxy._open_conn = fake_open
    test.addCleanup(lambda: setattr(proxy, "_open_conn", original))


class ConstructionTests(unittest.TestCase):
    def test_parses_https_host_and_port(self):
        p = UpstreamProxy("https://app.internal:8443")
        self.assertTrue(p.use_https)
        self.assertEqual(p.host, "app.internal")
        self.assertEqual(p.port, 8443)
        self.assertEqual(p.host_header, "app.internal:8443")

    def test_defaults_http_port_80(self):
        p = UpstreamProxy("http://127.0.0.1")
        self.assertFalse(p.use_https)
        self.assertEqual(p.port, 80)
        self.assertEqual(p.host_header, "127.0.0.1")

    def test_rejects_bad_scheme_and_missing_host(self):
        with self.assertRaises(ValueError):
            UpstreamProxy("ftp://example.com")
        with self.assertRaises(ValueError):
            UpstreamProxy("http://")


class HeaderFilteringTests(unittest.TestCase):
    def test_hop_by_hop_headers_are_stripped_from_request(self):
        conn = _FakeConn()
        _patch_conn(self, conn)
        p = UpstreamProxy("http://origin.test:9000")
        headers = {
            "User-Agent": "curl/8",
            "Connection": "keep-alive",
            "Keep-Alive": "timeout=5",
            "Transfer-Encoding": "chunked",
            "Upgrade": "websocket",
            "TE": "trailers",
            "Proxy-Authorization": "Basic xyz",
            "X-Custom": "keep-me",
        }
        p.forward("GET", "/", headers, b"")

        sent = {k.lower() for k in conn.sent["headers"]}
        for hop in HOP_BY_HOP_HEADERS:
            self.assertNotIn(hop, sent, f"{hop} should have been stripped")
        # Non-hop-by-hop headers survive.
        self.assertIn("user-agent", sent)
        self.assertIn("x-custom", sent)

    def test_hop_by_hop_headers_are_stripped_from_response(self):
        resp = _FakeResponse(
            status=200,
            headers={
                "Content-Type": "text/html",
                "Connection": "close",
                "Transfer-Encoding": "chunked",
                "X-App": "ok",
            },
            body=b"<html></html>",
        )
        conn = _FakeConn(response=resp)
        _patch_conn(self, conn)
        p = UpstreamProxy("http://origin.test")
        status, out_headers, body = p.forward("GET", "/", {}, b"")

        self.assertEqual(status, 200)
        lower = {k.lower() for k in out_headers}
        self.assertNotIn("connection", lower)
        self.assertNotIn("transfer-encoding", lower)
        self.assertIn("content-type", lower)
        self.assertIn("x-app", lower)
        self.assertEqual(body, b"<html></html>")

    def test_host_header_rewritten_to_upstream(self):
        conn = _FakeConn()
        _patch_conn(self, conn)
        p = UpstreamProxy("https://real.upstream:8443")
        p.forward("GET", "/", {"Host": "spoofed.evil.example"}, b"")
        # Client's Host is dropped; upstream Host (with port) is set.
        self.assertEqual(conn.sent["headers"].get("Host"), "real.upstream:8443")


class ForwardingHeaderTests(unittest.TestCase):
    def test_xff_injected_from_socket_peer(self):
        conn = _FakeConn()
        _patch_conn(self, conn)
        p = UpstreamProxy("http://origin.test")
        p.forward("GET", "/", {}, b"", client_ip="203.0.113.7", client_proto="https")
        self.assertEqual(conn.sent["headers"].get("X-Forwarded-For"), "203.0.113.7")
        self.assertEqual(conn.sent["headers"].get("X-Forwarded-Proto"), "https")

    def test_xff_appends_peer_to_existing_chain(self):
        conn = _FakeConn()
        _patch_conn(self, conn)
        p = UpstreamProxy("http://origin.test")
        p.forward(
            "GET",
            "/",
            {"X-Forwarded-For": "198.51.100.1"},
            b"",
            client_ip="203.0.113.7",
        )
        # Trustworthy socket peer goes on the right.
        self.assertEqual(
            conn.sent["headers"].get("X-Forwarded-For"),
            "198.51.100.1, 203.0.113.7",
        )

    def test_xff_proto_defaults_to_upstream_scheme(self):
        conn = _FakeConn()
        _patch_conn(self, conn)
        p = UpstreamProxy("https://origin.test")
        p.forward("GET", "/", {}, b"", client_ip="203.0.113.7")
        self.assertEqual(conn.sent["headers"].get("X-Forwarded-Proto"), "https")

    def test_client_cannot_spoof_proto(self):
        # A client-supplied X-Forwarded-Proto is dropped and replaced.
        conn = _FakeConn()
        _patch_conn(self, conn)
        p = UpstreamProxy("http://origin.test")
        p.forward(
            "GET",
            "/",
            {"X-Forwarded-Proto": "https"},
            b"",
            client_ip="203.0.113.7",
            client_proto="http",
        )
        self.assertEqual(conn.sent["headers"].get("X-Forwarded-Proto"), "http")


class BodyAndPathTests(unittest.TestCase):
    def test_content_length_recomputed_from_body(self):
        conn = _FakeConn()
        _patch_conn(self, conn)
        p = UpstreamProxy("http://origin.test")
        p.forward(
            "POST",
            "/submit",
            {"Content-Length": "9999"},
            b"abc",
        )
        self.assertEqual(conn.sent["headers"].get("Content-Length"), "3")
        self.assertEqual(conn.sent["body"], b"abc")

    def test_path_prefix_from_base_url(self):
        conn = _FakeConn()
        _patch_conn(self, conn)
        p = UpstreamProxy("http://origin.test/api")
        p.forward("GET", "/users", {}, b"")
        self.assertEqual(conn.sent["path"], "/api/users")

    def test_connection_args_forwarded_to_seam(self):
        conn = _FakeConn()
        record = {}
        _patch_conn(self, conn, record=record)
        p = UpstreamProxy("https://origin.test:8443", timeout=3.5)
        p.forward("GET", "/", {}, b"")
        self.assertEqual(record["host"], "origin.test")
        self.assertEqual(record["port"], 8443)
        self.assertTrue(record["use_https"])
        self.assertEqual(record["timeout"], 3.5)


class FailureTests(unittest.TestCase):
    def test_502_on_connect_failure(self):
        conn = _FakeConn(raise_on="request")
        _patch_conn(self, conn)
        p = UpstreamProxy("http://origin.test")
        status, headers, body = p.forward("GET", "/", {}, b"")
        self.assertEqual(status, 502)
        self.assertIn(b"Bad Gateway", body)
        self.assertEqual(headers.get("X-Proxy-Error"), "ConnectionRefusedError")
        self.assertTrue(conn.closed)  # connection still cleaned up

    def test_502_on_timeout(self):
        conn = _FakeConn(raise_on="getresponse")
        _patch_conn(self, conn)
        p = UpstreamProxy("http://origin.test")
        status, _headers, body = p.forward("GET", "/", {}, b"")
        self.assertEqual(status, 502)
        self.assertIn(b"TimeoutError", body)

    def test_502_when_open_conn_itself_raises(self):
        def boom(*_a, **_k):
            raise OSError("no route to host")

        original = proxy._open_conn
        proxy._open_conn = boom
        self.addCleanup(lambda: setattr(proxy, "_open_conn", original))
        p = UpstreamProxy("http://origin.test")
        status, _h, _b = p.forward("GET", "/", {}, b"")
        self.assertEqual(status, 502)

    def test_502_on_oversized_response(self):
        big = b"x" * (proxy.MAX_RESPONSE_BYTES + 10)
        conn = _FakeConn(response=_FakeResponse(body=big))
        _patch_conn(self, conn)
        p = UpstreamProxy("http://origin.test")
        status, _h, body = p.forward("GET", "/", {}, b"")
        self.assertEqual(status, 502)
        self.assertIn(b"size limit", body)


class ResultShapeTests(unittest.TestCase):
    def test_result_unpacks_as_tuple(self):
        conn = _FakeConn(response=_FakeResponse(status=201, body=b"made"))
        _patch_conn(self, conn)
        p = UpstreamProxy("http://origin.test")
        result = p.forward("POST", "/x", {}, b"data")
        self.assertIsInstance(result, ProxyResult)
        status, headers, body = result  # unpacks
        self.assertEqual(status, 201)
        self.assertEqual(body, b"made")
        self.assertIsInstance(headers, dict)


if __name__ == "__main__":
    unittest.main()
