"""Unit tests for the TAXII 2.1 client (artex_antidote.taxii).

All tests run offline: network I/O is replaced either by a fake ``transport``
callable injected into the client, or by monkeypatching the module-level
``_http_request`` seam. No admin, no sockets, no live server.
"""

import json
import unittest

from artex_antidote import taxii
from artex_antidote.taxii import TAXII_MEDIA_TYPE, Taxii21Client, TaxiiError


class RecordingTransport:
    """Fake transport that records the last request and returns a canned reply."""

    def __init__(self, status=202, body=None, headers=None):
        self.calls = []
        self._status = status
        self._body = body if body is not None else {"id": "ingest-1", "status": "complete"}
        self._headers = headers or {"Content-Type": TAXII_MEDIA_TYPE}

    def __call__(self, method, url, headers, body):
        decoded = json.loads(body.decode("utf-8")) if body else None
        self.calls.append(
            {"method": method, "url": url, "headers": headers, "body": decoded, "raw_body": body}
        )
        return {"status": self._status, "headers": self._headers, "body": self._body}


_BUNDLE = {
    "type": "bundle",
    "id": "bundle--11111111-1111-4111-8111-111111111111",
    "objects": [
        {"type": "ipv4-addr", "spec_version": "2.1", "id": "ipv4-addr--a", "value": "203.0.113.9"},
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--b",
            "pattern": "[ipv4-addr:value = '203.0.113.9']",
            "pattern_type": "stix",
            "valid_from": "2026-11-26T20:00:00.000Z",
            "labels": ["malicious-activity"],
        },
    ],
}


class TestPushObjects(unittest.TestCase):
    def test_url_is_taxii_21_objects_endpoint(self):
        t = RecordingTransport()
        client = Taxii21Client("https://taxii.example.org/api1", token="SECRET", transport=t)
        client.push_objects("collection-xyz", _BUNDLE)
        self.assertEqual(
            t.calls[0]["url"],
            "https://taxii.example.org/api1/collections/collection-xyz/objects/",
        )
        self.assertEqual(t.calls[0]["method"], "POST")

    def test_api_root_trailing_slash_is_normalized(self):
        t = RecordingTransport()
        client = Taxii21Client("https://taxii.example.org/api1/", token="SECRET", transport=t)
        client.push_objects("c1", _BUNDLE)
        self.assertEqual(
            t.calls[0]["url"], "https://taxii.example.org/api1/collections/c1/objects/"
        )

    def test_headers_media_type_and_bearer(self):
        t = RecordingTransport()
        client = Taxii21Client("https://taxii.example.org/api1", token="SECRET", transport=t)
        client.push_objects("c1", _BUNDLE)
        headers = t.calls[0]["headers"]
        self.assertEqual(headers["Accept"], "application/taxii+json;version=2.1")
        self.assertEqual(headers["Content-Type"], "application/taxii+json;version=2.1")
        self.assertEqual(headers["Authorization"], "Bearer SECRET")

    def test_body_is_objects_envelope_not_bundle(self):
        t = RecordingTransport()
        client = Taxii21Client("https://taxii.example.org/api1", token="SECRET", transport=t)
        client.push_objects("c1", _BUNDLE)
        sent = t.calls[0]["body"]
        # Envelope shape: exactly {"objects": [...]} -- no bundle "type"/"id".
        self.assertEqual(set(sent.keys()), {"objects"})
        self.assertNotIn("type", sent)
        self.assertNotIn("id", sent)
        self.assertEqual(sent["objects"], _BUNDLE["objects"])
        self.assertEqual(len(sent["objects"]), 2)

    def test_returns_status_resource_body(self):
        t = RecordingTransport(body={"id": "ingest-42", "status": "pending"})
        client = Taxii21Client("https://taxii.example.org/api1", token="SECRET", transport=t)
        result = client.push_objects("c1", _BUNDLE)
        self.assertEqual(result, {"id": "ingest-42", "status": "pending"})

    def test_no_token_omits_authorization(self):
        t = RecordingTransport()
        client = Taxii21Client("https://taxii.example.org/api1", token="", transport=t)
        client.push_objects("c1", _BUNDLE)
        self.assertNotIn("Authorization", t.calls[0]["headers"])

    def test_bundle_without_objects_rejected(self):
        t = RecordingTransport()
        client = Taxii21Client("https://taxii.example.org/api1", token="x", transport=t)
        with self.assertRaises(ValueError):
            client.push_objects("c1", {"type": "bundle", "id": "bundle--z"})
        self.assertEqual(t.calls, [])  # nothing sent

    def test_non_2xx_raises_taxii_error(self):
        t = RecordingTransport(status=401, body={"title": "unauthorized"})
        client = Taxii21Client("https://taxii.example.org/api1", token="bad", transport=t)
        with self.assertRaises(TaxiiError) as ctx:
            client.push_objects("c1", _BUNDLE)
        self.assertEqual(ctx.exception.status, 401)


class TestDiscoverCollections(unittest.TestCase):
    def test_discover_url_headers_and_parsing(self):
        collections = [
            {"id": "c1", "title": "Blocklist", "can_write": True},
            {"id": "c2", "title": "Indicators", "can_write": True},
        ]
        t = RecordingTransport(body={"collections": collections})
        client = Taxii21Client("https://taxii.example.org/api1", token="SECRET", transport=t)
        result = client.discover_collections()

        self.assertEqual(
            t.calls[0]["url"], "https://taxii.example.org/api1/collections/"
        )
        self.assertEqual(t.calls[0]["method"], "GET")
        self.assertEqual(t.calls[0]["headers"]["Accept"], TAXII_MEDIA_TYPE)
        # GET has no request body / Content-Type.
        self.assertIsNone(t.calls[0]["raw_body"])
        self.assertNotIn("Content-Type", t.calls[0]["headers"])
        self.assertEqual(result, collections)

    def test_discover_missing_collections_key_returns_empty(self):
        t = RecordingTransport(body={})
        client = Taxii21Client("https://taxii.example.org/api1", token="x", transport=t)
        self.assertEqual(client.discover_collections(), [])


class TestHttpSeamMonkeypatch(unittest.TestCase):
    """Exercise the default transport path by monkeypatching the _http_request seam."""

    def test_default_transport_uses_module_seam(self):
        captured = {}

        def fake_http(method, url, headers, body):
            captured.update(method=method, url=url, headers=headers, body=body)
            return {"status": 202, "headers": {"Content-Type": TAXII_MEDIA_TYPE}, "body": {"status": "ok"}}

        original = taxii._http_request
        taxii._http_request = fake_http
        try:
            # No transport injected -> client falls back to taxii._http_request.
            client = Taxii21Client("https://taxii.example.org/api1", token="TKN")
            out = client.push_objects("cc", _BUNDLE)
        finally:
            taxii._http_request = original

        self.assertEqual(out, {"status": "ok"})
        self.assertEqual(captured["url"], "https://taxii.example.org/api1/collections/cc/objects/")
        self.assertEqual(captured["headers"]["Authorization"], "Bearer TKN")
        self.assertEqual(json.loads(captured["body"].decode("utf-8")), {"objects": _BUNDLE["objects"]})


if __name__ == "__main__":
    unittest.main()
