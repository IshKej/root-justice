"""Unit tests for artex_antidote.posture (GAP #1 public-exposure auditing).

Fully offline and deterministic: every test passes a fake ``fetch`` seam, so no
network, DNS, admin rights, or clock reads are involved.
"""

from __future__ import annotations

import unittest

from artex_antidote import posture


def _fetch_const(status, body=""):
    """Return a fake probe seam that always answers ``(status, body)``."""
    def _f(url):
        return status, body
    return _f


class DetectProviderTests(unittest.TestCase):
    def test_s3_virtual_hosted(self):
        self.assertEqual(
            posture.detect_provider("https://logs.s3.amazonaws.com/"), "s3"
        )

    def test_s3_regional(self):
        self.assertEqual(
            posture.detect_provider("https://b.s3.us-east-1.amazonaws.com/"), "s3"
        )

    def test_gcs(self):
        self.assertEqual(
            posture.detect_provider("https://storage.googleapis.com/b/"), "gcs"
        )

    def test_azure(self):
        self.assertEqual(
            posture.detect_provider("https://acct.blob.core.windows.net/c/"),
            "azure",
        )

    def test_unknown(self):
        self.assertEqual(posture.detect_provider("https://example.com/"), "unknown")


class ClassifyResponseTests(unittest.TestCase):
    def test_403_is_private(self):
        self.assertEqual(posture.classify_response(403, ""), posture.PRIVATE)

    def test_401_is_private(self):
        self.assertEqual(posture.classify_response(401, ""), posture.PRIVATE)

    def test_access_denied_body_is_private(self):
        body = "<Error><Code>AccessDenied</Code></Error>"
        self.assertEqual(posture.classify_response(200, body), posture.PRIVATE)

    def test_s3_listing_is_public(self):
        body = '<?xml version="1.0"?><ListBucketResult><Contents/></ListBucketResult>'
        self.assertEqual(posture.classify_response(200, body), posture.PUBLIC)

    def test_200_with_content_is_public(self):
        self.assertEqual(
            posture.classify_response(200, "secret log line here"), posture.PUBLIC
        )

    def test_empty_200_is_unknown(self):
        self.assertEqual(posture.classify_response(200, ""), posture.UNKNOWN)

    def test_404_is_unknown(self):
        self.assertEqual(posture.classify_response(404, "nope"), posture.UNKNOWN)

    def test_network_error_status_zero_is_unknown(self):
        self.assertEqual(posture.classify_response(0, ""), posture.UNKNOWN)


class CheckBucketTests(unittest.TestCase):
    def test_public_bucket_verdict(self):
        fetch = _fetch_const(200, "<ListBucketResult><Contents/></ListBucketResult>")
        result = posture.check_bucket("https://open.s3.amazonaws.com/", fetch=fetch)
        self.assertEqual(result["verdict"], posture.PUBLIC)
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["url"], "https://open.s3.amazonaws.com/")
        self.assertEqual(result["provider"], "s3")

    def test_private_bucket_verdict(self):
        fetch = _fetch_const(403, "<Error><Code>AccessDenied</Code></Error>")
        result = posture.check_bucket("https://locked.s3.amazonaws.com/", fetch=fetch)
        self.assertEqual(result["verdict"], posture.PRIVATE)
        self.assertEqual(result["status"], 403)

    def test_result_shape(self):
        fetch = _fetch_const(403, "")
        result = posture.check_bucket("https://x.s3.amazonaws.com/", fetch=fetch)
        self.assertEqual(set(result), {"url", "provider", "status", "verdict"})

    def test_empty_url_rejected(self):
        with self.assertRaises(posture.PostureError):
            posture.check_bucket("   ", fetch=_fetch_const(200))

    def test_non_http_url_rejected(self):
        with self.assertRaises(posture.PostureError):
            posture.check_bucket("ftp://host/bucket", fetch=_fetch_const(200))

    def test_non_callable_fetch_rejected(self):
        with self.assertRaises(posture.PostureError):
            posture.check_bucket("https://x.s3.amazonaws.com/", fetch="nope")

    def test_fetch_exception_degrades_to_unknown(self):
        def boom(url):
            raise RuntimeError("probe blew up")

        result = posture.check_bucket("https://x.s3.amazonaws.com/", fetch=boom)
        self.assertEqual(result["verdict"], posture.UNKNOWN)
        self.assertEqual(result["status"], 0)

    def test_non_int_status_coerced(self):
        result = posture.check_bucket(
            "https://x.s3.amazonaws.com/", fetch=_fetch_const("weird", "")
        )
        self.assertEqual(result["status"], 0)
        self.assertEqual(result["verdict"], posture.UNKNOWN)


class AuditTests(unittest.TestCase):
    def test_audit_mixed(self):
        bodies = {
            "https://pub.s3.amazonaws.com/": (200, "<ListBucketResult/>"),
            "https://priv.s3.amazonaws.com/": (403, "AccessDenied"),
        }

        def fetch(url):
            return bodies[url]

        results = posture.audit(list(bodies), fetch=fetch)
        self.assertEqual(len(results), 2)
        verdicts = {r["url"]: r["verdict"] for r in results}
        self.assertEqual(verdicts["https://pub.s3.amazonaws.com/"], posture.PUBLIC)
        self.assertEqual(verdicts["https://priv.s3.amazonaws.com/"], posture.PRIVATE)

    def test_audit_preserves_order(self):
        urls = [
            "https://a.s3.amazonaws.com/",
            "https://b.s3.amazonaws.com/",
            "https://c.s3.amazonaws.com/",
        ]
        results = posture.audit(urls, fetch=_fetch_const(403, ""))
        self.assertEqual([r["url"] for r in results], urls)

    def test_audit_rejects_bare_string(self):
        with self.assertRaises(posture.PostureError):
            posture.audit("https://x.s3.amazonaws.com/", fetch=_fetch_const(403))

    def test_summarize_counts(self):
        urls = {
            "https://a.s3.amazonaws.com/": (200, "<ListBucketResult/>"),
            "https://b.s3.amazonaws.com/": (403, ""),
            "https://c.s3.amazonaws.com/": (500, "oops"),
        }
        results = posture.audit(list(urls), fetch=lambda u: urls[u])
        summary = posture.summarize(results)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["public"], 1)
        self.assertEqual(summary["private"], 1)
        self.assertEqual(summary["unknown"], 1)
        self.assertEqual(summary["public_urls"], ["https://a.s3.amazonaws.com/"])


class ChecklistTests(unittest.TestCase):
    def test_checklist_non_empty(self):
        steps = posture.posture_checklist()
        self.assertTrue(steps)
        self.assertTrue(all(isinstance(s, str) and s for s in steps))

    def test_checklist_covers_key_hardening(self):
        joined = " ".join(posture.posture_checklist()).lower()
        self.assertIn("block public access", joined)
        self.assertIn("policy", joined)
        self.assertIn("acl", joined)
        self.assertIn("logging", joined)


if __name__ == "__main__":
    unittest.main()
