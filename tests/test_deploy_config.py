"""Regression guards for the deploy artifacts (systemd unit, Docker, compose).

These are offline, text-level invariants for the deploy fixes:
  * systemd word-splits RJ_EXTRA_ARGS (unbraced) so enforcing deploys start,
    while single-value fields keep the braced form;
  * systemd does not re-declare RJ_EVIDENCE after EnvironmentFile (the env file
    stays authoritative);
  * docker-compose publishes the port on the host loopback only.
They parse the shipped files; they do not import the package.
"""

import os
import re
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(_REPO_ROOT, *parts), "r", encoding="utf-8") as fh:
        return fh.read()


class SystemdUnitTests(unittest.TestCase):
    def setUp(self):
        self.text = _read("deploy", "systemd", "root-justice.service")

    def _execstart(self):
        # Join the line-continued ExecStart into one logical line.
        joined = self.text.replace("\\\n", " ")
        for line in joined.splitlines():
            if line.strip().startswith("ExecStart="):
                return line
        self.fail("no ExecStart line found")

    def test_extra_args_is_unbraced(self):
        execstart = self._execstart()
        # Multi-value field must be unbraced so systemd splits it into argv.
        self.assertIn("$RJ_EXTRA_ARGS", execstart)
        self.assertNotIn("${RJ_EXTRA_ARGS}", execstart)

    def test_single_value_fields_stay_braced(self):
        execstart = self._execstart()
        for var in ("RJ_HOST", "RJ_PORT", "RJ_EVIDENCE"):
            self.assertIn("${%s}" % var, execstart)

    def test_no_inline_evidence_override(self):
        # EnvironmentFile must stay authoritative for RJ_EVIDENCE: no inline
        # Environment=RJ_EVIDENCE= directive anywhere in the unit.
        self.assertTrue(
            re.search(r"^\s*EnvironmentFile=", self.text, re.MULTILINE),
            "expected an EnvironmentFile= directive",
        )
        self.assertIsNone(
            re.search(r"^\s*Environment=RJ_EVIDENCE=", self.text, re.MULTILINE),
            "RJ_EVIDENCE must not be re-declared with Environment= after the env file",
        )


class DockerComposeTests(unittest.TestCase):
    def test_port_published_on_loopback_only(self):
        text = _read("docker-compose.yml")
        # Every published port mapping must be bound to 127.0.0.1.
        mappings = re.findall(r'-\s*"([0-9.:]+:\d+)"', text)
        self.assertTrue(mappings, "expected at least one published port mapping")
        for mapping in mappings:
            self.assertTrue(
                mapping.startswith("127.0.0.1:"),
                "port mapping %r should publish on the host loopback" % mapping,
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
