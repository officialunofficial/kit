#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check the published formula, input validation, and tap writes without secrets."""
import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import urllib.error

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("homebrew", ROOT / "homebrew.py")
homebrew = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(homebrew)
SUMS = (ROOT / "homebrew-0.8.1.sha256").read_text()


class Formula(unittest.TestCase):
    def test_formula_matches_the_published_tap_candidate(self):
        # This digest pins Formula/kit.rb in the tap; only the template renders it.
        expected = (ROOT / "homebrew-0.8.1-formula.sha256").read_text().strip()
        self.assertEqual(hashlib.sha256(homebrew.render("0.8.1", SUMS).encode()).hexdigest(), expected)

    def test_incomplete_duplicate_or_malformed_checksums_are_refused(self):
        for sums in ("", SUMS.splitlines()[0], SUMS + SUMS, SUMS.replace("947b", "xxxx")):
            with self.subTest(sums=sums[:40]), self.assertRaises(ValueError):
                homebrew.render("0.8.1", sums)

    def test_unstable_or_injected_versions_are_refused(self):
        for version in ("0.9.0-rc.1", '0.9.0"', "v0.9.0", "0.9.0\n"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                homebrew.render(version, SUMS)

    def test_missing_token_fails_before_any_network_request(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(homebrew.urllib.request, "urlopen") as request:
            with self.assertRaisesRegex(ValueError, "HOMEBREW_TAP_TOKEN is required"):
                homebrew.preflight()
            request.assert_not_called()

    def test_preflight_proves_write_access_without_changing_the_ref(self):
        with patch.object(homebrew, "api", side_effect=[{"object": {"sha": "head"}}, {}]) as api:
            homebrew.preflight()
            self.assertEqual(api.call_args_list[-1].args, (
                "PATCH", "git/refs/heads/main", {"sha": "head", "force": False}))

    def test_http_errors_do_not_disclose_credentials_or_response_bodies(self):
        error = urllib.error.HTTPError("https://api.github.com", 403, "private detail", {}, None)
        with patch.dict(os.environ, {"HOMEBREW_TAP_TOKEN": "sensitive"}), patch.object(
                homebrew.urllib.request, "urlopen", side_effect=error):
            with self.assertRaisesRegex(ValueError, "HTTP 403") as raised:
                homebrew.preflight()
            self.assertNotIn("sensitive", str(raised.exception))
            self.assertNotIn("private detail", str(raised.exception))

    def test_updates_use_the_current_file_sha_and_exact_formula(self):
        with patch.object(homebrew, "api", side_effect=[{
                "sha": "current", "content": base64.b64encode(homebrew.render("0.8.1", SUMS).replace("0.8.1", "0.8.0").encode()).decode()}, {}]) as api:
            homebrew.update("0.8.1", SUMS)
            method, path, body = api.call_args.args
            self.assertEqual((method, path, body["sha"], body["branch"]),
                             ("PUT", "contents/Formula/kit.rb", "current", "main"))
            self.assertEqual(base64.b64decode(body["content"]).decode(), homebrew.render("0.8.1", SUMS))

    def test_older_release_cannot_downgrade_the_tap(self):
        content = base64.b64encode(homebrew.render("0.8.1", SUMS).replace("0.8.1", "0.9.0").encode()).decode()
        with patch.object(homebrew, "api", return_value={"content": content}) as api:
            with self.assertRaisesRegex(ValueError, "newer tap version"):
                homebrew.update("0.8.1", SUMS)
            api.assert_called_once()

    def test_identical_formula_does_not_create_another_commit(self):
        content = base64.b64encode(homebrew.render("0.8.1", SUMS).encode()).decode()
        with patch.object(homebrew, "api", return_value={"content": content}) as api:
            homebrew.update("0.8.1", SUMS)
            api.assert_called_once()

    def test_update_waits_for_release_and_package_publication(self):
        workflow = (ROOT.parent / ".github/workflows/release.yml").read_text()
        job = workflow.split("\n  update-homebrew:")[1]
        self.assertIn("needs: [validate-release-tag, release, publish-npm, publish-crates]", job)
        self.assertNotIn("always()", job)
        self.assertIn("gh release download", job)
        self.assertLess(job.index("gh release download"), job.index("homebrew.py update"))
        validation = workflow.split("\n  build:")[0]
        self.assertLess(validation.index("Validate tag trust"), validation.index("homebrew.py preflight"))


if __name__ == "__main__":
    unittest.main()
