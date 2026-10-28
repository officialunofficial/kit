#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Pin the invariants of the Cloud Build files and of the GitHub split.

The checks read text only, so they need no YAML library. They cover:
  - one toolchain version: rust/rust-toolchain.toml is the source, and the
    places that cannot read it (the image tag, clippy.toml, Cargo.toml) match it;
  - mold on the nextest archive step only, a bounded number of build jobs and
    the compiler wrapper on every compiling step;
  - a step graph in which the test steps run from the archive;
  - no secret in a configuration file;
  - no gate that runs on both Cloud Build and GitHub Actions.

Run from any directory:  python3 -I -B scripts/test-ci-gates.py
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLOUD = ROOT / "cloudbuild"
WRAPPER = "/workspace/scripts/ci-rustc-wrapper.sh"
MAX_JOBS = 8
EXPECTED_STEPS = {
    "fmt", "lint", "docs", "nextest-archive", "nextest-1", "nextest-2",
    "nextest-3", "ignored-lane", "tests-misc", "version", "cli-baseline",
    "wasm", "fuzz-smoke", "golden", "generated", "writing", "unsafe",
    "supply", "workflows", "ci-gates",
}


def strip_comments(text):
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def split_steps(path):
    text = strip_comments(path.read_text())
    chunks = re.split(r"(?m)^  - name: ", text)[1:]
    return {re.search(r"(?m)^    id: (\S+)$", c).group(1): c for c in chunks}


def script_of(step):
    match = re.search(r"(?m)^      - \|\n((?:        [^\n]*\n|\n)*)", step + "\n")
    return match.group(1) if match else ""


def ci_steps():
    return split_steps(CLOUD / "ci.yaml")


class Gates(unittest.TestCase):
    def test_toolchain_version_is_one_value(self):
        channel = re.search(r'channel = "([^"]+)"', (ROOT / "rust/rust-toolchain.toml").read_text()).group(1)
        docker = (CLOUD / "Dockerfile.ci").read_text()
        self.assertIn("FROM rust:${RUST_VERSION}-bookworm", docker)
        self.assertNotIn(channel, strip_comments(docker))
        tag = f"kit-ci:rust-{channel}"
        self.assertIn(f'msrv = "{channel}"', (ROOT / "clippy.toml").read_text())
        self.assertRegex((ROOT / "rust/Cargo.toml").read_text(), rf'(?m)^rust-version = "{re.escape(channel)}"$')
        # Everything that can read the toolchain file does not repeat the version.
        readers = [ROOT / "scripts/setup-cloud-build.sh", ROOT / ".github/actions/setup-rust/action.yml"]
        readers += sorted((ROOT / ".github/workflows").glob("*.yml"))
        for path in readers:
            with self.subTest(reader=path.name):
                self.assertNotIn(channel, strip_comments(path.read_text()))
        result = subprocess.run(["bash", str(ROOT / "scripts/toolchain-version.sh")], text=True, capture_output=True)
        self.assertEqual((result.returncode, result.stdout), (0, channel + "\n"))
        files = sorted(CLOUD.glob("*.yaml"))
        for path in files:
            text = path.read_text()
            for match in re.finditer(r"/(kit-ci):(\S+)", text):
                with self.subTest(file=path.name):
                    self.assertEqual(f"{match.group(1)}:{match.group(2)}".rstrip('}"'), tag)
        self.assertIn(tag, (CLOUD / "builder.yaml").read_text())
        nightly = re.search(r"toolchain install (nightly-\d{4}-\d{2}-\d{2})", docker).group(1)
        self.assertIn(f"cargo +{nightly} fuzz run", ci_steps()["fuzz-smoke"])

    def test_tools_are_pinned_and_mold_is_installed(self):
        docker = (CLOUD / "Dockerfile.ci").read_text()
        self.assertRegex(docker, r"apt-get install[^\n]*(\\\n[^\n]*)*\bmold\b")
        block = re.search(r"cargo binstall -y \\\n((?:[^\n]*\\\n)+)", docker).group(1)
        tools = re.findall(r"^\s*(cargo-[\w-]+|sccache|b3sum)(@\S+)?\s*\\$", block, re.M)
        self.assertGreaterEqual(len(tools), 8)
        for name, version in tools:
            self.assertRegex(version, r"^@\d+\.\d+\.\d+$", f"{name} has no exact version")

    def test_mold_links_only_the_archive_step(self):
        steps = ci_steps()
        for step_id, step in steps.items():
            with self.subTest(step=step_id):
                if step_id == "nextest-archive":
                    self.assertIn('"RUSTFLAGS=-C link-arg=-fuse-ld=mold"', step)
                else:
                    self.assertNotRegex(step, r"(?<![A-Z])RUSTFLAGS=")
                    self.assertNotIn("mold", step)
        for path in CLOUD.glob("*.yaml"):
            if path.name != "ci.yaml":
                self.assertNotIn("fuse-ld", path.read_text(), path.name)

    def test_build_jobs_are_bounded(self):
        steps = ci_steps()
        archive = steps["nextest-archive"]
        match = re.search(r"cargo nextest archive --locked --workspace --all-features --build-jobs (\d+) "
                          r"--archive-file /workspace/nextest-archive\.tar\.zst", archive)
        self.assertIsNotNone(match)
        self.assertTrue(1 <= int(match.group(1)) <= MAX_JOBS)
        for step_id, step in steps.items():
            jobs = re.search(r'"CARGO_BUILD_JOBS=(\d+)"', step)
            if jobs:
                with self.subTest(step=step_id):
                    self.assertTrue(1 <= int(jobs.group(1)) <= MAX_JOBS)
            elif '"RUSTC_WRAPPER=' in step and step_id != "nextest-archive":
                self.fail(f"{step_id} compiles without a job bound")

    def test_timing_line_is_in_the_archive_step_only(self):
        steps = ci_steps()
        self.assertEqual(script_of(steps["nextest-archive"]).count("ci-timing:"), 1)
        for step_id, step in steps.items():
            if step_id != "nextest-archive":
                self.assertNotIn("ci-timing", step)

    def test_wrapper_is_used_by_compiling_steps(self):
        path = ROOT / "scripts/ci-rustc-wrapper.sh"
        self.assertTrue(os.access(path, os.X_OK), "the wrapper must be executable")
        for step_id, step in ci_steps().items():
            if '"RUSTC_WRAPPER=' in step:
                with self.subTest(step=step_id):
                    self.assertIn(f'"RUSTC_WRAPPER={WRAPPER}"', step)
        steps = ci_steps()
        for step_id in ("lint", "docs", "nextest-archive", "tests-misc", "version", "wasm"):
            self.assertIn(f'"RUSTC_WRAPPER={WRAPPER}"', steps[step_id])
        # cargo-geiger drives rustc itself, so its step has no wrapper.
        self.assertNotIn("RUSTC_WRAPPER", steps["unsafe"])

    def run_wrapper(self, cache_script):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "sccache"
            cache.write_text(cache_script)
            cache.chmod(0o755)
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ["PATH"])
            return subprocess.run(["bash", str(ROOT / "scripts/ci-rustc-wrapper.sh"), "rustc", "--crate-name", "x"],
                                  env=env, text=True, capture_output=True)

    def test_wrapper_passes_arguments_to_sccache(self):
        result = self.run_wrapper('#!/bin/sh\nprintf "%s\\n" "$@"\n')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.split(), ["rustc", "--crate-name", "x"])
        self.assertEqual(result.stderr, "")

    def test_wrapper_failure_is_visible_and_fails(self):
        result = self.run_wrapper('#!/bin/sh\necho "sccache: Compile terminated by signal 9"\nexit 2\n')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "sccache: Compile terminated by signal 9\n")

    def test_step_graph(self):
        steps = ci_steps()
        self.assertEqual(set(steps), EXPECTED_STEPS)
        for step_id, step in steps.items():
            with self.subTest(step=step_id):
                match = re.search(r"(?m)^    waitFor: \[(.*)\]$", step)
                self.assertIsNotNone(match, "no waitFor")
                for dep in [d.strip().strip("'\"") for d in match.group(1).split(",")]:
                    self.assertTrue(dep == "-" or dep in steps, f"unknown dependency {dep}")
                self.assertRegex(step, r"(?m)^    timeout: \d+s$")
                self.assertNotIn("allowFailure", step)
                self.assertNotIn("allowExitCodes", step)
                self.assertNotIn("|| true", step)
                script = script_of(step)
                self.assertTrue(script.lstrip().startswith("set -euo pipefail"))
                # Cloud Build rejects a step argument above 10,000 characters.
                self.assertLessEqual(len(script.encode()), 10_000)

    def test_partitions_run_from_the_archive(self):
        steps = ci_steps()
        parts = sorted(i for i in steps if re.fullmatch(r"nextest-\d+", i))
        self.assertEqual(parts, ["nextest-1", "nextest-2", "nextest-3"])
        script = (ROOT / "scripts/ci-nextest.sh").read_text()
        self.assertTrue(os.access(ROOT / "scripts/ci-nextest.sh", os.X_OK))
        self.assertIn(f"PARTITIONS={len(parts)}\n", script)
        self.assertIn('--partition "count:${partition}/${PARTITIONS}"', script)
        self.assertIn("export KIT_TEST_STRICT=1", script)
        for text in (script, steps["ignored-lane"]):
            self.assertIn("--archive-file /workspace/nextest-archive.tar.zst", text)
            self.assertIn("--workspace-remap /workspace/rust", text)
            self.assertIn("--no-fail-fast", text)
            self.assertNotRegex(text, r"cargo (build|test|check|clippy)\b")
        for index, step_id in enumerate(parts, 1):
            step = steps[step_id]
            self.assertIn("waitFor: [nextest-archive]", step)
            self.assertTrue(script_of(step).rstrip().endswith(f"bash scripts/ci-nextest.sh {index}"))
        self.assertIn('"KIT_TEST_STRICT=1"', steps["ignored-lane"])
        self.assertIn("--profile ignored-lane --no-fail-fast --run-ignored ignored-only", steps["ignored-lane"])

    def test_nextest_script_rejects_a_bad_partition(self):
        for arg in ([], ["0"], ["4"], ["x"]):
            result = subprocess.run(["bash", str(ROOT / "scripts/ci-nextest.sh"), *arg], text=True, capture_output=True)
            with self.subTest(arg=arg):
                self.assertEqual(result.returncode, 2)
                self.assertIn("partition", result.stderr)

    def test_readme_explains_every_github_workflow(self):
        readme = (CLOUD / "README.md").read_text()
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            self.assertIn(f"- `{path.name}` stays because", readme)

    def test_audit_ignores_match_deny_toml(self):
        deny = re.findall(r'\{ id = "(RUSTSEC-[\d-]+)"', (ROOT / "rust/deny.toml").read_text())
        audit = re.findall(r"--ignore (RUSTSEC-[\d-]+)", ci_steps()["supply"])
        self.assertTrue(deny)
        self.assertEqual(sorted(deny), sorted(audit))
        sweep = strip_comments((ROOT / ".github/workflows/rust-security.yml").read_text())
        self.assertEqual(sorted(deny), sorted(re.findall(r"--ignore (RUSTSEC-[\d-]+)", sweep)))

    def test_public_workflows_have_the_gate_job_and_no_secret(self):
        text = strip_comments((ROOT / ".github/workflows/rust.yml").read_text())
        jobs = re.findall(r"(?m)^  ([a-z-]+):$", text.split("\njobs:\n")[1])
        self.assertIn("ci-gate", jobs)
        needs = re.search(r"(?m)^    needs: \[(.*)\]$", text).group(1).split(", ")
        self.assertEqual(sorted(needs), sorted(j for j in jobs if j != "ci-gate"))
        for name in ("rust.yml", "rust-security.yml"):
            body = strip_comments((ROOT / ".github/workflows" / name).read_text())
            with self.subTest(workflow=name):
                self.assertNotIn("secrets.", body)
                self.assertRegex(body, r"(?m)^permissions:\n  contents: read$")

    def test_no_secret_in_any_cloud_file(self):
        names = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSPHRASE|PRIVATE_KEY|API_KEY|CREDENTIAL)", re.I)
        for path in sorted(CLOUD.iterdir()):
            text = strip_comments(path.read_text())
            with self.subTest(file=path.name):
                for key in ("secretEnv", "availableSecrets", "secretManager", "gcloud secrets"):
                    self.assertNotIn(key, text)
                self.assertNotRegex(text, r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
                if path.suffix == ".yaml":
                    for env in re.findall(r'(?m)^\s+- "([A-Z0-9_]+)=', text):
                        self.assertIsNone(names.search(env), f"secret-like variable {env}")
                if path.name == "Dockerfile.ci":
                    for arg in re.findall(r"(?m)^ARG (\w+)", text):
                        self.assertIsNone(names.search(arg), f"secret-like ARG {arg}")

    def test_no_gate_runs_on_both_services(self):
        gates = ["cargo fmt", "cargo clippy", "cargo deny", "cargo audit", "cargo doc",
                 "cargo about", "cargo geiger", "scripts/check-", "scripts/test-check-",
                 "scripts/test-install.sh"]
        # The release workflows run some of these commands at release time on
        # purpose. They are not gates of a pull request.
        release = {"release.yml", "release-verify.yml"}
        # These workflows repeat the gates on purpose, so that contributors
        # read the result on GitHub. The tests below pin the commands of the
        # first two.
        public = {"rust.yml", "rust-security.yml", "docs-lint.yml", "proto.yml", "third-party-notices.yml"}
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            if path.name in release or path.name in public:
                continue
            text = strip_comments(path.read_text())
            for gate in gates:
                if gate in text:
                    self.fail(f"{path.name} repeats the gate command: {gate}")

    def test_publish_check_never_publishes(self):
        script = ROOT / "scripts/check-publish.sh"
        text = strip_comments(script.read_text())
        for line in re.findall(r"(?m)^\s*(?:publish=\()?cargo publish\b.*$", text):
            self.assertIn("--dry-run", line)
        self.assertEqual(len(re.findall(r"cargo publish", text)), 1)
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "calls"
            fake = Path(tmp) / "bin"
            fake.mkdir()
            cargo = fake / "cargo"
            cargo.write_text(
                "#!/bin/sh\n"
                f'echo "$*" >> "{log}"\n'
                'if [ "$1" = metadata ]; then\n'
                f'  echo \'{{"target_directory":"{tmp}/target","packages":[{{"name":"a","publish":null}},{{"name":"b","publish":[]}}]}}\'\n'
                "fi\n"
                'if [ "$1" = package ]; then\n'
                f'  mkdir -p "{tmp}/target/package"; echo x > "{tmp}/target/package/a-0.1.0.crate"\n'
                "fi\n"
            )
            cargo.chmod(0o755)
            env = {**os.environ, "PATH": f"{fake}:{os.environ['PATH']}", "CARGO_REGISTRY_TOKEN": "t"}
            result = subprocess.run(["bash", str(script)], text=True, capture_output=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text().splitlines()
            publish = [c for c in calls if c.startswith("publish")]
            self.assertEqual(publish, ["publish --workspace --dry-run --locked"])
            package = [c for c in calls if c.startswith("package")]
            self.assertEqual(package, ["package -p a --locked --no-verify"])
            for arg in (["--no-dry-run"], ["--allow-dirty", "x"], ["publish"]):
                with self.subTest(arg=arg):
                    before = log.read_text()
                    result = subprocess.run(["bash", str(script), *arg], text=True, capture_output=True, env=env)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(log.read_text(), before)

    def test_publish_dry_run_is_a_supply_step(self):
        steps = split_steps(CLOUD / "supply.yaml")
        self.assertIn("publish-dry-run", steps)
        self.assertIn("bash scripts/check-publish.sh", script_of(steps["publish-dry-run"]))
        self.assertIn("scripts/check-publish.sh", (ROOT / "scripts/setup-cloud-build.sh").read_text())
        self.assertIn("`publish-dry-run`", (CLOUD / "README.md").read_text())

    def test_documents_agree_with_the_files(self):
        readme = (CLOUD / "README.md").read_text()
        setup = (ROOT / "scripts/setup-cloud-build.sh").read_text()
        self.assertIn("not yet measured", readme)
        self.assertIn("ci-timing", readme)
        for trigger in re.findall(r"\b(kit-[a-z-]+-(?:pr|main|weekly))\b", setup):
            self.assertIn(trigger.rsplit("-", 1)[0], readme)
        for name in ("ci", "supply", "connect"):
            self.assertIn(f"kit-{name}-pr", readme)
        for step_id in EXPECTED_STEPS:
            self.assertIn(f"`{step_id}`", readme)


if __name__ == "__main__":
    sys.exit(not unittest.main(exit=False).result.wasSuccessful())
