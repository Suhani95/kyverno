#!/usr/bin/env python3
"""Offline tests for scripts/psa-release-issues.py (requires PyYAML and git).

Each test builds a small local git repository shaped like the
kubernetes/pod-security-admission mirror, with dated kubernetes-1.* tags as
the mocked releases, and a small chart. GitHub is faked by replacing
GitHub.request or the gh process, so no network is used. WorkflowTest checks
the workflow file's permissions, pins, and defaults, but doesn't run it: only
a real run on GitHub Actions verifies the workflow itself.
"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
# Keep the import from writing scripts/__pycache__.
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("psa_release_issues", ROOT / "scripts/psa-release-issues.py")
psa = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(psa)

LICENSE = '/*\nCopyright The Kubernetes Authors.\n\nLicensed under the Apache License (the "License");\n*/\n\n'
CHECK_SYSCTLS = LICENSE + (
    'package policy\n\n'
    'import (\n\t"strings"\n)\n\n'
    'func CheckSysctls() Check {\n\treturn Check{\n\t\tID: "sysctls",\n'
    '\t\tVersions: []VersionedCheck{\n'
    '\t\t\t{MinimumVersion: api.MajorMinorVersion(1, 0), CheckPod: sysctlsV1Dot0},\n'
    '@GATES@\t\t},\n\t}\n}\n\n'
    'var allowed = sets.NewString(\n\t"kernel.shm_rmid_forced",\n@VALUES@)\n'
)


def check_sysctls(gates="", values=""):
    # Go braces rule out str.format.
    return CHECK_SYSCTLS.replace("@GATES@", gates).replace("@VALUES@", values)


CHECK_CAPS = 'package policy\n\nfunc CheckCapabilitiesBaseline() Check { return Check{ID: "capabilities_baseline"} }\n'
FIXTURE = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {name}\nspec: {{}}\n"
K8S_SHA = "b" * 40

HELPERS = '''{{- define "kyverno-policies.labels" -}}
app: kyverno
{{- end -}}

{{- define "kyverno-policies.podSecurityBaseline" -}}
true
{{- end -}}

{{/* Safe sysctls. */}}
{{- define "kyverno-policies.allowedSysctls" -}}
{{- $s := list "kernel.shm_rmid_forced" -}}
{{- if semverCompare ">=1.32.0-0" .Capabilities.KubeVersion.Version -}}
{{- $s = concat $s (list "net.ipv4.tcp_rmem") -}}
{{- end -}}
{{- if semverCompare ">=1.37.0-0" .Capabilities.KubeVersion.Version -}}
{{- $s = concat $s (list "net.ipv4.tcp_notsent_lowat") -}}
{{- end -}}
{{- end -}}
'''
TEMPLATE = '''{{{{- $name := "{name}" }}}}
{{{{- if eq (include "kyverno-policies.podSecurityBaseline" .) "true" }}}}
metadata:
  labels: {{{{ include "kyverno-policies.labels" . }}}}
{extra}
{{{{- end }}}}
'''
CONFIG = {
    "checks": {"sysctls": "restrict-sysctls", "capabilities_baseline": "disallow-capabilities"},
}


class Upstream:
    """A local repository shaped like the PSA mirror, with dated, annotated release tags."""

    def __init__(self, path):
        self.path = path
        self.when = int((datetime.now(timezone.utc) - timedelta(days=60)).timestamp())
        path.mkdir(parents=True)
        self.run("init", "-q", "-b", "master")
        self.write({
            "policy/check_sysctls.go": check_sysctls(gates="", values=""),
            "policy/check_capabilities_baseline.go": CHECK_CAPS,
            "policy/helpers.go": "package policy\n",
            "policy/check_sysctls_test.go": "package policy\n",
            "api/helpers.go": "package api\n",
            "test/run.go": "package test\n",
            "test/fixtures_sysctls.go": "package test\n",
            "test/testdata/baseline/v1.36/pass/sysctls0.yaml": FIXTURE.format(name="sysctls0"),
            "test/testdata/baseline/v1.36/fail/capabilities_baseline0.yaml": FIXTURE.format(name="caps0"),
            "go.mod": "module k8s.io/pod-security-admission\n",
        })
        self.commit("Initial")

    def env(self):
        stamp = f"{self.when} +0000"
        return dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com", GIT_COMMITTER_NAME="t",
                    GIT_COMMITTER_EMAIL="t@example.com", GIT_AUTHOR_DATE=stamp, GIT_COMMITTER_DATE=stamp)

    def run(self, *args):
        result = subprocess.run(["git", "-C", str(self.path), *args], capture_output=True, text=True, env=self.env())
        if result.returncode != 0:
            raise AssertionError(f"git {args}: {result.stderr}")
        return result.stdout.strip()

    def write(self, files):
        for name, content in files.items():
            path = self.path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")

    def commit(self, message, files=None, body=f"Kubernetes-commit: {K8S_SHA}"):
        if files:
            self.write(files)
        self.when += 60
        self.run("add", "-A")
        self.run("commit", "-q", "--allow-empty", "-m", f"{message}\n\n{body}")
        return self.run("rev-parse", "HEAD")

    def release(self, version, days_ago=1, branch_from=None):
        """Tags a release the way the publishing bot does: on a side commit that bumps go.mod.

        With branch_from, the release goes on a release branch cut from that
        tag, like a patch release.
        """
        self.when = int((datetime.now(timezone.utc) - timedelta(days=days_ago)).timestamp())
        head = self.run("rev-parse", "HEAD")
        self.run("checkout", "-q", "--detach", branch_from or head)
        sha = self.commit(f"Update dependencies to v0.{version} tag", {"go.mod": f"module psa // {version}\n"}, body="")
        self.run("tag", "-a", "-m", version, f"kubernetes-1.{version}", sha)
        # master continues from where it was, without the go.mod bump.
        self.run("checkout", "-q", "master")
        return sha


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.upstream = Upstream(self.dir / "upstream")
        self.chart = self.make_chart(self.dir / "kyverno")

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def make_chart(root):
        templates = root / psa.TEMPLATES_DIR
        (templates / "baseline").mkdir(parents=True)
        (templates / "_helpers.tpl").write_text(HELPERS, encoding="utf-8")
        (templates / "baseline/restrict-sysctls.cel.yaml").write_text(TEMPLATE.format(
            name="restrict-sysctls", extra='  expr: {{ include "kyverno-policies.allowedSysctls" . }}'), encoding="utf-8")
        for name in ("disallow-capabilities", "disallow-host-path", "disallow-proc-mount"):
            (templates / f"baseline/{name}.cel.yaml").write_text(TEMPLATE.format(name=name, extra=""), encoding="utf-8")
        tests = root / psa.CLI_TESTS_DIR
        for name in ("restrict-sysctls", "disallow-proc-mount-strict"):
            (tests / f"pss-{name}").mkdir(parents=True)
            (tests / f"pss-{name}/kyverno-test.yaml").write_text(f"policies: [{name}]\n", encoding="utf-8")
        return psa.Chart(root)

    def releases(self):
        work = self.dir / f"clone{len(list(self.dir.iterdir()))}"
        return work, psa.fetch_releases("git", str(self.upstream.path), work)

    def analyze(self, tag, previous, checks=None):
        repo, releases = self.releases()
        by_tag = {r.tag: r for r in releases}
        return psa.analyze("git", repo, by_tag[tag], by_tag[previous], checks or CONFIG["checks"])


class ReleaseTest(unittest.TestCase):
    def rels(self, *versions):
        return [psa.Release(f"kubernetes-1.{v}") for v in versions]

    def prev(self, version, releases, include=True):
        found = psa.previous_release(psa.Release(f"kubernetes-1.{version}"), releases, include)
        return found.version if found else None

    def test_parses_and_orders_tags(self):
        text = "\n".join(f"kubernetes-1.{v}\x1f2026-01-01T00:00:00+00:00" for v in
                         ["37.0", "37.0-rc.0", "37.0-alpha.1", "36.9", "37.0-beta.0", "37.1"]) + "\nv0.37.1\x1f\n"
        self.assertEqual([r.version for r in psa.parse_releases(text)],
                         ["v1.36.9", "v1.37.0-alpha.1", "v1.37.0-beta.0", "v1.37.0-rc.0", "v1.37.0", "v1.37.1"])
        self.assertEqual(psa.Release("kubernetes-1.37.1").psa_tag, "v0.37.1")

    def test_previous_release(self):
        all_ = self.rels("36.0", "36.1", "37.0-alpha.0", "37.0-alpha.1", "37.0-rc.0", "37.0", "37.1", "37.2")
        self.assertEqual(self.prev("37.2", all_), "v1.37.1")
        self.assertEqual(self.prev("37.1", all_), "v1.37.0")
        self.assertEqual(self.prev("37.0-rc.0", all_), "v1.37.0-alpha.1")
        self.assertEqual(self.prev("37.0-alpha.0", all_), "v1.36.0")
        # A new minor follows its last pre-release, or the previous minor without them.
        self.assertEqual(self.prev("37.0", all_), "v1.37.0-rc.0")
        self.assertEqual(self.prev("37.0", all_, include=False), "v1.36.0")
        self.assertIsNone(self.prev("40.0", all_))


class SignalsTest(unittest.TestCase):
    def test_ignores_comments_imports_and_check_ids(self):
        diff = "\n".join([
            "diff --git a/policy/check_x.go b/policy/check_x.go",
            "+/*",
            '+Licensed under the Apache License (the "License");',
            '+pods with "hostUsers: false" are allowed',
            "+*/",
            '+import "slices"',
            '+\tcorev1 "k8s.io/api/core/v1"',
            '+\tID: "procMount_restricted",',
            '+\t"net.ipv4.tcp_notsent_lowat", // safe',
            '-\t"net.ipv4.old",',
            '+\t{MinimumVersion: api.MajorMinorVersion(1, 37)},',
        ])
        signals = psa.diff_signals(diff, [], {"procMount_restricted"})
        self.assertEqual(signals["added_values"], ["net.ipv4.tcp_notsent_lowat"])
        self.assertEqual(signals["removed_values"], ["net.ipv4.old"])
        self.assertEqual(signals["gates"], ["1.37"])


class ChartTest(Base):
    def test_lookup(self):
        files = self.chart.lookup("restrict-sysctls")
        self.assertEqual(files["template"], f"{psa.TEMPLATES_DIR}/baseline/restrict-sysctls.cel.yaml")
        self.assertEqual(files["level"], "baseline")
        # labels is plumbing, podSecurity* selects a profile; nested {{ end }} doesn't cut the helper short.
        self.assertEqual(files["helpers"], ["allowedSysctls"])
        self.assertEqual(files["gates"], ["1.32", "1.37"])
        self.assertEqual(files["tests"], [f"{psa.CLI_TESTS_DIR}/pss-restrict-sysctls"])
        self.assertIn("net.ipv4.tcp_notsent_lowat", files["sources"])

    def test_test_lookup_matches_whole_names(self):
        self.assertEqual(self.chart.lookup("disallow-proc-mount")["tests"], [])
        self.assertIsNone(self.chart.lookup("no-such-policy"))


class AnalyzeTest(Base):
    def test_dependency_only_release_needs_no_action(self):
        self.upstream.release("37.0", days_ago=3)
        self.upstream.release("37.1", days_ago=2)
        analysis = self.analyze("kubernetes-1.37.1", "kubernetes-1.37.0")
        self.assertFalse(analysis.relevant)
        self.assertIn("no change", psa.no_action_reason(analysis))

    def test_test_code_only_asks_for_confirmation_without_the_manual_label(self):
        self.upstream.release("37.0", days_ago=3)
        self.upstream.commit("Refactor tests", {"test/run.go": "package test // v2\n",
                                                "test/fixtures_test.go": "package test // v2\n",
                                                "policy/check_sysctls_test.go": "package policy // v2\n"})
        self.upstream.release("37.1", days_ago=2)
        analysis = self.analyze("kubernetes-1.37.1", "kubernetes-1.37.0")
        # Never "no action needed": a person confirms test-only changes.
        self.assertTrue(analysis.relevant)
        # fixtures_test.go tests the generator, so it isn't a check called "test".
        self.assertEqual(sorted(c["path"] for c in analysis.groups["test-framework"]),
                         ["test/fixtures_test.go", "test/run.go"])
        mapped, uncertain, confirm = psa.map_changes(analysis, CONFIG, self.chart)
        self.assertEqual(sorted(e["group"] for e in mapped), ["sysctls", "test-framework"])
        self.assertTrue(all(e["test_only"] for e in mapped))
        self.assertEqual(uncertain, [])
        self.assertEqual(len(confirm), 1)
        self.assertEqual(psa.issue_kind(mapped, uncertain), "confirm")
        title, body = psa.render_issue(analysis, mapped, uncertain, confirm, "https://example.com/psa")
        self.assertEqual(title, "Pod Security Admission v1.37.1: confirm the PSS CEL policies need no change")
        self.assertNotIn("Manual review needed", body)
        self.assertIn("- [ ] Confirm that the test-only changes for 2 group(s) need no CEL change.", body)
        self.assertNotIn("| Upstream check |", body)
        self.assertNotIn("Add each new check", body)

    def test_generator_noise_collapses_and_real_changes_come_first(self):
        # Like upstream 1.35: every fixture generator changed, but only one check's code did.
        self.upstream.release("37.0-alpha.0", days_ago=3)
        self.upstream.commit("Regenerate and change sysctls", {
            "test/fixtures_sysctls.go": "package test // v2\n",
            "test/fixtures_capabilities_baseline.go": "package test // v2\n",
            "test/fixtures_privileged.go": "package test // v2\n",
            "test/testdata/baseline/v1.36/fail/capabilities_baseline0.yaml": FIXTURE.format(name="caps0-v2"),
            "policy/check_sysctls.go": check_sysctls(
                gates="\t\t\t{MinimumVersion: api.MajorMinorVersion(1, 37), CheckPod: sysctlsV1Dot37},\n", values=""),
        })
        self.upstream.release("37.0-alpha.1", days_ago=2)
        analysis = self.analyze("kubernetes-1.37.0-alpha.1", "kubernetes-1.37.0-alpha.0")
        mapped, uncertain, confirm = psa.map_changes(analysis, CONFIG, self.chart)
        self.assertEqual(uncertain, [])
        _, body = psa.render_issue(analysis, mapped, uncertain, confirm, "https://example.com/psa")
        rows = [line for line in body.splitlines() if line.startswith("| `")]
        # The code change first, then the fixture-only change. No row for test code.
        self.assertEqual([row.split(" | ")[0] for row in rows], ["| `sysctls`", "| `capabilities_baseline`"])
        self.assertIn("fixtures only", rows[1])
        self.assertIn("Test code only, with no fixture change, for 1 group(s): `privileged`.", body)

    def test_copied_fixture_version_needs_no_action(self):
        self.upstream.release("37.0", days_ago=3)
        self.upstream.commit("Regenerate fixtures for v1.37", {
            "test/testdata/baseline/v1.37/pass/sysctls0.yaml": FIXTURE.format(name="sysctls0"),
            "test/testdata/baseline/v1.37/fail/capabilities_baseline0.yaml": FIXTURE.format(name="caps0"),
        })
        self.upstream.release("38.0-alpha.1", days_ago=2)
        analysis = self.analyze("kubernetes-1.38.0-alpha.1", "kubernetes-1.37.0")
        self.assertFalse(analysis.relevant)
        self.assertEqual(analysis.copied, 2)
        self.assertEqual(analysis.new_versions, ["baseline/v1.37"])

    def test_check_change_with_new_fixtures_is_relevant(self):
        self.upstream.release("37.0-alpha.0", days_ago=3)
        self.upstream.commit("Add safe sysctls @someone fixes #12", {
            "policy/check_sysctls.go": check_sysctls(
                gates="\t\t\t{MinimumVersion: api.MajorMinorVersion(1, 37), CheckPod: sysctlsV1Dot37},\n",
                values='\t"net.ipv4.tcp_notsent_lowat",\n\t"net.ipv4.tcp_slow_start_after_idle",\n'),
            "test/testdata/baseline/v1.37/pass/sysctls0.yaml": FIXTURE.format(name="sysctls0"),
            "test/testdata/baseline/v1.37/pass/sysctls1.yaml": FIXTURE.format(name="sysctls1"),
            "test/testdata/baseline/v1.37/fail/capabilities_baseline0.yaml": FIXTURE.format(name="caps0"),
        })
        self.upstream.release("37.0-alpha.1", days_ago=2)
        analysis = self.analyze("kubernetes-1.37.0-alpha.1", "kubernetes-1.37.0-alpha.0")
        self.assertTrue(analysis.relevant)
        self.assertEqual(sorted(analysis.groups), ["sysctls"])
        kinds = sorted(c["kind"] for c in analysis.groups["sysctls"])
        self.assertEqual(kinds, ["check", "fixture"])
        self.assertEqual(analysis.copied, 2)
        self.assertEqual(analysis.signals["sysctls"]["gates"], ["1.37"])
        self.assertEqual(analysis.signals["sysctls"]["added_values"],
                         ["net.ipv4.tcp_notsent_lowat", "net.ipv4.tcp_slow_start_after_idle"])
        self.assertEqual(analysis.commits[0][2], K8S_SHA)
        self.assertEqual((analysis.unmapped_checks, analysis.stale_checks), ([], []))

        mapped, uncertain, confirm = psa.map_changes(analysis, CONFIG, self.chart)
        entry = mapped[0]
        self.assertEqual(entry["policy"], "restrict-sysctls")
        # tcp_notsent_lowat and the 1.37 gate are already in the helper.
        self.assertEqual(entry["missing_values"], ["net.ipv4.tcp_slow_start_after_idle"])
        self.assertEqual(entry["missing_gates"], [])
        self.assertFalse(entry["handled"])
        self.assertEqual((uncertain, confirm), ([], []))

        title, body = psa.render_issue(analysis, mapped, uncertain, confirm,
                                       "https://github.com/kubernetes/pod-security-admission")
        self.assertEqual(title, "Pod Security Admission v1.37.0-alpha.1: update the PSS CEL policies")
        for text in [
            "| `sysctls` | `restrict-sysctls` | baseline |",
            "version gate `>=1.37`",
            "- `restrict-sysctls`: template `charts/kyverno-policies/templates/baseline/restrict-sysctls.cel.yaml`; "
            "helpers `allowedSysctls`; gates `>=1.32`, `>=1.37`; CLI tests `test/cli/test-validating-policy/pss-restrict-sysctls`",
            "- [ ] Update `charts/kyverno-policies/templates/baseline/restrict-sysctls.cel.yaml` to match",
            "  - [ ] Handle `net.ipv4.tcp_slow_start_after_idle`",
            "- [ ] Each behavior change has a CLI test that passes with `make test-cli`.",
            "- [ ] `make verify-policies-sysctls` passes.",
            "https://github.com/kubernetes/kubernetes/tree/v1.37.0-alpha.1/staging/src/k8s.io/pod-security-admission",
            f"https://github.com/kubernetes/kubernetes/commit/{K8S_SHA}",
            # Upstream text can't ping people or link Kyverno issues.
            "`Add safe sysctls @someone fixes #12`",
            "## Acceptance criteria",
        ]:
            self.assertIn(text, body)
        self.assertNotIn("Manual review needed", body)
        self.assertTrue(body.endswith(psa.marker(analysis.release)))

    def test_handled_change_asks_for_confirmation_without_the_manual_label(self):
        self.upstream.release("37.0-alpha.0", days_ago=3)
        self.upstream.commit("Add a safe sysctl", {"policy/check_sysctls.go": check_sysctls(
            gates="\t\t\t{MinimumVersion: api.MajorMinorVersion(1, 37), CheckPod: sysctlsV1Dot37},\n",
            values='\t"net.ipv4.tcp_notsent_lowat",\n')})
        self.upstream.release("37.0-alpha.1", days_ago=2)
        analysis = self.analyze("kubernetes-1.37.0-alpha.1", "kubernetes-1.37.0-alpha.0")
        mapped, uncertain, confirm = psa.map_changes(analysis, CONFIG, self.chart)
        self.assertTrue(mapped[0]["handled"])
        self.assertEqual(uncertain, [])
        self.assertIn("may already handle this change", confirm[0])
        title, body = psa.render_issue(analysis, mapped, uncertain, confirm, "https://example.com/psa")
        self.assertIn("confirm the PSS CEL policies need no change", title)
        self.assertIn("- [ ] Confirm that `charts/kyverno-policies/templates/baseline/restrict-sysctls.cel.yaml` "
                      "already matches", body)
        # A handled change with a CLI test asks to confirm the test, not to write one.
        self.assertIn("  - [ ] Confirm that a CLI test under `test/cli/test-validating-policy/pss-restrict-sysctls` "
                      "covers the change.", body)
        self.assertNotIn("Add or update a CLI test", body)

        # A value that upstream removed but the template still has means it isn't handled.
        self.upstream.commit("Drop a sysctl", {"policy/check_sysctls.go": check_sysctls(
            gates="\t\t\t{MinimumVersion: api.MajorMinorVersion(1, 37), CheckPod: sysctlsV1Dot37},\n",
            values='\t"net.ipv4.tcp_notsent_lowat",\n').replace('\t"kernel.shm_rmid_forced",\n', "")})
        self.upstream.release("37.0-alpha.2", days_ago=1)
        analysis = self.analyze("kubernetes-1.37.0-alpha.2", "kubernetes-1.37.0-alpha.0")
        mapped, uncertain, confirm = psa.map_changes(analysis, CONFIG, self.chart)
        self.assertEqual(analysis.signals["sysctls"]["removed_values"], ["kernel.shm_rmid_forced"])
        self.assertFalse(mapped[0]["handled"])
        self.assertEqual(psa.issue_kind(mapped, uncertain), "update")
        _, body = psa.render_issue(analysis, mapped, uncertain, confirm, "https://example.com/psa")
        self.assertIn("  - Already in the template or its helpers: `net.ipv4.tcp_notsent_lowat`, `>=1.37`.", body)
        self.assertIn("  - [ ] Check whether the removed values must stay allowed", body)

    def test_check_change_without_signals_says_to_read_the_comparison(self):
        self.upstream.release("37.0-alpha.0", days_ago=3)
        self.upstream.commit("Refactor sysctls", {"policy/check_sysctls.go": check_sysctls() + "\nfunc helper() {}\n"})
        self.upstream.release("37.0-alpha.1", days_ago=2)
        analysis = self.analyze("kubernetes-1.37.0-alpha.1", "kubernetes-1.37.0-alpha.0")
        mapped, uncertain, confirm = psa.map_changes(analysis, CONFIG, self.chart)
        self.assertTrue(mapped[0]["no_signals"])
        self.assertIn("shows no version gate or value change", confirm[0])
        # A mapped code change still needs an update, so it isn't confirm-only.
        self.assertEqual(psa.issue_kind(mapped, uncertain), "update")
        _, body = psa.render_issue(analysis, mapped, uncertain, confirm, "https://example.com/psa")
        self.assertIn("no gate or value change found: read the comparison", body)

    def test_new_gate_asks_for_a_semver_gate(self):
        self.upstream.release("39.0-alpha.0", days_ago=3)
        self.upstream.commit("Gate sysctls", {"policy/check_sysctls.go": check_sysctls(
            gates="\t\t\t{MinimumVersion: api.MajorMinorVersion(1, 39), CheckPod: sysctlsV1Dot39},\n", values="")})
        self.upstream.release("39.0-alpha.1", days_ago=2)
        analysis = self.analyze("kubernetes-1.39.0-alpha.1", "kubernetes-1.39.0-alpha.0")
        mapped, uncertain, confirm = psa.map_changes(analysis, CONFIG, self.chart)
        self.assertEqual(mapped[0]["missing_gates"], ["1.39"])
        _, body = psa.render_issue(analysis, mapped, uncertain, confirm, "https://example.com/psa")
        self.assertIn('  - [ ] Add a `semverCompare ">=1.39.0-0"` gate', body)
        # Only sysctls has a dedicated make target.
        self.assertIn("`make verify-policies-sysctls` passes", body)

    def test_shared_api_and_new_checks_need_manual_review(self):
        self.upstream.release("37.0-alpha.0", days_ago=3)
        self.upstream.commit("Change shared code", {
            "policy/helpers.go": "package policy // changed\n",
            "api/helpers.go": "package api // changed\n",
            "policy/check_newThing.go": 'package policy\n\nfunc CheckNewThing() Check { return Check{ID: "newThing"} }\n',
        })
        self.upstream.release("37.0-alpha.1", days_ago=2)
        analysis = self.analyze("kubernetes-1.37.0-alpha.1", "kubernetes-1.37.0-alpha.0")
        self.assertEqual(sorted(analysis.groups), ["api", "newThing", "shared"])
        self.assertEqual(analysis.unmapped_checks, ["newThing"])
        mapped, uncertain, confirm = psa.map_changes(analysis, CONFIG, self.chart)
        # One note per cause: shared, api, and the new check (reported once).
        self.assertEqual(len(uncertain), 3)
        self.assertEqual(sum("newThing" in note for note in uncertain), 1)
        title, body = psa.render_issue(analysis, mapped, uncertain, confirm, "https://example.com/psa")
        self.assertIn("(manual review)", title)
        self.assertIn("| `newThing` | none (uncertain) |", body)
        self.assertIn("| shared | all (uncertain) |", body)
        self.assertIn("- [ ] Add each new check to `checks` in `scripts/psa-release-issues.yaml`.", body)

    def test_stale_mapping_and_renamed_check_need_manual_review(self):
        self.upstream.release("37.0-alpha.0", days_ago=3)
        self.upstream.run("mv", "policy/check_sysctls.go", "policy/check_sysctls_baseline.go")
        self.upstream.commit("Split sysctls")
        self.upstream.release("37.0-alpha.1", days_ago=2)
        config = dict(CONFIG, checks=dict(CONFIG["checks"], oldCheck="disallow-host-path"))
        analysis = self.analyze("kubernetes-1.37.0-alpha.1", "kubernetes-1.37.0-alpha.0", config["checks"])
        self.assertEqual(analysis.stale_checks, ["oldCheck"])
        mapped, uncertain, _ = psa.map_changes(analysis, config, self.chart)
        self.assertTrue(any("`oldCheck`, which upstream no longer declares" in note for note in uncertain))
        self.assertTrue(any("renamed or split" in note for note in uncertain))
        _, body = psa.render_issue(analysis, mapped, uncertain, [], "https://example.com/psa")
        self.assertIn("- [ ] Remove or rename the stale entries in `checks`", body)

    def test_mapped_policy_without_template_needs_manual_review(self):
        self.upstream.release("37.0-alpha.0", days_ago=3)
        self.upstream.commit("Change caps", {"policy/check_capabilities_baseline.go": CHECK_CAPS + "// v2\n"})
        self.upstream.release("37.0-alpha.1", days_ago=2)
        analysis = self.analyze("kubernetes-1.37.0-alpha.1", "kubernetes-1.37.0-alpha.0")
        mapping = dict(CONFIG, checks=dict(CONFIG["checks"], capabilities_baseline="gone-policy"))
        _, uncertain, _ = psa.map_changes(analysis, mapping, self.chart)
        self.assertIn("no `gone-policy.cel.yaml` template exists", uncertain[0])

    def test_upstream_code_stays_out_of_the_issue_and_files_link_to_the_comparison(self):
        self.upstream.release("37.0-alpha.0", days_ago=3)
        self.upstream.commit("Doc", {"policy/check_sysctls.go": check_sysctls() + "\n// ```\n// @someone\n"})
        self.upstream.release("37.0-alpha.1", days_ago=2)
        analysis = self.analyze("kubernetes-1.37.0-alpha.1", "kubernetes-1.37.0-alpha.0")
        mapped, uncertain, confirm = psa.map_changes(analysis, CONFIG, self.chart)
        _, body = psa.render_issue(analysis, mapped, uncertain, confirm, "https://example.com/psa")
        # No diff in the body, so upstream code can't break the Markdown or ping anyone.
        self.assertNotIn("@someone", body)
        self.assertNotIn("```", body)
        compare = "https://example.com/psa/compare/kubernetes-1.37.0-alpha.0...kubernetes-1.37.0-alpha.1"
        anchor = hashlib.sha256(b"policy/check_sysctls.go").hexdigest()
        self.assertIn(f"[`policy/check_sysctls.go`]({compare}#diff-{anchor}) (M)", body)
        self.assertIn(f"See the [full comparison]({compare}).", body)


class FakeGitHub(psa.GitHub):
    """Fakes the GitHub API behind GitHub.request, after the real allowlist check.

    fail maps a (method, path fragment) pair to an error message. on_create
    runs before each issue is stored, to simulate a concurrent run.
    """

    def __init__(self, bodies=(), fail=None, on_create=None):
        super().__init__("owner/kyverno")
        self.store = [{"number": i + 1, "body": b, "state": "closed"} for i, b in enumerate(bodies)]
        self.labels, self.comments, self.calls = set(), [], []
        self.fail = fail or {}
        self.on_create = on_create

    def add(self, body, **fields):
        issue = {"number": len(self.store) + 1, "body": body, "state": "open", **fields}
        self.store.append(issue)
        return issue

    def request(self, method, path, body=None, paginate=False):
        self.check_allowed(method, path, body)
        self.calls.append((method, path, body))
        for (fail_method, fragment), message in self.fail.items():
            if method == fail_method and fragment in path:
                raise psa.ReleaseError(message)
        if method == "GET" and "/issues?" in path:
            return [dict(i) for i in self.store]
        if method == "GET" and "/labels/" in path:
            return {} if path.rsplit("/", 1)[1] in self.labels else None
        if method == "POST" and path.endswith("/labels"):
            self.labels.add(body["name"].replace("/", "%2F"))
            return {}
        if method == "POST" and path.endswith("/comments"):
            self.comments.append((int(path.split("/")[-2]), body["body"]))
            return {}
        if method == "POST" and path.endswith("/issues"):
            if self.on_create:
                self.on_create(self, body)
            issue = self.add(body["body"], title=body["title"], labels=body["labels"])
            return {"number": issue["number"], "html_url": f"https://github.com/owner/kyverno/issues/{issue['number']}"}
        if method == "PATCH":
            issue = self.store[int(path.rsplit("/", 1)[1]) - 1]
            issue.update(body)
            return {}
        raise AssertionError(f"unexpected {method} {path}")

    def created(self):
        return [i for i in self.store if "title" in i]


class RunTest(Base):
    """Runs the whole check against the local mirror and a fake GitHub."""

    ALPHA1_TITLE = "Pod Security Admission v1.37.0-alpha.1: update the PSS CEL policies"

    def setUp(self):
        super().setUp()
        self.upstream.release("36.0", days_ago=40)
        # The baseline. Everything after it is checked, however old.
        self.upstream.release("37.0-alpha.0", days_ago=30)
        self.upstream.commit("Add a safe sysctl", {"policy/check_sysctls.go": check_sysctls(
            gates="", values='\t"net.ipv4.tcp_slow_start_after_idle",\n')})
        self.upstream.release("37.0-alpha.1", days_ago=20)
        self.upstream.release("36.1", days_ago=10, branch_from="kubernetes-1.36.0")

    def run_tool(self, github, **overrides):
        args = argparse.Namespace(repository=str(self.upstream.path), since="kubernetes-1.37.0-alpha.0",
                                  include_prereleases=True, tag=None, dry_run=False, out=str(self.dir / "out"))
        vars(args).update(overrides)
        Path(args.out).mkdir(exist_ok=True)
        with redirect_stderr(io.StringIO()):
            return psa.run(args, github, self.chart, CONFIG)

    def test_checks_every_release_after_the_baseline(self):
        github = FakeGitHub()
        summary, failures = self.run_tool(github)
        self.assertEqual(failures, [])
        # alpha.1 is 20 days old: no time window can miss it.
        self.assertEqual([i["title"] for i in github.created()], [self.ALPHA1_TITLE])
        self.assertEqual(github.created()[0]["labels"], ["psa-cel-update", "area/pss"])
        self.assertEqual(github.labels, {"psa-cel-update", "area%2Fpss"})
        self.assertEqual(summary, [
            "- `v1.36.1` (since `v1.36.0`): no action needed: no change in `policy/`, `api/`, or `test/`",
            "- `v1.37.0-alpha.1` (since `v1.37.0-alpha.0`): opened [#1](https://github.com/owner/kyverno/issues/1)",
        ])

    def test_release_selection(self):
        github = FakeGitHub()
        # A later baseline, or skipping pre-releases, leaves only v1.36.1, which needs no action.
        for overrides in ({"since": "kubernetes-1.37.0-alpha.1"}, {"include_prereleases": False}):
            summary, _ = self.run_tool(github, **overrides)
            self.assertEqual((github.created(), len(summary)), ([], 1), overrides)
        # --tag checks one release, whatever the baseline.
        self.run_tool(github, tag="kubernetes-1.37.0-alpha.1", since="kubernetes-1.37.0-alpha.1")
        self.assertEqual(len(github.created()), 1)
        with self.assertRaisesRegex(psa.ReleaseError, "baseline tag kubernetes-1.99.0 isn't in"):
            self.run_tool(github, since="kubernetes-1.99.0")
        with self.assertRaisesRegex(psa.ReleaseError, "tag kubernetes-1.99.0 isn't in"):
            self.run_tool(github, tag="kubernetes-1.99.0")

    def test_an_open_or_closed_issue_or_a_rerun_never_duplicates(self):
        marker = psa.marker(psa.Release("kubernetes-1.37.0-alpha.1"))
        github = FakeGitHub(bodies=[f"Closed earlier.\n{marker}"])
        summary, _ = self.run_tool(github)
        self.assertEqual(github.created(), [])
        self.assertIn("- `v1.37.0-alpha.1`: issue already exists (#1)", summary)
        github = FakeGitHub()
        for _ in range(3):
            self.run_tool(github)
        self.assertEqual(len(github.created()), 1)

    def test_a_concurrent_issue_before_create_is_reused(self):
        github = FakeGitHub()
        real_issues = github.issues
        calls = []

        def issues():
            calls.append(1)
            # Another run opens the issue after this run's first listing.
            if len(calls) == 2:
                github.add(f"Opened elsewhere.\n{psa.marker(psa.Release('kubernetes-1.37.0-alpha.1'))}")
            return real_issues()

        github.issues = issues
        summary, failures = self.run_tool(github)
        self.assertEqual(failures, [])
        self.assertEqual(github.created(), [])
        self.assertIn("- `v1.37.0-alpha.1` (since `v1.37.0-alpha.0`): issue #1 (opened by another run meanwhile)",
                      summary)

    def test_a_concurrent_create_closes_the_later_issue(self):
        def race(fake, body):
            # A concurrent run creates the same issue at the same moment, and wins.
            fake.add(body["body"], title=body["title"])

        github = FakeGitHub(on_create=race)
        summary, failures = self.run_tool(github)
        self.assertEqual(failures, [])
        first, second = github.store
        self.assertEqual(first["state"], "open")
        self.assertEqual((second["state"], second["state_reason"]), ("closed", "duplicate"))
        self.assertEqual(github.comments, [(2, "Duplicate of #1, which another run of this workflow opened first.")])
        self.assertTrue(any("closed the duplicate #2 that a concurrent run caused" in line for line in summary))

    def test_dry_run_writes_the_issue_and_changes_nothing(self):
        github = FakeGitHub()
        summary, _ = self.run_tool(github, dry_run=True)
        self.assertEqual([m for m, _, _ in github.calls], ["GET"])
        body = (self.dir / "out/kubernetes-1.37.0-alpha.1.md").read_text(encoding="utf-8")
        self.assertIn("net.ipv4.tcp_slow_start_after_idle", body)
        self.assertIn("- `v1.37.0-alpha.1` (since `v1.37.0-alpha.0`): would open an issue (dry run, see "
                      "kubernetes-1.37.0-alpha.1.md)", summary)

    def test_a_release_without_a_previous_one_fails_loudly(self):
        self.upstream.release("40.0-alpha.0", days_ago=1)
        github = FakeGitHub()
        summary, failures = self.run_tool(github)
        self.assertEqual(failures, ["kubernetes-1.40.0-alpha.0"])
        self.assertIn("- `v1.40.0-alpha.0`: **error**: no previous release to compare with; check this release by hand",
                      summary)

    def test_labels_follow_the_issue_kind(self):
        # Test-only: an issue to confirm, without the manual-review label.
        self.upstream.commit("Refactor tests", {"policy/check_sysctls_test.go": "package policy // v2\n"})
        self.upstream.release("37.0-alpha.2", days_ago=5)
        # Shared code: manual review.
        self.upstream.commit("Change shared code", {"policy/helpers.go": "package policy // changed\n"})
        self.upstream.release("37.0-alpha.3", days_ago=4)
        github = FakeGitHub()
        summary, failures = self.run_tool(github)
        self.assertEqual(failures, [])
        by_tag = {i["title"].split()[3].rstrip(":"): i for i in github.created()}
        self.assertEqual(by_tag["v1.37.0-alpha.1"]["labels"], ["psa-cel-update", "area/pss"])
        self.assertEqual(by_tag["v1.37.0-alpha.2"]["labels"], ["psa-cel-update", "area/pss"])
        self.assertIn("confirm the PSS CEL policies need no change", by_tag["v1.37.0-alpha.2"]["title"])
        self.assertEqual(by_tag["v1.37.0-alpha.3"]["labels"], ["psa-cel-update", "area/pss", "needs-manual-review"])
        self.assertIn("needs-manual-review", github.labels)
        self.assertTrue(any("alpha.2" in line and "(confirm only)" in line for line in summary))
        self.assertTrue(any("alpha.3" in line and "(manual review)" in line for line in summary))

    def test_failed_create_is_reported_and_the_rest_continue(self):
        self.upstream.commit("Another sysctl", {"policy/check_sysctls.go": check_sysctls(
            gates="", values='\t"net.ipv4.tcp_slow_start_after_idle",\n\t"net.ipv4.other",\n')})
        self.upstream.release("37.0-alpha.2", days_ago=5)
        calls = []

        def fail_first(fake, body):
            calls.append(body["title"])
            if len(calls) == 1:
                raise psa.ReleaseError("gh api POST repos/owner/kyverno/issues failed: HTTP 502")

        github = FakeGitHub(on_create=fail_first)
        summary, failures = self.run_tool(github)
        self.assertEqual(failures, ["kubernetes-1.37.0-alpha.1"])
        self.assertEqual([i["title"] for i in github.created()],
                         ["Pod Security Admission v1.37.0-alpha.2: update the PSS CEL policies"])
        self.assertTrue(any("**error**: gh api POST" in line and "HTTP 502" in line for line in summary))
        # The next run retries the failed release.
        github.on_create = None
        _, failures = self.run_tool(github)
        self.assertEqual(failures, [])
        self.assertEqual(len(github.created()), 2)

    def test_failed_label_creation_fails_the_release(self):
        github = FakeGitHub(fail={("POST", "/labels"): "HTTP 403: Resource not accessible by integration"})
        summary, failures = self.run_tool(github)
        self.assertEqual(failures, ["kubernetes-1.37.0-alpha.1"])
        self.assertEqual(github.created(), [])
        self.assertTrue(any("HTTP 403" in line for line in summary))

    def test_failed_issue_listing_stops_the_run(self):
        github = FakeGitHub(fail={("GET", "/issues?"): "HTTP 500"})
        with self.assertRaisesRegex(psa.ReleaseError, "HTTP 500"):
            self.run_tool(github)
        self.assertEqual(github.created(), [])

    def test_caps_issues_per_run(self):
        for n in range(2, 2 + psa.MAX_ISSUES_PER_RUN):
            self.upstream.commit(f"Sysctl {n}", {"policy/check_sysctls.go": check_sysctls(
                gates="", values=f'\t"net.ipv4.value{n}",\n')})
            self.upstream.release(f"37.0-alpha.{n}", days_ago=5)
        github = FakeGitHub()
        summary, _ = self.run_tool(github)
        self.assertEqual(len(github.created()), psa.MAX_ISSUES_PER_RUN)
        self.assertTrue(any("waits for the next run" in line for line in summary))
        # The next run picks up the rest.
        self.run_tool(github)
        self.assertEqual(len(github.created()), psa.MAX_ISSUES_PER_RUN + 1)


class GitHubTest(unittest.TestCase):
    def test_allows_only_issue_reads_creates_and_duplicate_closing(self):
        github = psa.GitHub("owner/kyverno")
        for method, path, body in [
            ("DELETE", "repos/owner/kyverno/issues/1", None),
            ("PATCH", "repos/owner/kyverno/issues/1", {"title": "changed"}),
            ("PATCH", "repos/owner/kyverno/issues/1", {"state": "open"}),
            ("POST", "repos/owner/kyverno/issues/1", {}),
            ("POST", "repos/owner/kyverno/pulls", {}),
            ("GET", "repos/other/repo/issues", None),
        ]:
            with self.assertRaises(psa.ReleaseError, msg=f"{method} {path} {body}"):
                github.check_allowed(method, path, body)
        github.check_allowed("PATCH", "repos/owner/kyverno/issues/1", {"state": "closed", "state_reason": "duplicate"})
        github.check_allowed("POST", "repos/owner/kyverno/issues/1/comments", {"body": "x"})
        github.check_allowed("GET", "repos/owner/kyverno/issues?labels=psa-cel-update&state=all", None)
        with self.assertRaises(psa.ReleaseError):
            psa.GitHub("not a repo")


class GhCommandTest(unittest.TestCase):
    """Runs the real GitHub.request with a faked `gh` process."""

    def run_gh(self, returncode=0, stdout="", stderr="", **kwargs):
        calls = []

        def fake(args):
            calls.append(args)
            return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

        with mock.patch.object(psa, "run_command", fake):
            result = psa.GitHub("owner/kyverno").request(**kwargs)
        return result, calls[0]

    def test_pagination_parses_one_issue_per_line_across_pages(self):
        # `gh api --paginate --jq '.[] | @json'` prints one JSON object per line, for every page.
        pages = "\n".join(json.dumps({"number": n, "body": f"body {n}\nsecond line"}) for n in range(1, 151))
        issues, command = self.run_gh(stdout=pages + "\n", method="GET", paginate=True,
                                      path="repos/owner/kyverno/issues?labels=psa-cel-update&state=all&per_page=100")
        self.assertEqual(len(issues), 150)
        self.assertEqual(issues[149]["body"], "body 150\nsecond line")
        self.assertEqual(command[:4], ["gh", "api", "-X", "GET"])
        self.assertIn("--paginate", command)
        self.assertEqual(command[command.index("--jq") + 1], ".[] | @json")

    def test_issues_skips_pull_requests(self):
        lines = [json.dumps({"number": 1, "body": "a"}), json.dumps({"number": 2, "body": "b", "pull_request": {}})]
        with mock.patch.object(psa, "run_command", lambda args: SimpleNamespace(
                returncode=0, stdout="\n".join(lines), stderr="")):
            self.assertEqual(psa.GitHub("owner/kyverno").issues(), [{"number": 1, "body": "a"}])

    def test_a_missing_label_is_none_and_other_errors_raise(self):
        result, _ = self.run_gh(returncode=1, stderr="gh: Not Found (HTTP 404)", method="GET",
                                path="repos/owner/kyverno/labels/psa-cel-update")
        self.assertIsNone(result)
        with self.assertRaisesRegex(psa.ReleaseError, "HTTP 502"):
            self.run_gh(returncode=1, stderr="gh: Bad Gateway (HTTP 502)", method="GET",
                        path="repos/owner/kyverno/labels/psa-cel-update")
        # A 404 on a write is an error, not "missing".
        with self.assertRaisesRegex(psa.ReleaseError, "HTTP 404"):
            self.run_gh(returncode=1, stderr="gh: Not Found (HTTP 404)", method="POST",
                        path="repos/owner/kyverno/issues", body={"title": "t"})

    def test_output_is_decoded_as_utf8_whatever_the_locale(self):
        # A real run against kyverno/kyverno issues failed on a Windows cp1252 locale before this.
        script = "import sys; sys.stdout.buffer.write('caf\\u00e9 \\u201cquoted\\u201d \\u2014 \\U0001f680'.encode())"
        result = psa.run_command([sys.executable, "-c", script])
        self.assertEqual(result.stdout, "café “quoted” — \U0001f680")

    def test_a_body_goes_through_a_file_not_the_command_line(self):
        _, command = self.run_gh(stdout="{}", method="POST", path="repos/owner/kyverno/issues",
                                 body={"title": "t", "body": "$(rm -rf /)"})
        self.assertIn("--input", command)
        self.assertNotIn("$(rm -rf /)", " ".join(command))


class WorkflowTest(unittest.TestCase):
    """Checks the workflow file for the security and safety rules it relies on."""

    @classmethod
    def setUpClass(cls):
        cls.path = ROOT / ".github/workflows/psa-release-issues.yaml"
        cls.workflow = yaml.safe_load(cls.path.read_text(encoding="utf-8"))
        # PyYAML reads the `on` key as True.
        cls.on = cls.workflow.get("on", cls.workflow.get(True))
        cls.jobs = cls.workflow["jobs"]

    def steps(self):
        return [step for job in self.jobs.values() for step in job.get("steps", [])]

    def test_least_privilege_permissions(self):
        self.assertEqual(self.workflow["permissions"], {})
        self.assertEqual(self.jobs["test"]["permissions"], {"contents": "read"})
        self.assertEqual(self.jobs["check"]["permissions"], {"contents": "read", "issues": "write"})
        self.assertEqual(self.jobs["sync-issue"]["permissions"], {"contents": "read", "issues": "write"})
        # No secret other than the built-in token.
        text = self.path.read_text(encoding="utf-8")
        self.assertNotIn("secrets.", text)

    def test_actions_are_pinned_and_checkouts_drop_credentials(self):
        for step in self.steps():
            uses = step.get("uses")
            if not uses or uses.startswith("./"):
                continue
            self.assertRegex(uses, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", uses)
            if uses.startswith("actions/checkout@"):
                self.assertIs(step["with"]["persist-credentials"], False)

    def test_every_job_has_a_timeout(self):
        for name, job in self.jobs.items():
            self.assertIsInstance(job.get("timeout-minutes"), int, name)

    def test_run_blocks_take_inputs_only_through_the_environment(self):
        # ${{ }} inside run: is a script injection risk.
        for step in self.steps():
            self.assertNotIn("${{", step.get("run", ""), step.get("name"))

    def test_safe_defaults(self):
        inputs = self.on["workflow_dispatch"]["inputs"]
        self.assertIs(inputs["dry-run"]["default"], True)
        check = self.jobs["check"]
        # Scheduled runs are opt-in, and only the default branch opens issues.
        self.assertIn("vars.PSA_CEL_UPDATE_ISSUES == 'true'", check["if"])
        self.assertIn("github.ref_name != github.event.repository.default_branch", check["env"]["DRY_RUN"])
        self.assertNotIn("pull_request", check["if"])
        self.assertEqual(check["needs"], ["test"])

    def test_one_check_job_at_a_time_per_repository(self):
        concurrency = self.jobs["check"]["concurrency"]
        # The group must not include the ref, or runs of two branches could race.
        self.assertEqual(concurrency["group"], "psa-cel-update-issues-${{ github.repository }}")
        self.assertIs(concurrency["cancel-in-progress"], False)

    def test_pull_requests_run_the_tests_for_every_input_file(self):
        paths = set(self.on["pull_request"]["paths"])
        self.assertEqual(paths, {"scripts/psa-release-issues.py", "scripts/test-psa-release-issues.py",
                                 "scripts/psa-release-issues.yaml", ".github/workflows/psa-release-issues.yaml"})


class MainTest(unittest.TestCase):
    def test_rejects_a_non_https_repository(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()) as out:
            code = psa.main(["--repo", "owner/kyverno", "--out", tmp, "--repository", "file:///tmp/psa"])
        self.assertEqual(code, 1)
        self.assertIn("https://", out.getvalue())

    def test_committed_config_maps_every_check_to_a_template(self):
        config = psa.load_config(psa.CONFIG_FILE)
        self.assertTrue(psa.TAG_RE.match(config["since"]))
        chart = psa.Chart(ROOT)
        missing = [p for p in config["checks"].values() if not chart.lookup(p)]
        self.assertEqual(missing, [])

    def test_rejects_an_invalid_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yaml"
            for text, error in [
                ("since: v0.37.1\nchecks: {sysctls: restrict-sysctls}\n", "since must be"),
                ("since: kubernetes-1.37.1\n", "checks must be a non-empty map"),
                ("since: kubernetes-1.37.1\nchecks: {sysctls: ''}\n", "must map to a policy name"),
                ("since: kubernetes-1.37.1\nchecks: {sysctls: a, Sysctls: b}\n", "unique ignoring case"),
            ]:
                path.write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(psa.ReleaseError, error):
                    psa.load_config(path)


if __name__ == "__main__":
    unittest.main()
