#!/usr/bin/env python3
"""Opens one Kyverno issue for each Pod Security Admission (PSA) release that needs CEL policy work.

The script reads the kubernetes-1.* tags of the read-only PSA mirror, compares
each release after the baseline in scripts/psa-release-issues.yaml with the
previous relevant release, maps the changes to the PSS CEL templates, and opens
an issue unless one exists. It stores no state. See
docs/dev/psa-release-issues/README.md for the rules.

Exit codes: 0 when every release was handled, 1 on an error.
"""

import argparse
import hashlib
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONFIG_NAME = "scripts/psa-release-issues.yaml"
CONFIG_FILE = ROOT / CONFIG_NAME
TEMPLATES_DIR = "charts/kyverno-policies/templates"
HELPERS_FILE = f"{TEMPLATES_DIR}/_helpers.tpl"
CLI_TESTS_DIR = "test/cli/test-validating-policy"
DEFAULT_REPOSITORY = "https://github.com/kubernetes/pod-security-admission"
STAGING_PATH = "staging/src/k8s.io/pod-security-admission"
LABEL = "psa-cel-update"
MANUAL_LABEL = "needs-manual-review"
LABEL_INFO = {
    LABEL: ("0E8A16", "A Pod Security Admission release that may need PSS CEL policy updates"),
    MANUAL_LABEL: ("D93F0B", "Changes the PSA release check couldn't map with confidence"),
    "area/pss": ("607D8B", "Pod Security Standards"),
}
# Groups that belong to no single check.
UNMAPPED_GROUPS = ("shared", "api", "test-framework")
MAX_ISSUES_PER_RUN = 5
MAX_BODY_CHARS = 65000
MAX_LISTED_COMMITS = 50

TAG_RE = re.compile(r"^kubernetes-1\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.(\d+))?$")
PRE_ORDER = {"alpha": 0, "beta": 1, "rc": 2}
FIXTURE_RE = re.compile(r"^test/testdata/(baseline|restricted)/v1\.(\d+)/(pass|fail)/([^/]+)\.yaml$")
RELEVANT_PATHS = ["policy", "api", "test"]
# Changes that make a release relevant. Test code is listed only as context.
RELEVANT_KINDS = {"check", "shared", "api", "fixture"}


class ReleaseError(Exception):
    """An error that stops the check of one release, or of the whole run."""


def log(message):
    print(f"[psa-release-issues] {message}", file=sys.stderr)


def run_command(args):
    # Git must never wait for a password: a missing or private repository has
    # to fail at once, not hang.
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        # gh and git print UTF-8 whatever the locale, and issue text can hold any character.
        return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
    except OSError as err:
        raise ReleaseError(f"can't run {args[0]}: {err}") from err


def git(git_bin, repo, *args):
    """Runs git in repo and returns stdout, or raises ReleaseError."""
    result = run_command([git_bin, "-C", str(repo), *args])
    if result.returncode != 0:
        raise ReleaseError(f"git {' '.join(args[:3])} failed: {result.stderr.strip()[-500:]}")
    return result.stdout


def check_id_of(path, content):
    """Returns the check ID that a policy/check_*.go file declares.

    A check sets its ID inline (ID: "sysctls") or through a CheckID constant.
    Without either, the ID comes from the file name.
    """
    match = re.search(r'\bID:\s*"([^"]+)"', content) or re.search(r'CheckID\s*=\s*"([^"]+)"', content)
    return match.group(1) if match else path.rsplit("/", 1)[-1][len("check_"):-len(".go")]


def fixture_check_id(fixture):
    """Returns the lowercased check ID of a fixture name, such as "sysctls" for "sysctls1"."""
    return re.sub(r"\d+$", "", fixture).lower()


def load_config(path):
    """Reads and validates the baseline and the check-to-policy map."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    since = data.get("since")
    if not isinstance(since, str) or not TAG_RE.match(since):
        raise ReleaseError(f"{path}: since must be a kubernetes-1.<minor>.<patch> tag")
    checks = data.get("checks")
    if not isinstance(checks, dict) or not checks:
        raise ReleaseError(f"{path}: checks must be a non-empty map")
    for check_id, policy in checks.items():
        if not isinstance(check_id, str) or not isinstance(policy, str) or not policy:
            raise ReleaseError(f"{path}: checks.{check_id} must map to a policy name")
    lowered = [check_id.lower() for check_id in checks]
    if len(set(lowered)) != len(lowered):
        raise ReleaseError(f"{path}: check IDs must be unique ignoring case")
    return {"since": since, "checks": checks}


class Release:
    """A Kubernetes release, named by its kubernetes-1.* tag in the PSA mirror."""

    def __init__(self, tag, date=None):
        match = TAG_RE.match(tag)
        if not match:
            raise ValueError(f"not a release tag: {tag}")
        self.tag = tag
        self.date = date
        self.minor, self.patch = int(match.group(1)), int(match.group(2))
        self.pre = (match.group(3), int(match.group(4))) if match.group(3) else None

    @property
    def version(self):
        """The Kubernetes version, for example v1.37.0-rc.1."""
        return "v" + self.tag[len("kubernetes-"):]

    @property
    def psa_tag(self):
        """The matching v0.* tag in the PSA mirror."""
        return self.version.replace("v1.", "v0.", 1)

    def key(self):
        pre = (0, PRE_ORDER[self.pre[0]], self.pre[1]) if self.pre else (1, 0, 0)
        return (self.minor, self.patch, *pre)

    def __repr__(self):
        return self.tag


def parse_releases(text):
    """Parses `git for-each-ref` lines of "<tag>\\x1f<ISO date>" into releases."""
    releases = []
    for line in text.splitlines():
        tag, _, date = line.partition("\x1f")
        if TAG_RE.match(tag):
            releases.append(Release(tag, datetime.fromisoformat(date) if date else None))
    return sorted(releases, key=Release.key)


def previous_release(release, releases, include_prereleases=True):
    """Returns the release to compare with, or None.

    A patch release follows the previous stable patch of its minor. A
    pre-release or a vX.Y.0 release follows the previous tracked tag of its
    minor, or v1.<minor - 1>.0 when the minor has no earlier tracked tag.
    """
    def tracked(r):
        return include_prereleases or not r.pre

    earlier = [r for r in releases if r.key() < release.key() and r.minor == release.minor and tracked(r)]
    if release.patch > 0 and not release.pre:
        earlier = [r for r in earlier if not r.pre]
    if earlier:
        return max(earlier, key=Release.key)
    fallback = [r for r in releases if r.minor == release.minor - 1 and r.patch == 0 and not r.pre]
    return fallback[0] if fallback else None


def fetch_releases(git_bin, repository, dest):
    """Fetches the mirror's kubernetes-1.* tags into a blobless clone and returns the releases."""
    dest.mkdir(parents=True)
    git(git_bin, dest, "init", "-q")
    git(git_bin, dest, "remote", "add", "origin", repository)
    result = run_command([git_bin, "-C", str(dest), "fetch", "-q", "--filter=blob:none", "--no-tags",
                          "origin", "+refs/tags/kubernetes-1.*:refs/tags/kubernetes-1.*"])
    if result.returncode != 0:
        lines = result.stderr.strip().splitlines()
        raise ReleaseError(f"can't fetch the kubernetes-1.* tags from {repository}: "
                           f"{lines[-1] if lines else 'no output'}")
    refs = git(git_bin, dest, "for-each-ref", "--format=%(refname:short)%1f%(creatordate:iso-strict)",
               "refs/tags/kubernetes-1.*")
    return parse_releases(refs)


class Analysis:
    """The relevant upstream changes between two releases."""

    def __init__(self, release, previous):
        self.release = release
        self.previous = previous
        # group -> list of {"path", "status", "kind", "level", "version", "fixture"}
        self.groups = {}
        self.new_versions = []
        self.copied = 0
        self.signals = {}
        self.commits = []
        # Upstream check IDs missing from the config, and config IDs missing upstream.
        self.unmapped_checks = []
        self.stale_checks = []

    def add(self, group, change):
        self.groups.setdefault(group, []).append(change)

    @property
    def relevant(self):
        """True for any change other than fixtures copied unchanged to a new version.

        Test-only changes count too: they get an issue that asks a person to
        confirm them, never "no action needed".
        """
        return bool(self.groups or self.unmapped_checks or self.stale_checks)


def tree_blobs(git_bin, repo, ref, path):
    """Returns {relative path: blob SHA} for the files under path at ref."""
    result = run_command([git_bin, "-C", str(repo), "ls-tree", "-r", ref, "--", path])
    blobs = {}
    for line in result.stdout.splitlines() if result.returncode == 0 else []:
        meta, _, name = line.partition("\t")
        blobs[name[len(path) + 1:]] = meta.split()[2]
    return blobs


def show(git_bin, repo, ref, path):
    result = run_command([git_bin, "-C", str(repo), "show", f"{ref}:{path}"])
    return result.stdout if result.returncode == 0 else ""


def check_group(git_bin, repo, release, previous, path, lowered):
    """Returns (group, kind) for a changed path."""
    name = path.rsplit("/", 1)[-1]
    if path.startswith("policy/"):
        is_test = name.endswith("_test.go")
        source = path[:-len("_test.go")] + ".go" if is_test else path
        if not name.startswith("check_"):
            return "shared", "shared-test" if is_test else "shared"
        content = show(git_bin, repo, release.tag, source) or show(git_bin, repo, previous.tag, source)
        return check_id_of(source, content), "check-test" if is_test else "check"
    if path.startswith("api/"):
        return "api", "api-test" if name.endswith("_test.go") else "api"
    match = re.fullmatch(r"test/fixtures_(\w+)\.go", path)
    # fixtures_test.go tests the generator itself, not one check.
    if match and not name.endswith("_test.go"):
        return lowered.get(match.group(1).lower(), match.group(1)), "fixture-generator"
    return "test-framework", "test-framework"


def upstream_check_ids(git_bin, repo, ref):
    """Returns {check ID: path} for every non-test policy/check_*.go file at ref."""
    names = git(git_bin, repo, "ls-tree", "--name-only", ref, "policy/").split()
    paths = [n for n in names if re.fullmatch(r"policy/check_\w+\.go", n) and not n.endswith("_test.go")]
    return {check_id_of(p, show(git_bin, repo, ref, p)): p for p in paths}


def analyze(git_bin, repo, release, previous, checks):
    """Compares two releases and returns an Analysis."""
    analysis = Analysis(release, previous)
    lowered = {check_id.lower(): check_id for check_id in checks}
    out = git(git_bin, repo, "diff", "--name-status", "--no-renames", previous.tag, release.tag,
                   "--", *RELEVANT_PATHS)
    changes = [line.split("\t", 1) for line in out.splitlines() if "\t" in line]

    # A new fixture directory is mostly a copy of the previous version. Keep
    # only the files that differ from it.
    old_dirs = {(m.group(1), m.group(2)) for m in
                (FIXTURE_RE.match(f"test/testdata/{p}") for p in tree_blobs(git_bin, repo, previous.tag, "test/testdata"))
                if m}
    # (level, minor) -> (blobs of v1.<minor - 1>, blobs of v1.<minor>), both at the release.
    new_dirs = {}
    for status, path in changes:
        match = FIXTURE_RE.match(path)
        if match and (match.group(1), match.group(2)) not in old_dirs and (match.group(1), match.group(2)) not in new_dirs:
            level, minor = match.group(1), int(match.group(2))
            new_dirs[(level, match.group(2))] = (
                tree_blobs(git_bin, repo, release.tag, f"test/testdata/{level}/v1.{minor - 1}"),
                tree_blobs(git_bin, repo, release.tag, f"test/testdata/{level}/v1.{minor}"),
            )
    analysis.new_versions = sorted((f"{level}/v1.{minor}" for level, minor in new_dirs),
                                   key=lambda v: (v.split("/")[0], int(v.split(".")[-1])))

    for status, path in changes:
        match = FIXTURE_RE.match(path)
        if match:
            level, minor, kind, fixture = match.groups()
            if (level, minor) in new_dirs:
                before, after = new_dirs[(level, minor)]
                relative = path.split(f"/v1.{minor}/", 1)[1]
                if before.get(relative) == after.get(relative):
                    analysis.copied += 1
                    continue
                # Compared with the previous version, not with the previous release.
                status = "M" if relative in before else "A"
            group = "shared" if fixture.startswith("base") else lowered.get(fixture_check_id(fixture),
                                                                             fixture_check_id(fixture))
            analysis.add(group, {"path": path, "status": status, "kind": "fixture", "level": level,
                                 "version": f"1.{minor}", "fixture": fixture, "result": kind})
            continue
        if path.startswith("test/testdata/"):
            continue
        group, kind = check_group(git_bin, repo, release, previous, path, lowered)
        analysis.add(group, {"path": path, "status": status, "kind": kind})

    # The set of upstream checks can only change when a check file changes.
    if any(c["kind"] == "check" for items in analysis.groups.values() for c in items):
        upstream = upstream_check_ids(git_bin, repo, release.tag)
        analysis.unmapped_checks = sorted(set(upstream) - set(checks))
        analysis.stale_checks = sorted(set(checks) - set(upstream))

    for group, items in analysis.groups.items():
        code = [c["path"] for c in items if c["kind"] in ("check", "shared", "api")]
        if code:
            diff = git(git_bin, repo, "diff", previous.tag, release.tag, "--", *code)
            analysis.signals[group] = diff_signals(diff, items, set(checks) | {group})
    analysis.commits = upstream_commits(git_bin, repo, previous, release)
    return analysis


def strip_comments(code, in_comment):
    """Removes Go comments from a line. Returns (code, in_comment) for the next line."""
    kept = ""
    while code:
        if in_comment:
            end = code.find("*/")
            if end < 0:
                return kept, True
            code, in_comment = code[end + 2:], False
        else:
            start = code.find("/*")
            if start < 0:
                kept, code = kept + code, ""
            else:
                kept, code, in_comment = kept + code[:start], code[start + 2:], True
    return kept.split("//", 1)[0], in_comment


def diff_signals(diff, items, check_ids=()):
    """Returns behavior hints from a Go diff: version gates and changed string values.

    Comments, import paths, and check IDs aren't values, so they're left out.
    """
    signals = {"new": [], "removed": [], "gates": [], "added_values": [], "removed_values": []}
    for change in items:
        if change["kind"] == "check" and change["status"] == "A":
            signals["new"].append(change["path"])
        if change["kind"] == "check" and change["status"] == "D":
            signals["removed"].append(change["path"])
    in_comment = False
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            in_comment = False
        if line.startswith(("+++", "---")) or line[:1] not in ("+", "-", " "):
            continue
        # Context lines only track whether a block comment is open.
        code, in_comment = strip_comments(line[1:], in_comment)
        if line[0] == " ":
            continue
        # Import paths, such as "slices" or corev1 "k8s.io/api/core/v1", aren't values.
        if re.fullmatch(r'\s*(import\s+)?(\w+\s+)?"[^"]+"\s*', code):
            continue
        if line[0] == "+":
            signals["gates"] += [f"1.{m}" for m in re.findall(r"MajorMinorVersion\(\s*1\s*,\s*(\d+)\s*\)", code)]
        values = [v for v in re.findall(r'"([^"\s]+)"', code) if v not in check_ids]
        signals["added_values" if line[0] == "+" else "removed_values"] += values
    added, removed = set(signals["added_values"]), set(signals["removed_values"])
    # A value on both sides moved rather than changed.
    signals["added_values"] = sorted(added - removed)
    signals["removed_values"] = sorted(removed - added)
    signals["gates"] = sorted(set(signals["gates"]), key=lambda v: int(v.split(".")[1]))
    return signals


def upstream_commits(git_bin, repo, previous, release):
    """Returns [(sha, subject, kubernetes commit or None)] for commits that touch relevant paths."""
    out = git(git_bin, repo, "log", "--no-merges", f"--max-count={MAX_LISTED_COMMITS + 1}",
                   "--format=%H%x1f%s%x1f%b%x1e", f"{previous.tag}..{release.tag}", "--",
                   "policy", "api", "test/testdata")
    commits = []
    for record in out.split("\x1e"):
        if not record.strip():
            continue
        sha, subject, body = (record.strip("\n").split("\x1f") + ["", ""])[:3]
        trailer = re.search(r"^Kubernetes-commit:\s*([0-9a-f]{40})\s*$", body, re.MULTILINE)
        commits.append((sha, subject, trailer.group(1) if trailer else None))
    return commits


class Chart:
    """Looks up the Kyverno files that implement a PSS policy."""

    def __init__(self, root):
        self.root = Path(root)
        self.templates = {p.name[:-len(".cel.yaml")]: p for p in
                          sorted((self.root / TEMPLATES_DIR).glob("*/*.cel.yaml"))}
        # A helper's body runs to the next define. Its own {{ end }} can't mark
        # the end, because nested if blocks also end with {{ end }}.
        parts = re.split(r'\{\{-?\s*define\s+"kyverno-policies\.(\w+)"\s*-?\}\}', self.read(HELPERS_FILE))
        self.helpers = dict(zip(parts[1::2], parts[2::2]))
        self.tests = sorted(p for p in (self.root / CLI_TESTS_DIR).glob("pss-*") if p.is_dir())
        usage = {name: sum(1 for t in self.templates.values() if self.includes(t, name)) for name in self.helpers}
        # A helper used by most templates, or one that selects a profile, is
        # plumbing, not check logic.
        self.check_helpers = {name for name, count in usage.items()
                              if 0 < count < len(self.templates) / 2 and not name.startswith("podSecurity")}

    def read(self, relative):
        path = self.root / relative
        return path.read_text(encoding="utf-8") if path.is_file() else ""

    @staticmethod
    def includes(template, helper):
        return f'"kyverno-policies.{helper}"' in template.read_text(encoding="utf-8")

    def relative(self, path):
        return path.relative_to(self.root).as_posix()

    def lookup(self, policy):
        """Returns the template, check helpers, version gates, and tests for a policy."""
        template = self.templates.get(policy)
        if not template:
            return None
        text = template.read_text(encoding="utf-8")
        helpers = sorted(h for h in self.check_helpers if self.includes(template, h))
        sources = [text] + [self.helpers[h] for h in helpers]
        gates = sorted({m for s in sources for m in re.findall(r'semverCompare\s+"\s*>=\s*1\.(\d+)', s)}, key=int)
        tests = [self.relative(t) for t in self.tests
                 # disallow-proc-mount must not match disallow-proc-mount-strict.
                 if any(re.search(rf"(?<![\w-]){re.escape(policy)}(?![\w-])", f.read_text(encoding="utf-8"))
                        for f in t.glob("*.yaml"))]
        return {"template": self.relative(template), "level": template.parent.name, "helpers": helpers,
                "gates": [f"1.{g}" for g in gates], "tests": tests, "sources": "\n".join(sources)}


def map_changes(analysis, mapping, chart):
    """Maps each changed group to Kyverno files. Returns (mapped, uncertain, confirm).

    mapped is a list of dicts per group. uncertain lists the changes that
    can't be tied to the Kyverno policies with confidence, and marks the issue
    for manual review. confirm lists the changes that are mapped but that a
    person must still confirm, such as test-only changes.
    """
    mapped, uncertain, confirm = [], [], []
    for check_id in analysis.unmapped_checks:
        uncertain.append(f"Upstream declares check {code(check_id)}, which has no entry in `checks` in "
                         f"`{CONFIG_NAME}`. Map it to a policy, or add a policy for it.")
    for check_id in analysis.stale_checks:
        uncertain.append(f"`checks` in `{CONFIG_NAME}` maps {code(check_id)}, which upstream no longer declares. "
                         "The check may be renamed or removed.")
    test_only = []
    for group in sorted(analysis.groups):
        items = analysis.groups[group]
        signals = analysis.signals.get(group, {})
        if not any(c["kind"] in RELEVANT_KINDS for c in items):
            # Test code can encode a behavior change that the fixtures don't
            # show yet, so a person confirms it.
            test_only.append(group)
            mapped.append({"group": group, "policy": mapping["checks"].get(group), "items": items,
                           "signals": signals, "files": None, "test_only": True})
            continue
        if group in UNMAPPED_GROUPS:
            where = "`api/`" if group == "api" else "shared `policy/` code or base fixtures"
            uncertain.append(f"Changes in {where} can affect every check, so they map to no single policy. "
                             f"Review them against all {len(chart.templates)} PSS CEL templates.")
            mapped.append({"group": group, "policy": None, "items": items, "signals": signals, "files": None})
            continue
        policy = mapping["checks"].get(group)
        files = chart.lookup(policy) if policy else None
        entry = {"group": group, "policy": policy, "items": items, "signals": signals, "files": files}
        if not policy:
            # The upstream check scan already reported a declared, unmapped check.
            if group not in analysis.unmapped_checks:
                uncertain.append(f"Check `{group}` has no entry in `checks` in `{CONFIG_NAME}`. It may be a "
                                 "new upstream check that needs a new policy, or a renamed one.")
        elif not files:
            uncertain.append(f"Check `{group}` maps to policy `{policy}`, but no `{policy}.cel.yaml` template "
                             f"exists under `{TEMPLATES_DIR}`.")
        else:
            missing = [v for v in signals.get("added_values", []) if v not in files["sources"]]
            entry["missing_values"] = missing
            entry["present_values"] = [v for v in signals.get("added_values", []) if v not in missing]
            entry["missing_gates"] = [g for g in signals.get("gates", []) if g not in files["gates"]]
            entry["present_gates"] = [g for g in signals.get("gates", []) if g in files["gates"]]
            # A value that upstream removed but the template still has may need work, so it isn't handled.
            kept = [v for v in signals.get("removed_values", []) if v in files["sources"]]
            entry["handled"] = (bool(signals.get("added_values") or signals.get("gates"))
                                and not missing and not entry["missing_gates"] and not kept)
            if signals.get("new") and signals.get("removed"):
                uncertain.append(f"A check file for `{group}` was renamed or split, so the check ID or its "
                                 "level may have moved. Confirm the mapping.")
            if entry["handled"]:
                confirm.append(f"Every value and version gate added to `{group}` already appears in "
                               f"`{files['template']}` or its helpers, so Kyverno may already handle this change.")
            elif any(c["kind"] == "check" for c in items) and not (signals.get("gates") or signals.get("added_values")
                                                                   or signals.get("removed_values")):
                # The heuristics found nothing, which doesn't mean nothing changed.
                entry["no_signals"] = True
                confirm.append(f"The `{group}` check code changed, but the diff shows no version gate or value "
                               "change. Read the comparison to find what changed.")
        mapped.append(entry)
    if test_only:
        confirm.append(f"Only upstream test code changed for {len(test_only)} check group(s), and their fixtures "
                       "didn't change: " + ", ".join(code(g) for g in test_only) +
                       ". No CEL change is expected, but confirm that the tests don't encode a behavior change.")
    return mapped, uncertain, confirm


def code(value):
    return f"`{value}`"


def inert(text):
    """Puts upstream text in a code span, so @mentions and #refs don't ping or link anyone."""
    return f"`{text.replace('`', chr(39))}`" if text else ""


def issue_kind(mapped, uncertain):
    """Returns "manual", "update", or "confirm" for an issue."""
    if uncertain:
        return "manual"
    if any(not e.get("test_only") and not e.get("handled") for e in mapped):
        return "update"
    return "confirm"


def render_issue(analysis, mapped, uncertain, confirm, repository):
    """Returns (title, body) for a release with upstream changes.

    An uncertain mapping marks the issue for manual review. An issue with only
    changes to confirm, such as test-only changes, asks a person to confirm
    that the policies need no change.
    """
    rel, prev = analysis.release, analysis.previous
    base = repository[:-4] if repository.endswith(".git") else repository
    k8s = "https://github.com/kubernetes/kubernetes"
    kind = issue_kind(mapped, uncertain)
    title = {
        "manual": f"Pod Security Admission {rel.version}: review the PSS CEL policies (manual review)",
        "update": f"Pod Security Admission {rel.version}: update the PSS CEL policies",
        "confirm": f"Pod Security Admission {rel.version}: confirm the PSS CEL policies need no change",
    }[kind]
    lines = [
        f"Kubernetes {rel.version} changes the upstream Pod Security Admission (PSA) checks, fixtures, or tests. "
        "Review the changes below and update the Kyverno PSS `ValidatingPolicy` templates in "
        f"`{TEMPLATES_DIR}` where needed.",
        "",
    ]
    if uncertain:
        lines += [
            "> [!IMPORTANT]",
            f"> **Manual review needed.** {len(uncertain)} change(s) couldn't be mapped to the Kyverno policies with "
            "confidence. A person must check each one under **Uncertain mappings** before closing this issue.",
            "",
        ]
    lines += [
        "## Release",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Release | [{code(rel.version)}]({k8s}/releases/tag/{rel.version}) |",
        f"| Published | {rel.date.isoformat() if rel.date else 'unknown'} |",
        f"| Compared with | {code(prev.version)} |",
        f"| PSA source | [{code(STAGING_PATH)}]({k8s}/tree/{rel.version}/{STAGING_PATH}) |",
        f"| PSA mirror tags | [{code(rel.tag)}]({base}/tree/{rel.tag}), [{code(rel.psa_tag)}]({base}/tree/{rel.psa_tag}) |",
        f"| Comparison | [{code(prev.tag + '...' + rel.tag)}]({base}/compare/{prev.tag}...{rel.tag}) |",
        "",
        "## Changed controls",
        "",
    ]
    # Code changes first, then fixture-only changes. Test-only groups get one line.
    changed = sorted((e for e in mapped if not e.get("test_only")),
                     key=lambda e: (not any(c["kind"] in ("check", "shared", "api") for c in e["items"]), e["group"]))
    test_only = [e["group"] for e in mapped if e.get("test_only")]
    if changed:
        lines += ["| Upstream check | Kyverno policy | Level | Upstream changes | Behavior signals |",
                  "| --- | --- | --- | --- | --- |"]
    for entry in changed:
        files, signals = entry["files"], entry["signals"]
        changes = ", ".join(f"{len(v)} {k}" for k, v in sorted(_by_kind(entry["items"]).items()))
        hints = []
        if signals.get("new") and signals.get("removed"):
            hints.append("check file renamed or split")
        elif signals.get("new"):
            hints.append("new check file")
        elif signals.get("removed"):
            hints.append("check file removed")
        if signals.get("gates"):
            hints.append("version gate " + ", ".join(code(">=" + g) for g in signals["gates"]))
        if signals.get("added_values"):
            hints.append("added " + ", ".join(code(v) for v in signals["added_values"][:10]))
        if signals.get("removed_values"):
            hints.append("removed " + ", ".join(code(v) for v in signals["removed_values"][:10]))
        if entry.get("no_signals"):
            hints.append("no gate or value change found: read the comparison")
        versions = sorted({c["version"] for c in entry["items"] if c["kind"] == "fixture"},
                          key=lambda v: int(v.split(".")[1]))
        if versions:
            hints.append("fixtures for " + ", ".join(code(v) for v in versions))
        if not any(c["kind"] in ("check", "shared", "api") for c in entry["items"]):
            hints.append("fixtures only")
        name = code(entry["group"]) if entry["policy"] or entry["group"] not in UNMAPPED_GROUPS else entry["group"]
        if entry["policy"]:
            policy = code(entry["policy"])
        elif entry["group"] in UNMAPPED_GROUPS:
            policy = "all (uncertain)"
        else:
            policy = "none (uncertain)"
        level = files["level"] if files else "unknown"
        lines.append(f"| {name} | {policy} | {level} | {changes} | {'; '.join(hints) or 'none'} |")
    if test_only:
        lines += ["", f"Test code only, with no fixture change, for {len(test_only)} group(s): " +
                  ", ".join(code(g) for g in test_only) + ". See the changed files."]
    if analysis.new_versions:
        lines += ["", "New fixture versions: " + ", ".join(code(v) for v in analysis.new_versions) +
                  f". {analysis.copied} copied fixtures that match the previous version are left out."]

    def listed(values, empty="none"):
        return ", ".join(code(v) for v in values) or empty

    lines += ["", "## Affected Kyverno files", ""]
    for entry in (e for e in changed if e["files"]):
        files = entry["files"]
        lines.append(f"- {code(entry['policy'])}: template {code(files['template'])}; helpers "
                     f"{listed(files['helpers'])}; gates {listed('>=' + g for g in files['gates'])}; "
                     f"CLI tests {listed(files['tests'], 'none found: add one')}")
    if not any(e["files"] for e in changed):
        lines.append("No changed check maps to a CEL template. See the notes below.")
    lines.append("")

    lines += ["## Uncertain mappings", ""]
    lines += [f"- {note}" for note in uncertain] or ["None. Every change maps to the Kyverno policies."]
    if confirm:
        lines += ["", "## Review notes", "", *(f"- {note}" for note in confirm)]
    lines += ["", "_The behavior signals come from the Go diff: added `MajorMinorVersion(1, N)` gates and changed "
              "string literals. They are hints, not a complete analysis. Read the comparison._"]

    lines += ["", "## Required updates", ""]
    for entry in changed:
        files, signals = entry["files"], entry["signals"]
        if not files:
            target = "a new or existing policy" if entry["group"] not in UNMAPPED_GROUPS else "the affected templates"
            lines.append(f"- [ ] Decide which CEL changes `{entry['group']}` needs, and update {target}.")
            continue
        handled = entry.get("handled")
        verb, tail = ("Confirm that", " already matches") if handled else ("Update", " to match")
        lines.append(f"- [ ] {verb} {code(files['template'])}{tail} the upstream `{entry['group']}` check.")
        present = entry.get("present_values", []) + [">=" + g for g in entry.get("present_gates", [])]
        if present and not handled:
            # Don't ask for work that the template already has.
            lines.append(f"  - Already in the template or its helpers: {listed(present)}.")
        for value in entry.get("missing_values", []):
            lines.append(f"  - [ ] Handle {code(value)}, which doesn't appear in the template or its helpers yet.")
        for gate in entry.get("missing_gates", []):
            lines.append(f"  - [ ] Add a `semverCompare \">={gate}.0-0\"` gate, because upstream changes behavior "
                         f"from {gate}.")
        if signals.get("removed_values"):
            lines.append("  - [ ] Check whether the removed values must stay allowed for older Kubernetes versions.")
        tests = ", ".join(code(t) for t in files["tests"]) if files["tests"] else f"`{CLI_TESTS_DIR}/pss-*`"
        if handled and files["tests"]:
            lines.append(f"  - [ ] Confirm that a CLI test under {tests} covers the change.")
        else:
            lines.append(f"  - [ ] Add or update a CLI test under {tests}.")
    if test_only:
        lines.append(f"- [ ] Confirm that the test-only changes for {len(test_only)} group(s) need no CEL change.")
    if analysis.unmapped_checks or any(not e["policy"] and e["group"] not in UNMAPPED_GROUPS
                                       and not e.get("test_only") for e in mapped):
        lines.append(f"- [ ] Add each new check to `checks` in `{CONFIG_NAME}`.")
    if analysis.stale_checks:
        lines.append(f"- [ ] Remove or rename the stale entries in `checks` in `{CONFIG_NAME}`.")

    sysctls = ["- [ ] `make verify-policies-sysctls` passes."] if any(e["group"] == "sysctls" for e in changed) else []
    lines += [
        "", "## Acceptance criteria", "",
        f"- [ ] The PSS CEL templates match upstream PSA at {code(rel.version)} for each changed control: each "
        f"upstream `pass` and `fail` fixture in `test/testdata/` for that control gets the same result.",
        "- [ ] Each behavior change has a CLI test that passes with `make test-cli`.", *sysctls,
        "- [ ] Each change that starts at a Kubernetes version is gated with `semverCompare`, so older versions "
        "keep the old behavior.",
        "- [ ] The chart renders with `helm template charts/kyverno-policies` on the oldest and newest supported "
        "Kubernetes versions.",
    ]

    lines += ["", "## Upstream commits", ""]
    if analysis.commits:
        for sha, subject, k8s_sha in analysis.commits[:MAX_LISTED_COMMITS]:
            # Commit links, not PR links: a PR link would add a cross-reference to the upstream PR.
            source = f" ([kubernetes/kubernetes@{k8s_sha[:12]}]({k8s}/commit/{k8s_sha}))" if k8s_sha else ""
            lines.append(f"- [{code(sha[:12])}]({base}/commit/{sha}) {inert(subject)}{source}")
        if len(analysis.commits) > MAX_LISTED_COMMITS:
            lines.append(f"- More commits: see the [comparison]({base}/compare/{prev.tag}...{rel.tag}).")
    else:
        lines.append("None found in `policy/`, `api/`, or `test/testdata/`.")

    # The issue carries no diff. Go code files link to their section of the comparison,
    # which GitHub anchors as "diff-" plus the SHA-256 of the path.
    compare = f"{base}/compare/{prev.tag}...{rel.tag}"

    def changed_file(change):
        if change["kind"] in ("check", "shared", "api"):
            anchor = hashlib.sha256(change["path"].encode()).hexdigest()
            return f"[{code(change['path'])}]({compare}#diff-{anchor}) ({change['status']})"
        return f"{code(change['path'])} ({change['status']})"

    lines += ["", "## Changed files", "", f"See the [full comparison]({compare}).", ""]
    for entry in mapped:
        lines.append(f"- {entry['group']}: " + ", ".join(changed_file(c) for c in entry["items"][:30]) +
                     (f", and {len(entry['items']) - 30} more" if len(entry["items"]) > 30 else ""))

    lines += ["", "---", "", "_Opened by `.github/workflows/psa-release-issues.yaml`._", "", marker(rel)]
    body = "\n".join(lines)
    if len(body) > MAX_BODY_CHARS:
        body = body[:MAX_BODY_CHARS - 200].rsplit("\n", 1)[0] + "\n\n_Truncated._\n\n" + marker(rel)
    return title, body


def _by_kind(items):
    groups = {}
    for c in items:
        groups.setdefault(c["kind"], []).append(c)
    return groups


def marker(release):
    return f"<!-- psa-cel-update: {release.tag} -->"


def no_action_reason(analysis):
    """Explains a release without changes. Only call it when analysis.relevant is False."""
    if analysis.copied:
        return (f"only {analysis.copied} fixtures copied unchanged to " +
                ", ".join(code(v) for v in analysis.new_versions or ["a new version"]))
    return "no change in `policy/`, `api/`, or `test/`"


class GitHub:
    """A small GitHub REST client on top of `gh api`, limited to issues, issue comments, and labels.

    The only change it makes to an existing issue is closing a duplicate that
    this script opened.
    """

    def __init__(self, repo):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise ReleaseError(f"invalid repository: {repo}")
        self.repo = repo

    def check_allowed(self, method, path, body):
        prefix = f"repos/{re.escape(self.repo)}"
        allowed = (
            # Reading the repository itself, to check that Issues are on.
            method == "GET" and path == f"repos/{self.repo}"
        ) or (
            method in ("GET", "POST") and re.match(rf"^{prefix}/(issues|labels)(\?|/|$)", path)
            and not re.match(rf"^{prefix}/issues/\d+$", path)
        ) or (
            # Closing a duplicate is the only issue update.
            method == "PATCH" and re.fullmatch(rf"{prefix}/issues/\d+", path)
            and set(body or {}) <= {"state", "state_reason"} and (body or {}).get("state") == "closed"
        )
        if not allowed:
            raise ReleaseError(f"refusing {method} {path}")

    def request(self, method, path, body=None, paginate=False):
        self.check_allowed(method, path, body)
        command = ["gh", "api", "-X", method, path, "-H", "Accept: application/vnd.github+json"]
        if paginate:
            command += ["--paginate", "--jq", ".[] | @json"]
        body_file = None
        if body is not None:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
                json.dump(body, handle)
                body_file = handle.name
            command += ["--input", body_file]
        try:
            result = run_command(command)
        finally:
            if body_file:
                os.unlink(body_file)
        if result.returncode != 0:
            if method == "GET" and "(HTTP 404)" in result.stderr:
                return None
            raise ReleaseError(f"gh api {method} {path} failed: {(result.stderr or result.stdout).strip()[-500:]}")
        if paginate:
            return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        return json.loads(result.stdout) if result.stdout.strip() else {}

    def issues_enabled(self):
        """Returns whether the repository has Issues turned on."""
        return bool((self.request("GET", f"repos/{self.repo}") or {}).get("has_issues"))

    def issues(self):
        """Returns [{"number", "body"}] for every open and closed issue with the label."""
        issues = self.request("GET", f"repos/{self.repo}/issues?labels={LABEL}&state=all&per_page=100", paginate=True)
        return [{"number": i["number"], "body": i.get("body") or ""} for i in issues if "pull_request" not in i]

    def ensure_labels(self, names):
        for name in names:
            if self.request("GET", f"repos/{self.repo}/labels/{name.replace('/', '%2F')}") is None:
                color, description = LABEL_INFO[name]
                self.request("POST", f"repos/{self.repo}/labels",
                             {"name": name, "color": color, "description": description})

    def create_issue(self, title, body, labels):
        return self.request("POST", f"repos/{self.repo}/issues", {"title": title, "body": body, "labels": list(labels)})

    def close_duplicate(self, number, original):
        self.request("POST", f"repos/{self.repo}/issues/{number}/comments",
                     {"body": f"Duplicate of #{original}, which another run of this workflow opened first."})
        self.request("PATCH", f"repos/{self.repo}/issues/{number}", {"state": "closed", "state_reason": "duplicate"})


def matching(issues, release):
    return sorted(i["number"] for i in issues if marker(release) in i["body"])


def open_issue(github, release, title, body, labels):
    """Opens the issue unless one exists. Returns (number, url, note).

    The workflow runs one job at a time, but a second run elsewhere, such as a
    local run, can still race. So the script re-reads the issues right before
    it creates one, and after creating, keeps the oldest issue for the release
    and closes its own as a duplicate.
    """
    existing = matching(github.issues(), release)
    if existing:
        return existing[0], None, "opened by another run meanwhile"
    issue = github.create_issue(title, body, labels)
    number = issue.get("number")
    found = matching(github.issues(), release)
    first = min(found + [number])
    if first != number:
        github.close_duplicate(number, first)
        return first, None, f"closed the duplicate #{number} that a concurrent run caused"
    return number, issue.get("html_url"), None


def select_releases(releases, args):
    """Returns the releases to check: one tag, or every release published after the baseline."""
    if args.tag:
        selected = [r for r in releases if r.tag == args.tag]
        if not selected:
            raise ReleaseError(f"tag {args.tag} isn't in {args.repository}")
        return selected
    baseline = next((r for r in releases if r.tag == args.since), None)
    if not baseline or not baseline.date:
        raise ReleaseError(f"baseline tag {args.since} isn't in {args.repository}")
    # Dates, not versions: a patch for an older minor can come out after the baseline.
    return [r for r in releases if r.date and r.date > baseline.date and (args.include_prereleases or not r.pre)]


def run(args, github, chart, config, git_bin="git"):
    """Checks every release after the baseline. Returns (summary lines, failures).

    No state is stored: each run recomputes the result for every release after
    the baseline from the mirror's tags, and the issue markers record which
    releases already have an issue. A failed or skipped run loses nothing.
    """
    # With Issues off, listing issues still works but creating one fails, so a
    # dry run would pass and the real run would fail. Check first, in both.
    if not github.issues_enabled():
        raise ReleaseError(f"Issues are turned off in {github.repo}. Turn them on under Settings > General > "
                           "Features, or run the workflow in another repository.")
    summary, failures = [], []
    with tempfile.TemporaryDirectory(prefix="psa-release-") as tmp:
        repo = Path(tmp) / "upstream"
        releases = fetch_releases(git_bin, args.repository, repo)
        selected = select_releases(releases, args)
        log(f"{len(releases)} releases, {len(selected)} to check")
        issues = github.issues()
        created, labeled = 0, set()
        for release in sorted(selected, key=Release.key):
            line = f"- {code(release.version)}"
            try:
                if matching(issues, release):
                    summary.append(f"{line}: issue already exists (#{matching(issues, release)[0]})")
                    continue
                previous = previous_release(release, releases, args.include_prereleases or bool(release.pre))
                if not previous:
                    raise ReleaseError("no previous release to compare with; check this release by hand")
                line += f" (since {code(previous.version)})"
                analysis = analyze(git_bin, repo, release, previous, config["checks"])
                if not analysis.relevant:
                    summary.append(f"{line}: no action needed: {no_action_reason(analysis)}")
                    continue
                if created >= MAX_ISSUES_PER_RUN:
                    summary.append(f"{line}: waits for the next run (limit of {MAX_ISSUES_PER_RUN} issues per run)")
                    continue
                mapped, uncertain, confirm = map_changes(analysis, config, chart)
                title, body = render_issue(analysis, mapped, uncertain, confirm, args.repository)
                labels = [LABEL, "area/pss"] + ([MANUAL_LABEL] if uncertain else [])
                review = {"manual": " (manual review)", "confirm": " (confirm only)",
                          "update": ""}[issue_kind(mapped, uncertain)]
                out = Path(args.out) / f"{release.tag}.md"
                out.write_text(f"# {title}\n\nLabels: {', '.join(labels)}\n\n{body}\n", encoding="utf-8")
                if args.dry_run:
                    summary.append(f"{line}: would open an issue{review} (dry run, see {out.name})")
                else:
                    github.ensure_labels([name for name in labels if name not in labeled])
                    labeled.update(labels)
                    number, url, note = open_issue(github, release, title, body, labels)
                    link = f"[#{number}]({url})" if url else f"#{number}"
                    summary.append(f"{line}: {'opened' if not note else 'issue'} {link}{review}"
                                   + (f" ({note})" if note else ""))
                    issues.append({"number": number, "body": marker(release)})
                created += 1
            except (ReleaseError, OSError) as err:
                log(f"{release.tag}: {err}")
                summary.append(f"{line}: **error**: {err}")
                failures.append(release.tag)
    return summary, failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", required=True, help="the repository to open issues in, as OWNER/NAME")
    parser.add_argument("--out", required=True, help="directory for summary.md and the issue bodies")
    parser.add_argument("--dry-run", action="store_true", help="write the issues to --out instead of opening them")
    parser.add_argument("--since", help="baseline tag: check releases published after it (default: since in --config)")
    parser.add_argument("--skip-prereleases", dest="include_prereleases", action="store_false",
                        help="skip alpha, beta, and rc releases")
    parser.add_argument("--tag", help="check only this kubernetes-1.* tag")
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY,
                        help="the PSA mirror to read, https://github.com/OWNER/REPO (a fork for testing)")
    parser.add_argument("--config", default=str(CONFIG_FILE), help="baseline and check-to-policy map")
    parser.add_argument("--git", default="git", help="path to git")
    args = parser.parse_args(argv)
    for name in ("tag", "since"):
        if getattr(args, name) and not TAG_RE.match(getattr(args, name)):
            parser.error(f"--{name} must look like kubernetes-1.<minor>.<patch>")
    try:
        # The URL goes to git remote add, and the issue links assume GitHub, so
        # allow only a GitHub repository URL. A fork works for testing.
        if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
            raise ReleaseError("--repository must look like https://github.com/OWNER/REPO")
        config = load_config(args.config)
        args.since = args.since or config["since"]
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        summary, failures = run(args, GitHub(args.repo), Chart(ROOT), config, args.git)
    except (ReleaseError, OSError, yaml.YAMLError) as err:
        print(f"ERROR: {err}")
        return 1
    mode = " (dry run)" if args.dry_run else ""
    scope = f"release {args.tag}" if args.tag else f"releases published after {args.since}"
    report = "\n".join([f"# Pod Security Admission release check{mode}", "", f"Checked {scope}.", "",
                        *(summary or ["- No new releases."]), ""])
    (out / "summary.md").write_text(report, encoding="utf-8")
    print(report)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
