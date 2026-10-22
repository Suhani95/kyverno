# PSA release issues

The `PSA release issues` workflow (`.github/workflows/psa-release-issues.yaml`) opens a GitHub issue for each
Kubernetes Pod Security Admission (PSA) release whose upstream changes the Pod Security Standards (PSS)
`ValidatingPolicy` templates in `charts/kyverno-policies` may need. The logic is in
`scripts/psa-release-issues.py`, the baseline and the check-to-policy map are in `scripts/psa-release-issues.yaml`,
and the tests are in `scripts/test-psa-release-issues.py`.

## How it works

PSA is developed in `kubernetes/kubernetes` under `staging/src/k8s.io/pod-security-admission`. The Kubernetes
publishing bot mirrors that directory to the read-only `kubernetes/pod-security-admission` repository, and tags
each release there as `kubernetes-1.<minor>.<patch>` and `v0.<minor>.<patch>` on the same commit. The script
fetches the `kubernetes-1.*` tags into a blobless clone, and diffs two tags to get the change to the staging
directory.

GitHub can't start a workflow from a release in another owner's repository, so the workflow polls every 6 hours.
An issue opens within about 6 hours of a release. GitHub can delay scheduled runs, and disables them in a public
repository after 60 days without activity.

Each release is compared with the previous relevant release. The trees are compared, not the history, because
release branches diverge from `master`.

| Release | Compared with |
|---|---|
| A patch, such as `v1.37.2` | The previous patch of the same minor, `v1.37.1` |
| A pre-release, such as `v1.38.0-rc.0` | The previous pre-release of the same minor, or `v1.37.0` for the first one |
| A new minor, such as `v1.38.0` | Its last pre-release. With `--skip-prereleases`, `v1.37.0`. |

Every change in `policy/`, `api/`, or `test/` needs an issue, except fixtures that a new
`test/testdata/<level>/v1.<N>/` directory copies unchanged from `v1.<N - 1>`. Only a release with no other change
is reported as **no action needed**.

The script maps each changed `policy/check_*.go` file or fixture to its check ID, and through `checks` to a
policy. From the policy, it finds the `*.cel.yaml` template, the check-specific helpers in `_helpers.tpl`, and the
`test/cli/test-validating-policy/pss-*` tests. From the Go diff, it reads new `MajorMinorVersion(1, N)` gates and
changed string values, and checks whether the template already has them. These signals are string matches, not a
semantic analysis, so read the comparison before you decide. The issue doesn't include the diff: it links the
comparison, and each changed Go file links to its section of it.

When the template already has every added value and gate, and doesn't keep a value that upstream removed, the
issue asks a person to confirm the change, and to confirm that a CLI test covers it. When it has only some of
them, the issue lists what's already there and asks only for the rest.

### Issue kinds

| Kind | Title ends with | `needs-manual-review` | When |
|---|---|---|---|
| Manual review | `review the PSS CEL policies (manual review)` | Yes | A change can't be mapped with confidence |
| Update | `update the PSS CEL policies` | No | Every change maps, and at least one needs an update |
| Confirm | `confirm the PSS CEL policies need no change` | No | Only test code changed, or the templates already seem to handle the change |

These changes are uncertain, and appear under **Uncertain mappings**:

- Shared `policy/` code, such as `helpers.go`, or base fixtures, which can affect every check.
- A change in `api/`.
- An upstream check ID that isn't in `checks`, or an entry in `checks` that upstream no longer declares. The
  script compares them whenever a release changes a check file.
- A check file that was renamed or split, or a mapped policy without a template.

These changes appear under **Review notes**, for a person to confirm:

- Test code only, with no fixture change, such as a regenerated fixture generator. The **Changed controls**
  table gives them one line, not a row each, and lists code changes before fixture-only changes.
- Values and version gates that already appear in the template or its helpers.
- A check code change in which the script finds no gate or value change.

Upstream text can't ping anyone or link elsewhere: commit subjects are in code spans, the issue links commits
rather than pull requests, and no upstream code goes into the issue body.

### Release tracking and duplicates

The script stores no state. Each run checks every release published after `since`, whatever its age, so a
failed or skipped run misses nothing. It compares publish dates, so a later patch for an older minor is checked
too.

Each issue ends with a hidden marker, such as `<!-- psa-cel-update: kubernetes-1.37.1 -->`, and the script skips
each release whose marker is in an open or closed issue with the `psa-cel-update` label. For concurrent runs:

1. The workflow runs one `Check releases` job at a time per repository, for every ref.
1. The script reads the issues again right before it creates one.
1. After creating one, it reads them once more, and closes its own issue as a duplicate if another run opened
   one first.

Don't remove the `psa-cel-update` label from these issues, and don't edit the marker.

## Enable the scheduled runs

Scheduled runs are off until a repository admin adds the repository variable `PSA_CEL_UPDATE_ISSUES` with the
value `true`, under **Settings** > **Secrets and variables** > **Actions** > **Variables**. Set it to `false` to
pause them.

The workflow uses the default `GITHUB_TOKEN` with `contents: read` and `issues: write`, and no secret. It creates
the `psa-cel-update`, `needs-manual-review`, and `area/pss` labels if they don't exist. When a scheduled run
fails, the `sync-issue` job opens a workflow-failure issue.

## Run the workflow manually

1. Go to **Actions** > **PSA release issues** > **Run workflow**.
1. Set the inputs:

   | Input | Default | Description |
   |---|---|---|
   | `dry-run` | `true` | Writes the issues to the job summary and an artifact instead of opening them |
   | `tag` | none | Checks only this tag, such as `kubernetes-1.37.0-alpha.1` |
   | `since` | none | Overrides the baseline tag |
   | `skip-prereleases` | `false` | Skips alpha, beta, and rc releases |

1. Click **Run workflow**, and read the job summary.

Only a run of the default branch opens issues.

## Handle an issue

1. Read **Changed controls** and **Uncertain mappings**, and open the comparison for each changed Go file.
1. Make the changes under **Required updates** in a pull request that references the issue.
1. Check each item under **Acceptance criteria**, such as `make test-cli`.
1. Close the issue. A closed issue is never reopened or recreated.

To move the baseline, change `since` to a release whose changes the chart already handles. When upstream adds a
check, add it to `checks`. The tests fail when a mapped policy has no template.

## Test a change

The `Test` job runs `scripts/test-psa-release-issues.py` on each pull request that changes the workflow, the
script, or the configuration. The tests use a local git repository shaped like the mirror, a fake GitHub API,
and a fake `gh` process, and they read the workflow file to check its permissions, pinned actions, timeouts,
inputs, defaults, and concurrency group. They don't run the workflow.

Only a real run verifies the workflow. Before you rely on it, in a fork:

1. Run it with `dry-run` set, and read the job summary.
1. Run it with `dry-run` cleared and a `tag` that needs an issue, and check the issue and its labels.
1. Run it again, and check that it doesn't open a second issue.
1. Set `PSA_CEL_UPDATE_ISSUES` to `true`, and check that a scheduled run starts.

To run the script locally, you need Python 3 with PyYAML and Git, and the GitHub CLI signed in with access to
`OWNER/NAME`, the repository that holds the issues:

```bash
python3 scripts/test-psa-release-issues.py
python3 scripts/psa-release-issues.py --repo OWNER/NAME --out /tmp/psa-release --dry-run
```

A dry run writes `summary.md` and one file per issue to `--out`. The script exits with `1` when it can't fetch
the mirror or handle a release, and the next run retries. It opens at most five issues per run, and a release
with no previous release to compare with fails the run, so a person checks it.
