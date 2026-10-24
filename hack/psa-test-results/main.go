// Checks the expected results of the pss-psa-version CLI tests against upstream
// Pod Security Admission (PSA).
//
// For each test directory it evaluates every listed Pod with the PSA check behind
// the policy, at the directory's version, and fails if the expected result differs.
// A latest-k8s-v1.x directory uses the latest floors below, which keep the
// allow-lists of earlier chart releases.
//
// Usage: go run . <pss-psa-version test dir>
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"
	"sigs.k8s.io/yaml"
)

// checks maps each policy to its upstream PSA check.
var checks = map[string]policy.CheckID{
	"restrict-sysctls":             "sysctls",
	"disallow-selinux":             "seLinuxOptions",
	"disallow-host-probes":         "hostProbesAndHostLifecycle",
	"disallow-proc-mount":          "procMount",
	"require-run-as-nonroot":       "runAsNonRoot",
	"require-run-as-non-root-user": "runAsUser",
}

// latestFloors is the oldest PSA version each check uses with podSecurityVersion: latest.
// The user namespace floors assume podSecurityUserNamespaces: true. The tool also assumes it
// at pinned versions. verify-policies-psa-version.sh renders every test directory with it.
var latestFloors = map[policy.CheckID]int{
	"sysctls":        29,
	"seLinuxOptions": 31,
	"procMount":      35,
	"runAsNonRoot":   35,
	"runAsUser":      35,
}

var dirName = regexp.MustCompile(`^(latest-k8s-)?v1\.(\d+)$`)

type testFile struct {
	Results []struct {
		Policy    string   `json:"policy"`
		Resources []string `json:"resources"`
		Result    string   `json:"result"`
	} `json:"results"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run . <pss-psa-version test dir>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	pods, err := readPods(filepath.Join(dir, "resources.yaml"))
	if err != nil {
		return err
	}
	byID := map[policy.CheckID]policy.Check{}
	for _, c := range policy.DefaultChecks() {
		byID[c.ID] = c
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var mismatches []string
	total := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m := dirName.FindStringSubmatch(e.Name())
		if m == nil {
			return fmt.Errorf("unknown test directory %s, want v1.x or latest-k8s-v1.x", e.Name())
		}
		latest := m[1] != ""
		minor, _ := strconv.Atoi(m[2])
		data, err := os.ReadFile(filepath.Join(dir, e.Name(), "kyverno-test.yaml"))
		if err != nil {
			return err
		}
		var test testFile
		if err := yaml.Unmarshal(data, &test); err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
		for _, r := range test.Results {
			id, ok := checks[r.Policy]
			if !ok {
				return fmt.Errorf("%s: no PSA check for policy %s", e.Name(), r.Policy)
			}
			version := minor
			if latest && latestFloors[id] > version {
				version = latestFloors[id]
			}
			for _, name := range r.Resources {
				pod, ok := pods[name]
				if !ok {
					return fmt.Errorf("%s: unknown Pod %s", e.Name(), name)
				}
				want := "fail"
				if allowed(byID[id], version, pod) {
					want = "pass"
				}
				total++
				if want != r.Result {
					mismatches = append(mismatches, fmt.Sprintf("%s: %s on %s is %s, PSA v1.%d says %s", e.Name(), r.Policy, name, r.Result, version, want))
				}
			}
		}
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("%d of %d expected results differ from upstream PSA:\n%s", len(mismatches), total, strings.Join(mismatches, "\n"))
	}
	fmt.Printf("%d expected results match upstream PSA\n", total)
	return nil
}

// allowed runs the newest version of the check that applies to v1.minor.
// A check with no version that applies, such as host probes before v1.34, allows the Pod.
func allowed(check policy.Check, minor int, pod *corev1.Pod) bool {
	want := api.MajorMinorVersion(1, minor)
	var fn policy.CheckPodFn
	// Versions are in increasing order, so the last one that applies wins.
	for _, v := range check.Versions {
		if !want.Older(v.MinimumVersion) {
			fn = v.CheckPod
		}
	}
	return fn == nil || fn(&pod.ObjectMeta, &pod.Spec).Allowed
}

func readPods(path string) (map[string]*corev1.Pod, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pods := map[string]*corev1.Pod{}
	for _, doc := range regexp.MustCompile(`(?m)^---\s*$`).Split(strings.ReplaceAll(string(data), "\r", ""), -1) {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var pod corev1.Pod
		if err := yaml.UnmarshalStrict([]byte(doc), &pod); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if pod.Kind == "Pod" {
			if _, ok := pods[pod.Name]; ok {
				return nil, fmt.Errorf("%s: duplicate Pod %s", path, pod.Name)
			}
			pods[pod.Name] = &pod
		}
	}
	return pods, nil
}
