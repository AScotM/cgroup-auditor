package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHumanBytes(t *testing.T) {
	for _, tc := range []struct {
		input float64
		want  string
	}{{0, "0 B"}, {1024, "1.0 KiB"}, {1048576, "1.0 MiB"}, {1073741824, "1.0 GiB"}} {
		if got := humanBytes(tc.input); got != tc.want {
			t.Errorf("humanBytes(%v)=%q want %q", tc.input, got, tc.want)
		}
	}
}
func TestMetricParsing(t *testing.T) {
	c, err := newCollector(Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ file, input, want string }{
		{"cpu.stat", "usage_usec 123\nuser_usec 34\n", "cpu.stat:usage_usec"},
		{"cpu.max", "100000 100000", "cpu.max:quota"},
		{"memory.pressure", "some avg10=0.00 avg60=0.02 avg300=0.03 total=123\n", "memory.pressure:some.avg10"},
		{"io.stat", "8:0 rbytes=99 wbytes=20", "io.stat:8:0.rbytes"},
	} {
		got := c.parseMetrics(tc.file, tc.input)
		found := false
		for _, m := range got {
			if m.Name == tc.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: missing %s in %+v", tc.file, tc.want, got)
		}
	}
}
func TestAssessNode(t *testing.T) {
	mem := float64(95)
	limit := float64(100)
	oom := float64(2)
	n := Node{Path: "/test", Metrics: []Metric{{Name: "memory.current:value", Numeric: &mem}, {Name: "memory.max:value", Numeric: &limit}, {Name: "memory.events:oom_kill", Numeric: &oom}}}
	findings := assessNode(n)
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings: %+v", findings)
	}
}
func TestSyntheticCollection(t *testing.T) {
	root := t.TempDir()
	for name, data := range map[string]string{"cgroup.controllers": "cpu memory pids\n", "cgroup.type": "domain\n", "memory.current": "95\n", "memory.max": "100\n", "pids.current": "2\n", "pids.max": "5\n", "cpu.stat": "usage_usec 100\n", "cgroup.procs": "123\n456\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var output, stderr bytes.Buffer
	err := run([]string{"--root", root, "--max-depth", "0", "--format", "json"}, &output, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	var report Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Summary.Nodes != 1 {
		t.Fatalf("unexpected nodes: %d", report.Summary.Nodes)
	}
	if report.Summary.UniqueProcesses != 2 {
		t.Fatalf("unexpected processes: %d", report.Summary.UniqueProcesses)
	}
	if report.Summary.Findings["warning"] == 0 {
		t.Fatal("missing resource-limit warning")
	}
}
func TestSecureSubpath(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := secureSubpath(root, "/child"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := secureSubpath(root, "/link"); err == nil {
		t.Fatal("expected symlink rejection")
	}
}
func TestCatalogUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range metricCatalog() {
		key := m.File + ":" + m.Key
		if seen[key] {
			t.Errorf("duplicate metric %s", key)
		}
		seen[key] = true
	}
}
func TestRenderCSV(t *testing.T) {
	r := Report{Nodes: []Node{{Path: "/", Name: "/"}}}
	var b bytes.Buffer
	if err := renderCSV(&b, r, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "memory_bytes") {
		t.Fatal("missing CSV header")
	}
}
