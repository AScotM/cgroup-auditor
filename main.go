package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

type MetricSpec struct {
	File        string `json:"file"`
	Key         string `json:"key"`
	Unit        string `json:"unit"`
	Group       string `json:"group"`
	Kind        string `json:"kind"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type Metric struct {
	Name        string   `json:"name"`
	Value       string   `json:"value"`
	Numeric     *float64 `json:"numeric,omitempty"`
	Unit        string   `json:"unit,omitempty"`
	Group       string   `json:"group,omitempty"`
	Description string   `json:"description,omitempty"`
}

type Finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Path     string `json:"path"`
	Message  string `json:"message"`
	Detail   string `json:"detail,omitempty"`
}

type Process struct {
	PID      int    `json:"pid"`
	Name     string `json:"name,omitempty"`
	State    string `json:"state,omitempty"`
	UID      string `json:"uid,omitempty"`
	Command  string `json:"command,omitempty"`
	RSSBytes uint64 `json:"rss_bytes,omitempty"`
}

type Node struct {
	Path           string            `json:"path"`
	Parent         string            `json:"parent,omitempty"`
	Depth          int               `json:"depth"`
	Name           string            `json:"name"`
	Controllers    []string          `json:"controllers,omitempty"`
	SubtreeControl []string          `json:"subtree_control,omitempty"`
	Type           string            `json:"type,omitempty"`
	Processes      []Process         `json:"processes,omitempty"`
	PIDs           []int             `json:"pids,omitempty"`
	Metrics        []Metric          `json:"metrics,omitempty"`
	Raw            map[string]string `json:"raw,omitempty"`
	Findings       []Finding         `json:"findings,omitempty"`
	Errors         []string          `json:"errors,omitempty"`
}

type Summary struct {
	Nodes           int            `json:"nodes"`
	Processes       int            `json:"processes"`
	UniqueProcesses int            `json:"unique_processes"`
	Metrics         int            `json:"metrics"`
	Findings        map[string]int `json:"findings"`
	Errors          int            `json:"errors"`
	DurationMillis  int64          `json:"duration_millis"`
}

type Report struct {
	Schema        string    `json:"schema"`
	GeneratedAt   time.Time `json:"generated_at"`
	Hostname      string    `json:"hostname"`
	Kernel        string    `json:"kernel"`
	GoVersion     string    `json:"go_version"`
	Root          string    `json:"root"`
	CgroupVersion string    `json:"cgroup_version"`
	Options       Options   `json:"options"`
	Summary       Summary   `json:"summary"`
	Nodes         []Node    `json:"nodes"`
	Findings      []Finding `json:"findings"`
	Errors        []string  `json:"errors,omitempty"`
	Fingerprint   string    `json:"fingerprint"`
}

type Options struct {
	Root         string        `json:"root"`
	ProcRoot     string        `json:"proc_root"`
	Path         string        `json:"path"`
	Format       string        `json:"format"`
	Output       string        `json:"output,omitempty"`
	MaxDepth     int           `json:"max_depth"`
	MaxNodes     int           `json:"max_nodes"`
	MaxPIDs      int           `json:"max_pids"`
	MaxFileBytes int64         `json:"max_file_bytes"`
	Timeout      time.Duration `json:"timeout"`
	Processes    bool          `json:"processes"`
	Raw          bool          `json:"raw"`
	All          bool          `json:"all"`
	Hidden       bool          `json:"hidden"`
	Strict       bool          `json:"strict"`
	Sort         string        `json:"sort"`
	Filter       string        `json:"filter,omitempty"`
	Severity     string        `json:"severity"`
	Baseline     string        `json:"baseline,omitempty"`
	SaveBaseline string        `json:"save_baseline,omitempty"`
	ShowCatalog  bool          `json:"show_catalog"`
	ShowTree     bool          `json:"tree"`
	Top          int           `json:"top"`
}

type Collector struct {
	opts    Options
	specs   map[string]MetricSpec
	filter  *regexp.Regexp
	report  Report
	seen    map[int]bool
	started time.Time
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "cgroup-auditor:", err)
		os.Exit(1)
	}
}

func run(args []string, out, errout io.Writer) error {
	opts, err := parseOptions(args, errout)
	if err != nil {
		return err
	}
	if opts.ShowCatalog {
		return printCatalog(out, opts.Format)
	}
	if opts.Format == "help" {
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	c, err := newCollector(opts)
	if err != nil {
		return err
	}
	report := c.collect(ctx)
	if opts.Baseline != "" {
		findings, err := compareBaseline(opts.Baseline, report)
		if err != nil {
			return err
		}
		report.Findings = append(report.Findings, findings...)
		for i := range report.Nodes {
			for _, f := range findings {
				if f.Path == report.Nodes[i].Path {
					report.Nodes[i].Findings = append(report.Nodes[i].Findings, f)
				}
			}
		}
	}
	finalize(&report, c.started)
	if opts.SaveBaseline != "" {
		if err := writeJSONAtomic(opts.SaveBaseline, report); err != nil {
			return err
		}
	}
	if opts.Output != "" {
		var b bytes.Buffer
		if err := render(&b, report, opts); err != nil {
			return err
		}
		return writeAtomic(opts.Output, b.Bytes(), 0644)
	}
	if err := render(out, report, opts); err != nil {
		return err
	}
	if opts.Strict && (report.Summary.Findings["critical"] > 0 || report.Summary.Errors > 0) {
		return errors.New("strict mode: critical findings or collection errors")
	}
	return nil
}

func parseOptions(args []string, errout io.Writer) (Options, error) {
	o := Options{}
	f := flag.NewFlagSet("cgroup-auditor", flag.ContinueOnError)
	f.SetOutput(errout)
	f.StringVar(&o.Root, "root", "/sys/fs/cgroup", "cgroup v2 filesystem mount")
	f.StringVar(&o.ProcRoot, "proc", "/proc", "procfs mount")
	f.StringVar(&o.Path, "path", "/", "subtree path within cgroup mount")
	f.StringVar(&o.Format, "format", "text", "text, json, ndjson, csv, tree")
	f.StringVar(&o.Output, "output", "", "write output atomically to file")
	f.IntVar(&o.MaxDepth, "max-depth", 16, "maximum subtree depth")
	f.IntVar(&o.MaxNodes, "max-nodes", 5000, "maximum cgroup directories")
	f.IntVar(&o.MaxPIDs, "max-pids", 128, "maximum PIDs per cgroup")
	f.Int64Var(&o.MaxFileBytes, "max-file-bytes", 1048576, "maximum bytes read from any cgroup file")
	f.DurationVar(&o.Timeout, "timeout", 30*time.Second, "collection timeout")
	f.BoolVar(&o.Processes, "processes", false, "include process details from procfs")
	f.BoolVar(&o.Raw, "raw", false, "include raw cgroup file content")
	f.BoolVar(&o.All, "all", false, "read additional cgroup diagnostic files")
	f.BoolVar(&o.Hidden, "hidden", false, "include hidden directories")
	f.BoolVar(&o.Strict, "strict", false, "fail if critical findings or collection errors occur")
	f.StringVar(&o.Sort, "sort", "path", "path, memory, cpu, pids, findings")
	f.StringVar(&o.Filter, "filter", "", "regular expression matching cgroup paths")
	f.StringVar(&o.Severity, "severity", "info", "minimum finding severity: info, warning, critical")
	f.StringVar(&o.Baseline, "compare", "", "compare report against saved JSON baseline")
	f.StringVar(&o.SaveBaseline, "save-baseline", "", "save complete report to JSON")
	f.BoolVar(&o.ShowCatalog, "catalog", false, "display built-in metric catalog")
	f.BoolVar(&o.ShowTree, "tree", false, "show hierarchy in text output")
	f.IntVar(&o.Top, "top", 0, "limit rendered nodes (0 means all)")
	f.Usage = func() {
		fmt.Fprintln(errout, "cgroup-auditor: read-only Linux cgroup v2 inspection and diagnostics")
		fmt.Fprintln(errout, "Usage: cgroup-auditor [options]")
		f.PrintDefaults()
	}
	if err := f.Parse(args); err != nil {
		return o, err
	}
	if len(f.Args()) > 0 {
		return o, fmt.Errorf("unexpected positional arguments: %v", f.Args())
	}
	if o.MaxDepth < 0 || o.MaxNodes < 1 || o.MaxPIDs < 0 || o.MaxFileBytes < 64 || o.Timeout <= 0 || o.Top < 0 {
		return o, errors.New("invalid numeric limit")
	}
	switch o.Format {
	case "text", "json", "ndjson", "csv", "tree":
	default:
		return o, fmt.Errorf("unsupported format %q", o.Format)
	}
	switch o.Sort {
	case "path", "memory", "cpu", "pids", "findings":
	default:
		return o, fmt.Errorf("unsupported sort %q", o.Sort)
	}
	if severityRank(o.Severity) < 0 {
		return o, fmt.Errorf("unsupported severity %q", o.Severity)
	}
	o.Root = filepath.Clean(o.Root)
	o.ProcRoot = filepath.Clean(o.ProcRoot)
	o.Path = filepath.Clean("/" + strings.TrimPrefix(o.Path, "/"))
	return o, nil
}

func newCollector(o Options) (*Collector, error) {
	var filter *regexp.Regexp
	if o.Filter != "" {
		var err error
		filter, err = regexp.Compile(o.Filter)
		if err != nil {
			return nil, fmt.Errorf("invalid filter: %w", err)
		}
	}
	specs := make(map[string]MetricSpec)
	for _, spec := range metricCatalog() {
		specs[spec.File+":"+spec.Key] = spec
	}
	return &Collector{opts: o, specs: specs, filter: filter, seen: make(map[int]bool), started: time.Now()}, nil
}

func (c *Collector) collect(ctx context.Context) Report {
	host, _ := os.Hostname()
	r := Report{Schema: "cgroup-auditor/v1", GeneratedAt: time.Now().UTC(), Hostname: host, Kernel: kernelRelease(), GoVersion: runtime.Version(), Root: c.opts.Root, CgroupVersion: "unknown", Options: c.opts, Nodes: []Node{}, Findings: []Finding{}}
	c.report = r
	if _, err := os.Stat(filepath.Join(c.opts.Root, "cgroup.controllers")); err != nil {
		c.report.Errors = append(c.report.Errors, "cgroup v2 controllers unavailable: "+err.Error())
		return c.report
	}
	c.report.CgroupVersion = "v2"
	start, err := secureSubpath(c.opts.Root, c.opts.Path)
	if err != nil {
		c.report.Errors = append(c.report.Errors, err.Error())
		return c.report
	}
	if _, err := os.Stat(start); err != nil {
		c.report.Errors = append(c.report.Errors, err.Error())
		return c.report
	}
	type pending struct {
		full     string
		relative string
		depth    int
		parent   string
	}
	queue := []pending{{full: start, relative: c.opts.Path, depth: 0}}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			c.report.Errors = append(c.report.Errors, "collection interrupted: "+err.Error())
			break
		}
		if len(c.report.Nodes) >= c.opts.MaxNodes {
			c.report.Errors = append(c.report.Errors, "maximum node count reached")
			break
		}
		item := queue[0]
		queue = queue[1:]
		node := c.readNode(ctx, item.full, item.relative, item.parent, item.depth)
		if c.filter == nil || c.filter.MatchString(node.Path) {
			c.report.Nodes = append(c.report.Nodes, node)
		}
		if item.depth >= c.opts.MaxDepth {
			continue
		}
		entries, err := os.ReadDir(item.full)
		if err != nil {
			c.report.Errors = append(c.report.Errors, fmt.Sprintf("%s: %v", item.relative, err))
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			if !c.opts.Hidden && strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			childFull := filepath.Join(item.full, entry.Name())
			if entry.Type()&os.ModeSymlink != 0 {
				continue
			}
			childRel := filepath.Join(item.relative, entry.Name())
			queue = append(queue, pending{full: childFull, relative: childRel, parent: item.relative, depth: item.depth + 1})
		}
	}
	return c.report
}

func secureSubpath(root, path string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	joined := filepath.Join(rootAbs, strings.TrimPrefix(filepath.Clean("/"+path), "/"))
	rel, err := filepath.Rel(rootAbs, joined)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("path escapes cgroup root")
	}
	current := rootAbs
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		if part == "." || part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink not allowed in cgroup path: %s", current)
		}
	}
	return joined, nil
}

var baseFiles = []string{
	"cgroup.controllers", "cgroup.subtree_control", "cgroup.type", "cgroup.events", "cgroup.stat", "cgroup.max.depth", "cgroup.max.descendants", "cgroup.freeze",
	"cpu.stat", "cpu.max", "cpu.max.burst", "cpu.weight", "cpu.weight.nice", "cpu.pressure", "cpu.uclamp.min", "cpu.uclamp.max", "cpu.idle",
	"memory.current", "memory.min", "memory.low", "memory.high", "memory.max", "memory.peak", "memory.events", "memory.events.local", "memory.stat", "memory.numa_stat", "memory.pressure", "memory.swap.current", "memory.swap.high", "memory.swap.max", "memory.swap.peak", "memory.swap.events", "memory.zswap.current", "memory.zswap.max", "memory.oom.group",
	"io.stat", "io.max", "io.weight", "io.pressure", "io.latency", "io.cost.qos", "io.cost.model",
	"pids.current", "pids.max", "pids.events", "pids.peak",
	"cpuset.cpus", "cpuset.cpus.effective", "cpuset.cpus.partition", "cpuset.mems", "cpuset.mems.effective", "cpuset.cpus.exclusive", "cpuset.cpus.exclusive.effective",
	"hugetlb.2MB.current", "hugetlb.2MB.max", "hugetlb.2MB.events", "hugetlb.1GB.current", "hugetlb.1GB.max", "hugetlb.1GB.events",
	"rdma.current", "rdma.max", "misc.current", "misc.max", "misc.events", "dmem.current", "dmem.max",
}
var extraFiles = []string{"cgroup.threads", "cgroup.procs", "cgroup.kill", "cgroup.pressure", "memory.reclaim", "memory.oom_control", "cpu.stat.local", "io.stat.local", "memory.stat.local", "cgroup.stat.local"}
var readUnsafe = map[string]bool{"cgroup.kill": true, "memory.reclaim": true, "memory.oom_control": true}

func (c *Collector) readNode(ctx context.Context, full, relative, parent string, depth int) Node {
	n := Node{Path: relative, Parent: parent, Depth: depth, Name: filepath.Base(relative), Metrics: []Metric{}, Findings: []Finding{}}
	if relative == "/" {
		n.Name = "/"
	}
	if c.opts.Raw {
		n.Raw = make(map[string]string)
	}
	files := append([]string{}, baseFiles...)
	if c.opts.All {
		files = append(files, extraFiles...)
	}
	for _, name := range files {
		if ctx.Err() != nil {
			n.Errors = append(n.Errors, ctx.Err().Error())
			break
		}
		if readUnsafe[name] {
			continue
		}
		content, err := readBounded(filepath.Join(full, name), c.opts.MaxFileBytes)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENODEV) && !errors.Is(err, syscall.EOPNOTSUPP) {
				n.Errors = append(n.Errors, name+": "+err.Error())
			}
			continue
		}
		if c.opts.Raw {
			n.Raw[name] = content
		}
		switch name {
		case "cgroup.controllers":
			n.Controllers = strings.Fields(content)
		case "cgroup.subtree_control":
			n.SubtreeControl = strings.Fields(content)
		case "cgroup.type":
			n.Type = strings.TrimSpace(content)
		}
		n.Metrics = append(n.Metrics, c.parseMetrics(name, content)...)
	}
	pids, err := readPIDList(filepath.Join(full, "cgroup.procs"), c.opts.MaxPIDs, c.opts.MaxFileBytes)
	if err == nil {
		n.PIDs = pids
		if c.opts.Processes {
			for _, pid := range pids {
				n.Processes = append(n.Processes, readProcess(c.opts.ProcRoot, pid))
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		n.Errors = append(n.Errors, "cgroup.procs: "+err.Error())
	}
	n.Findings = append(n.Findings, assessNode(n)...)
	return n
}

func readBounded(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(b)) > limit {
		return "", fmt.Errorf("file exceeds %d bytes", limit)
	}
	return string(b), nil
}

func readPIDList(path string, max int, limit int64) ([]int, error) {
	s, err := readBounded(path, limit)
	if err != nil {
		return nil, err
	}
	result := make([]int, 0)
	for _, field := range strings.Fields(s) {
		if len(result) >= max {
			break
		}
		pid, err := strconv.Atoi(field)
		if err == nil && pid > 0 {
			result = append(result, pid)
		}
	}
	sort.Ints(result)
	return result, nil
}

func readProcess(proc string, pid int) Process {
	p := Process{PID: pid}
	status, err := readBounded(filepath.Join(proc, strconv.Itoa(pid), "status"), 65536)
	if err == nil {
		for _, line := range strings.Split(status, "\n") {
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			value = strings.TrimSpace(value)
			switch key {
			case "Name":
				p.Name = value
			case "State":
				p.State = value
			case "Uid":
				parts := strings.Fields(value)
				if len(parts) > 0 {
					p.UID = parts[0]
				}
			case "VmRSS":
				parts := strings.Fields(value)
				if len(parts) > 0 {
					v, _ := strconv.ParseUint(parts[0], 10, 64)
					p.RSSBytes = v * 1024
				}
			}
		}
	}
	cmd, err := readBounded(filepath.Join(proc, strconv.Itoa(pid), "cmdline"), 65536)
	if err == nil {
		p.Command = strings.TrimSpace(strings.ReplaceAll(cmd, "\x00", " "))
	}
	return p
}

func (c *Collector) parseMetrics(file, content string) []Metric {
	result := []Metric{}
	content = strings.TrimSpace(content)
	if content == "" {
		return result
	}
	if strings.HasSuffix(file, ".pressure") || file == "cgroup.pressure" {
		for _, line := range strings.Split(content, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			for _, token := range fields[1:] {
				key, value, ok := strings.Cut(token, "=")
				if !ok {
					continue
				}
				result = append(result, c.metric(file, fields[0]+"."+key, value))
			}
		}
		return result
	}
	if file == "cpu.max" {
		fields := strings.Fields(content)
		if len(fields) > 0 {
			result = append(result, c.metric(file, "quota", fields[0]))
		}
		if len(fields) > 1 {
			result = append(result, c.metric(file, "period", fields[1]))
		}
		return result
	}
	if strings.HasSuffix(file, ".max") && (file == "io.max" || file == "rdma.max" || file == "dmem.max") {
		for _, line := range strings.Split(content, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			for _, token := range fields[1:] {
				key, value, ok := strings.Cut(token, "=")
				if ok {
					result = append(result, c.metric(file, fields[0]+"."+key, value))
				}
			}
		}
		return result
	}
	if file == "io.stat" || file == "io.stat.local" || file == "io.weight" || file == "rdma.current" || file == "misc.current" || file == "misc.max" || file == "dmem.current" || file == "io.cost.qos" || file == "io.cost.model" {
		for _, line := range strings.Split(content, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if len(fields) == 1 {
				result = append(result, c.metric(file, "value", fields[0]))
				continue
			}
			for _, token := range fields[1:] {
				key, value, ok := strings.Cut(token, "=")
				if ok {
					result = append(result, c.metric(file, fields[0]+"."+key, value))
				} else {
					result = append(result, c.metric(file, fields[0], token))
				}
			}
		}
		return result
	}
	if strings.HasSuffix(file, ".stat") || strings.HasSuffix(file, ".events") || strings.HasSuffix(file, ".events.local") || strings.HasSuffix(file, ".numa_stat") || strings.HasSuffix(file, ".stat.local") {
		for _, line := range strings.Split(content, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			if strings.Contains(fields[1], "=") {
				for _, token := range fields[1:] {
					key, value, ok := strings.Cut(token, "=")
					if ok {
						result = append(result, c.metric(file, fields[0]+"."+key, value))
					}
				}
			} else {
				result = append(result, c.metric(file, fields[0], fields[1]))
			}
		}
		return result
	}
	if strings.Contains(content, "\n") {
		for i, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			result = append(result, c.metric(file, fmt.Sprintf("line.%d", i), line))
		}
		return result
	}
	result = append(result, c.metric(file, "value", content))
	return result
}

func (c *Collector) metric(file, key, value string) Metric {
	spec, ok := c.specs[file+":"+key]
	if !ok {
		spec = MetricSpec{File: file, Key: key, Group: strings.Split(file, ".")[0], Kind: "gauge", Unit: "raw", Description: "Kernel-exported cgroup metric"}
	}
	m := Metric{Name: file + ":" + key, Value: value, Unit: spec.Unit, Group: spec.Group, Description: spec.Description}
	if value != "max" {
		if v, err := strconv.ParseFloat(value, 64); err == nil && !math.IsNaN(v) && !math.IsInf(v, 0) {
			m.Numeric = &v
		}
	}
	return m
}

func metricValue(n Node, name string) (float64, bool) {
	for _, m := range n.Metrics {
		if m.Name == name && m.Numeric != nil {
			return *m.Numeric, true
		}
	}
	return 0, false
}
func metricText(n Node, name string) string {
	for _, m := range n.Metrics {
		if m.Name == name {
			return m.Value
		}
	}
	return ""
}
func finding(severity, code, path, message, detail string) Finding {
	return Finding{Severity: severity, Code: code, Path: path, Message: message, Detail: detail}
}

func assessNode(n Node) []Finding {
	out := []Finding{}
	if n.Type == "domain invalid" {
		out = append(out, finding("critical", "CGROUP_INVALID_TYPE", n.Path, "Invalid cgroup domain state", "Inspect threaded/domain transitions"))
	}
	if n.Type == "domain threaded" {
		out = append(out, finding("info", "CGROUP_THREADED_DOMAIN", n.Path, "Threaded domain cgroup", "Threaded subtree semantics apply"))
	}
	if v, ok := metricValue(n, "memory.events:oom_kill"); ok && v > 0 {
		out = append(out, finding("warning", "MEMORY_OOM_KILL", n.Path, "OOM kills recorded", fmt.Sprintf("oom_kill=%g (cumulative)", v)))
	}
	if v, ok := metricValue(n, "memory.events:oom"); ok && v > 0 {
		out = append(out, finding("warning", "MEMORY_OOM", n.Path, "Memory OOM events recorded", fmt.Sprintf("oom=%g (cumulative)", v)))
	}
	if v, ok := metricValue(n, "memory.events:high"); ok && v > 0 {
		out = append(out, finding("info", "MEMORY_HIGH_EVENTS", n.Path, "Memory high boundary crossed", fmt.Sprintf("high=%g (cumulative)", v)))
	}
	if v, ok := metricValue(n, "pids.events:max"); ok && v > 0 {
		out = append(out, finding("warning", "PIDS_MAX_EVENTS", n.Path, "PID limit hits recorded", fmt.Sprintf("max=%g (cumulative)", v)))
	}
	if v, ok := metricValue(n, "cgroup.events:frozen"); ok && v == 1 {
		out = append(out, finding("info", "CGROUP_FROZEN", n.Path, "Cgroup is frozen", ""))
	}
	if v, ok := metricValue(n, "cgroup.events:populated"); ok && v == 0 && n.Depth > 0 {
		out = append(out, finding("info", "CGROUP_EMPTY", n.Path, "Cgroup is not populated", ""))
	}
	for _, pair := range [][3]string{{"memory.current:value", "memory.max:value", "MEMORY_LIMIT_NEAR"}, {"memory.swap.current:value", "memory.swap.max:value", "SWAP_LIMIT_NEAR"}, {"pids.current:value", "pids.max:value", "PIDS_LIMIT_NEAR"}} {
		current, ok1 := metricValue(n, pair[0])
		limit, ok2 := metricValue(n, pair[1])
		if ok1 && ok2 && limit > 0 && current/limit >= 0.9 {
			sev := "warning"
			if current >= limit {
				sev = "critical"
			}
			out = append(out, finding(sev, pair[2], n.Path, "Resource usage near configured limit", fmt.Sprintf("%.1f%% of limit", current/limit*100)))
		}
	}
	for _, scope := range []string{"cpu", "memory", "io"} {
		for _, kind := range []string{"some", "full"} {
			key := scope + ".pressure:" + kind + ".avg10"
			if v, ok := metricValue(n, key); ok && v >= 20 {
				sev := "warning"
				if v >= 50 {
					sev = "critical"
				}
				out = append(out, finding(sev, "PRESSURE_"+strings.ToUpper(scope)+"_"+strings.ToUpper(kind), n.Path, "Elevated recent resource pressure", fmt.Sprintf("%s avg10=%.2f%%", scope, v)))
			}
		}
	}
	return out
}

func severityRank(s string) int {
	switch s {
	case "info":
		return 0
	case "warning":
		return 1
	case "critical":
		return 2
	default:
		return -1
	}
}
func finalize(r *Report, started time.Time) {
	r.Summary = Summary{Findings: map[string]int{"info": 0, "warning": 0, "critical": 0}, DurationMillis: time.Since(started).Milliseconds()}
	unique := map[int]bool{}
	for i := range r.Nodes {
		n := &r.Nodes[i]
		r.Summary.Nodes++
		r.Summary.Processes += len(n.PIDs)
		r.Summary.Metrics += len(n.Metrics)
		r.Summary.Errors += len(n.Errors)
		for _, pid := range n.PIDs {
			unique[pid] = true
		}
		for _, f := range n.Findings {
			r.Summary.Findings[f.Severity]++
		}
	}
	r.Summary.UniqueProcesses = len(unique)
	r.Summary.Errors += len(r.Errors)
	for _, f := range r.Findings {
		r.Summary.Findings[f.Severity]++
	}
	r.Fingerprint = fingerprint(*r)
}
func fingerprint(r Report) string {
	type entry struct {
		Path    string
		Metrics []Metric
		PIDs    []int
	}
	items := make([]entry, 0, len(r.Nodes))
	for _, n := range r.Nodes {
		items = append(items, entry{n.Path, n.Metrics, n.PIDs})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	b, _ := json.Marshal(items)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}

func compareBaseline(path string, now Report) ([]Finding, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var old Report
	if err := json.Unmarshal(b, &old); err != nil {
		return nil, fmt.Errorf("invalid baseline: %w", err)
	}
	if old.Schema != "cgroup-auditor/v1" {
		return nil, fmt.Errorf("unsupported baseline schema %q", old.Schema)
	}
	oldNodes := map[string]Node{}
	newNodes := map[string]Node{}
	for _, n := range old.Nodes {
		oldNodes[n.Path] = n
	}
	for _, n := range now.Nodes {
		newNodes[n.Path] = n
	}
	out := []Finding{}
	for path, n := range newNodes {
		prev, ok := oldNodes[path]
		if !ok {
			out = append(out, finding("info", "NODE_ADDED", path, "Cgroup added since baseline", ""))
			continue
		}
		before := map[string]string{}
		for _, m := range prev.Metrics {
			before[m.Name] = m.Value
		}
		for _, m := range n.Metrics {
			oldValue, ok := before[m.Name]
			if !ok {
				continue
			}
			if oldValue == m.Value {
				continue
			}
			if strings.HasSuffix(m.Name, ":value") && (strings.Contains(m.Name, ".max") || strings.Contains(m.Name, ".high") || strings.Contains(m.Name, ".low") || strings.Contains(m.Name, ".min")) {
				out = append(out, finding("warning", "RESOURCE_LIMIT_CHANGED", path, "Resource configuration changed", m.Name+": "+oldValue+" -> "+m.Value))
			}
		}
		if strings.Join(prev.Controllers, ",") != strings.Join(n.Controllers, ",") {
			out = append(out, finding("info", "CONTROLLERS_CHANGED", path, "Available controllers changed", ""))
		}
		if strings.Join(prev.SubtreeControl, ",") != strings.Join(n.SubtreeControl, ",") {
			out = append(out, finding("warning", "DELEGATION_CHANGED", path, "Subtree controller delegation changed", ""))
		}
	}
	for path := range oldNodes {
		if _, ok := newNodes[path]; !ok {
			out = append(out, finding("info", "NODE_REMOVED", path, "Cgroup removed since baseline", ""))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].Code < out[j].Code
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

func writeJSONAtomic(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(b, '\n'), 0644)
}
func writeAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".cgroup-auditor-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func render(w io.Writer, r Report, o Options) error {
	switch o.Format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "ndjson":
		return renderNDJSON(w, r, o)
	case "csv":
		return renderCSV(w, r, o)
	case "tree":
		return renderTree(w, r, o)
	default:
		return renderText(w, r, o)
	}
}
func sortedNodes(r Report, o Options) []Node {
	nodes := append([]Node{}, r.Nodes...)
	score := func(n Node) float64 {
		switch o.Sort {
		case "memory":
			v, _ := metricValue(n, "memory.current:value")
			return v
		case "cpu":
			v, _ := metricValue(n, "cpu.stat:usage_usec")
			return v
		case "pids":
			v, _ := metricValue(n, "pids.current:value")
			return v
		case "findings":
			return float64(len(n.Findings))
		}
		return 0
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if o.Sort == "path" {
			return nodes[i].Path < nodes[j].Path
		}
		a, b := score(nodes[i]), score(nodes[j])
		if a == b {
			return nodes[i].Path < nodes[j].Path
		}
		return a > b
	})
	if o.Top > 0 && len(nodes) > o.Top {
		nodes = nodes[:o.Top]
	}
	return nodes
}
func renderText(w io.Writer, r Report, o Options) error {
	fmt.Fprintf(w, "CGROUP AUDITOR  %s\n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "Host: %s  Kernel: %s  Version: %s\n", r.Hostname, r.Kernel, r.CgroupVersion)
	fmt.Fprintf(w, "Root: %s  Nodes: %d  Processes: %d  Metrics: %d  Errors: %d\n", r.Root, r.Summary.Nodes, r.Summary.UniqueProcesses, r.Summary.Metrics, r.Summary.Errors)
	fmt.Fprintf(w, "Findings: critical=%d warning=%d info=%d\n\n", r.Summary.Findings["critical"], r.Summary.Findings["warning"], r.Summary.Findings["info"])
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CGROUP\tPIDS\tMEMORY\tCPU USEC\tFINDINGS")
	for _, n := range sortedNodes(r, o) {
		memory, _ := metricValue(n, "memory.current:value")
		cpu, _ := metricValue(n, "cpu.stat:usage_usec")
		fmt.Fprintf(tw, "%s\t%d\t%s\t%.0f\t%d\n", n.Path, len(n.PIDs), humanBytes(memory), cpu, len(n.Findings))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if o.ShowTree {
		fmt.Fprintln(w)
		if err := renderTree(w, r, o); err != nil {
			return err
		}
	}
	findings := collectFindings(r, o.Severity)
	if len(findings) > 0 {
		fmt.Fprintln(w, "\nFINDINGS")
		for _, f := range findings {
			fmt.Fprintf(w, "[%s] %s %s: %s", strings.ToUpper(f.Severity), f.Code, f.Path, f.Message)
			if f.Detail != "" {
				fmt.Fprintf(w, " (%s)", f.Detail)
			}
			fmt.Fprintln(w)
		}
	}
	for _, err := range r.Errors {
		fmt.Fprintln(w, "ERROR:", err)
	}
	return nil
}
func humanBytes(v float64) string {
	if v < 1024 {
		return fmt.Sprintf("%.0f B", v)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	i := -1
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}
func collectFindings(r Report, min string) []Finding {
	out := []Finding{}
	rank := severityRank(min)
	for _, n := range r.Nodes {
		for _, f := range n.Findings {
			if severityRank(f.Severity) >= rank {
				out = append(out, f)
			}
		}
	}
	for _, f := range r.Findings {
		if severityRank(f.Severity) >= rank {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return severityRank(out[i].Severity) > severityRank(out[j].Severity)
		}
		return out[i].Path < out[j].Path
	})
	return out
}
func renderTree(w io.Writer, r Report, o Options) error {
	nodes := append([]Node{}, r.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Path < nodes[j].Path })
	for _, n := range nodes {
		indent := strings.Repeat("  ", n.Depth)
		_, err := fmt.Fprintf(w, "%s%s  [pids=%d findings=%d]\n", indent, n.Name, len(n.PIDs), len(n.Findings))
		if err != nil {
			return err
		}
	}
	return nil
}
func renderNDJSON(w io.Writer, r Report, o Options) error {
	enc := json.NewEncoder(w)
	if err := enc.Encode(map[string]any{"type": "header", "schema": r.Schema, "generated_at": r.GeneratedAt, "hostname": r.Hostname, "summary": r.Summary}); err != nil {
		return err
	}
	for _, n := range sortedNodes(r, o) {
		if err := enc.Encode(map[string]any{"type": "node", "data": n}); err != nil {
			return err
		}
	}
	for _, f := range collectFindings(r, o.Severity) {
		if err := enc.Encode(map[string]any{"type": "finding", "data": f}); err != nil {
			return err
		}
	}
	return nil
}
func renderCSV(w io.Writer, r Report, o Options) error {
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{"path", "depth", "pid_count", "memory_bytes", "cpu_usage_usec", "pids_current", "findings", "errors", "controllers", "type"}); err != nil {
		return err
	}
	for _, n := range sortedNodes(r, o) {
		memory, _ := metricValue(n, "memory.current:value")
		cpu, _ := metricValue(n, "cpu.stat:usage_usec")
		pids, _ := metricValue(n, "pids.current:value")
		if err := writer.Write([]string{n.Path, strconv.Itoa(n.Depth), strconv.Itoa(len(n.PIDs)), strconv.FormatFloat(memory, 'f', 0, 64), strconv.FormatFloat(cpu, 'f', 0, 64), strconv.FormatFloat(pids, 'f', 0, 64), strconv.Itoa(len(n.Findings)), strconv.Itoa(len(n.Errors)), strings.Join(n.Controllers, " "), n.Type}); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}
func printCatalog(w io.Writer, format string) error {
	specs := metricCatalog()
	sort.Slice(specs, func(i, j int) bool {
		if specs[i].File == specs[j].File {
			return specs[i].Key < specs[j].Key
		}
		return specs[i].File < specs[j].File
	})
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(specs)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "FILE\tKEY\tUNIT\tGROUP\tDESCRIPTION")
	for _, s := range specs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.File, s.Key, s.Unit, s.Group, s.Description)
	}
	return tw.Flush()
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func scanLines(reader io.Reader, fn func(string) error) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	for scanner.Scan() {
		if err := fn(scanner.Text()); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func metricCatalog() []MetricSpec {
	return []MetricSpec{
		{
			File:        "cgroup.events",
			Key:         "populated",
			Unit:        "count",
			Group:       "cgroup",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cgroup kernel metric populated reported by cgroup.events",
		},
		{
			File:        "cgroup.events",
			Key:         "frozen",
			Unit:        "count",
			Group:       "cgroup",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cgroup kernel metric frozen reported by cgroup.events",
		},
		{
			File:        "cgroup.stat",
			Key:         "nr_descendants",
			Unit:        "count",
			Group:       "cgroup",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cgroup kernel metric nr descendants reported by cgroup.stat",
		},
		{
			File:        "cgroup.stat",
			Key:         "nr_dying_descendants",
			Unit:        "count",
			Group:       "cgroup",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cgroup kernel metric nr dying descendants reported by cgroup.stat",
		},
		{
			File:        "cgroup.stat",
			Key:         "nr_subsys_cpu",
			Unit:        "count",
			Group:       "cgroup",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cgroup kernel metric nr subsys cpu reported by cgroup.stat",
		},
		{
			File:        "cgroup.stat",
			Key:         "nr_subsys_cpuset",
			Unit:        "count",
			Group:       "cgroup",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cgroup kernel metric nr subsys cpuset reported by cgroup.stat",
		},
		{
			File:        "cgroup.stat",
			Key:         "nr_subsys_io",
			Unit:        "count",
			Group:       "cgroup",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cgroup kernel metric nr subsys io reported by cgroup.stat",
		},
		{
			File:        "cgroup.stat",
			Key:         "nr_subsys_memory",
			Unit:        "count",
			Group:       "cgroup",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cgroup kernel metric nr subsys memory reported by cgroup.stat",
		},
		{
			File:        "cgroup.stat",
			Key:         "nr_subsys_pids",
			Unit:        "count",
			Group:       "cgroup",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cgroup kernel metric nr subsys pids reported by cgroup.stat",
		},
		{
			File:        "cgroup.stat.local",
			Key:         "nr_descendants",
			Unit:        "count",
			Group:       "cgroup",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cgroup kernel metric nr descendants reported by cgroup.stat.local",
		},
		{
			File:        "cgroup.stat.local",
			Key:         "nr_dying_descendants",
			Unit:        "count",
			Group:       "cgroup",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cgroup kernel metric nr dying descendants reported by cgroup.stat.local",
		},
		{
			File:        "cpu.stat",
			Key:         "usage_usec",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric usage usec reported by cpu.stat",
		},
		{
			File:        "cpu.stat",
			Key:         "user_usec",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric user usec reported by cpu.stat",
		},
		{
			File:        "cpu.stat",
			Key:         "system_usec",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric system usec reported by cpu.stat",
		},
		{
			File:        "cpu.stat",
			Key:         "nr_periods",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric nr periods reported by cpu.stat",
		},
		{
			File:        "cpu.stat",
			Key:         "nr_throttled",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric nr throttled reported by cpu.stat",
		},
		{
			File:        "cpu.stat",
			Key:         "throttled_usec",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric throttled usec reported by cpu.stat",
		},
		{
			File:        "cpu.stat",
			Key:         "nr_bursts",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric nr bursts reported by cpu.stat",
		},
		{
			File:        "cpu.stat",
			Key:         "burst_usec",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric burst usec reported by cpu.stat",
		},
		{
			File:        "cpu.stat",
			Key:         "nr_wait",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric nr wait reported by cpu.stat",
		},
		{
			File:        "cpu.stat",
			Key:         "nr_migrations",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric nr migrations reported by cpu.stat",
		},
		{
			File:        "cpu.stat.local",
			Key:         "usage_usec",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric usage usec reported by cpu.stat.local",
		},
		{
			File:        "cpu.stat.local",
			Key:         "user_usec",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric user usec reported by cpu.stat.local",
		},
		{
			File:        "cpu.stat.local",
			Key:         "system_usec",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric system usec reported by cpu.stat.local",
		},
		{
			File:        "cpu.stat.local",
			Key:         "nr_periods",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric nr periods reported by cpu.stat.local",
		},
		{
			File:        "cpu.stat.local",
			Key:         "nr_throttled",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric nr throttled reported by cpu.stat.local",
		},
		{
			File:        "cpu.stat.local",
			Key:         "throttled_usec",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric throttled usec reported by cpu.stat.local",
		},
		{
			File:        "memory.events",
			Key:         "low",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric low reported by memory.events",
		},
		{
			File:        "memory.events",
			Key:         "high",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric high reported by memory.events",
		},
		{
			File:        "memory.events",
			Key:         "max",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric max reported by memory.events",
		},
		{
			File:        "memory.events",
			Key:         "oom",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric oom reported by memory.events",
		},
		{
			File:        "memory.events",
			Key:         "oom_kill",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric oom kill reported by memory.events",
		},
		{
			File:        "memory.events",
			Key:         "oom_group_kill",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric oom group kill reported by memory.events",
		},
		{
			File:        "memory.events.local",
			Key:         "low",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric low reported by memory.events.local",
		},
		{
			File:        "memory.events.local",
			Key:         "high",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric high reported by memory.events.local",
		},
		{
			File:        "memory.events.local",
			Key:         "max",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric max reported by memory.events.local",
		},
		{
			File:        "memory.events.local",
			Key:         "oom",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric oom reported by memory.events.local",
		},
		{
			File:        "memory.events.local",
			Key:         "oom_kill",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric oom kill reported by memory.events.local",
		},
		{
			File:        "memory.events.local",
			Key:         "oom_group_kill",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric oom group kill reported by memory.events.local",
		},
		{
			File:        "memory.swap.events",
			Key:         "high",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric high reported by memory.swap.events",
		},
		{
			File:        "memory.swap.events",
			Key:         "max",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric max reported by memory.swap.events",
		},
		{
			File:        "memory.swap.events",
			Key:         "fail",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric fail reported by memory.swap.events",
		},
		{
			File:        "pids.events",
			Key:         "max",
			Unit:        "count",
			Group:       "pids",
			Kind:        "counter",
			Severity:    "info",
			Description: "Pids kernel metric max reported by pids.events",
		},
		{
			File:        "hugetlb.2MB.events",
			Key:         "max",
			Unit:        "count",
			Group:       "hugetlb",
			Kind:        "counter",
			Severity:    "info",
			Description: "Hugetlb kernel metric max reported by hugetlb.2MB.events",
		},
		{
			File:        "hugetlb.1GB.events",
			Key:         "max",
			Unit:        "count",
			Group:       "hugetlb",
			Kind:        "counter",
			Severity:    "info",
			Description: "Hugetlb kernel metric max reported by hugetlb.1GB.events",
		},
		{
			File:        "misc.events",
			Key:         "max",
			Unit:        "count",
			Group:       "misc",
			Kind:        "counter",
			Severity:    "info",
			Description: "Misc kernel metric max reported by misc.events",
		},
		{
			File:        "memory.stat",
			Key:         "anon",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric anon reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "file",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric file reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "kernel",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric kernel reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "kernel_stack",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric kernel stack reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pagetables",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pagetables reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "sec_pagetables",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric sec pagetables reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "percpu",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric percpu reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "sock",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric sock reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "vmalloc",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric vmalloc reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "shmem",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric shmem reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "zswap",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric zswap reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "zswapped",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric zswapped reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "file_mapped",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric file mapped reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "file_dirty",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric file dirty reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "file_writeback",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric file writeback reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "swapcached",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric swapcached reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "anon_thp",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric anon thp reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "file_thp",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric file thp reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "shmem_thp",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric shmem thp reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "inactive_anon",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric inactive anon reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "active_anon",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric active anon reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "inactive_file",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric inactive file reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "active_file",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric active file reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "unevictable",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric unevictable reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "slab_reclaimable",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric slab reclaimable reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "slab_unreclaimable",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric slab unreclaimable reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "slab",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric slab reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "workingset_refault_anon",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric workingset refault anon reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "workingset_refault_file",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric workingset refault file reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "workingset_activate_anon",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric workingset activate anon reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "workingset_activate_file",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric workingset activate file reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "workingset_restore_anon",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric workingset restore anon reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "workingset_restore_file",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric workingset restore file reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "workingset_nodereclaim",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric workingset nodereclaim reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgdemote_kswapd",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgdemote kswapd reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgdemote_direct",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgdemote direct reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgdemote_khugepaged",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgdemote khugepaged reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgpromote_success",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgpromote success reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgscan",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgscan reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgscan_kswapd",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgscan kswapd reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgscan_direct",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgscan direct reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgscan_khugepaged",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgscan khugepaged reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgsteal",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgsteal reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgsteal_kswapd",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgsteal kswapd reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgsteal_direct",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgsteal direct reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgsteal_khugepaged",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgsteal khugepaged reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgfault",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgfault reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgmajfault",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgmajfault reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgrefill",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgrefill reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgactivate",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgactivate reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgdeactivate",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgdeactivate reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pglazyfree",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pglazyfree reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pglazyfreed",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pglazyfreed reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "thp_fault_alloc",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric thp fault alloc reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "thp_collapse_alloc",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric thp collapse alloc reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "thp_swpout",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric thp swpout reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "thp_swpout_fallback",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric thp swpout fallback reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "numa_pages_migrated",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric numa pages migrated reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "numa_pte_updates",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric numa pte updates reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "numa_hint_faults",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric numa hint faults reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "numa_hint_faults_local",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric numa hint faults local reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgscan_anon",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgscan anon reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgscan_file",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgscan file reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgsteal_anon",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgsteal anon reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgsteal_file",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgsteal file reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pswpin",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pswpin reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pswpout",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pswpout reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "allocstall",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric allocstall reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "allocstall_dma",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric allocstall dma reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "allocstall_dma32",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric allocstall dma32 reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "allocstall_normal",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric allocstall normal reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "allocstall_movable",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric allocstall movable reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "compact_fail",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric compact fail reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "compact_success",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric compact success reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "compact_stall",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric compact stall reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgmigrate_success",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgmigrate success reported by memory.stat",
		},
		{
			File:        "memory.stat",
			Key:         "pgmigrate_fail",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgmigrate fail reported by memory.stat",
		},
		{
			File:        "memory.stat.local",
			Key:         "anon",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric anon reported by memory.stat.local",
		},
		{
			File:        "memory.stat.local",
			Key:         "file",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric file reported by memory.stat.local",
		},
		{
			File:        "memory.stat.local",
			Key:         "kernel",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric kernel reported by memory.stat.local",
		},
		{
			File:        "memory.stat.local",
			Key:         "kernel_stack",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric kernel stack reported by memory.stat.local",
		},
		{
			File:        "memory.stat.local",
			Key:         "pagetables",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pagetables reported by memory.stat.local",
		},
		{
			File:        "memory.stat.local",
			Key:         "slab",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric slab reported by memory.stat.local",
		},
		{
			File:        "memory.stat.local",
			Key:         "pgfault",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgfault reported by memory.stat.local",
		},
		{
			File:        "memory.stat.local",
			Key:         "pgmajfault",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgmajfault reported by memory.stat.local",
		},
		{
			File:        "memory.stat.local",
			Key:         "pgscan",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgscan reported by memory.stat.local",
		},
		{
			File:        "memory.stat.local",
			Key:         "pgsteal",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgsteal reported by memory.stat.local",
		},
		{
			File:        "memory.numa_stat",
			Key:         "anon",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric anon reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "file",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric file reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "kernel",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric kernel reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "kernel_stack",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric kernel stack reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "pagetables",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pagetables reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "shmem",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric shmem reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "file_mapped",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric file mapped reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "file_dirty",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric file dirty reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "file_writeback",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric file writeback reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "swapcached",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric swapcached reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "anon_thp",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric anon thp reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "file_thp",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric file thp reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "shmem_thp",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric shmem thp reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "inactive_anon",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric inactive anon reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "active_anon",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric active anon reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "inactive_file",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric inactive file reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "active_file",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric active file reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "unevictable",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric unevictable reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "slab_reclaimable",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric slab reclaimable reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "slab_unreclaimable",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric slab unreclaimable reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "workingset_refault_anon",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric workingset refault anon reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "workingset_refault_file",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric workingset refault file reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "workingset_activate_anon",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric workingset activate anon reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "workingset_activate_file",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric workingset activate file reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "pgdemote_kswapd",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgdemote kswapd reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "pgdemote_direct",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgdemote direct reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "pgdemote_khugepaged",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgdemote khugepaged reported by memory.numa_stat",
		},
		{
			File:        "memory.numa_stat",
			Key:         "pgpromote_success",
			Unit:        "count",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric pgpromote success reported by memory.numa_stat",
		},
		{
			File:        "cpu.pressure",
			Key:         "some.avg10",
			Unit:        "percent",
			Group:       "cpu",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpu kernel metric some avg10 reported by cpu.pressure",
		},
		{
			File:        "cpu.pressure",
			Key:         "some.avg60",
			Unit:        "percent",
			Group:       "cpu",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpu kernel metric some avg60 reported by cpu.pressure",
		},
		{
			File:        "cpu.pressure",
			Key:         "some.avg300",
			Unit:        "percent",
			Group:       "cpu",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpu kernel metric some avg300 reported by cpu.pressure",
		},
		{
			File:        "cpu.pressure",
			Key:         "some.total",
			Unit:        "microseconds",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric some total reported by cpu.pressure",
		},
		{
			File:        "cpu.pressure",
			Key:         "full.avg10",
			Unit:        "percent",
			Group:       "cpu",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpu kernel metric full avg10 reported by cpu.pressure",
		},
		{
			File:        "cpu.pressure",
			Key:         "full.avg60",
			Unit:        "percent",
			Group:       "cpu",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpu kernel metric full avg60 reported by cpu.pressure",
		},
		{
			File:        "cpu.pressure",
			Key:         "full.avg300",
			Unit:        "percent",
			Group:       "cpu",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpu kernel metric full avg300 reported by cpu.pressure",
		},
		{
			File:        "cpu.pressure",
			Key:         "full.total",
			Unit:        "microseconds",
			Group:       "cpu",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cpu kernel metric full total reported by cpu.pressure",
		},
		{
			File:        "memory.pressure",
			Key:         "some.avg10",
			Unit:        "percent",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric some avg10 reported by memory.pressure",
		},
		{
			File:        "memory.pressure",
			Key:         "some.avg60",
			Unit:        "percent",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric some avg60 reported by memory.pressure",
		},
		{
			File:        "memory.pressure",
			Key:         "some.avg300",
			Unit:        "percent",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric some avg300 reported by memory.pressure",
		},
		{
			File:        "memory.pressure",
			Key:         "some.total",
			Unit:        "microseconds",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric some total reported by memory.pressure",
		},
		{
			File:        "memory.pressure",
			Key:         "full.avg10",
			Unit:        "percent",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric full avg10 reported by memory.pressure",
		},
		{
			File:        "memory.pressure",
			Key:         "full.avg60",
			Unit:        "percent",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric full avg60 reported by memory.pressure",
		},
		{
			File:        "memory.pressure",
			Key:         "full.avg300",
			Unit:        "percent",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric full avg300 reported by memory.pressure",
		},
		{
			File:        "memory.pressure",
			Key:         "full.total",
			Unit:        "microseconds",
			Group:       "memory",
			Kind:        "counter",
			Severity:    "info",
			Description: "Memory kernel metric full total reported by memory.pressure",
		},
		{
			File:        "io.pressure",
			Key:         "some.avg10",
			Unit:        "percent",
			Group:       "io",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Io kernel metric some avg10 reported by io.pressure",
		},
		{
			File:        "io.pressure",
			Key:         "some.avg60",
			Unit:        "percent",
			Group:       "io",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Io kernel metric some avg60 reported by io.pressure",
		},
		{
			File:        "io.pressure",
			Key:         "some.avg300",
			Unit:        "percent",
			Group:       "io",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Io kernel metric some avg300 reported by io.pressure",
		},
		{
			File:        "io.pressure",
			Key:         "some.total",
			Unit:        "microseconds",
			Group:       "io",
			Kind:        "counter",
			Severity:    "info",
			Description: "Io kernel metric some total reported by io.pressure",
		},
		{
			File:        "io.pressure",
			Key:         "full.avg10",
			Unit:        "percent",
			Group:       "io",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Io kernel metric full avg10 reported by io.pressure",
		},
		{
			File:        "io.pressure",
			Key:         "full.avg60",
			Unit:        "percent",
			Group:       "io",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Io kernel metric full avg60 reported by io.pressure",
		},
		{
			File:        "io.pressure",
			Key:         "full.avg300",
			Unit:        "percent",
			Group:       "io",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Io kernel metric full avg300 reported by io.pressure",
		},
		{
			File:        "io.pressure",
			Key:         "full.total",
			Unit:        "microseconds",
			Group:       "io",
			Kind:        "counter",
			Severity:    "info",
			Description: "Io kernel metric full total reported by io.pressure",
		},
		{
			File:        "cgroup.pressure",
			Key:         "some.avg10",
			Unit:        "percent",
			Group:       "cgroup",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cgroup kernel metric some avg10 reported by cgroup.pressure",
		},
		{
			File:        "cgroup.pressure",
			Key:         "some.avg60",
			Unit:        "percent",
			Group:       "cgroup",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cgroup kernel metric some avg60 reported by cgroup.pressure",
		},
		{
			File:        "cgroup.pressure",
			Key:         "some.avg300",
			Unit:        "percent",
			Group:       "cgroup",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cgroup kernel metric some avg300 reported by cgroup.pressure",
		},
		{
			File:        "cgroup.pressure",
			Key:         "some.total",
			Unit:        "microseconds",
			Group:       "cgroup",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cgroup kernel metric some total reported by cgroup.pressure",
		},
		{
			File:        "cgroup.pressure",
			Key:         "full.avg10",
			Unit:        "percent",
			Group:       "cgroup",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cgroup kernel metric full avg10 reported by cgroup.pressure",
		},
		{
			File:        "cgroup.pressure",
			Key:         "full.avg60",
			Unit:        "percent",
			Group:       "cgroup",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cgroup kernel metric full avg60 reported by cgroup.pressure",
		},
		{
			File:        "cgroup.pressure",
			Key:         "full.avg300",
			Unit:        "percent",
			Group:       "cgroup",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cgroup kernel metric full avg300 reported by cgroup.pressure",
		},
		{
			File:        "cgroup.pressure",
			Key:         "full.total",
			Unit:        "microseconds",
			Group:       "cgroup",
			Kind:        "counter",
			Severity:    "info",
			Description: "Cgroup kernel metric full total reported by cgroup.pressure",
		},
		{
			File:        "memory.current",
			Key:         "value",
			Unit:        "bytes",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric value reported by memory.current",
		},
		{
			File:        "memory.min",
			Key:         "value",
			Unit:        "bytes",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric value reported by memory.min",
		},
		{
			File:        "memory.low",
			Key:         "value",
			Unit:        "bytes",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric value reported by memory.low",
		},
		{
			File:        "memory.high",
			Key:         "value",
			Unit:        "bytes",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric value reported by memory.high",
		},
		{
			File:        "memory.max",
			Key:         "value",
			Unit:        "bytes",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric value reported by memory.max",
		},
		{
			File:        "memory.peak",
			Key:         "value",
			Unit:        "bytes",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric value reported by memory.peak",
		},
		{
			File:        "memory.swap.current",
			Key:         "value",
			Unit:        "bytes",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric value reported by memory.swap.current",
		},
		{
			File:        "memory.swap.high",
			Key:         "value",
			Unit:        "bytes",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric value reported by memory.swap.high",
		},
		{
			File:        "memory.swap.max",
			Key:         "value",
			Unit:        "bytes",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric value reported by memory.swap.max",
		},
		{
			File:        "memory.swap.peak",
			Key:         "value",
			Unit:        "bytes",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric value reported by memory.swap.peak",
		},
		{
			File:        "memory.zswap.current",
			Key:         "value",
			Unit:        "bytes",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric value reported by memory.zswap.current",
		},
		{
			File:        "memory.zswap.max",
			Key:         "value",
			Unit:        "bytes",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric value reported by memory.zswap.max",
		},
		{
			File:        "hugetlb.2MB.current",
			Key:         "value",
			Unit:        "bytes",
			Group:       "hugetlb",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Hugetlb kernel metric value reported by hugetlb.2MB.current",
		},
		{
			File:        "hugetlb.2MB.max",
			Key:         "value",
			Unit:        "bytes",
			Group:       "hugetlb",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Hugetlb kernel metric value reported by hugetlb.2MB.max",
		},
		{
			File:        "hugetlb.1GB.current",
			Key:         "value",
			Unit:        "bytes",
			Group:       "hugetlb",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Hugetlb kernel metric value reported by hugetlb.1GB.current",
		},
		{
			File:        "hugetlb.1GB.max",
			Key:         "value",
			Unit:        "bytes",
			Group:       "hugetlb",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Hugetlb kernel metric value reported by hugetlb.1GB.max",
		},
		{
			File:        "pids.current",
			Key:         "value",
			Unit:        "count",
			Group:       "pids",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Pids kernel metric value reported by pids.current",
		},
		{
			File:        "pids.max",
			Key:         "value",
			Unit:        "count",
			Group:       "pids",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Pids kernel metric value reported by pids.max",
		},
		{
			File:        "pids.peak",
			Key:         "value",
			Unit:        "count",
			Group:       "pids",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Pids kernel metric value reported by pids.peak",
		},
		{
			File:        "cpu.weight",
			Key:         "value",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpu kernel metric value reported by cpu.weight",
		},
		{
			File:        "cpu.weight.nice",
			Key:         "value",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpu kernel metric value reported by cpu.weight.nice",
		},
		{
			File:        "cpu.max.burst",
			Key:         "value",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpu kernel metric value reported by cpu.max.burst",
		},
		{
			File:        "cpu.uclamp.min",
			Key:         "value",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpu kernel metric value reported by cpu.uclamp.min",
		},
		{
			File:        "cpu.uclamp.max",
			Key:         "value",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpu kernel metric value reported by cpu.uclamp.max",
		},
		{
			File:        "cpu.idle",
			Key:         "value",
			Unit:        "count",
			Group:       "cpu",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpu kernel metric value reported by cpu.idle",
		},
		{
			File:        "cgroup.max.depth",
			Key:         "value",
			Unit:        "count",
			Group:       "cgroup",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cgroup kernel metric value reported by cgroup.max.depth",
		},
		{
			File:        "cgroup.max.descendants",
			Key:         "value",
			Unit:        "count",
			Group:       "cgroup",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cgroup kernel metric value reported by cgroup.max.descendants",
		},
		{
			File:        "cgroup.freeze",
			Key:         "value",
			Unit:        "count",
			Group:       "cgroup",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cgroup kernel metric value reported by cgroup.freeze",
		},
		{
			File:        "memory.oom.group",
			Key:         "value",
			Unit:        "count",
			Group:       "memory",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Memory kernel metric value reported by memory.oom.group",
		},
		{
			File:        "cpu.max",
			Key:         "quota",
			Unit:        "microseconds",
			Group:       "cpu",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpu kernel metric quota reported by cpu.max",
		},
		{
			File:        "cpu.max",
			Key:         "period",
			Unit:        "microseconds",
			Group:       "cpu",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpu kernel metric period reported by cpu.max",
		},
		{
			File:        "io.stat",
			Key:         "8:0.rbytes",
			Unit:        "count",
			Group:       "io",
			Kind:        "counter",
			Severity:    "info",
			Description: "Io kernel metric 8:0 rbytes reported by io.stat",
		},
		{
			File:        "io.stat",
			Key:         "8:0.wbytes",
			Unit:        "count",
			Group:       "io",
			Kind:        "counter",
			Severity:    "info",
			Description: "Io kernel metric 8:0 wbytes reported by io.stat",
		},
		{
			File:        "io.stat",
			Key:         "8:0.rios",
			Unit:        "count",
			Group:       "io",
			Kind:        "counter",
			Severity:    "info",
			Description: "Io kernel metric 8:0 rios reported by io.stat",
		},
		{
			File:        "io.stat",
			Key:         "8:0.wios",
			Unit:        "count",
			Group:       "io",
			Kind:        "counter",
			Severity:    "info",
			Description: "Io kernel metric 8:0 wios reported by io.stat",
		},
		{
			File:        "io.stat",
			Key:         "8:0.dbytes",
			Unit:        "count",
			Group:       "io",
			Kind:        "counter",
			Severity:    "info",
			Description: "Io kernel metric 8:0 dbytes reported by io.stat",
		},
		{
			File:        "io.stat",
			Key:         "8:0.dios",
			Unit:        "count",
			Group:       "io",
			Kind:        "counter",
			Severity:    "info",
			Description: "Io kernel metric 8:0 dios reported by io.stat",
		},
		{
			File:        "io.stat.local",
			Key:         "8:0.rbytes",
			Unit:        "count",
			Group:       "io",
			Kind:        "counter",
			Severity:    "info",
			Description: "Io kernel metric 8:0 rbytes reported by io.stat.local",
		},
		{
			File:        "io.stat.local",
			Key:         "8:0.wbytes",
			Unit:        "count",
			Group:       "io",
			Kind:        "counter",
			Severity:    "info",
			Description: "Io kernel metric 8:0 wbytes reported by io.stat.local",
		},
		{
			File:        "io.stat.local",
			Key:         "8:0.rios",
			Unit:        "count",
			Group:       "io",
			Kind:        "counter",
			Severity:    "info",
			Description: "Io kernel metric 8:0 rios reported by io.stat.local",
		},
		{
			File:        "io.stat.local",
			Key:         "8:0.wios",
			Unit:        "count",
			Group:       "io",
			Kind:        "counter",
			Severity:    "info",
			Description: "Io kernel metric 8:0 wios reported by io.stat.local",
		},
		{
			File:        "io.stat.local",
			Key:         "8:0.dbytes",
			Unit:        "count",
			Group:       "io",
			Kind:        "counter",
			Severity:    "info",
			Description: "Io kernel metric 8:0 dbytes reported by io.stat.local",
		},
		{
			File:        "io.stat.local",
			Key:         "8:0.dios",
			Unit:        "count",
			Group:       "io",
			Kind:        "counter",
			Severity:    "info",
			Description: "Io kernel metric 8:0 dios reported by io.stat.local",
		},
		{
			File:        "io.max",
			Key:         "8:0.rbps",
			Unit:        "count",
			Group:       "io",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Io kernel metric 8:0 rbps reported by io.max",
		},
		{
			File:        "io.max",
			Key:         "8:0.wbps",
			Unit:        "count",
			Group:       "io",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Io kernel metric 8:0 wbps reported by io.max",
		},
		{
			File:        "io.max",
			Key:         "8:0.riops",
			Unit:        "count",
			Group:       "io",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Io kernel metric 8:0 riops reported by io.max",
		},
		{
			File:        "io.max",
			Key:         "8:0.wiops",
			Unit:        "count",
			Group:       "io",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Io kernel metric 8:0 wiops reported by io.max",
		},
		{
			File:        "io.weight",
			Key:         "8:0.rbps",
			Unit:        "count",
			Group:       "io",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Io kernel metric 8:0 rbps reported by io.weight",
		},
		{
			File:        "io.weight",
			Key:         "8:0.wbps",
			Unit:        "count",
			Group:       "io",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Io kernel metric 8:0 wbps reported by io.weight",
		},
		{
			File:        "io.weight",
			Key:         "8:0.riops",
			Unit:        "count",
			Group:       "io",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Io kernel metric 8:0 riops reported by io.weight",
		},
		{
			File:        "io.weight",
			Key:         "8:0.wiops",
			Unit:        "count",
			Group:       "io",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Io kernel metric 8:0 wiops reported by io.weight",
		},
		{
			File:        "cpuset.cpus",
			Key:         "value",
			Unit:        "raw",
			Group:       "cpuset",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpuset kernel metric value reported by cpuset.cpus",
		},
		{
			File:        "cpuset.cpus.effective",
			Key:         "value",
			Unit:        "raw",
			Group:       "cpuset",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpuset kernel metric value reported by cpuset.cpus.effective",
		},
		{
			File:        "cpuset.mems",
			Key:         "value",
			Unit:        "raw",
			Group:       "cpuset",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpuset kernel metric value reported by cpuset.mems",
		},
		{
			File:        "cpuset.mems.effective",
			Key:         "value",
			Unit:        "raw",
			Group:       "cpuset",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpuset kernel metric value reported by cpuset.mems.effective",
		},
		{
			File:        "cpuset.cpus.partition",
			Key:         "value",
			Unit:        "raw",
			Group:       "cpuset",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpuset kernel metric value reported by cpuset.cpus.partition",
		},
		{
			File:        "cpuset.cpus.exclusive",
			Key:         "value",
			Unit:        "raw",
			Group:       "cpuset",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpuset kernel metric value reported by cpuset.cpus.exclusive",
		},
		{
			File:        "cpuset.cpus.exclusive.effective",
			Key:         "value",
			Unit:        "raw",
			Group:       "cpuset",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cpuset kernel metric value reported by cpuset.cpus.exclusive.effective",
		},
		{
			File:        "cgroup.type",
			Key:         "value",
			Unit:        "raw",
			Group:       "cgroup",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cgroup kernel metric value reported by cgroup.type",
		},
		{
			File:        "cgroup.controllers",
			Key:         "value",
			Unit:        "raw",
			Group:       "cgroup",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cgroup kernel metric value reported by cgroup.controllers",
		},
		{
			File:        "cgroup.subtree_control",
			Key:         "value",
			Unit:        "raw",
			Group:       "cgroup",
			Kind:        "gauge",
			Severity:    "info",
			Description: "Cgroup kernel metric value reported by cgroup.subtree_control",
		},
	}
}
