package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/HUA503/mcprism/internal/baseline"
	"github.com/HUA503/mcprism/internal/config"
	"github.com/HUA503/mcprism/internal/policy"
	"github.com/HUA503/mcprism/internal/protocol"
	"github.com/HUA503/mcprism/internal/report"
	"github.com/HUA503/mcprism/internal/rules"
	"github.com/HUA503/mcprism/internal/tui"
	"github.com/spf13/cobra"
)

// auditOpts 是 scan 与 vet 共用的审查参数。
type auditOpts struct {
	format     string
	output     string
	failOn     string
	policyFile string
	profile    string
	suppFile   string
	baseline   string
	timeout    time.Duration
	interact   bool
	inheritEnv bool
}

// probeConcurrency bounds how many servers are probed at once so a config with
// several hung servers does not make the scan wait timeout*N sequentially.
const probeConcurrency = 4

// addAuditFlags 注册 scan 与 vet 共用的标志。
func addAuditFlags(cmd *cobra.Command, o *auditOpts) {
	cmd.Flags().StringVarP(&o.format, "format", "f", "table", "output format: table|json|sarif|md|html|junit|cyclonedx|csv")
	cmd.Flags().StringVarP(&o.output, "output", "o", "", "write the report to a file instead of stdout")
	cmd.Flags().DurationVar(&o.timeout, "timeout", 10*time.Second, "per-server connection timeout")
	cmd.Flags().StringVar(&o.failOn, "fail-on", "", "exit non-zero when a finding of this severity exists (critical|high|medium|low)")
	cmd.Flags().BoolVarP(&o.interact, "interactive", "i", false, "open the interactive terminal UI")
	cmd.Flags().StringVarP(&o.policyFile, "policy", "p", "", "path to a policy YAML file")
	cmd.Flags().StringVar(&o.profile, "profile", "", "built-in profile: default|strict|ci")
	cmd.Flags().StringVar(&o.suppFile, "suppressions", "", "path to a suppressions YAML file")
	cmd.Flags().StringVar(&o.baseline, "baseline", "", "path to a previous -f json report; findings already in it are accepted and only new findings are reported")
	cmd.Flags().BoolVar(&o.inheritEnv, "inherit-env", false, "give dynamically launched servers the full parent environment (default: a minimal allowlist so host credentials are not leaked)")
}

// audit 对一组已解析的 server 执行策略加载、可选动态探测、规则分析、
// 合规判定、渲染与退出码处理。scan 和 vet 共用这条流程。
//
// dynamic 决定是否真正启动进程或连接服务器：两者都默认静态、零副作用，
// scan 用 --dynamic、vet 用 --probe 显式开启动态枚举。
func audit(servers []*config.Server, files []string, dynamic bool, o auditOpts) error {
	pol, err := policy.Builtin(o.profile)
	if err != nil {
		return err
	}
	policyPath := ""
	if o.policyFile != "" {
		pol, err = policy.Load(o.policyFile)
		if err != nil {
			return err
		}
		policyPath = o.policyFile
	}
	if len(servers) == 0 {
		return fmt.Errorf("no MCP servers to audit")
	}

	// Dynamic probing launches real processes; control how much of the host
	// environment they receive before any server is started.
	protocol.InheritChildEnv = o.inheritEnv

	inputs := make([]rules.Input, len(servers))
	if !dynamic {
		for i, srv := range servers {
			inputs[i] = rules.Input{Server: srv}
		}
	} else {
		// Probe in parallel (bounded) so a few hung servers don't add their
		// timeouts in series; results are written back by index to keep order.
		sem := make(chan struct{}, probeConcurrency)
		var wg sync.WaitGroup
		for i, srv := range servers {
			wg.Add(1)
			go func(i int, srv *config.Server) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				inputs[i] = probeServer(context.Background(), srv, o.timeout)
			}(i, srv)
		}
		wg.Wait()
	}

	results := rules.AnalyzeAll(inputs)
	results = policy.Enforce(results, pol)

	var sups []policy.Suppression
	if o.suppFile != "" {
		sups, err = policy.LoadSuppressions(o.suppFile)
		if err != nil {
			return err
		}
	}
	results = policy.ApplySuppressions(results, sups, time.Now())
	if o.baseline != "" {
		base, berr := baseline.Load(o.baseline)
		if berr != nil {
			return berr
		}
		baseline.Apply(results, base, o.baseline)
	}
	for _, r := range results {
		rules.Rescore(r)
	}

	compliance := policy.Evaluate(results, pol, o.profile, policyPath)

	if o.interact {
		if err := tui.Run(results); err != nil {
			return fmt.Errorf("interactive mode requires a real terminal; rerun without -i for normal output: %w", err)
		}
		return nil
	}

	rep := report.Build(results, files, version, time.Now().Format(time.RFC3339))
	rep.Compliance = &compliance
	out, err := renderReport(rep, o.format)
	if err != nil {
		return err
	}
	if o.output != "" {
		if err := os.WriteFile(o.output, out, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "report written to %s\n", o.output)
	} else {
		fmt.Print(string(out))
	}

	if !compliance.Pass || (o.failOn != "" && reaches(rep, o.failOn)) {
		os.Exit(1)
	}
	return nil
}
