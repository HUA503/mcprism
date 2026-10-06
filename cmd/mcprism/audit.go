package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/HUA503/mcprism/internal/config"
	"github.com/HUA503/mcprism/internal/policy"
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
	timeout    time.Duration
	interact   bool
}

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
}

// audit 对一组已解析的 server 执行策略加载、可选动态探测、规则分析、
// 合规判定、渲染与退出码处理。scan 和 vet 共用这条流程。
//
// dynamic 决定是否真正启动进程或连接服务器：scan 默认开启，可用
// --no-dynamic 关闭；vet 默认关闭（静态、零副作用），用 --probe 开启。
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

	inputs := make([]rules.Input, 0, len(servers))
	for _, srv := range servers {
		if !dynamic {
			inputs = append(inputs, rules.Input{Server: srv})
			continue
		}
		inputs = append(inputs, probeServer(context.Background(), srv, o.timeout))
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
