// Package report 将规则引擎的结果聚合为统一报告，并渲染为多种格式：
// 终端表格、JSON、SARIF、Markdown 与 HTML。
package report

import "github.com/HUA503/mcprism/internal/rules"

// Report 聚合一次扫描的全部结果与元信息。
type Report struct {
	Tool         string            `json:"tool"`
	Version      string            `json:"version"`
	GeneratedAt  string            `json:"generatedAt"`
	ScannedFiles []string          `json:"scannedFiles,omitempty"`
	Results      []*rules.Result   `json:"results"`
	Summary      Summary           `json:"summary"`
	Compliance   *rules.Compliance `json:"compliance,omitempty"`
}

// Summary 是全报告的计数汇总。
type Summary struct {
	Servers    int `json:"servers"`
	Connected  int `json:"connected"`
	Tools      int `json:"tools"`
	Findings   int `json:"findings"`
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Suppressed int `json:"suppressed"`
}

// Build 由引擎结果构造报告并计算汇总。
func Build(results []*rules.Result, files []string, version, generatedAt string) *Report {
	r := &Report{
		Tool: "mcprism", Version: version, GeneratedAt: generatedAt,
		Results: results, ScannedFiles: files,
	}
	for _, res := range results {
		r.Summary.Servers++
		if res.Connected {
			r.Summary.Connected++
		}
		r.Summary.Tools += res.ToolCount
		r.Summary.Suppressed += len(res.Suppressed)
		for _, fnd := range res.Findings {
			r.Summary.Findings++
			switch fnd.Severity {
			case rules.SeverityCritical:
				r.Summary.Critical++
			case rules.SeverityHigh:
				r.Summary.High++
			case rules.SeverityMedium:
				r.Summary.Medium++
			case rules.SeverityLow:
				r.Summary.Low++
			}
		}
	}
	return r
}

func severityRank(s rules.Severity) int {
	switch s {
	case rules.SeverityCritical:
		return 4
	case rules.SeverityHigh:
		return 3
	case rules.SeverityMedium:
		return 2
	case rules.SeverityLow:
		return 1
	}
	return 0
}

// MaxSeverity 返回报告中出现过的最高严重级。
func (r *Report) MaxSeverity() rules.Severity {
	max := rules.SeverityInfo
	for _, res := range r.Results {
		for _, fnd := range res.Findings {
			if severityRank(fnd.Severity) > severityRank(max) {
				max = fnd.Severity
			}
		}
	}
	return max
}
