package report

import (
	"encoding/json"

	"github.com/HUA503/mcprism/internal/rules"
)

// SARIF 2.1.0 结构（仅包含 mcprism 需要的字段）。
type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
	HelpURI          string       `json:"helpUri,omitempty"`
	DefaultConfig    sarifConfig  `json:"defaultConfiguration,omitempty"`
}
type sarifConfig struct {
	Level string `json:"level"`
}
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifMessage struct {
	Text string `json:"text"`
}

func sarifLevel(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical, rules.SeverityHigh:
		return "error"
	case rules.SeverityMedium:
		return "warning"
	}
	return "note"
}

// RenderSARIF 渲染 SARIF 2.1.0，可直接上传到 GitHub code scanning。
func RenderSARIF(r *Report) ([]byte, error) {
	ruleDefs := map[string]sarifRule{}
	var results []sarifResult

	for _, res := range r.Results {
		uri := res.Server.Source
		if uri == "" {
			uri = res.Server.Name
		}
		for _, f := range res.Findings {
			if _, ok := ruleDefs[f.RuleID]; !ok {
				help := ""
				if len(f.References) > 0 {
					help = f.References[0]
				}
				ruleDefs[f.RuleID] = sarifRule{
					ID:               f.RuleID,
					ShortDescription: sarifMessage{Text: f.Title},
					HelpURI:          help,
					DefaultConfig:    sarifConfig{Level: sarifLevel(f.Severity)},
				}
			}
			msg := f.Title + ". " + f.Advice
			if f.Evidence != "" {
				msg = f.Title + " — " + f.Evidence + ". " + f.Advice
			}
			results = append(results, sarifResult{
				RuleID:  f.RuleID,
				Level:   sarifLevel(f.Severity),
				Message: sarifMessage{Text: msg},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}},
				}},
			})
		}
	}

	rulesList := make([]sarifRule, 0, len(ruleDefs))
	for _, d := range ruleDefs {
		rulesList = append(rulesList, d)
	}

	out := sarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "mcprism",
				Version:        r.Version,
				InformationURI: "https://github.com/HUA503/mcprism",
				Rules:          rulesList,
			}},
			Results: results,
		}},
	}
	return json.MarshalIndent(out, "", "  ")
}
