package report

import (
	"encoding/json"

	"github.com/HUA503/mcprism/internal/rules"
)

type cdxBOM struct {
	BOMFormat       string         `json:"bomFormat"`
	SpecVersion     string         `json:"specVersion"`
	Version         int            `json:"version"`
	Metadata        cdxMetadata    `json:"metadata"`
	Components      []cdxComponent `json:"components,omitempty"`
	Vulnerabilities []cdxVuln      `json:"vulnerabilities,omitempty"`
}

type cdxMetadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []cdxTool `json:"tools"`
}

type cdxTool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxComponent struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
}

type cdxVuln struct {
	ID          string      `json:"id"`
	Description string      `json:"description,omitempty"`
	Ratings     []cdxRating `json:"ratings,omitempty"`
}

type cdxRating struct {
	Severity string `json:"severity"`
	Method   string `json:"method"`
}

// RenderCycloneDX writes a CycloneDX 1.5 BOM with the servers as components
// and findings as vulnerabilities (JSON).
func RenderCycloneDX(r *Report) ([]byte, error) {
	bom := cdxBOM{
		BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1,
		Metadata: cdxMetadata{
			Timestamp: r.GeneratedAt,
			Tools:     []cdxTool{{Vendor: "mcprism", Name: "mcprism", Version: r.Version}},
		},
	}
	for _, res := range r.Results {
		bom.Components = append(bom.Components, cdxComponent{
			Type: "application", Name: res.Server.Name, Description: res.Server.Target(),
		})
		for _, fnd := range res.Findings {
			bom.Vulnerabilities = append(bom.Vulnerabilities, cdxVuln{
				ID: fnd.RuleID, Description: fnd.Title,
				Ratings: []cdxRating{{Severity: cdxSeverity(fnd.Severity), Method: "other"}},
			})
		}
	}
	b, err := json.MarshalIndent(bom, "", "  ")
	return b, err
}

func cdxSeverity(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical:
		return "critical"
	case rules.SeverityHigh:
		return "high"
	case rules.SeverityMedium:
		return "medium"
	case rules.SeverityLow:
		return "low"
	}
	return "none"
}
