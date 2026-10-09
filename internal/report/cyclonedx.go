package report

import (
	"encoding/json"
	"strconv"
	"strings"

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
	BOMRef      string `json:"bom-ref"`
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
}

type cdxVuln struct {
	ID          string        `json:"id"`
	Source      cdxSource     `json:"source"`
	Description string        `json:"description,omitempty"`
	Ratings     []cdxRating   `json:"ratings,omitempty"`
	Affects     []cdxAffect   `json:"affects,omitempty"`
	Properties  []cdxProperty `json:"properties,omitempty"`
}

type cdxSource struct {
	Name string `json:"name"`
}

type cdxRating struct {
	Severity string `json:"severity"`
	Method   string `json:"method"`
}

type cdxAffect struct {
	Ref string `json:"ref"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// RenderCycloneDX writes a CycloneDX 1.5 BOM with each server as a component
// and each finding as a vulnerability. Findings reference their component via
// bom-ref/affects, as required by the schema; mcprism rule ids are carried in
// properties (they are not CVEs and so are not used as the vulnerability id).
func RenderCycloneDX(r *Report) ([]byte, error) {
	bom := cdxBOM{
		BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1,
		Metadata: cdxMetadata{
			Timestamp: r.GeneratedAt,
			Tools:     []cdxTool{{Vendor: "mcprism", Name: "mcprism", Version: r.Version}},
		},
	}
	seq := 0
	for _, res := range r.Results {
		ref := componentRef(res.Server.Name)
		bom.Components = append(bom.Components, cdxComponent{
			Type: "application", BOMRef: ref, Name: res.Server.Name, Description: res.Server.Target(),
		})
		for _, fnd := range res.Findings {
			seq++
			bom.Vulnerabilities = append(bom.Vulnerabilities, cdxVuln{
				ID:          "MCPRISM-" + fnd.RuleID + "-" + strconv.Itoa(seq),
				Source:      cdxSource{Name: "mcprism"},
				Description: fnd.Title,
				Ratings:     []cdxRating{{Severity: cdxSeverity(fnd.Severity), Method: "Other"}},
				Affects:     []cdxAffect{{Ref: ref}},
				Properties:  []cdxProperty{{Name: "mcprism:ruleId", Value: fnd.RuleID}},
			})
		}
	}
	b, err := json.MarshalIndent(bom, "", "  ")
	return b, err
}

// componentRef builds a unique, schema-safe bom-ref for a server name.
func componentRef(name string) string {
	safe := strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ":", "-").Replace(name)
	if safe == "" {
		safe = "server"
	}
	return "mcprism:server:" + safe
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
