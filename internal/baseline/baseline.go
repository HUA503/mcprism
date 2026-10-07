// Package baseline compares a scan against a saved JSON report. Findings that
// already exist in the baseline are treated as accepted risk, so a team can
// start scanning a messy codebase and only fail the build on new problems.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/HUA503/mcprism/internal/rules"
)

// Key uniquely identifies a finding. Location is included so the same rule
// firing on two different tools or files is counted separately.
func Key(server, ruleID, location string) string {
	return server + "\x00" + ruleID + "\x00" + location
}

type jsonReport struct {
	Results []struct {
		Findings []struct {
			RuleID   string `json:"ruleId"`
			Server   string `json:"server"`
			Location string `json:"location"`
		} `json:"findings"`
	} `json:"results"`
}

// Load reads a previous report written with `-f json` and returns the set of
// findings it contains.
func Load(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var rep jsonReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse baseline %q (use a previous report written with -f json): %w", path, err)
	}
	set := make(map[string]bool)
	for _, res := range rep.Results {
		for _, fnd := range res.Findings {
			set[Key(fnd.Server, fnd.RuleID, fnd.Location)] = true
		}
	}
	return set, nil
}

// Apply moves findings present in the baseline into each result's Suppressed
// list with a "baseline" reason. Only new findings stay active and affect the
// score and compliance gate, while accepted ones remain visible for audit.
func Apply(results []*rules.Result, base map[string]bool, source string) {
	for _, r := range results {
		active := make([]rules.Finding, 0, len(r.Findings))
		for _, fnd := range r.Findings {
			if base[Key(fnd.Server, fnd.RuleID, fnd.Location)] {
				r.Suppressed = append(r.Suppressed, rules.SuppressedFinding{
					Finding: fnd,
					Reason:  "baseline: " + source,
				})
				continue
			}
			active = append(active, fnd)
		}
		r.Findings = active
	}
}
