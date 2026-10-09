// Package baseline compares a scan against a saved JSON report. Findings that
// already exist in the baseline are treated as accepted risk, so a team can
// start scanning a messy codebase and only fail the build on new problems.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/HUA503/mcprism/internal/rules"
)

var wsRe = regexp.MustCompile(`\s+`)

// fingerprint normalizes free-form evidence (case-insensitive, whitespace
// collapsed) and hashes it, so two instances of the same rule with different
// evidence are not collapsed into one accepted finding.
func fingerprint(evidence string) string {
	s := wsRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(evidence)), " ")
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

// Key uniquely identifies a finding. Besides server/rule/location it includes
// the severity (so a finding whose severity was upgraded is reported again
// rather than staying accepted) and a normalized evidence fingerprint (so
// distinct instances with an empty location are not over-suppressed).
func Key(server, ruleID, location, severity, evidence string) string {
	return strings.Join([]string{server, ruleID, location, severity, fingerprint(evidence)}, "\x00")
}

type jsonReport struct {
	Results []struct {
		Findings []struct {
			RuleID   string `json:"ruleId"`
			Server   string `json:"server"`
			Location string `json:"location"`
			Severity string `json:"severity"`
			Evidence string `json:"evidence"`
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
			set[Key(fnd.Server, fnd.RuleID, fnd.Location, fnd.Severity, fnd.Evidence)] = true
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
			if base[Key(fnd.Server, fnd.RuleID, fnd.Location, string(fnd.Severity), fnd.Evidence)] {
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
