package report

import (
	"encoding/xml"
	"strings"

	"github.com/HUA503/mcprism/internal/rules"
)

type junitTestSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Type    string `xml:"type,attr"`
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

// RenderJUnit renders JUnit XML that Jenkins, GitLab and GitHub test reports
// can consume directly.
func RenderJUnit(r *Report) ([]byte, error) {
	ts := junitTestSuites{Name: "mcprism"}
	for _, res := range r.Results {
		s := junitSuite{Name: res.Server.Name}
		for _, fnd := range res.Findings {
			c := junitCase{Classname: res.Server.Name, Name: fnd.RuleID + " - " + fnd.Title}
			if junitIsFailure(fnd.Severity) {
				c.Failure = &junitFailure{
					Type: string(fnd.Severity), Message: fnd.Title,
					Body: strings.Join(nonEmpty(fnd.Evidence, fnd.Description, fnd.Advice), "\n\n"),
				}
				s.Failures++
			}
			s.Tests++
			s.Cases = append(s.Cases, c)
		}
		ts.Tests += s.Tests
		ts.Failures += s.Failures
		ts.Suites = append(ts.Suites, s)
	}
	b, err := xml.MarshalIndent(ts, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), b...), nil
}

func junitIsFailure(s rules.Severity) bool {
	return s == rules.SeverityMedium || s == rules.SeverityHigh || s == rules.SeverityCritical
}

func nonEmpty(parts ...string) []string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
