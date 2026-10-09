package report

import (
	"bytes"
	"encoding/csv"
	"strconv"
)

// csvSafe neutralizes spreadsheet formula injection. Evidence and server names
// can come from attacker-controlled tool descriptions, source lines or URLs,
// and a cell beginning with = + - @ (or Tab/CR) would be evaluated as a
// formula by Excel/LibreOffice. A leading single quote forces text.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// RenderCSV writes one row per finding for GRC/audit teams to open in a
// spreadsheet.
func RenderCSV(r *Report) ([]byte, error) {
	buf := &bytes.Buffer{}
	w := csv.NewWriter(buf)
	_ = w.Write([]string{"server", "grade", "score", "rule", "severity", "owasp", "location", "evidence", "advice"})
	for _, res := range r.Results {
		for _, fnd := range res.Findings {
			_ = w.Write([]string{
				csvSafe(res.Server.Name), csvSafe(res.Grade), strconv.Itoa(res.Score),
				csvSafe(fnd.RuleID), csvSafe(string(fnd.Severity)), csvSafe(fnd.OWASP), csvSafe(fnd.Location),
				csvSafe(fnd.Evidence), csvSafe(fnd.Advice),
			})
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}
