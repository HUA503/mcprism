package report

import (
	"bytes"
	"encoding/csv"
	"strconv"
)

// RenderCSV writes one row per finding for GRC/audit teams to open in a
// spreadsheet.
func RenderCSV(r *Report) ([]byte, error) {
	buf := &bytes.Buffer{}
	w := csv.NewWriter(buf)
	_ = w.Write([]string{"server", "grade", "score", "rule", "severity", "owasp", "location", "evidence", "advice"})
	for _, res := range r.Results {
		for _, fnd := range res.Findings {
			_ = w.Write([]string{
				res.Server.Name, res.Grade, strconv.Itoa(res.Score),
				fnd.RuleID, string(fnd.Severity), fnd.OWASP, fnd.Location,
				fnd.Evidence, fnd.Advice,
			})
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}
