package report

import "encoding/json"

// RenderJSON 渲染缩进的 JSON 报告，适合程序处理与归档。
func RenderJSON(r *Report) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
