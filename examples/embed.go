// Package examples embeds the small config samples used by `mcprism demo`.
package examples

import "embed"

// FS contains examples that are shipped inside the mcprism binary.
//
//go:embed clean.mcp.json vulnerable.mcp.json
var FS embed.FS
