package sast

import "strings"

// splitCallArgs separates a call's arguments while respecting nested
// expressions and quoted strings.
func splitCallArgs(s string) []string {
	var out []string
	for strings.TrimSpace(s) != "" {
		arg, rest := splitTopComma(s)
		out = append(out, strings.TrimSpace(arg))
		if rest == "" || rest == s {
			break
		}
		s = rest
	}
	return out
}
