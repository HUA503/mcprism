package rules

import (
	"fmt"
	"regexp"
	"strings"
)

// injectionSigs 是元数据中的提示注入特征。
var injectionSigs = []struct {
	re  *regexp.Regexp
	sev Severity
}{
	{regexp.MustCompile(`(?i)ignore (all |any |the )?previous (instructions|prompts|directives|rules)`), SeverityCritical},
	{regexp.MustCompile(`(?i)disregard (all |any |the )?previous`), SeverityCritical},
	{regexp.MustCompile(`(?i)ignore (the |your )?system prompt`), SeverityCritical},
	{regexp.MustCompile(`(?i)reveal (the |your )?(system prompt|instructions|system message)`), SeverityCritical},
	{regexp.MustCompile(`(?i)(send|upload|post|exfiltrat\w*|pipe) (all |the |your )?(files|data|secrets|credentials|contents|context|environment)`), SeverityCritical},
	{regexp.MustCompile(`(?i)you are now `), SeverityHigh},
	{regexp.MustCompile(`(?i)(new|updated|override) instructions[: ]`), SeverityHigh},
	{regexp.MustCompile(`(?i)(secretly|silently|covertly|without (telling|informing|notifying) (the )?user)`), SeverityHigh},
	{regexp.MustCompile(`(?i)do not (tell|inform|notify) (the )?user`), SeverityHigh},
	{regexp.MustCompile(`(?i)before (you |completing|finishing|answering|ending)`), SeverityHigh},
	{regexp.MustCompile(`(?i)(execute|run) (the |this |following )?command`), SeverityHigh},
	{regexp.MustCompile(`(?i)include (all |the )?environment variables`), SeverityHigh},
	{regexp.MustCompile(`(?i)(curl|wget|fetch|download)\s+[a-z0-9]+://`), SeverityHigh},
}

var (
	b64Blob    = regexp.MustCompile(`[A-Za-z0-9+/]{80,}={0,2}`)
	hexBlob    = regexp.MustCompile(`\b[a-f0-9]{120,}\b`)
	hiddenHTML = regexp.MustCompile(`(?i)(<!--|<script|<img\s|<!\[)`)
	hiddenMD   = regexp.MustCompile(`!\[[^\]]*\]\(|<a\s`)
	imperative = regexp.MustCompile(`(?i)\b(you (must|will|need to)|always |never |before (calling|using|invoking)|make sure to|do not (use|call|invoke))`)
)

// metadataPoisoningRules checks every piece of metadata the server loads into
// the agent's context: tools, resources and prompt templates. All three can
// carry injected instructions, hidden Unicode or encoded payloads.
func metadataPoisoningRules(in Input) []Finding {
	var f []Finding

	for _, t := range in.Tools {
		scan := strings.Join([]string{t.Name, t.Title, t.Description, string(t.Annotations), string(t.InputSchema)}, "\n")
		f = append(f, scanMetadata(in.Server.Name, "tool", "tool:"+t.Name, scan)...)

		// Tool-only availability checks (MCP206): missing description / schema.
		if strings.TrimSpace(t.Description) == "" {
			f = append(f, Finding{
				RuleID: "MCP206", Title: "Tool without a description",
				Severity: SeverityLow, Server: in.Server.Name, Location: "tool:" + t.Name,
				Description: "The tool has no description, so the agent cannot reliably decide when or how to use it.",
				Advice:      "Add a clear description and documented parameters.",
			})
		}
		if schemaEmpty(t.InputSchema) {
			f = append(f, Finding{
				RuleID: "MCP206", Title: "Tool without an input schema",
				Severity: SeverityInfo, Server: in.Server.Name, Location: "tool:" + t.Name,
				Description: "The tool declares no input schema, so arguments are unvalidated and opaque to the agent.",
				Advice:      "Provide a JSON Schema for the tool's parameters.",
			})
		}
	}

	for _, r := range in.Resources {
		scan := strings.Join([]string{r.URI, r.Name, r.Description, r.MIMEType}, "\n")
		loc := "resource:" + r.Name
		if strings.TrimSpace(r.Name) == "" {
			loc = "resource:" + r.URI
		}
		f = append(f, scanMetadata(in.Server.Name, "resource", loc, scan)...)
	}

	for _, p := range in.Prompts {
		var b strings.Builder
		b.WriteString(p.Name)
		b.WriteByte('\n')
		b.WriteString(p.Description)
		for _, a := range p.Arguments {
			b.WriteByte('\n')
			b.WriteString(a.Name)
			b.WriteByte(' ')
			b.WriteString(a.Description)
		}
		f = append(f, scanMetadata(in.Server.Name, "prompt", "prompt:"+p.Name, b.String())...)
	}

	return f
}

// scanMetadata runs the shared poisoning checks (MCP201–MCP205) over one
// metadata blob. kind is "tool", "resource" or "prompt" and only adjusts the
// wording and location shown in the report.
func scanMetadata(server, kind, loc, scan string) []Finding {
	var f []Finding
	noun := kind

	// 1. Prompt injection (aggregate every hit on this object, keep the worst).
	var hits []string
	worst := SeverityInfo
	for _, sig := range injectionSigs {
		if m := sig.re.FindString(scan); m != "" {
			hits = append(hits, clipEvidence(m, 60))
			if sevRank(sig.sev) > sevRank(worst) {
				worst = sig.sev
			}
		}
	}
	if len(hits) > 0 {
		f = append(f, Finding{
			RuleID: "MCP201", Title: "Prompt injection in " + noun + " metadata",
			Severity: worst, OWASP: "MCP03", Server: server, Location: loc,
			Evidence:    clipEvidence(strings.Join(hits, " | "), 200),
			Description: "This metadata is server-controlled and is loaded into the agent's context. The model may follow these instructions over the system prompt, leading to data exfiltration or unauthorized actions (metadata poisoning).",
			Advice:      "Treat server metadata as untrusted data; remove the server or sanitize it; add guardrails that block injected directives.",
			References:  []string{"https://genai.owasp.org/resource/mcp-tool-poisoning/"},
		})
	}

	// 2. Invisible / bidi Unicode.
	if r, bad := invisibleRune(scan); bad {
		sev := SeverityHigh
		if isBidi(r) {
			sev = SeverityCritical
		}
		f = append(f, Finding{
			RuleID: "MCP202", Title: "Invisible or bidirectional Unicode in " + noun + " metadata",
			Severity: sev, OWASP: "MCP03", Server: server, Location: loc,
			Evidence:    "character U+" + fmt.Sprintf("%04X", r),
			Description: "Zero-width or bidirectional-override characters can hide instructions or visually rearrange text so reviewers and the model see different things.",
			Advice:      "Strip non-text-control Unicode from names, descriptions and schemas before loading them.",
		})
	}

	// 3. Hidden HTML / Markdown.
	if m := hiddenHTML.FindString(scan); m != "" {
		f = append(f, Finding{
			RuleID: "MCP203", Title: "Hidden HTML in " + noun + " metadata",
			Severity: SeverityHigh, OWASP: "MCP03", Server: server, Location: loc, Evidence: clipEvidence(m, 80),
			Description: "Hidden HTML comments or tags can carry instructions that are not visibly shown but may be acted on by the model.",
			Advice:      "Remove HTML comments/script tags from server metadata.",
		})
	}
	if m := hiddenMD.FindString(scan); m != "" {
		f = append(f, Finding{
			RuleID: "MCP203", Title: "Embedded image/link in " + noun + " metadata",
			Severity: SeverityMedium, OWASP: "MCP03", Server: server, Location: loc, Evidence: clipEvidence(m, 80),
			Description: "Embedded images/links can be used for tracking or to exfiltrate data via request parameters when rendered or fetched.",
			Advice:      "Avoid external image/link references in server metadata.",
		})
	}

	// 4. Large encoded blobs.
	if m := b64Blob.FindString(scan); m != "" {
		f = append(f, Finding{
			RuleID: "MCP204", Title: "Large encoded blob in " + noun + " metadata",
			Severity: SeverityMedium, OWASP: "MCP03", Server: server, Location: loc, Evidence: "base64 length " + fmt.Sprint(len(m)),
			Description: "A long base64 blob may conceal a payload or instructions that avoid plaintext review.",
			Advice:      "Decode and inspect encoded blobs; remove those that are not required.",
		})
	}
	if m := hexBlob.FindString(scan); m != "" {
		f = append(f, Finding{
			RuleID: "MCP204", Title: "Large hex blob in " + noun + " metadata",
			Severity: SeverityMedium, OWASP: "MCP03", Server: server, Location: loc, Evidence: "hex length " + fmt.Sprint(len(m)),
			Description: "A long hex blob may conceal a payload that avoids plaintext review.",
			Advice:      "Decode and inspect encoded blobs; remove those that are not required.",
		})
	}

	// 5. Directive language (weak signal).
	if m := imperative.FindString(scan); m != "" {
		f = append(f, Finding{
			RuleID: "MCP205", Title: noun + " metadata uses directive language",
			Severity: SeverityLow, OWASP: "MCP03", Server: server, Location: loc, Evidence: clipEvidence(m, 80),
			Description: "The metadata phrases behavior as instructions to the model. This is a weak signal worth reviewing when it constrains or steers agent behavior.",
			Advice:      "Prefer factual descriptions over directives that command the model.",
		})
	}
	return f
}

func invisibleRune(s string) (rune, bool) {
	for _, r := range s {
		switch r {
		case 0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060,
			0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
			0x2066, 0x2067, 0x2068, 0x2069:
			return r, true
		}
	}
	return 0, false
}

func isBidi(r rune) bool {
	switch r {
	case 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069:
		return true
	}
	return false
}

func schemaEmpty(raw []byte) bool {
	t := strings.TrimSpace(string(raw))
	if t == "" || t == "null" {
		return true
	}
	// Empty object schema: {"type":"object"} with no properties.
	if strings.Contains(t, `"properties"`) {
		return false
	}
	return true
}

func sevRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

func clipEvidence(s string, max int) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
