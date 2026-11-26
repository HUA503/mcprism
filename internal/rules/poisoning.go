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
	// Chinese-language directives are matched explicitly so offline scanning
	// does not depend on translation or a language model.
	{regexp.MustCompile(`忽略.{0,8}(之前|先前|上文|以上|原有|系统|系統).{0,8}(指令|指示|提示词|提示詞|提示|规则|規則)`), SeverityCritical},
	{regexp.MustCompile(`(泄露|洩露|显示|顯示|输出|輸出|打印|揭示).{0,8}(系统提示词|系統提示詞|系统指令|系統指令|内部指令|內部指令|隐藏指令|隱藏指令|提示词|提示詞)`), SeverityCritical},
	{regexp.MustCompile(`(发送|上傳|上传|回传|回傳|窃取|竊取|外传|外傳).{0,12}(密钥|金鑰|凭据|憑證|憑據|环境变量|環境變數|系统提示词|系統提示詞|内部指令|內部指令|私钥|私鑰|令牌|權杖|cookie|机密信息|機密信息)`), SeverityCritical},
	{regexp.MustCompile(`(发送|上傳|上传|回传|回傳|窃取|竊取|外传|外傳).{0,8}(所有|全部|整个|整個|本地).{0,6}(文件|檔案|数据|資料|上下文|环境变量|環境變數)`), SeverityCritical},
	{regexp.MustCompile(`(你现在是|你現在是|从现在开始你是|從現在開始你是)`), SeverityHigh},
	{regexp.MustCompile(`(新的|新增的).{0,5}(系统|系統)?(指令|指示)|覆盖.{0,8}(原有|之前|系统).{0,5}(指令|规则)|覆寫.{0,8}(原有|之前|系統).{0,5}(指令|規則)|更新.{0,8}(系统提示词|系統提示詞|系统指令|系統指令|指令|指示)`), SeverityHigh},
	{regexp.MustCompile(`(不要|請勿|请勿).{0,5}(告诉|告知|通知).{0,5}用户`), SeverityHigh},
	{regexp.MustCompile(`(必须|務必|立刻|立即).{0,5}(执行|執行|运行|運行).{0,5}(命令|指令|代码|程式碼|脚本|腳本)`), SeverityHigh},
	{regexp.MustCompile(`(立即|立刻|務必).{0,5}(执行|執行|运行|運行)(以下|这个|此|該).{0,5}(命令|指令|代码|程式碼|脚本|腳本)`), SeverityHigh},
	{regexp.MustCompile(`(忽略|无视|無視|不要遵守|不必遵守|绕过|繞過|跳过|跳過|违反|違反).{0,10}(安全|系统|系統|开发者|開發者|平台|审核|審核).{0,6}(规则|規則|策略|限制|指令|政策)`), SeverityCritical},
	{regexp.MustCompile(`(进入|進入|切换到|切換到|启用|啟用|开启|開啟).{0,6}(开发者|開發者|管理员|管理員|无限制|無限制|越狱|越獄).{0,4}模式`), SeverityHigh},
	{regexp.MustCompile(`(把|将|將).{0,8}(以下|下面|此|这段|這段|本文).{0,6}(内容|內容|文本|訊息|消息).{0,6}(作为|作為|视为|視為|当作|當作).{0,8}(最高优先级|最高優先級|系统|系統|开发者|開發者).{0,4}(指令|提示|消息|訊息)`), SeverityHigh},
	{regexp.MustCompile(`(显示|顯示|输出|輸出|打印|揭示|复述|複述|逐字输出|逐字輸出).{0,8}(思维链|思維鏈|推理过程|推理過程|隐藏提示词|隱藏提示詞|系统提示词|系統提示詞|开发者消息|開發者訊息)`), SeverityCritical},
	// Japanese directives are checked with language-specific high-signal phrases;
	// gaps allow ordinary particles without interpreting free-form text.
	{regexp.MustCompile(`(以前|前の|これまでの|上記の|既存の).{0,4}(指示|命令|ルール|プロンプト).{0,6}(無視|忘れ|破棄)`), SeverityCritical},
	{regexp.MustCompile(`(システムプロンプト|システム指示|内部指示|隠されたプロンプト|隠しプロンプト).{0,8}(明か|開示|表示|出力|漏ら|送信)`), SeverityCritical},
	{regexp.MustCompile(`(明か|開示|表示|出力|漏ら).{0,8}(システムプロンプト|システム指示|内部指示|隠されたプロンプト|隠しプロンプト)`), SeverityCritical},
	{regexp.MustCompile(`(秘密|認証情報|環境変数|ファイル|データ|コンテキスト|資格情報).{0,8}(送信|アップロード|外部送信|漏洩|盗み出)`), SeverityCritical},
	{regexp.MustCompile(`(あなた|君)は今から|これから(あなた|君)は`), SeverityHigh},
	{regexp.MustCompile(`(安全|システム|開発者).{0,5}(ポリシー|規則|指示).{0,5}(無視|回避|上書き|変更)`), SeverityCritical},
	{regexp.MustCompile(`(ユーザー|利用者)に(知らせず|伝えず|通知せず)|秘密裏に|密かに(送信|実行)`), SeverityHigh},
	// Korean equivalents cover role changes, policy overrides and exfiltration.
	{regexp.MustCompile(`(이전|앞선|기존|위의).{0,4}(지시|명령|프롬프트).{0,6}(무시|잊어|폐기)`), SeverityCritical},
	{regexp.MustCompile(`(시스템 프롬프트|시스템 지시|내부 지시|숨겨진 프롬프트).{0,8}(공개|표시|출력|누설|유출|전송)`), SeverityCritical},
	{regexp.MustCompile(`(공개|표시|출력|누설|유출).{0,8}(시스템 프롬프트|시스템 지시|내부 지시|숨겨진 프롬프트)`), SeverityCritical},
	{regexp.MustCompile(`(비밀|자격 증명|환경 변수|파일|데이터|컨텍스트).{0,8}(전송|업로드|외부 전송|유출|탈취)`), SeverityCritical},
	{regexp.MustCompile(`(이제부터|지금부터)\s*(너는|당신은)`), SeverityHigh},
	{regexp.MustCompile(`(안전|시스템|개발자).{0,5}(정책|규칙|지침).{0,5}(무시|우회|덮어쓰기|재정의)`), SeverityCritical},
	{regexp.MustCompile(`(사용자에게 알리지|사용자에게 말하지|몰래|은밀히).{0,6}(전송|실행|업로드|수행)`), SeverityHigh},
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
	// Fold NFKC compatibility forms and Cyrillic/Greek homoglyphs so injection
	// phrasing hidden behind full-width letters or look-alike code points still
	// matches the English signatures.
	folded := normalizeForScan(scan)

	// 1. Prompt injection (aggregate every hit on this object, keep the worst).
	var hits []string
	worst := SeverityInfo
	for _, sig := range injectionSigs {
		if m := sig.re.FindString(folded); m != "" {
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

	// 2. Invisible / bidi / Tags Unicode.
	obfuscated := false
	if r, invKind, bad := findInvisible(scan); bad {
		obfuscated = true
		sev := SeverityHigh
		if isBidi(r) {
			sev = SeverityCritical
		}
		f = append(f, Finding{
			RuleID: "MCP202", Title: "Invisible or bidirectional Unicode in " + noun + " metadata",
			Severity: sev, OWASP: "MCP03", Server: server, Location: loc,
			Evidence:    fmt.Sprintf("%s character U+%04X", invKind, r),
			Description: "Zero-width, bidirectional-override or Unicode Tags characters can hide instructions or visually rearrange text so reviewers and the model see different things.",
			Advice:      "Strip non-text-control Unicode (Cf/Tags) from names, descriptions and schemas before loading them.",
		})
	}
	// 2b. Mixed-script homoglyph token (e.g. Cyrillic look-alikes in English).
	if tok := findMixedScriptToken(scan); tok != "" {
		obfuscated = true
		f = append(f, Finding{
			RuleID: "MCP202", Title: "Mixed-script homoglyph in " + noun + " metadata",
			Severity: SeverityHigh, OWASP: "MCP03", Server: server, Location: loc,
			Evidence:    "mixed-script token: " + clipEvidence(tok, 60),
			Description: "A single token mixes Latin with Cyrillic/Greek letters that look nearly identical, a common way to disguise keywords from plaintext review and ASCII-based scanners.",
			Advice:      "Confine tool metadata to one script, or normalize confusable code points before loading them.",
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

	// 5. Directive language is reported only alongside real obfuscation. Plain
	// guidance such as "Before calling this tool, make sure the file exists" is
	// normal API documentation and must not be flagged on its own.
	if obfuscated {
		if m := imperative.FindString(folded); m != "" {
			f = append(f, Finding{
				RuleID: "MCP205", Title: "Directive language combined with hidden text in " + noun + " metadata",
				Severity: SeverityInfo, OWASP: "MCP03", Server: server, Location: loc, Evidence: clipEvidence(m, 80),
				Description: "Imperative phrasing steers the model, and here it appears together with invisible or confusable characters, which is a strong poisoning indicator.",
				Advice:      "Prefer factual descriptions and strip the hidden/confusable characters.",
			})
		}
	}
	return f
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
