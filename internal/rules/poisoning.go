package rules

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
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
	{regexp.MustCompile(`(忘记|忘記|忘掉|遺忘).{0,8}(之前|先前|上文|以上|原有|系统|系統).{0,8}(指令|指示|提示词|提示詞|提示|规则|規則)`), SeverityCritical},
	{regexp.MustCompile(`(泄露|洩露|显示|顯示|输出|輸出|打印|揭示).{0,8}(系统提示词|系統提示詞|系统指令|系統指令|内部指令|內部指令|隐藏指令|隱藏指令|提示词|提示詞)`), SeverityCritical},
	{regexp.MustCompile(`(发送|上傳|上传|回传|回傳|窃取|竊取|外传|外傳).{0,12}(密钥|金鑰|凭据|憑證|憑據|环境变量|環境變數|系统提示词|系統提示詞|内部指令|內部指令|私钥|私鑰|令牌|權杖|cookie|机密信息|機密信息)`), SeverityCritical},
	{regexp.MustCompile(`(读取|讀取|获取|取得|搜集|收集|查找|搜索).{0,12}(密钥|金鑰|凭据|憑證|憑據|环境变量|環境變數|私钥|私鑰|令牌|權杖|cookie|机密信息|機密信息).{0,16}(发送|傳送|傳輸|上传|上傳|回传|回傳|外传|外傳|提交)`), SeverityCritical},
	{regexp.MustCompile(`(把|将|將).{0,8}(密钥|金鑰|凭据|憑證|憑據|环境变量|環境變數|私钥|私鑰|令牌|權杖|cookie|机密信息|機密信息).{0,12}(附加|写入|寫入|嵌入|放入).{0,10}(请求|請求|回复|回覆|消息|訊息|内容|內容).{0,8}(发送|傳送|傳輸|上传|上傳|提交)`), SeverityCritical},
	{regexp.MustCompile(`(发送|上傳|上传|回传|回傳|窃取|竊取|外传|外傳).{0,8}(所有|全部|整个|整個|本地).{0,6}(文件|檔案|数据|資料|上下文|环境变量|環境變數)`), SeverityCritical},
	{regexp.MustCompile(`(你现在是|你現在是|从现在开始你是|從現在開始你是)`), SeverityHigh},
	{regexp.MustCompile(`(新的|新增的).{0,5}(系统|系統)?(指令|指示)|覆盖.{0,8}(原有|之前|系统).{0,5}(指令|规则)|覆寫.{0,8}(原有|之前|系統).{0,5}(指令|規則)|更新.{0,8}(系统提示词|系統提示詞|系统指令|系統指令|指令|指示)`), SeverityHigh},
	{regexp.MustCompile(`(不要|請勿|请勿).{0,5}(告诉|告知|通知).{0,5}用户`), SeverityHigh},
	{regexp.MustCompile(`(趁|在).{0,8}(用户|用戶).{0,8}(不知情|不注意|离开|離開).{0,8}(发送|傳送|傳輸|执行|執行|上传|上傳|删除|刪除)`), SeverityHigh},
	{regexp.MustCompile(`(必须|務必|立刻|立即).{0,5}(执行|執行|运行|運行).{0,5}(命令|指令|代码|程式碼|脚本|腳本)`), SeverityHigh},
	{regexp.MustCompile(`(立即|立刻|務必).{0,5}(执行|執行|运行|運行)(以下|这个|此|該).{0,5}(命令|指令|代码|程式碼|脚本|腳本)`), SeverityHigh},
	{regexp.MustCompile(`(忽略|无视|無視|不要遵守|不必遵守|绕过|繞過|跳过|跳過|违反|違反).{0,10}(安全|系统|系統|开发者|開發者|平台|审核|審核).{0,6}(规则|規則|策略|限制|指令|政策)`), SeverityCritical},
	{regexp.MustCompile(`(把|将|將).{0,8}(安全|系统|系統|开发者|開發者).{0,6}(规则|規則|策略|限制|指令|政策).{0,5}(视为|視為|当作|當作|認為).{0,5}(无效|無效|不存在|不适用|不適用)`), SeverityCritical},
	{regexp.MustCompile(`(不要|請勿|请勿).{0,8}(遵循|遵从|遵從|服从|服從).{0,8}(安全|系统|系統|开发者|開發者).{0,6}(规则|規則|策略|限制|指令|政策)`), SeverityCritical},
	{regexp.MustCompile(`(进入|進入|切换到|切換到|启用|啟用|开启|開啟).{0,6}(开发者|開發者|管理员|管理員|无限制|無限制|越狱|越獄).{0,4}模式`), SeverityHigh},
	{regexp.MustCompile(`(?i)(扮演|假装|假裝|假设你是|假設你是|想象你是|想像你是).{0,12}(不受.{0,4}限制|没有.{0,4}限制|沒有.{0,4}限制|无约束|無約束|未审查|未審查|越狱|越獄|DAN|开发者模式|開發者模式)`), SeverityHigh},
	{regexp.MustCompile(`(这条|這條|本条|本條|以下|新的).{0,8}(指令|消息|訊息|内容|內容).{0,12}(优先于|優先於|高于|高於|覆盖|覆蓋|取代|凌驾于|凌駕於).{0,8}(系统|系統|开发者|開發者|原有|之前|安全).{0,6}(提示|指令|规则|規則|政策|策略)?`), SeverityCritical},
	{regexp.MustCompile(`(把|将|將).{0,8}(以下|下面|此|这段|這段|本文).{0,6}(内容|內容|文本|訊息|消息).{0,6}(作为|作為|视为|視為|当作|當作).{0,8}(最高优先级|最高優先級|系统|系統|开发者|開發者).{0,4}(指令|提示|消息|訊息)`), SeverityHigh},
	{regexp.MustCompile(`(从现在开始|從現在開始|接下来|接下來|今后|今後).{0,8}(只|仅|僅|唯一).{0,6}(听从|聽從|遵循|遵從|服从|服從).{0,8}(我|用户|用戶|本文|本条|本條|这段|這段).{0,4}(的)?(指令|要求|内容|內容)?`), SeverityHigh},
	{regexp.MustCompile(`(安全|系统|系統|开发者|開發者).{0,6}(规则|規則|策略|限制|审核|審核).{0,6}(只是|仅是|僅是|不过是|不過是).{0,5}(参考|參考|建议|建議|示例|範例)`), SeverityHigh},
	{regexp.MustCompile(`(如果|若).{0,8}(与|和|跟).{0,6}(系统|系統|开发者|開發者|安全).{0,6}(指令|规则|規則|策略).{0,6}(冲突|衝突).{0,8}(以|按|按照|遵循).{0,8}(本文|本条|本條|这段|這段|用户|用戶)`), SeverityHigh},
	{regexp.MustCompile(`(显示|顯示|输出|輸出|打印|揭示|复述|複述|逐字输出|逐字輸出).{0,8}(思维链|思維鏈|推理过程|推理過程|隐藏提示词|隱藏提示詞|系统提示词|系統提示詞|开发者消息|開發者訊息)`), SeverityCritical},
	{regexp.MustCompile(`(不要|不得|禁止|不准).{0,5}(拒绝|拒絕|拒答).{0,8}(用户|用戶|请求|請求|命令|指令)?`), SeverityHigh},
	{regexp.MustCompile(`(无条件|無條件|绝对|絕對|必须|必須).{0,5}(服从|服從|遵从|遵從).{0,8}(用户|用戶|请求|請求|命令|指令)`), SeverityHigh},
	{regexp.MustCompile(`(绕过|繞過|规避|規避|禁用|停用).{0,6}(拒绝|拒絕|安全审查|安全審查|内容限制|內容限制|安全限制)`), SeverityCritical},
	{regexp.MustCompile(`(获得|取得|拥有|擁有|授予).{0,8}(最高|管理员|管理員|root).{0,6}(权限|權限)`), SeverityHigh},
	// Spanish, French, German and Portuguese signatures focus on direct
	// overrides, hidden-prompt disclosure and credential exfiltration.
	{regexp.MustCompile(`(?i)(ignora|ignoren|ignorar|olvida|olvidar|desestima).{0,12}(instrucciones|indicaciones|reglas|directivas|prompt).{0,8}(anteriores|previas|del sistema)`), SeverityCritical},
	{regexp.MustCompile(`(?i)(revela|muestra|imprime|expone|divulga).{0,12}(prompt|instrucciones|mensaje).{0,8}(del sistema|ocultas|internas)`), SeverityCritical},
	{regexp.MustCompile(`(?i)(env[ií]a|sube|carga|filtra|exfiltra|roba).{0,12}(secretos|credenciales|claves|archivos|datos|variables de entorno)`), SeverityCritical},
	{regexp.MustCompile(`(?i)(sin (decir|avisar|informar) al usuario|no (le )?(digas|avises|informes) al usuario)`), SeverityHigh},
	{regexp.MustCompile(`(?i)(ignore|oublie|oubliez|efface|méprise).{0,12}(instructions|règles|consignes|directives).{0,8}(précédentes|antérieures|du système)`), SeverityCritical},
	{regexp.MustCompile(`(?i)(révèle|affiche|imprime|divulgue).{0,12}(prompt|instructions|message).{0,8}(système|caché|internes)`), SeverityCritical},
	{regexp.MustCompile(`(?i)(envoie|téléverse|transmets|exfiltre|vole).{0,12}(secrets|identifiants|clés|fichiers|données|variables d.environment)`), SeverityCritical},
	{regexp.MustCompile(`(?i)(sans (le )?dire à l.utilisateur|ne (dis|préviens|notifie) pas l.utilisateur)`), SeverityHigh},
	{regexp.MustCompile(`(?i)(ignoriere|missachte|vergiss|verwirf).{0,12}(vorherigen|bisherigen|früheren|System).{0,8}(Anweisungen|Regeln|Vorgaben|Prompt)`), SeverityCritical},
	{regexp.MustCompile(`(?i)(verrate|zeige|offenbare|gib preis).{0,12}(System.?prompt|versteckte Anweisungen|interne Anweisungen|Systemnachricht)`), SeverityCritical},
	{regexp.MustCompile(`(?i)(sende|schicke|lade hoch|übertrage|exfiltriere|stiehl).{0,12}(Geheimnisse|Zugangsdaten|Schlüssel|Dateien|Daten|Umgebungsvariablen)`), SeverityCritical},
	{regexp.MustCompile(`(?i)(ohne es dem Benutzer zu sagen|sage es dem Benutzer nicht|informiere den Benutzer nicht)`), SeverityHigh},
	{regexp.MustCompile(`(?i)(ignore|esqueça|esquece|desconsidere).{0,12}(instruções|instrucoes|regras|diretivas|prompt).{0,8}(anteriores|prévias|previas|do sistema)`), SeverityCritical},
	{regexp.MustCompile(`(?i)(revele|mostre|exiba|imprima|divulgue).{0,12}(prompt|instruções|instrucoes|mensagem).{0,8}(do sistema|ocultas|internas)`), SeverityCritical},
	{regexp.MustCompile(`(?i)(envie|envia|carregue|transfira|exfiltre|roube).{0,12}(segredos|credenciais|senhas|chaves|arquivos|dados|variáveis de ambiente|variaveis de ambiente)`), SeverityCritical},
	{regexp.MustCompile(`(?i)(sem (contar|avisar|informar) ao usuário|não (diga|avise|informe) ao usuário)`), SeverityHigh},
	// Russian and Arabic signatures cover direct reset, disclosure and theft requests.
	{regexp.MustCompile(`(игнорируй|забудь|отбрось|не учитывай).{0,12}(предыдущие|прежние|системные).{0,8}(инструкции|правила|указания|промпт)`), SeverityCritical},
	{regexp.MustCompile(`(?i)(раскрой|покажи|выведи|напечатай|раскройте).{0,12}(системн[а-яё]* промпт|скрыт[а-яё]* инструкц[а-яё]*|внутренн[а-яё]* инструкц[а-яё]*)`), SeverityCritical},
	{regexp.MustCompile(`(?i)(отправь|загрузи|передай|укради|эксфильтр[а-яё]*).{0,12}(секрет[а-яё]*|учетн[а-яё]* данн[а-яё]*|учётн[а-яё]* данн[а-яё]*|ключ[а-яё]*|файл[а-яё]*|данн[а-яё]*|переменн[а-яё]* окружения)`), SeverityCritical},
	{regexp.MustCompile(`(не говори|не сообщай|не уведомляй).{0,8}пользовател|тайно.{0,8}(отправь|выполни|загрузи)`), SeverityHigh},
	{regexp.MustCompile(`تجاهل.{0,12}(التعليمات|الأوامر|القواعد).{0,12}(السابقة|النظام|المطور)`), SeverityCritical},
	{regexp.MustCompile(`(اكشف|اعرض|اطبع|أظهر).{0,12}(تعليمات النظام|الموجه النظامي|التعليمات المخفية|الرسالة الداخلية)`), SeverityCritical},
	{regexp.MustCompile(`(أرسل|ارفع|سرّب|اسرق).{0,12}(الأسرار|بيانات الاعتماد|المفاتيح|الملفات|البيانات|متغيرات البيئة)`), SeverityCritical},
	{regexp.MustCompile(`(لا تخبر|لا تبلغ|لا تُعلم).{0,8}المستخدم|سرّاً.{0,8}(أرسل|نفذ|ارفع)`), SeverityHigh},
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

// metadataPoisoningRules checks server-provided text loaded into the agent's
// context: instructions, tools, resources and prompt templates. Any of these
// can carry injected instructions, hidden Unicode or encoded payloads.
func metadataPoisoningRules(in Input) []Finding {
	var f []Finding
	if in.Init != nil && strings.TrimSpace(in.Init.Instructions) != "" {
		f = append(f, scanMetadata(in.Server.Name, "server instructions", "server:instructions", in.Init.Instructions)...)
	}
	for _, content := range in.ContentText {
		location := content.Kind + "-content:" + content.Name
		f = append(f, scanMetadata(in.Server.Name, content.Kind+" content", location, content.Text)...)
	}

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
	textLabel := kind + " metadata"
	if strings.HasSuffix(kind, " content") {
		textLabel = kind
		noun = strings.TrimSuffix(kind, " content")
	}
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
		title := "Prompt injection in " + noun + " metadata"
		if kind == "server instructions" {
			title = "Prompt injection in server instructions"
		} else if strings.HasSuffix(kind, " content") {
			title = "Prompt injection in " + kind
		}
		f = append(f, Finding{
			RuleID: "MCP201", Title: title,
			Severity: worst, OWASP: "MCP03", Server: server, Location: loc,
			Evidence:    clipEvidence(strings.Join(hits, " | "), 200),
			Description: "This server-controlled text is loaded into the agent's context. The model may follow these instructions over the system prompt, leading to data exfiltration or unauthorized actions (metadata poisoning).",
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
			RuleID: "MCP202", Title: "Invisible or bidirectional Unicode in " + textLabel,
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
			RuleID: "MCP202", Title: "Mixed-script homoglyph in " + textLabel,
			Severity: SeverityHigh, OWASP: "MCP03", Server: server, Location: loc,
			Evidence:    "mixed-script token: " + clipEvidence(tok, 60),
			Description: "A single token mixes Latin with Cyrillic/Greek letters that look nearly identical, a common way to disguise keywords from plaintext review and ASCII-based scanners.",
			Advice:      "Confine tool metadata to one script, or normalize confusable code points before loading them.",
		})
	}

	// 3. Hidden HTML / Markdown.
	if m := hiddenHTML.FindString(scan); m != "" {
		f = append(f, Finding{
			RuleID: "MCP203", Title: "Hidden HTML in " + textLabel,
			Severity: SeverityHigh, OWASP: "MCP03", Server: server, Location: loc, Evidence: clipEvidence(m, 80),
			Description: "Hidden HTML comments or tags can carry instructions that are not visibly shown but may be acted on by the model.",
			Advice:      "Remove HTML comments/script tags from server metadata.",
		})
	}
	if m := hiddenMD.FindString(scan); m != "" {
		f = append(f, Finding{
			RuleID: "MCP203", Title: "Embedded image/link in " + textLabel,
			Severity: SeverityMedium, OWASP: "MCP03", Server: server, Location: loc, Evidence: clipEvidence(m, 80),
			Description: "Embedded images/links can be used for tracking or to exfiltrate data via request parameters when rendered or fetched.",
			Advice:      "Avoid external image/link references in server metadata.",
		})
	}

	// 4. Large encoded blobs.
	if m := b64Blob.FindString(scan); m != "" {
		f = append(f, Finding{
			RuleID: "MCP204", Title: "Large encoded blob in " + textLabel,
			Severity: SeverityMedium, OWASP: "MCP03", Server: server, Location: loc, Evidence: "base64 length " + fmt.Sprint(len(m)),
			Description: "A long base64 blob may conceal a payload or instructions that avoid plaintext review.",
			Advice:      "Decode and inspect encoded blobs; remove those that are not required.",
		})
	}
	if m := hexBlob.FindString(scan); m != "" {
		f = append(f, Finding{
			RuleID: "MCP204", Title: "Large hex blob in " + textLabel,
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
				RuleID: "MCP205", Title: "Directive language combined with hidden text in " + textLabel,
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
		end := max
		for end > 0 && end < len(s) && !utf8.RuneStart(s[end]) {
			end--
		}
		return s[:end] + "..."
	}
	return s
}
