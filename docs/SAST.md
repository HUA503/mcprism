# Source-code review (SAST)

Configuration review answers "how is this server launched and what is it allowed
to do". It does not answer "what does the handler do with a tool argument".
Most real vulnerabilities in an MCP server sit in that second question:

- A tool takes a `command` parameter and hands it to a shell.
- A tool takes a `url` parameter and fetches it.
- A tool takes a `path` parameter and opens it.

The agent that calls these tools is not a trusted caller. It can be steered by
prompt injection from a webpage, an email or another tool's output. An argument
that looks like user input is therefore attacker input, and passing it to a
shell, a request or a file path is a server-side bug even when "the agent is
supposed to use this tool".

mcprism reads the implementation and traces tool arguments into dangerous
sinks. It needs no build, no installed dependencies and no network.

```sh
mcprism vet ./path/to/server      # a whole checkout
mcprism vet ./path/to/server.py   # one file
```

## Languages and frameworks

| Language | Entry points recognized |
|---|---|
| JavaScript / TypeScript | `McpServer.tool(...)`, `Server.setRequestHandler(CallToolRequestSchema, ...)`, generic `.tool(...)` registrations |
| Python | `FastMCP` `@mcp.tool()`, low-level `call_tool` handler |
| Go | mcp-go `server.AddTool(...)` / `mcp.AddTool(...)` callbacks |
| Rust | official `rmcp` SDK methods marked with `#[tool]` |

Files with the extensions `.js .jsx .ts .tsx .mts .cts .mjs .cjs`, `.py`, `.go`
and `.rs` are reviewed. Cargo projects are recognized through `Cargo.toml`, and
Rust build output under `target/` is skipped. Other dependency and build directories
(`node_modules`, `dist`, `venv`, `__pycache__`, and similar) are skipped.

For Go, tool arguments are read through `req.RequireString`, `req.GetString` or
`req.Params.Arguments[...]`. Go has no `eval` and no standard-library
deserialization that runs code, so MCP804 and MCP805 are not emitted for Go;
the command, SSRF, path and secret rules (MCP801/802/803/806) are.

## How taint is tracked

For every registered tool, the handler parameters are marked as controlled by
the agent. JavaScript/TypeScript, Python and Go analysis follows simple local
assignments and propagates taint through arguments passed to unambiguous helper
functions. JavaScript/TypeScript helper tracking covers function declarations
and block-bodied `const`/`let`/`var` arrow functions. Go uses the standard
library parser to identify function boundaries and follows unique free-function
helpers across files in the same package; selector calls into another file are
left unresolved. Python follows explicitly imported functions and helper calls
across same-directory modules. JS/TS follows named imports of exported
helpers from same-directory modules and continues through helper calls in those
modules. Python and JS/TS cross-module traversal is bounded by eight imports
deep, 64 source files and 16 MiB of source per analyzed entry file. Rust
recognizes the official `rmcp` `#[tool]` macro and follows local aliases through
unique same-file helper functions, including multi-step calls. Rust does not
expand macros or resolve trait-based dispatch.
Sink recognition remains pattern-based. Common safe patterns are recognized
where implemented.

This is not a full-program data-flow analyzer. Cross-file tracking is limited to
bounded Go same-package free-function calls and explicitly imported Python and
JS/TS helpers. JS/TS follows named imports and local helper calls in imported
modules within the limits above. It does not track object properties, returned
values, dynamic dispatch, re-exports or other import forms. The bounded analysis
keeps the scanner dependency-free and predictable.

---

## MCP801 — Tool input reaches a command/process sink

Severity: critical. CWE-78.

An argument the agent controls is used as the command, or passed to a shell. A
prompt-injected agent can run arbitrary commands on the host.

Vulnerable (JavaScript):

```js
server.tool("run", { command: z.string() }, async ({ command }) => {
  exec(command, (err, stdout) => callback(stdout));
});
```

The same flow is followed through unambiguous same-file helpers:

```js
function runCommand(command) {
  exec(command, (err, stdout) => callback(stdout));
}

server.tool("run", { command: z.string() }, async ({ command }) => {
  runCommand(command);
});
```

JS/TS can also follow a named import of an exported helper in a neighboring
source file to a direct sink:

```js
// server.js
import { runWithShell as runLocal } from "./local-helpers.js";

server.tool("run", { command: z.string() }, async ({ command }) => {
  runLocal(command);
});
```

```js
// local-helpers.js
export function runWithShell(command) {
  exec(command, (err, stdout) => callback(stdout));
}
```

The finding points to the sink in `local-helpers.js`. If `runWithShell` calls
another same-module helper with the controlled argument, analysis follows that
call as well. The same applies to further named imports within the traversal
limits.

Vulnerable (Python):

```python
@mcp.tool()
def run(command: str):
    os.system(command)

@mcp.tool()
def shell(cmd: str):
    subprocess.run(cmd, shell=True)
```

Python handlers can also pass tool input through imported helper chains in
same-directory modules:

```python
# server.py
from local_helpers import run_with_shell as run_local

@mcp.tool()
def run(command: str):
    run_local(command)
```

```python
# local_helpers.py
def run_with_shell(command: str):
    subprocess.run(command, shell=True)
```

The finding points to the sink in `local_helpers.py`. The same analysis follows
further unambiguous local helper calls and named imports within its resource
limits.

Vulnerable (Go), a tool argument handed to a shell:

```go
s.AddTool(mcp.NewTool("run_command",
	mcp.String("command", mcp.Required())),
	func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		command := req.RequireString("command")
		c := exec.Command("sh", "-c", command)
		out, _ := c.Output()
		return mcp.NewToolResultText(string(out)), nil
	})
```

Vulnerable (Rust, official `rmcp` SDK):

```rust
fn run_with_shell(command: String) {
    Command::new("sh").arg("-c").arg(command).output().unwrap();
}

#[tool]
async fn run(&self, Parameters(args): Parameters<RunArgs>) -> String {
    run_with_shell(args.command);
    "done".into()
}
```

mcprism follows the tool argument through the local helper and flags the shell
sink in `run_with_shell`.

Fixed: keep a fixed set of commands and pass arguments without a shell.

```js
const ALLOWED = { status: ["git", "status"], log: ["git", "log", "-5"] };
server.tool("git", { name: z.string() }, async ({ name }) => {
  const spec = ALLOWED[name];
  if (!spec) throw new Error("not allowed");
  const [cmd, ...args] = spec;
  return execFile(cmd, args);
});
```

```python
ALLOWED = {"status": ["git", "status"], "log": ["git", "log", "-5"]}

@mcp.tool()
def git(name: str):
    spec = ALLOWED.get(name)
    if spec is None:
        raise ValueError("not allowed")
    return subprocess.run(spec, capture_output=True)
```

A fixed command with unvalidated arguments in an array is reported at medium
instead of critical, since it usually leads to argument injection rather than
full command execution.

## MCP802 — Tool input controls a request URL (SSRF)

Severity: high. CWE-918.

An argument is used as the URL of an outbound request. The agent can point it at
cloud metadata (`http://169.254.169.254/latest/meta-data/`), internal admin
panels, or `localhost` services, and read or trigger the response.

Vulnerable:

```js
server.tool("fetch_page", { url: z.string() }, async ({ url }) => {
  return (await fetch(url)).text();
});
```

```python
@mcp.tool()
def fetch_page(url: str):
    return requests.get(url).text
```

```go
s.AddTool(mcp.NewTool("fetch_page",
	mcp.String("url", mcp.Required())),
	func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		target := req.RequireString("url")
		r, err := http.Get(target)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(r.Status)
	})
```

Vulnerable (Rust, official `rmcp` SDK):

```rust
#[tool]
async fn fetch(&self, Parameters(args): Parameters<FetchArgs>) -> String {
    reqwest::get(args.url).await.unwrap().text().await.unwrap()
}
```

Fixed: pin a constant base URL or allow-list hosts, and block metadata and
private address ranges.

```js
server.tool("fetch_page", { id: z.string() }, async ({ id }) => {
  return (await fetch(`https://api.example.com/v1/${encodeURIComponent(id)}`)).text();
});
```

A constant URL prefix with the input appended to the path is not flagged, since
the host stays fixed. A full URL supplied by the agent is.

## MCP803 — Tool input used as a file path

Severity: high. CWE-22.

An argument is used as a filesystem path without being confined. Values such as
`../../etc/passwd` can read or overwrite files outside the intended directory.

Vulnerable:

```js
server.tool("read_file", { path: z.string() }, async ({ path }) => {
  fs.readFile(path, (err, data) => send(data));
});
```

```python
@mcp.tool()
def read_file(path: str):
    with open(path) as fh:
        return fh.read()
```

```go
s.AddTool(mcp.NewTool("read_file",
	mcp.String("file", mcp.Required())),
	func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		p := req.RequireString("file")
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(string(data)), nil
	})
```

Vulnerable (Rust, official `rmcp` SDK):

```rust
#[tool]
async fn read_file(&self, Parameters(args): Parameters<ReadArgs>) -> String {
    tokio::fs::read_to_string(args.path).await.unwrap()
}
```

Fixed: resolve the path and confirm it stays inside one base directory.

```js
server.tool("read_file", { name: z.string() }, async ({ name }) => {
  const base = "/var/data";
  const full = path.resolve(base, name);
  if (!full.startsWith(base)) throw new Error("outside base");
  return fs.promises.readFile(full);
});
```

```python
@mcp.tool()
def read_file(name: str):
    base = "/var/data"
    full = os.path.realpath(os.path.join(base, name))
    if not full.startswith(base):
        raise ValueError("outside base")
    with open(full) as fh:
        return fh.read()
```

Note that `path.join` / `os.path.join` alone do not stop traversal; the analyzer
only treats the path as safe when a resolve/realpath is combined with a
`startsWith` / `startswith` boundary check.

## MCP804 — Dynamic code execution

Severity: high (critical when the input reaches it). CWE-94.

`eval`, the `Function` constructor and Python `exec` turn text into code. When
agent input reaches them, the agent runs code inside the server process.

Vulnerable:

```js
server.tool("calc", { expr: z.string() }, async ({ expr }) => eval(expr));
```

```python
@mcp.tool()
def calc(expr: str):
    return eval(expr)
```

Fixed: remove the dynamic evaluation. For a calculator, parse a restricted
grammar or use a sandboxed expression library that does not evaluate arbitrary
code. Run it in an isolated process if code execution is genuinely required, and
never feed it agent-controlled text.

## MCP805 — Unsafe deserialization

Severity: high. CWE-502.

`pickle.loads`, `marshal.loads` and `yaml.load` without a safe loader rebuild
objects from data. Crafted payloads can trigger code execution (pickle,
marshal) or construct unexpected objects (unsafe YAML).

Vulnerable:

```python
@mcp.tool()
def load_blob(blob: bytes):
    return pickle.loads(blob)

@mcp.tool()
def load_cfg(text: str):
    return yaml.load(text)
```

Fixed: use safe formats and loaders.

```python
@mcp.tool()
def load_cfg(text: str):
    return yaml.safe_load(text)

# or: yaml.load(text, Loader=yaml.SafeLoader)
```

Do not deserialize pickle or marshal from data an agent can supply. Use JSON for
structured input.

## MCP806 — Hardcoded credential

Severity: high for recognized credential formats, medium for suspected secrets.
CWE-798.

A credential is written into the source. Anyone with the code or the built
artifact can extract and reuse it.

Vulnerable:

```js
const API_TOKEN = "sk-abcdef1234567890ABCDEFzz";
```

```python
API_TOKEN = "sk-abcdef1234567890ABCDEFzz"
```

Fixed: load it from the environment or a secret store, and rotate the exposed
value.

```js
const apiToken = process.env.API_TOKEN;
```

```python
api_token = os.environ["API_TOKEN"]
```

Values read from `process.env` or `os.environ`, and obvious placeholders, are
not flagged.

## MCP807 — Agent-controlled module loading

Severity: medium. CWE-829.

A handler passes an agent-controlled value to `require()`. The agent can then
select an unexpected installed module whose initialization code runs inside
the server process.

Vulnerable:

```js
server.tool("load", { name: z.string() }, async ({ name }) => {
  const module = require(name);
  return module.run();
});
```

Fixed: import the supported modules statically and map user choices to that
fixed set.

```js
const modules = {
  weather: require("./weather"),
  calendar: require("./calendar"),
};

server.tool("load", { name: z.enum(["weather", "calendar"]) }, async ({ name }) => {
  return modules[name].run();
});
```

Do not construct a module name or path from tool input.

---

## Limits

- JavaScript/TypeScript and Rust taint follows simple aliases and arguments
  passed to unambiguous same-file helpers. JS/TS also follows named imports of
  exported helpers and their local helper chains across same-directory modules,
  with bounded depth, file count and total source size. Python follows explicit
  imports and helper chains across same-directory modules within the same limits.
  Go follows unique
  same-package free functions across files. JS/TS helper tracking
  currently recognizes function declarations and block-bodied arrow functions;
  Rust helper resolution uses unique names and does not model trait dispatch or
  macro expansion. Other values passed through files, object properties,
  return values, dynamic dispatch, re-exports and unsupported import forms may
  be missed.
- Sink detection is pattern-based, not a full AST/data-flow analysis. Unusual
  formatting or a framework not listed above can hide or misclassify a sink.
  Common low-level patterns (`exec(`, `fetch(`, `open(`) are also matched.
- No exploit and no proof. Findings point at risky data flow; they do not
  confirm the path is reachable in every deployment.

Run the scanner as one input among others. A clean source review, like a clean
config review, does not prove a server is safe.
