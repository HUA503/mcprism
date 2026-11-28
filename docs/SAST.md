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
mcprism vet --repo https://github.com/owner/repo --ref main
```

`--repo` fetches a public GitHub source archive for static analysis. It does
not check out submodules, fetch dependencies or execute repository code. The
archive is size-bounded and extracted to a temporary directory that is removed
when the scan exits. Omit `--ref` to use the default branch. Since this option
downloads source, it is the one `vet` source mode that needs network access.

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

Go sink matching follows explicit package aliases for `os/exec`, `net/http`,
`os`, `io/ioutil`, `path/filepath` and `strings`. Dot imports and aliases
created through local variables are not resolved, except simple local function
values for process execution such as `run := exec.Command` and chains of those
assignments. When a local name is assigned different values in the analyzed
block, it is treated as ambiguous and is not followed.

When scanning a source tree with `go.mod`, Go analysis also follows calls to
exported free functions in explicitly imported packages that are present in
that tree. It uses the module path to map imports to local directories, follows
the argument through further helpers in that package, and reports the sink at
its source file and line. It does not download dependencies. This traversal is
limited to eight imported-package hops, 64 source files and 16 MiB per tool
entry. Imported methods, external modules, workspaces without a matching local
module, and packages outside the scanned tree are not resolved.

Python sink checks follow explicit import aliases for `os`, `subprocess`,
`requests`, `httpx`, `urllib`, `pathlib`, `pickle`, `marshal` and `yaml`,
including both `import module as alias` and `from module import function as
alias` forms. They also follow simple local callable assignments such as
`run = subprocess.run` and chains of those assignments; reassignments and
dynamic callable expressions are not resolved.

JavaScript/TypeScript command and request checks follow named ES imports and
destructured CommonJS imports from `child_process`, `axios`, `http`, `https`,
`got`, `request`, `node-fetch` and `undici`. Statically imported module objects
are also recognized for the supported request libraries.

Rust process and file sinks follow direct and grouped aliases of
`std::process::Command` and `std::fs::File` in explicit `use` declarations.
During Cargo directory scans, Rust also follows explicit `use crate::...`,
`use self::...` and `use super::...` imports to uniquely named free functions
in the same package. This traversal is limited to eight import hops, 64 source
files and 16 MiB per tool entry. It excludes `tests`, `examples`, `benches` and
`src/bin` from the shared helper index. Grouped imports, re-exports, external
crates, direct qualified calls such as `helpers::run_command(...)`, and
ambiguous helper names are not resolved.

## How taint is tracked

For every registered tool, the handler parameters are marked as controlled by
the agent. JavaScript/TypeScript, Python and Go analysis follows simple local
assignments and propagates taint through arguments passed to unambiguous helper
functions. JavaScript/TypeScript helper tracking covers function declarations
and block-bodied `const`/`let`/`var` arrow functions. Go uses the standard
library parser to identify function boundaries and follows unique free-function
helpers plus receiver-type-matched methods across files in the same package.
It also follows exported functions imported from local packages in the same Go
module and the helper chains they call, within the traversal limits above.
Method calls are followed when the receiver type can be identified from a
same-file declaration or composite literal, a unique same-package constructor
return type, or the current method receiver. Python follows explicitly imported
functions and helpers called through explicit module aliases across
same-directory modules, including parent-package modules reached through
explicit relative imports. Parent traversal requires an `__init__.py` marker
at each package level, so a crafted import cannot expand a single-file scan
into unrelated parent directories.
JS/TS follows named and namespace ES imports, destructured CommonJS
`require()` imports, and direct named calls through a statically required
CommonJS module object when they reference exported helpers from same-directory
modules. It continues through helper calls in those modules. Python and JS/TS cross-module traversal
is bounded by eight imports deep, 64 source files and 16 MiB of source per
analyzed entry file. Rust recognizes the official `rmcp` `#[tool]` macro and
follows local aliases through same-file helpers and explicitly imported,
uniquely named free functions in the scanned Cargo package, within the bounds
above. Rust does not expand macros or resolve trait-based dispatch.
Sink recognition remains pattern-based. Common safe patterns are recognized
where implemented.

JavaScript/TypeScript, Python and Go preserve taint through simple statically
named fields assigned from controlled input. Python also follows literal
dictionary keys, and Go follows literal string map keys. Dynamic keys, nested
container mutation, and values returned from a function are not modeled.

This is not a full-program data-flow analyzer. Cross-file tracking is limited to
bounded Go same-package free-function calls, methods with an inferable receiver
type, and exported free functions in local module packages; explicitly
imported Python and JS/TS helpers; and explicitly imported Rust helpers from
the same Cargo package. Go leaves imported methods and calls on
opaque or ambiguous receivers unresolved. Captured receivers are followed when
their type has a unique same-file declaration or constructor.
Python supports
named imports and direct module imports with an alias, including multi-level
relative imports inside marked packages; JS/TS follows named and namespace ES
imports plus CommonJS `require()` imports and local helper calls in imported
modules within the limits above. Default ES imports, computed module-object
properties, re-exports, package resolution and other import forms are not
resolved. The analyzers do not model arbitrary object graphs, returned values
or dynamic dispatch. Field tracking is limited to direct, statically named
assignments and reads. The bounded analysis keeps the scanner dependency-free
and predictable.

Prompt-injection checks use offline signatures rather than a language model.
The current signatures include common English, Simplified/Traditional Chinese,
Japanese and Korean patterns, including some multi-step credential collection
and exfiltration phrasing. They can still miss paraphrases, indirect semantic
coercion, uncommon languages and instructions whose meaning depends on context;
a clean result is not proof that metadata is safe. Conversely, matching generic
phrases in benign documentation can produce false positives.

Python and Go also use a conservative expression-level rule for local
assignments: if the right-hand side contains a tainted name, the assigned value
is treated as tainted. This can catch values passed through wrapper calls, but
it does not summarize what a helper actually returns. For example, a helper
that always returns a fixed allow-listed command can still make its caller's
assignment look tainted. Review findings in context; the analyzer may
over-report such flows as well as miss flows hidden by dynamic dispatch or
unsupported syntax. Simple tuple/list unpacking assignments propagate taint to
each named Python target, including a starred `*rest` target, when the
right-hand side contains controlled input. Go assignments
with one expression per target, including `var` declarations, preserve that
position; when a single helper call returns multiple values, each target is
conservatively treated as tainted if the call receives controlled input.

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

Namespace imports are followed when the call directly names an exported
helper:

```ts
import * as localHelpers from "./local-helpers.js";

server.tool("run", { command: z.string() }, async ({ command }) => {
  localHelpers.runWithShell(command);
});
```

CommonJS named exports and destructured `require()` imports are also followed:

```js
// server.cjs
const { runWithShell: runLocal } = require("./local-helpers.cjs");

server.tool("run", { command: z.string() }, async ({ command }) => {
  runLocal(command);
});
```

```js
// local-helpers.cjs
function runWithShell(command) {
  exec(command, (err, stdout) => callback(stdout));
}

module.exports = { runWithShell };
```

The scanner resolves quoted relative module paths and unambiguous named
bindings. It also follows a direct property call through a module alias, such
as `helpers.runWithShell(command)`. It does not resolve package names or
computed calls such as `helpers[name](command)`.

The same CommonJS export can be reached through a statically required module
object:

```js
// server.cjs
const helpers = require("./local-helpers.cjs");

server.tool("run", { command: z.string() }, async ({ command }) => {
  helpers.runWithShell(command);
});
```

The analysis follows only direct calls to exported named properties.

An explicitly imported module alias is also followed:

```python
# server.py
import local_helpers as helpers

@mcp.tool()
def run(command: str):
    helpers.run_with_shell(command)
```

This is limited to an unambiguous local module file and the same traversal
budgets. Multi-level relative imports are resolved only while each parent
package has an `__init__.py` marker. Absolute dotted package imports and dynamic
module names are not resolved.

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
limits. In a package, `from ..shell import run` is also followed when each
parent package level has an `__init__.py` file.

Vulnerable (Go), a tool argument handed to a shell:

```go
import process "os/exec"

s.AddTool(mcp.NewTool("run_command",
	mcp.String("command", mcp.Required())),
	func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		command := req.RequireString("command")
		c := process.Command("sh", "-c", command)
		out, _ := c.Output()
		return mcp.NewToolResultText(string(out)), nil
	})
```

Go also follows same-package methods when it can infer the receiver type. In
this example, `commandRunner.go` defines `NewCommandRunner() *CommandRunner` and
`func (r *CommandRunner) run(command string)`. The analyzer uses the constructor
signature to identify the captured receiver and follows the handler call into
that method:

```go
runner := NewCommandRunner()
s.AddTool(mcp.NewTool("run_command", mcp.String("command", mcp.Required())),
	func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		command := req.RequireString("command")
		runner.run(command)
		return mcp.NewToolResultText("done"), nil
	})
```

Calls through a receiver whose type is ambiguous or cannot be inferred from the
same source file remain unresolved.

For directory scans, a same-module import of an exported helper is followed as
well. The module path from `go.mod` maps the import to source already in the
scanned tree; the scanner does not fetch packages:

```go
// server.go, module example.com/server
import "example.com/server/internal/runner"

func register(s *server) {
	s.AddTool("run", func(command string) {
		runner.Execute(command)
	})
}
```

```go
// internal/runner/runner.go
package runner

import "os/exec"

func Execute(command string) error {
	return execute(command)
}

func execute(command string) error {
	return exec.Command("sh", "-c", command).Run()
}
```

The finding points to `internal/runner/runner.go`. Only exported package
functions are imported directly; methods on imported types and code outside
the scanned tree are not followed.

Vulnerable (Rust, official `rmcp` SDK):

```rust
use std::process::Command as Process;

fn run_with_shell(command: String) {
    Process::new("sh").arg("-c").arg(command).output().unwrap();
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
  passed to unambiguous same-file helpers. Rust also follows direct `crate`,
  `self` and `super` imports of uniquely named functions during Cargo directory
  scans, within eight import hops, 64 files and 16 MiB per entry; it excludes
  `tests`, `examples`, `benches` and `src/bin` from the shared helper index.
  JS/TS also follows named ES imports
  and static CommonJS `require()` imports or direct named calls through a
  module object for exported helpers and their local helper chains across
  same-directory modules, with bounded depth, file count and total source size.
  Python follows explicit imports and helper chains across same-directory
  modules and marked parent packages within the same limits. Absolute dotted
  package imports and re-exports are not resolved.
  Go follows unique same-package free functions and receiver-type-matched
  methods across files, plus exported functions imported from local packages
  in the same module within eight package hops, 64 helper files and 16 MiB per
  entry. It does not resolve imported methods or packages outside the scanned
  tree. JS/TS helper tracking
  currently recognizes function declarations and block-bodied arrow functions;
  Rust does not resolve grouped imports, re-exports, direct qualified calls,
  trait dispatch or macro expansion. Other values passed through files, object properties,
  return values, dynamic dispatch, re-exports, computed module-object calls and
  unsupported import forms may be missed.
- Sink detection is pattern-based, not a full AST/data-flow analysis. Unusual
  formatting or a framework not listed above can hide or misclassify a sink.
  Common low-level patterns (`exec(`, `fetch(`, `open(`) are also matched.
- No exploit and no proof. Findings point at risky data flow; they do not
  confirm the path is reachable in every deployment.

Run the scanner as one input among others. A clean source review, like a clean
config review, does not prove a server is safe.
