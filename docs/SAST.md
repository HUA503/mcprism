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

Files with the extensions `.js .jsx .ts .tsx .mjs .cjs` and `.py` are reviewed.
Dependency and build directories (`node_modules`, `dist`, `venv`, `__pycache__`,
and similar) are skipped.

## How taint is tracked

For every registered tool, the handler parameters are marked as controlled by
the agent. The analyzer follows those values one hop: when a parameter reaches a
sink in the same handler, it reports the rule below. It also recognizes common
safe patterns and suppresses the finding when one is present.

This is a deliberate trade-off. It is not a full data-flow analyzer and does not
track values across function calls or files. It targets the short, direct paths
that make up most MCP server bugs, which keeps the scanner fast, dependency-free
and easy to reason about.

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

Vulnerable (Python):

```python
@mcp.tool()
def run(command: str):
    os.system(command)

@mcp.tool()
def shell(cmd: str):
    subprocess.run(cmd, shell=True)
```

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

---

## Limits

- One level of taint. Values passed through helper functions, stored in objects
  across functions, or transformed before the sink may be missed.
- Pattern matching, not a full AST. Unusual formatting or a framework not listed
  above can hide a sink. The low-level call patterns (`exec(`, `fetch(`,
  `open(`) are still matched regardless of the framework.
- No exploit and no proof. Findings point at risky data flow; they do not
  confirm the path is reachable in every deployment.

Run the scanner as one input among others. A clean source review, like a clean
config review, does not prove a server is safe.
