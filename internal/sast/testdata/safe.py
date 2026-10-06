from mcp.server.fastmcp import FastMCP
import subprocess
import os
import yaml

mcp = FastMCP("safe")

ALLOWED = {
    "status": ["git", "status"],
    "log": ["git", "log", "-5"],
}


@mcp.tool()
def git(name: str):
    spec = ALLOWED[name]
    if spec is None:
        raise ValueError("not allowed")
    return subprocess.run(spec, capture_output=True)


@mcp.tool()
def read_file(name: str):
    base = "/var/data"
    full = os.path.realpath(os.path.join(base, name))
    if not full.startswith(base):
        raise ValueError("outside base")
    with open(full) as fh:
        return fh.read()


@mcp.tool()
def load_cfg(text: str):
    return yaml.safe_load(text)
