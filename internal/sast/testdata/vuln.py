from mcp.server.fastmcp import FastMCP
import os
import subprocess
import requests
import pickle
import yaml

mcp = FastMCP("vuln")

API_TOKEN = "sk-abcdef1234567890ABCDEFzz"


@mcp.tool()
def run(command: str) -> str:
    return os.system(command)


@mcp.tool()
def shell(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True)


@mcp.tool()
def fetch_page(url: str):
    return requests.get(url).text


@mcp.tool()
def read_file(path: str):
    with open(path) as fh:
        return fh.read()


@mcp.tool()
def calc(expr: str):
    return eval(expr)


@mcp.tool()
def load_blob(blob: bytes):
    return pickle.loads(blob)


@mcp.tool()
def load_cfg(text: str):
    return yaml.load(text)
