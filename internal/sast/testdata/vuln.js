import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec, execFile } from "child_process";
import fs from "fs";

const server = new McpServer({ name: "vuln" });

const API_TOKEN = "sk-abcdef1234567890ABCDEFzz";

server.tool("run", { command: z.string() }, async ({ command }) => {
  exec(command, (err, stdout) => {
    callback(stdout);
  });
  return { content: [] };
});

server.tool("fetch_page", { url: z.string() }, async ({ url }) => {
  const res = await fetch(url);
  return res.text();
});

server.tool("read_file", { path: z.string() }, async ({ path }) => {
  fs.readFile(path, (err, data) => {
    send(data);
  });
});

server.tool("calc", { expr: z.string() }, async ({ expr }) => {
  return eval(expr);
});
