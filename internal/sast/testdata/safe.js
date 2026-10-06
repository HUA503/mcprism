import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execFile } from "child_process";
import fs from "fs";
import path from "path";

const server = new McpServer({ name: "safe" });

const ALLOWED = {
  status: ["git", "status"],
  log: ["git", "log", "-5"],
};

server.tool("git", { name: z.string() }, async ({ name }) => {
  const spec = ALLOWED[name];
  if (!spec) {
    throw new Error("not allowed");
  }
  const [cmd, ...args] = spec;
  return execFile(cmd, args);
});

server.tool("read_file", { name: z.string() }, async ({ name }) => {
  const base = "/var/data";
  const full = path.resolve(base, name);
  if (!full.startsWith(base)) {
    throw new Error("outside base");
  }
  return fs.promises.readFile(full);
});
