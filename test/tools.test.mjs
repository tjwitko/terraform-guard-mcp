import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

import { resolveWorkingDir } from "../lib/paths.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.resolve(__dirname, "..", "index.mjs");
const FIXTURES = path.resolve(__dirname, "..", "fixtures");

/**
 * Drives the real server over stdio, the way an MCP client does.
 *
 * This file exists because `terraform_validate` never worked. It called
 * `resolveWorkingDir(working_dir)` while the function takes `(path, root)`, so every invocation
 * failed with `The "paths[0]" argument must be of type string. Received undefined` -- a Node path
 * error naming neither the tool nor the missing root, which reads like the caller's environment is
 * misconfigured. Two of three call sites passed the root; one did not.
 *
 * 130 tests did not catch it. They cover this tool's classification logic and never its handler,
 * and agent-gate's corpus calls `terraform_plan` rather than `terraform_validate`, so the gate
 * could not see it either. It surfaced when a model was told to use the tool and reported honestly
 * that it errored on every call.
 *
 * So these tests invoke the tools rather than the functions behind them. That is the layer that
 * shipped broken.
 */
function callTool(name, args, { timeoutMs = 60_000 } = {}) {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [SERVER], {
      env: { ...process.env, TF_WORKING_ROOT: FIXTURES },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let out = "";
    let settled = false;
    const done = (fn, v) => { if (!settled) { settled = true; proc.kill(); fn(v); } };
    const timer = setTimeout(() => done(reject, new Error(`${name} timed out`)), timeoutMs);

    proc.stdout.on("data", (d) => {
      out += d.toString();
      for (const line of out.split("\n")) {
        if (!line.trim().startsWith("{")) continue;
        let msg;
        try { msg = JSON.parse(line); } catch { continue; }
        if (msg.id === 2) { clearTimeout(timer); done(resolve, msg); }
      }
    });
    proc.on("error", (e) => { clearTimeout(timer); done(reject, e); });

    const send = (o) => proc.stdin.write(`${JSON.stringify(o)}\n`);
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {
      protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "test", version: "0" } } });
    send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
    send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name, arguments: args } });
  });
}

const textOf = (msg) => (msg?.result?.content || []).map((c) => c.text).join("\n");

// The exact failure, at the layer it happened.
test("terraform_validate resolves its working directory instead of crashing on an undefined root", async () => {
  const msg = await callTool("terraform_validate", { working_dir: "aws-secure" });
  const text = textOf(msg);
  assert.doesNotMatch(text, /paths\[0\]/, "the path resolver must receive a root");
  assert.doesNotMatch(text, /outside undefined/, "the containment root must not be undefined");
  assert.doesNotMatch(text, /requires a containment root/, "the server must pass its own root");
});

// Containment still holds. A fix that resolved the crash by dropping the check would be worse than
// the crash: this tool takes a caller-supplied path.
test("terraform_validate still refuses a directory outside the working root", async () => {
  const msg = await callTool("terraform_validate", { working_dir: "../../etc" });
  const text = textOf(msg);
  assert.match(text, /Refusing to validate|refuses to operate outside/i);
  assert.doesNotMatch(text, /paths\[0\]/);
});

// The defect was one call site of three disagreeing with the others, so the contract is pinned
// directly rather than only through the tools.
test("resolveWorkingDir refuses to run without a containment root", () => {
  assert.throws(() => resolveWorkingDir("terraform"), /requires a containment root/);
  assert.throws(() => resolveWorkingDir("terraform", ""), /requires a containment root/);
});

test("resolveWorkingDir resolves inside its root and rejects escapes", () => {
  const root = "/srv/project";
  assert.equal(resolveWorkingDir("terraform", root), "/srv/project/terraform");
  assert.equal(resolveWorkingDir(root, root), root);
  assert.throws(() => resolveWorkingDir("../elsewhere", root), /refuses to operate outside/);
  // The `+ path.sep` guard: a sibling sharing the root's prefix is outside it.
  assert.throws(() => resolveWorkingDir("/srv/projectevil", root), /refuses to operate outside/);
});
