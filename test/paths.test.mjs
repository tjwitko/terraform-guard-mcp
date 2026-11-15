import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, realpathSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { resolveWorkingDir } from "../lib/paths.mjs";

// Path containment, over a real tree. The comparison has to be made between real paths: a
// symlink inside the root that points outside it is outside it, and a root reached through a
// symlink still contains what is under it. Comparing the text of path.resolve() gets both wrong.
//
//   <base>/root/src/app.py
//   <base>/root/escape     -> <base>/outside      (a directory link out of the root)
//   <base>/root/leak.txt   -> <base>/outside/creds (a file link out of the root)
//   <base>/root/inner      -> <base>/root/src     (a link that stays inside)
//   <base>/root/dangling   -> <base>/nowhere
//   <base>/rootlink        -> <base>/root         (the root, reached through a link)
//   <base>/root-evil/x                          (a sibling sharing the root's prefix)
//   <base>/outside/creds
function tree() {
  const base = realpathSync(mkdtempSync(path.join(tmpdir(), "paths-")));
  const root = path.join(base, "root");
  mkdirSync(path.join(root, "src"), { recursive: true });
  mkdirSync(path.join(base, "outside"));
  mkdirSync(path.join(base, "root-evil"));
  writeFileSync(path.join(root, "src", "app.py"), "x = 1\n");
  writeFileSync(path.join(base, "outside", "creds"), "outside\n");
  writeFileSync(path.join(base, "root-evil", "x"), "outside\n");
  symlinkSync(path.join(base, "outside"), path.join(root, "escape"));
  symlinkSync(path.join(base, "outside", "creds"), path.join(root, "leak.txt"));
  symlinkSync(path.join(root, "src"), path.join(root, "inner"));
  symlinkSync(path.join(base, "nowhere"), path.join(root, "dangling"));
  symlinkSync(root, path.join(base, "rootlink"));
  return { base, root, rootlink: path.join(base, "rootlink"), done: () => rmSync(base, { recursive: true, force: true }) };
}

test("resolves paths inside the root to their real location", () => {
  const t = tree();
  try {
    assert.equal(resolveWorkingDir(".", t.root), t.root);
    assert.equal(resolveWorkingDir("src/app.py", t.root), path.join(t.root, "src", "app.py"));
    assert.equal(resolveWorkingDir(path.join(t.root, "src"), t.root), path.join(t.root, "src"));
    // A link that stays inside the root is followed, and the real path is what comes back.
    assert.equal(resolveWorkingDir("inner/app.py", t.root), path.join(t.root, "src", "app.py"));
  } finally {
    t.done();
  }
});

test("refuses paths that leave the root lexically", () => {
  const t = tree();
  try {
    assert.throws(() => resolveWorkingDir("../outside/creds", t.root), /refuses to operate outside/);
    assert.throws(() => resolveWorkingDir(path.join(t.base, "outside"), t.root), /refuses to operate outside/);
    // String-prefix checks without the separator let root-evil through.
    assert.throws(() => resolveWorkingDir(path.join(t.base, "root-evil", "x"), t.root), /refuses to operate outside/);
  } finally {
    t.done();
  }
});

test("refuses a symlink inside the root that points outside it", () => {
  const t = tree();
  try {
    assert.throws(() => resolveWorkingDir("escape", t.root), /refuses to operate outside/);
    assert.throws(() => resolveWorkingDir("escape/creds", t.root), /refuses to operate outside/);
    assert.throws(() => resolveWorkingDir("leak.txt", t.root), /refuses to operate outside/);
  } finally {
    t.done();
  }
});

test("a root reached through a symlink still contains what is under it", () => {
  const t = tree();
  try {
    assert.equal(resolveWorkingDir(".", t.rootlink), t.root);
    assert.equal(resolveWorkingDir("src/app.py", t.rootlink), path.join(t.root, "src", "app.py"));
    // The real spelling of a path inside the root is inside it, whichever spelling the root has.
    assert.equal(resolveWorkingDir(path.join(t.root, "src"), t.rootlink), path.join(t.root, "src"));
    assert.equal(resolveWorkingDir(path.join(t.rootlink, "src"), t.root), path.join(t.root, "src"));
    assert.throws(() => resolveWorkingDir("escape", t.rootlink), /refuses to operate outside/);
  } finally {
    t.done();
  }
});

test("refuses a target that does not exist", () => {
  const t = tree();
  try {
    assert.throws(() => resolveWorkingDir("missing", t.root), /does not exist/);
    assert.throws(() => resolveWorkingDir("dangling", t.root), /does not exist/);
    // Below a link that leaves the root, the answer is "outside", not "does not exist": the
    // refusal must not tell a caller anything about what exists out there.
    assert.throws(() => resolveWorkingDir("escape/missing", t.root), /refuses to operate outside/);
    assert.throws(() => resolveWorkingDir("../nowhere", t.root), /refuses to operate outside/);
    assert.throws(() => resolveWorkingDir(".", path.join(t.base, "no-root")), /does not exist/);
  } finally {
    t.done();
  }
});
