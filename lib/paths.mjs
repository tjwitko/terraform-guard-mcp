import { realpathSync } from "fs";
import path from "path";

// Same containment pattern as dep-audit-mcp's resolveScanPath / local-delegate-mcp's
// resolveContextPath: resolve against a fixed root and reject anything that escapes it. The
// `+ path.sep` guard matters — without it, a root of "/foo/bar" would wrongly accept
// "/foo/barevil".
//
// Real paths, not resolved text. path.resolve() only normalises the string, so a symlink inside
// the root that points outside it passed, and a root reached through a symlink refused the real
// spelling of paths under it. Both the root and the target are resolved with realpathSync and the
// real target is what comes back, so terraform runs in the directory that was checked rather than
// a link that could be followed somewhere else. A target that does not exist is refused, except
// that a path below a link out of the root is refused as outside: the walk up to the nearest
// existing ancestor is there so a refusal never says what does or does not exist out there.
//
// The same function, line for line below the argument check, is dep-audit-mcp's, identity-guard-mcp's
// and secret-guard-mcp's resolveScanPath. Change them together.
export function resolveWorkingDir(relOrAbsPath, scanRoot) {
  // Called with one argument for as long as terraform_validate has existed, which made every call
  // to that tool fail with `The "paths[0]" argument must be of type string. Received undefined` --
  // a Node path error naming neither the tool nor the missing root, so it read as a configuration
  // problem in the caller's environment rather than a bug here. Two of the three call sites passed
  // the root and one did not, and nothing said so.
  //
  // A missing root is a programming error in this server, not bad input from a caller, so it says
  // that plainly instead of failing several frames later on something unrecognisable.
  if (typeof scanRoot !== "string" || scanRoot === "") {
    throw new Error(
      "resolveWorkingDir requires a containment root as its second argument; " +
        `received ${scanRoot === undefined ? "undefined" : JSON.stringify(scanRoot)}. ` +
        "This is a defect in terraform-guard-mcp, not in the request."
    );
  }
  const root = realpathOrNull(scanRoot);
  if (root === null) throw new Error(`containment root does not exist: ${scanRoot}`);
  const requested = path.resolve(root, relOrAbsPath);
  let existing = requested;
  let real = realpathOrNull(existing);
  while (real === null && path.dirname(existing) !== existing) {
    existing = path.dirname(existing);
    real = realpathOrNull(existing);
  }
  if (real === null || (real !== root && !real.startsWith(root + path.sep))) {
    throw new Error(`refuses to operate outside ${scanRoot}: ${relOrAbsPath}`);
  }
  if (existing !== requested) throw new Error(`does not exist: ${relOrAbsPath}`);
  return real;
}

function realpathOrNull(p) {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
}
