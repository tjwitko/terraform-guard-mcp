import path from "path";

// Same containment pattern as dep-audit-mcp's resolveScanPath / local-delegate-mcp's
// resolveContextPath: resolve against a fixed root and reject anything that escapes it. The
// `+ path.sep` guard matters — without it, a root of "/foo/bar" would wrongly accept
// "/foo/barevil".
export function resolveWorkingDir(relOrAbsPath, root) {
  // Called with one argument for as long as terraform_validate has existed, which made every call
  // to that tool fail with `The "paths[0]" argument must be of type string. Received undefined` --
  // a Node path error naming neither the tool nor the missing root, so it read as a configuration
  // problem in the caller's environment rather than a bug here. Two of the three call sites passed
  // the root and one did not, and nothing said so.
  //
  // A missing root is a programming error in this server, not bad input from a caller, so it says
  // that plainly instead of failing several frames later on something unrecognisable.
  if (typeof root !== "string" || root === "") {
    throw new Error(
      "resolveWorkingDir requires a containment root as its second argument; " +
        `received ${root === undefined ? "undefined" : JSON.stringify(root)}. ` +
        "This is a defect in terraform-guard-mcp, not in the request."
    );
  }
  const resolved = path.resolve(root, relOrAbsPath);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) {
    throw new Error(`refuses to operate outside ${root}: ${relOrAbsPath}`);
  }
  return resolved;
}
