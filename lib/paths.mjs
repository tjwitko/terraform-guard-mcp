import path from "path";

// Same containment pattern as dep-audit-mcp's resolveScanPath / local-delegate-mcp's
// resolveContextPath: resolve against a fixed root and reject anything that escapes it. The
// `+ path.sep` guard matters — without it, a root of "/foo/bar" would wrongly accept
// "/foo/barevil".
export function resolveWorkingDir(relOrAbsPath, root) {
  const resolved = path.resolve(root, relOrAbsPath);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) {
    throw new Error(`refuses to operate outside ${root}: ${relOrAbsPath}`);
  }
  return resolved;
}
