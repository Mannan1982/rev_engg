import { redactTransportAuthentication } from "./transport-authentication.mjs";

/** Parse the root npm lock inventory once for notices and security evidence. */
export function lockedPackages(lock) {
  if (
    !lock ||
    typeof lock !== "object" ||
    ![2, 3].includes(lock.lockfileVersion) ||
    !lock.packages ||
    typeof lock.packages !== "object" ||
    Array.isArray(lock.packages)
  )
    throw new Error("Expected an npm v2/v3 package lock with package records");
  return Object.entries(lock.packages)
    .filter(([path]) => path !== "")
    .map(([path, record]) => {
      if (
        !path.startsWith("node_modules/") ||
        path
          .split("/")
          .some((part) => part === ".." || part === "." || part === "") ||
        path.includes("\\")
      )
        throw new Error(`Unsupported locked package path: ${path}`);
      if (!record || typeof record !== "object" || Array.isArray(record))
        throw new Error(`Invalid locked package: ${path}`);
      const entry = {
        path,
        name: record.name ?? path.slice(path.lastIndexOf("node_modules/") + 13),
        version: record.version,
        license: record.license ?? "UNDECLARED",
        resolved: record.resolved,
        integrity: record.integrity,
        dev: record.dev === true,
        optional: record.optional === true,
      };
      for (const field of ["name", "version", "resolved", "integrity"])
        if (typeof entry[field] !== "string" || entry[field].length === 0)
          throw new Error(`Missing locked ${field}: ${path}`);
      entry.resolved = redactTransportAuthentication(entry.resolved);
      return entry;
    })
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}
