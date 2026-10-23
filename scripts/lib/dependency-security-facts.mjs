import { createHash } from "node:crypto";
import { isAbsolute, relative, sep } from "node:path";

const record = (value) =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const count = (value) => Number.isSafeInteger(value) && value >= 0;

export function registryIdentity(resolved, integrity) {
  try {
    const url = new URL(resolved);
    return (
      url.protocol === "https:" &&
      url.hostname === "registry.npmjs.org" &&
      url.port === "" &&
      url.username === "" &&
      url.password === "" &&
      /^sha512-[A-Za-z0-9+/]{86}==$/u.test(integrity)
    );
  } catch {
    return false;
  }
}

export function requireRegistryLock(packages) {
  for (const entry of packages)
    if (!registryIdentity(entry.resolved, entry.integrity))
      throw new Error(`Unsupported registry or integrity for ${entry.path}`);
}
export function advisoryFacts(value, exitCode) {
  const counts = value?.metadata?.vulnerabilities;
  const keys = ["info", "low", "moderate", "high", "critical", "total"];
  if (
    !record(counts) ||
    !keys.every((key) => count(counts[key])) ||
    keys.slice(0, -1).reduce((sum, key) => sum + counts[key], 0) !==
      counts.total ||
    value.error !== undefined
  )
    return {
      status: "unavailable",
      reason: "invalid_advisory_report",
      affected_packages: null,
    };
  const status =
    counts.total > 0
      ? "failed"
      : exitCode === 0 && value.error === undefined
        ? "passed"
        : "unavailable";
  return {
    status,
    reason: status === "unavailable" ? "advisory_command_failed" : null,
    affected_packages: counts.total,
    severity: Object.fromEntries(keys.map((key) => [key, counts[key]])),
  };
}
export function signatureFacts(value, exitCode) {
  if (
    !record(value) ||
    !Array.isArray(value.invalid) ||
    !Array.isArray(value.missing)
  )
    return {
      status: "unavailable",
      reason: "invalid_signature_report",
      invalid: null,
      missing: null,
      verified: null,
    };
  const status =
    value.invalid.length || value.missing.length
      ? "failed"
      : exitCode === 0 && value.error === undefined
        ? "passed"
        : "unavailable";
  return {
    status,
    reason: status === "unavailable" ? "signature_command_failed" : null,
    invalid: value.invalid.length,
    missing: value.missing.length,
    verified: null,
  };
}

/** Use npm's resolved relationships, never implement a second dependency resolver. */
export function dependencyGraph(value, directory, installedPackages) {
  if (!record(value) || value.path !== directory)
    throw new Error("Installed tree root does not match the selected project");
  const nodes = new Map(),
    edges = new Map(),
    omissions = new Map(),
    unknowns = [];
  const locked = new Map(installedPackages.map((entry) => [entry.path, entry]));
  const pending = [{ value, from: null, dependency: null }];
  while (pending.length) {
    const item = pending.pop(),
      node = item.value;
    if (
      !record(node) ||
      typeof node.path !== "string" ||
      !isAbsolute(node.path)
    ) {
      unknowns.push({
        from: item.from,
        dependency: item.dependency,
        reason: "unresolved_identity",
      });
      continue;
    }
    const path = relative(directory, node.path);
    if (
      path === ".." ||
      path.startsWith(".." + sep) ||
      isAbsolute(path) ||
      typeof node.name !== "string" ||
      node.name.length === 0 ||
      typeof node.version !== "string" ||
      node.version.length === 0
    ) {
      unknowns.push({
        from: item.from,
        dependency: item.dependency,
        reason: "invalid_package_identity",
      });
      continue;
    }
    const id = path.split(sep).join("/") || ".";
    const selected = locked.get(id);
    // npm ls may read package.json without integrity when its hidden cache is
    // stale. Join npm's actual identities/edges to the selected project's lock,
    // which owns declared integrity, using the exact installation path.
    const matched =
      selected?.name === node.name &&
      selected.version === node.version &&
      (node.resolved === undefined || selected.resolved === node.resolved);
    if (
      item.from !== null &&
      (!matched ||
        (node.integrity !== undefined && node.integrity !== selected.integrity))
    )
      unknowns.push({ id, reason: "installed_identity_not_bound_to_lock" });
    if (
      node.error !== undefined ||
      (Array.isArray(node.problems) && node.problems.length)
    )
      unknowns.push({ id, reason: "npm_reported_problem" });
    const fact = {
      id,
      name: node.name,
      version: node.version,
      integrity: matched ? selected.integrity : null,
      source_url: matched
        ? selected.resolved
        : typeof node.resolved === "string"
          ? node.resolved
          : null,
    };
    if (nodes.has(id) && JSON.stringify(nodes.get(id)) !== JSON.stringify(fact))
      unknowns.push({ id, reason: "conflicting_package_identity" });
    else nodes.set(id, fact);
    if (item.from !== null) {
      const edge = { from: item.from, name: item.dependency, to: id };
      edges.set(JSON.stringify(edge), edge);
    }
    if (node.dependencies === undefined) continue;
    if (!record(node.dependencies)) {
      unknowns.push({ id, reason: "invalid_dependency_relationships" });
      continue;
    }
    for (const [name, child] of Object.entries(node.dependencies)) {
      if (
        record(child) &&
        Object.keys(child).length === 0 &&
        (Object.hasOwn(node.optionalDependencies ?? {}, name) ||
          node.peerDependenciesMeta?.[name]?.optional === true)
      ) {
        const omission = { from: id, name, reason: "optional_not_reported" };
        omissions.set(JSON.stringify(omission), omission);
      } else pending.push({ value: child, from: id, dependency: name });
    }
  }
  const facts = {
    nodes: [...nodes.values()].sort((a, b) => compare(a.id, b.id)),
    edges: [...edges.values()].sort((a, b) =>
      compare(JSON.stringify(a), JSON.stringify(b)),
    ),
    omissions: [...omissions.values()].sort((a, b) =>
      compare(JSON.stringify(a), JSON.stringify(b)),
    ),
  };
  return {
    ...facts,
    unknowns,
    fingerprint: unknowns.length
      ? null
      : createHash("sha256")
          .update(
            JSON.stringify({
              ...facts,
              // Preserve URLs as evidence, but exclude temporary archive locations
              // from the content identity of otherwise identical installed trees.
              nodes: facts.nodes.map(
                ({ source_url: _source, ...identity }) => identity,
              ),
            }),
          )
          .digest("hex"),
  };
}

/** Version drift is allowed for consumers; changed bytes of a locked identity are not. */
export function sourceIdentityDifferences(nodes, reference, runtimeOnly) {
  const packages = new Map();
  for (const entry of reference.filter((entry) => !runtimeOnly || !entry.dev)) {
    if (!packages.has(entry.name)) packages.set(entry.name, []);
    packages
      .get(entry.name)
      .push({ version: entry.version, integrity: entry.integrity });
  }
  return nodes
    .filter(
      (node) =>
        node.id !== "." &&
        (!runtimeOnly || node.id !== "node_modules/rea-agents"),
    )
    .flatMap((node) => {
      const expected = packages.get(node.name) ?? [];
      const sameVersion = expected.filter(
        (entry) => entry.version === node.version,
      );
      if (sameVersion.some((entry) => entry.integrity === node.integrity))
        return [];
      return [
        {
          ...node,
          source_identities: expected,
          reason: sameVersion.length
            ? "integrity_differs"
            : "version_not_locked",
        },
      ];
    });
}
