import { redactTransportAuthentication } from "./transport-authentication.mjs";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile, stat } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { verifyPublishedPackageIntegrity } from "../ci/qualified-package-envelope.mjs";
import { lockedPackages } from "./npm-locked-packages.mjs";
import {
  advisoryFacts,
  signatureFacts,
  dependencyGraph,
  sourceIdentityDifferences,
  registryIdentity,
  requireRegistryLock,
} from "./dependency-security-facts.mjs";

import { execNpm } from "./npm-command.mjs";
// CI evidence budget, not a package-format limit. Overflow is unavailable evidence.
export const SECURITY_OUTPUT_BYTES = 16 * 1024 * 1024;
const digest = (text) => createHash("sha256").update(text).digest("hex");
const unavailable = (reason) => ({ status: "unavailable", reason });

async function executeNpm(args, options) {
  const started = performance.now();
  try {
    const result = await execNpm(args, {
      ...options,
      encoding: "utf8",
      maxBuffer: SECURITY_OUTPUT_BYTES,
      timeout: 180_000,
    });
    return {
      ...result,
      exitCode: 0,
      elapsedMs: Math.round(performance.now() - started),
      failure: null,
    };
  } catch (error) {
    return {
      stdout: error.stdout ?? "",
      stderr: error.stderr ?? error.message,
      exitCode: typeof error.code === "number" ? error.code : null,
      elapsedMs: Math.round(performance.now() - started),
      failure: String(error.code ?? error.signal ?? "command_failed"),
    };
  }
}

/** One scan implementation for CI source locks and the actual installed release consumer. */
export async function checkDependencySecurity(
  {
    directory,
    evidenceDirectory,
    referenceLockfile,
    mode = "source",
    sourceSha = null,
    expectedVersion = null,
    qualifiedTarball = null,
    environment = process.env,
  },
  run = executeNpm,
) {
  directory = resolve(directory);
  await mkdir(evidenceDirectory, { recursive: true, mode: 0o700 });
  const evidence = await mkdtemp(join(resolve(evidenceDirectory), "run-"));
  const report = {
    schema_version: 1,
    checks_passed: false,
    mode,
    started_at: new Date().toISOString(),
    source_sha: sourceSha,
    node_version: process.version,
    npm_version: null,
    platform: process.platform,
    architecture: process.arch,
    evidence_directory: evidence,
    reference_lock_sha256: null,
    advisory: unavailable("not_observed"),
    signatures: { ...unavailable("not_observed"), verified: null },
    tree: unavailable("not_observed"),
    coverage: {
      advisory: "selected project lock",
      signatures:
        "npm-supported installed registry dependencies on this platform; verified count not exposed",
      graph:
        "npm-reported installed identities/relationships bound to selected-lock declared origins/integrities; optional omissions retained; installed files not rehashed",
      consumer_policy:
        mode === "consumer"
          ? "semver resolution; source lock does not pin consumers"
          : null,
    },
    commands: [],
  };
  const finish = async () => {
    report.completed_at = new Date().toISOString();
    await writeFile(
      join(evidence, "report.json"),
      JSON.stringify(report, null, 2) + "\n",
    );
    return report;
  };
  let reference;
  let selectedLockSha;
  let installedPackages;
  try {
    const lockStat = await stat(referenceLockfile);
    if (!lockStat.isFile() || lockStat.size > SECURITY_OUTPUT_BYTES)
      throw new Error(
        "Reference lock exceeds CI evidence budget or is not a file",
      );
    const bytes = await readFile(referenceLockfile);
    report.reference_lock_sha256 = digest(bytes);
    reference = lockedPackages(JSON.parse(bytes));
    requireRegistryLock(reference);
    if (!["source", "consumer"].includes(mode))
      throw new Error("Unknown dependency security mode");
    const localLock = join(directory, "package-lock.json");
    const localStat = await stat(localLock);
    if (!localStat.isFile() || localStat.size > SECURITY_OUTPUT_BYTES)
      throw new Error("Selected project has no consumer lock");
    const selectedBytes = await readFile(localLock);
    selectedLockSha = digest(selectedBytes);
    installedPackages = lockedPackages(JSON.parse(selectedBytes));
    report.selected_lock_sha256 = selectedLockSha;
    const retainedLock = redactTransportAuthentication(
      selectedBytes.toString("utf8"),
    );
    await writeFile(join(evidence, "selected-package-lock.json"), retainedLock);
    report.retained_lock_sha256 = digest(retainedLock);
    const product = JSON.parse(
      await readFile(
        join(
          directory,
          ...(mode === "consumer" ? ["node_modules", "rea-agents"] : []),
          "package.json",
        ),
        "utf8",
      ),
    );
    if (
      product.name !== "rea-agents" ||
      typeof product.version !== "string" ||
      (expectedVersion !== null && product.version !== expectedVersion)
    )
      throw new Error(
        "Installed REA identity differs from the selected release",
      );
    report.product = { name: product.name, version: product.version };
  } catch (error) {
    report.precondition = unavailable(error.message);
    return finish();
  }
  const userconfig = join(evidence, ".empty-user.npmrc"),
    globalconfig = join(evidence, ".empty-global.npmrc");
  await writeFile(userconfig, "", { mode: 0o600 });
  await writeFile(globalconfig, "", { mode: 0o600 });
  const common = [
    "--ignore-scripts",
    "--registry=https://registry.npmjs.org",
    "--maxsockets=2",
    "--prefer-online",
    `--userconfig=${userconfig}`,
    `--globalconfig=${globalconfig}`,
  ];
  const collect = async (name, args, json = true) => {
    const result = await run([...args, ...common], {
      cwd: directory,
      env: environment,
    });
    const oversized =
      Buffer.byteLength(result.stdout) > SECURITY_OUTPUT_BYTES ||
      Buffer.byteLength(result.stderr) > SECURITY_OUTPUT_BYTES;
    if (oversized) {
      result.exitCode = null;
      result.failure = "output_limit";
    }
    const bounded = (value) =>
      Buffer.byteLength(value) <= SECURITY_OUTPUT_BYTES
        ? value
        : Buffer.from(value)
            .subarray(0, SECURITY_OUTPUT_BYTES)
            .toString("utf8");
    const stdout = redactTransportAuthentication(bounded(result.stdout)),
      stderr = redactTransportAuthentication(bounded(result.stderr));
    await writeFile(join(evidence, `${name}.${json ? "json" : "txt"}`), stdout);
    await writeFile(join(evidence, `${name}.stderr.txt`), stderr);
    report.commands.push({
      name,
      exit_code: result.exitCode,
      elapsed_ms: result.elapsedMs,
      failure: result.failure,
      stdout_sha256: digest(stdout),
      stderr_sha256: digest(stderr),
    });
    let value = null;
    try {
      value = oversized ? null : json ? JSON.parse(stdout) : stdout.trim();
    } catch {
      /* Raw malformed evidence is retained; never interpret it as zero. */
    }
    return { value, exitCode: result.exitCode };
  };
  const version = await collect("npm-version", ["--version"], false);
  if (
    version.exitCode !== 0 ||
    typeof version.value !== "string" ||
    !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/u.test(version.value)
  ) {
    report.precondition = unavailable("npm_toolchain_unavailable");
    return finish();
  }
  report.npm_version = version.value;
  const audit = await collect("audit", [
    "audit",
    "--package-lock-only",
    "--include=dev",
    "--include=optional",
    "--json",
  ]);
  report.advisory = advisoryFacts(audit.value, audit.exitCode);
  const signatures = await collect("signatures", [
    "audit",
    "signatures",
    "--include=dev",
    "--include=optional",
    "--json",
  ]);
  report.signatures = signatureFacts(signatures.value, signatures.exitCode);
  const tree = await collect("installed-tree", [
    "ls",
    "--all",
    "--include=dev",
    "--include=optional",
    "--json",
    "--long",
  ]);
  try {
    const graph = dependencyGraph(tree.value, directory, installedPackages);
    if (
      graph.nodes.length < 2 ||
      (mode === "source" &&
        !graph.nodes.some(
          (node) =>
            node.id === "." &&
            node.name === report.product.name &&
            node.version === report.product.version,
        )) ||
      (mode === "consumer" &&
        !graph.nodes.some(
          (node) =>
            node.id === "node_modules/rea-agents" &&
            node.name === "rea-agents" &&
            node.version === report.product.version,
        ))
    )
      throw new Error("Installed REA dependency tree is incomplete");
    if (tree.exitCode !== 0) graph.fingerprint = null;
    for (const node of graph.nodes.filter((node) => node.id !== ".")) {
      if (
        mode === "consumer" &&
        node.id === "node_modules/rea-agents" &&
        qualifiedTarball !== null
      ) {
        if (
          node.name !== "rea-agents" ||
          node.version !== report.product.version ||
          typeof node.source_url !== "string" ||
          fileURLToPath(
            new URL(node.source_url, pathToFileURL(directory + sep)),
          ) !== resolve(qualifiedTarball)
        )
          throw new Error(
            "Consumer archive identity differs from the selected qualified tarball",
          );
        await verifyPublishedPackageIntegrity(qualifiedTarball, node.integrity);
        report.qualified_archive = {
          path: resolve(qualifiedTarball),
          integrity: node.integrity,
        };
      } else if (!registryIdentity(node.source_url, node.integrity)) {
        graph.unknowns.push({
          id: node.id,
          reason: "unsupported_registry_or_integrity",
        });
      }
    }
    if (graph.unknowns.length) graph.fingerprint = null;
    const differences = sourceIdentityDifferences(
      graph.nodes,
      reference,
      mode === "consumer",
    );
    await writeFile(
      join(evidence, "tree-facts.json"),
      JSON.stringify(graph, null, 2) + "\n",
    );
    await writeFile(
      join(evidence, "source-identity-differences.json"),
      JSON.stringify(differences, null, 2) + "\n",
    );
    const byteDifferences = differences.filter(
      (entry) => entry.reason === "integrity_differs",
    );
    const status =
      graph.unknowns.length || tree.exitCode !== 0
        ? "unavailable"
        : byteDifferences.length || (mode === "source" && differences.length)
          ? "failed"
          : "passed";
    report.tree = {
      status,
      nodes: graph.nodes.length,
      edges: graph.edges.length,
      optional_not_reported: graph.omissions.length,
      unknowns: graph.unknowns.length,
      content_graph_sha256: graph.fingerprint,
      versions_outside_source_lock: differences.length - byteDifferences.length,
      changed_locked_integrities: byteDifferences.length,
    };
  } catch (error) {
    report.tree = unavailable(error.message);
  }
  report.checks_passed = [
    report.advisory,
    report.signatures,
    report.tree,
  ].every((value) => value.status === "passed");
  try {
    const lock = join(directory, "package-lock.json");
    if (
      (await stat(lock)).size > SECURITY_OUTPUT_BYTES ||
      digest(await readFile(lock)) !== selectedLockSha
    )
      throw new Error("selected_lock_changed_during_scan");
  } catch (error) {
    report.checks_passed = false;
    report.precondition = unavailable(error.message);
  }
  return finish();
}
