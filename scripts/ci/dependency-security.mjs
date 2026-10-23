import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { checkDependencySecurity } from "../lib/dependency-security.mjs";
import { requireRegistryLock } from "../lib/dependency-security-facts.mjs";
import { lockedPackages } from "../lib/npm-locked-packages.mjs";
import { installCanaryPackage } from "../lib/release-package-install.mjs";

const { values } = parseArgs({
  options: {
    mode: { type: "string", default: "source" },
    evidence: { type: "string", default: ".cache/dependency-security" },
  },
});
const referenceLockfile = resolve("package-lock.json");
// This pre-install check uses only Node built-ins and executes no dependency code.
requireRegistryLock(
  lockedPackages(JSON.parse(await readFile(referenceLockfile, "utf8"))),
);
if (values.mode === "preflight") {
  console.log(
    "Source lock uses the supported npm registry and SHA-512 identities",
  );
} else if (values.mode === "source") {
  const report = await checkDependencySecurity({
    directory: process.cwd(),
    referenceLockfile,
    evidenceDirectory: values.evidence,
    sourceSha: process.env.GITHUB_SHA ?? null,
  });
  console.log(JSON.stringify(report));
  if (!report.checks_passed) process.exitCode = 1;
} else if (values.mode === "published") {
  const response = await fetch("https://registry.npmjs.org/rea-agents/latest", {
    signal: AbortSignal.timeout(30_000),
    headers: { accept: "application/json" },
  });
  if (!response.ok)
    throw new Error(`Published REA metadata unavailable: ${response.status}`);
  const product = await response.json();
  if (
    product.name !== "rea-agents" ||
    typeof product.version !== "string" ||
    !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u.test(
      product.version,
    )
  )
    throw new Error("Invalid published REA identity");
  const workspace = await mkdtemp(join(tmpdir(), "rea-dependency-consumer-"));
  let report;
  try {
    const userconfig = join(workspace, "user.npmrc"),
      globalconfig = join(workspace, "global.npmrc");
    await writeFile(userconfig, "", { mode: 0o600 });
    await writeFile(globalconfig, "", { mode: 0o600 });
    const environment = {
      ...process.env,
      npm_config_registry: "https://registry.npmjs.org",
      npm_config_userconfig: userconfig,
      npm_config_globalconfig: globalconfig,
      npm_config_maxsockets: "2",
      npm_config_prefer_online: "true",
    };
    await installCanaryPackage(
      `rea-agents@${product.version}`,
      workspace,
      environment,
    );
    report = await checkDependencySecurity({
      directory: join(workspace, "installed"),
      referenceLockfile,
      evidenceDirectory: values.evidence,
      mode: "consumer",
      expectedVersion: product.version,
      sourceSha: process.env.GITHUB_SHA ?? null,
      environment,
    });
  } finally {
    // A cleanup failure propagates; never report a successful completed run first.
    await rm(workspace, { recursive: true, force: true });
  }
  console.log(JSON.stringify(report));
  if (!report.checks_passed) process.exitCode = 1;
} else throw new Error("Expected --mode=preflight, source, or published");
