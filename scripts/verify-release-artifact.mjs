import { installCanaryPackage } from "./lib/release-package-install.mjs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { valid } from "semver";
import { verifyInstalledCanaryPackage } from "./lib/release-package-canary.mjs";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    "dependency-security": { type: "string" },
  },
});
const [tarball, version, ...extra] = positionals;
if (
  tarball === undefined ||
  typeof version !== "string" ||
  valid(version) !== version ||
  extra.length
)
  throw new Error(
    "Usage: node scripts/verify-release-artifact.mjs <qualified-tarball> <version> [--dependency-security=directory]",
  );
const source = resolve(tarball);
const verifierRun = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-release-rehearsal-"));
const environment = {
  ...process.env,
  npm_config_cache: join(workspace, "npm-cache"),
};
delete environment.HOPPER_TARGET_PATH;
let result;
try {
  const packageRoot = await installCanaryPackage(
    source,
    workspace,
    environment,
  );
  if (values["dependency-security"] !== undefined) {
    const { checkDependencySecurity } =
      await import("./lib/dependency-security.mjs");
    const report = await checkDependencySecurity({
      directory: join(workspace, "installed"),
      evidenceDirectory: values["dependency-security"],
      referenceLockfile: resolve("package-lock.json"),
      mode: "consumer",
      sourceSha: process.env.GITHUB_SHA ?? null,
      expectedVersion: version,
      qualifiedTarball: source,
      environment,
    });
    if (!report.checks_passed)
      throw new Error(
        `Qualified consumer dependency checks failed: ${report.evidence_directory}`,
      );
  }
  result = await verifyInstalledCanaryPackage(
    packageRoot,
    version,
    workspace,
    environment,
  );
} finally {
  await rm(workspace, { recursive: true, force: true });
}
process.stdout.write(
  `${JSON.stringify({ verifier_run: await completeVerifierRun(verifierRun), package: "rea-agents", version, source, ...result })}\n`,
);
