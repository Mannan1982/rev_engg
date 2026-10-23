import { installCanaryPackage } from "./lib/release-package-install.mjs";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { parseArgs, promisify } from "node:util";
import { pathToFileURL } from "node:url";

import { lt, prerelease, rcompare, valid } from "semver";
import { readNpmRelease, stableUpdateVersion } from "./ci/npm-release.mjs";

import { verifyInstalledCanaryPackage } from "./lib/release-package-canary.mjs";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";

const verifierRun = createVerifierRun();
const execFileAsync = promisify(execFile);
const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    "dependency-security": { type: "string" },
  },
});
const [version] = positionals;
if (
  typeof version !== "string" ||
  valid(version) !== version ||
  positionals.length !== 1
)
  throw new Error(
    "Usage: node scripts/verify-published-package.mjs <version> [--dependency-security=directory]",
  );

const canaryRoot = await mkdtemp(join(tmpdir(), "rea-published-canary-"));
const serverEnvironment = {
  ...process.env,
  npm_config_cache: join(canaryRoot, "npm-cache"),
};
delete serverEnvironment.HOPPER_TARGET_PATH;
let surface;
let update;
try {
  const publishedRoot = await installCanaryPackage(
    `rea-agents@${version}`,
    canaryRoot,
    serverEnvironment,
  );
  if (values["dependency-security"] !== undefined) {
    const { checkDependencySecurity } =
      await import("./lib/dependency-security.mjs");
    const report = await checkDependencySecurity({
      directory: join(canaryRoot, "installed"),
      evidenceDirectory: values["dependency-security"],
      referenceLockfile: resolve("package-lock.json"),
      mode: "consumer",
      sourceSha: process.env.GITHUB_SHA ?? null,
      expectedVersion: version,
      environment: serverEnvironment,
    });
    if (!report.checks_passed)
      throw new Error(
        `Published consumer dependency checks failed: ${report.evidence_directory}`,
      );
  }
  surface = await verifyInstalledCanaryPackage(
    publishedRoot,
    version,
    canaryRoot,
    serverEnvironment,
  );
  update = await verifyPublishedUpdate({
    version,
    canaryRoot,
    updaterRoot: publishedRoot,
  });
} finally {
  await rm(canaryRoot, { recursive: true, force: true });
}
process.stdout.write(
  `${JSON.stringify({ verifier_run: await completeVerifierRun(verifierRun), package: "rea-agents", version, ...surface, update })}\n`,
);

async function verifyPublishedUpdate({
  version: targetVersion,
  canaryRoot,
  updaterRoot,
}) {
  const updateVersion = stableUpdateVersion(
    targetVersion,
    await readNpmRelease(targetVersion),
  );
  const prefix = join(canaryRoot, "update-prefix");
  const home = join(canaryRoot, "update-home");
  const environment = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    APPDATA: join(home, "AppData", "Roaming"),
    LOCALAPPDATA: join(home, "AppData", "Local"),
    CLAUDE_CONFIG_DIR: home,
    CODEX_HOME: join(home, ".codex"),
    COPILOT_HOME: join(home, ".copilot"),
    GROK_HOME: join(home, ".grok"),
    SAND_DATA_ROOT: join(home, ".grokbot"),
    OMP_PROFILE: undefined,
    PI_CODING_AGENT_DIR: undefined,
    PI_CONFIG_DIR: undefined,
    PI_PROFILE: undefined,
    XDG_CONFIG_HOME: join(home, ".config"),
    OPENCODE_CONFIG: join(home, ".config", "opencode", "opencode.json"),
    npm_config_cache: join(canaryRoot, "npm-cache"),
    npm_config_prefix: prefix,
    PATH: `${join(prefix, "bin")}${delimiter}${process.env.PATH ?? ""}`,
  };
  const previousVersion = await findPreviousPublishedVersion(
    updateVersion,
    canaryRoot,
    environment,
  );

  await execFileAsync(
    "npm",
    [
      "install",
      "--global",
      "--ignore-scripts",
      "--prefix",
      prefix,
      `rea-agents@${previousVersion}`,
    ],
    { cwd: canaryRoot, env: environment, maxBuffer: 16 * 1024 * 1024 },
  );

  const npmRoot = (
    await execFileAsync("npm", ["root", "--global"], {
      cwd: canaryRoot,
      env: environment,
    })
  ).stdout.trim();
  // Older releases may predate the update command. Exercise the new published
  // updater's production workflow against that real previous installation.
  const harness = join(canaryRoot, "update.mjs");
  await writeFile(
    harness,
    `
import { runUpdate } from ${JSON.stringify(pathToFileURL(join(updaterRoot, "dist/application/Update.js")).href)};
import { systemUpdateHost } from ${JSON.stringify(pathToFileURL(join(updaterRoot, "dist/application/UpdateRuntime.js")).href)};
const result = await runUpdate(${JSON.stringify(previousVersion)}, systemUpdateHost(${JSON.stringify(join(npmRoot, "rea-agents"))}, ${JSON.stringify(home)}), "structured");
process.stdout.write(JSON.stringify(result));
if (result.status === "failed") process.exitCode = 1;
`,
  );
  const { stdout } = await execFileAsync(process.execPath, [harness], {
    cwd: canaryRoot,
    env: environment,
    maxBuffer: 16 * 1024 * 1024,
  });
  const result = JSON.parse(stdout);
  if (
    result.status !== "updated" ||
    result.previousVersion !== previousVersion ||
    result.latestVersion !== updateVersion ||
    result.installedVersion !== updateVersion ||
    result.command.at(-1) !== `rea-agents@${updateVersion}`
  )
    throw new Error(
      `Published REA updater did not update ${previousVersion} to stable ${updateVersion}: ${stdout}`,
    );

  const installed = JSON.parse(
    await readFile(join(npmRoot, "rea-agents", "package.json"), "utf8"),
  );
  if (installed.version !== updateVersion)
    throw new Error(
      `REA update installed ${installed.version}, expected stable ${updateVersion}`,
    );

  const help = (
    await execFileAsync(join(prefix, "bin", "rea-agents"), ["--help"], {
      cwd: canaryRoot,
      env: environment,
    })
  ).stdout;
  if (!/^\s{2}update\s/mu.test(help) || /^\s{2}upgrade\s/mu.test(help))
    throw new Error(
      "the updated executable did not expose only the update command",
    );

  return {
    status: result.status,
    previousVersion,
    latestVersion: result.latestVersion,
    installedVersion: installed.version,
  };
}

async function findPreviousPublishedVersion(targetVersion, cwd, environment) {
  const { stdout } = await execFileAsync(
    "npm",
    ["view", "rea-agents", "versions", "--json"],
    { cwd, env: environment, maxBuffer: 16 * 1024 * 1024 },
  );
  const versions = JSON.parse(stdout);
  const previous = versions
    .filter(
      (candidate) =>
        typeof candidate === "string" &&
        valid(candidate) === candidate &&
        prerelease(candidate) === null &&
        lt(candidate, targetVersion),
    )
    .sort(rcompare)[0];
  if (previous === undefined)
    throw new Error(
      `No published rea-agents version precedes ${targetVersion}`,
    );
  return previous;
}
