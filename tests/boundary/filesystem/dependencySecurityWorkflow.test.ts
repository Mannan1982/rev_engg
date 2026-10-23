import { execFile } from "node:child_process";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { expect, it } from "vitest";
import { parse } from "yaml";
import { z } from "zod";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const execute = promisify(execFile);
const step = z
  .object({
    run: z.string().optional(),
    if: z.string().optional(),
    uses: z.string().optional(),
    with: z.record(z.string(), z.unknown()).optional(),
  })
  .passthrough();
const readWorkflow = async (name: string) =>
  z
    .object({
      jobs: z.record(
        z.string(),
        z
          .object({
            needs: z.union([z.string(), z.array(z.string())]).optional(),
            if: z.string().optional(),
            permissions: z.record(z.string(), z.string()).optional(),
            env: z.record(z.string(), z.string()).optional(),
            steps: z.array(step).optional(),
          })
          .passthrough(),
      ),
    })
    .parse(parse(await readFile(`.github/workflows/${name}.yml`, "utf8")));

it("requires fresh read-only registry checks with bounded installation and retained evidence", async () => {
  const { jobs } = await readWorkflow("ci");
  const job = jobs["dependency-security"];
  expect(job?.needs).toBe("changes");
  expect(job?.if).toBe(
    "needs.changes.outputs.dependency_security == 'true' || needs.changes.outputs.tier == 'reused'",
  );
  expect(job?.permissions).toEqual({ contents: "read" });
  expect(job?.env).toMatchObject({
    TURBO_TOKEN: "",
    TURBO_CACHE: "local:rw",
    NODE_OPTIONS: "--max-old-space-size=1024",
    UV_THREADPOOL_SIZE: "1",
  });
  expect(job?.["timeout-minutes"]).toBe(15);
  const steps = job?.steps ?? [];
  const preflight = steps.findIndex((entry) =>
    entry.run?.includes("--mode=preflight"),
  );
  const install = steps.findIndex((entry) => entry.run?.startsWith("npm ci "));
  const source = steps.findIndex((entry) =>
    entry.run?.includes("--mode=source"),
  );
  expect(preflight).toBeGreaterThanOrEqual(0);
  expect(install).toBeGreaterThan(preflight);
  expect(steps[install]?.run).toContain("--ignore-scripts");
  expect(steps[install]?.run).toContain("--maxsockets=2");
  expect(source).toBeGreaterThan(install);
  expect(
    steps.find((entry) => entry.run?.includes("--mode=published"))?.if,
  ).toBe(
    "github.event_name == 'schedule' && github.event.schedule == '23 3 * * *'",
  );
  const evidence = steps.find((entry) =>
    entry.uses?.startsWith("actions/upload-artifact@"),
  );
  expect(evidence?.if).toBe("always()");
  expect(evidence?.with?.path).toBe(".cache/dependency-security/");
});
it.each([
  ["release", "rehearsal"],
  ["release", "verify-npm"],
  ["release-recovery", "verify"],
])(
  "retains live consumer checks and failure evidence in %s/%s",
  async (workflow, name) => {
    const job = (await readWorkflow(workflow)).jobs[name];
    const canaries =
      job?.steps?.filter((entry) =>
        /verify-(?:release-artifact|published-package)\.mjs/u.test(
          entry.run ?? "",
        ),
      ) ?? [];
    expect(canaries.length).toBeGreaterThan(0);
    for (const canary of canaries) {
      expect(canary.run).toContain(
        "--dependency-security=.cache/dependency-security",
      );
      expect(canary.if).toBeUndefined();
      expect(canary["continue-on-error"]).toBeUndefined();
    }
    expect(
      job?.steps?.find(
        (entry) => entry.with?.path === ".cache/dependency-security/",
      )?.if,
    ).toBe("always()");
  },
);

it("validates lock identities before npm installation without importing installed dependencies", async () => {
  const directory = await createTestTempDirectory(
    "rea-security-no-dependencies-",
  );
  for (const file of [
    "scripts/ci/dependency-security.mjs",
    "scripts/ci/qualified-package-envelope.mjs",
    "scripts/lib/dependency-security.mjs",
    "scripts/lib/dependency-security-facts.mjs",
    "scripts/lib/npm-command.mjs",
    "scripts/lib/npm-locked-packages.mjs",
    "scripts/lib/transport-authentication.mjs",
    "scripts/lib/release-package-install.mjs",
  ]) {
    await mkdir(dirname(join(directory, file)), { recursive: true });
    await copyFile(file, join(directory, file));
  }
  const lock = {
    lockfileVersion: 3,
    packages: {
      "node_modules/a": {
        version: "1.0.0",
        resolved: "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
        integrity: `sha512-${Buffer.alloc(64).toString("base64")}`,
      },
    },
  };
  const lockfile = join(directory, "package-lock.json");
  await writeFile(lockfile, JSON.stringify(lock));
  const run = () =>
    execute(
      process.execPath,
      ["scripts/ci/dependency-security.mjs", "--mode=preflight"],
      { cwd: directory },
    );
  expect((await run()).stdout).toContain("supported npm registry");
  lock.packages["node_modules/a"].resolved = "https://other.example/a.tgz";
  await writeFile(lockfile, JSON.stringify(lock));
  await expect(run()).rejects.toMatchObject({
    code: 1,
    stderr: expect.stringContaining("Unsupported registry"),
  });
});
