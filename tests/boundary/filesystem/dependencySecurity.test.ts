import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import {
  advisoryFacts,
  dependencyGraph as resolvedGraph,
  registryIdentity,
  signatureFacts,
} from "../../../scripts/lib/dependency-security-facts.mjs";
import {
  checkDependencySecurity,
  SECURITY_OUTPUT_BYTES,
} from "../../../scripts/lib/dependency-security.mjs";
import type { NpmObservation } from "../../../scripts/lib/dependency-security.mjs";
import { lockedPackages } from "../../../scripts/lib/npm-locked-packages.mjs";
import { redactTransportAuthentication } from "../../../scripts/lib/transport-authentication.mjs";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const sri = `sha512-${Buffer.alloc(64, 1).toString("base64")}`;
const registry = "https://registry.npmjs.org";
const clean = {
  metadata: {
    vulnerabilities: {
      info: 0,
      low: 0,
      moderate: 0,
      high: 0,
      critical: 0,
      total: 0,
    },
  },
};
const observation = (value: unknown, exitCode = 0): NpmObservation => ({
  stdout: JSON.stringify(value),
  stderr: "",
  exitCode,
  elapsedMs: 1,
  failure: null,
});

it.each([
  null,
  {},
  {
    metadata: {
      vulnerabilities: { ...clean.metadata.vulnerabilities, total: 1 },
    },
  },
  {
    metadata: {
      vulnerabilities: { ...clean.metadata.vulnerabilities, info: -1 },
    },
  },
  { ...clean, error: {} },
])(
  "keeps missing or contradictory advisory evidence unavailable: %j",
  (value) => {
    expect(advisoryFacts(value, 0)).toMatchObject({
      status: "unavailable",
      affected_packages: null,
    });
  },
);
it("distinguishes known vulnerabilities from command failure and never invents signature counts", () => {
  expect(advisoryFacts(clean, 0)).toMatchObject({
    status: "passed",
    affected_packages: 0,
  });
  expect(advisoryFacts(clean, 1)).toMatchObject({ status: "unavailable" });
  expect(
    advisoryFacts(
      {
        metadata: {
          vulnerabilities: {
            ...clean.metadata.vulnerabilities,
            high: 1,
            total: 1,
          },
        },
      },
      1,
    ),
  ).toMatchObject({ status: "failed", affected_packages: 1 });
  expect(signatureFacts({ invalid: [], missing: [] }, 0)).toEqual({
    status: "passed",
    reason: null,
    invalid: 0,
    missing: 0,
    verified: null,
  });
  expect(signatureFacts({ invalid: [], missing: [] }, 1).status).toBe(
    "unavailable",
  );
  expect(signatureFacts({}, 0).status).toBe("unavailable");
  expect(signatureFacts({ invalid: [{}], missing: [] }, 1).status).toBe(
    "failed",
  );
  expect(signatureFacts({ invalid: [], missing: [{}] }, 1).status).toBe(
    "failed",
  );
});
it("accepts only supported registry identities and redacts only transport authentication", () => {
  expect(registryIdentity(`${registry}/a/-/a-1.0.0.tgz`, sri)).toBe(true);
  for (const url of [
    "http://registry.npmjs.org/a",
    "https://other.example/a",
    "https://user:pass@registry.npmjs.org/a",
    "file:///a",
  ])
    expect(registryIdentity(url, sri)).toBe(false);
  expect(registryIdentity(`${registry}/a`, "sha1-legacy")).toBe(false);
  const text =
    "name=secret token=caller-value /tmp/secret https://user:p%40ss@EXAMPLE.com/a?q=token#keep";
  expect(redactTransportAuthentication(text)).toBe(
    "name=secret token=caller-value /tmp/secret https://EXAMPLE.com/a?q=token#keep",
  );
  expect(() =>
    lockedPackages({
      lockfileVersion: 3,
      packages: { "node_modules/../a": {} },
    }),
  ).toThrow("path");
});

const packageNode = (directory: string, name: string, version = "1.0.0") => ({
  name,
  version,
  path: join(directory, "node_modules", name),
  integrity: sri,
  resolved: `${registry}/${name}/-/${name}-${version}.tgz`,
});
const dependencyGraph = (value: unknown, directory: string) =>
  resolvedGraph(
    value,
    directory,
    lockedPackages({
      lockfileVersion: 3,
      packages: Object.fromEntries(
        ["a", "b"].map((name) => [
          `node_modules/${name}`,
          packageNode(directory, name),
        ]),
      ),
    }),
  );
it("keeps npm deduplication edges, optional omissions and stable content identities across workspaces", () => {
  const make = (directory: string) => {
    const a = packageNode(directory, "a");
    return dependencyGraph(
      {
        name: "rea-agents",
        version: "6.7.0",
        path: directory,
        dependencies: {
          a,
          b: {
            ...packageNode(directory, "b"),
            peerDependenciesMeta: { optional: { optional: true } },
            dependencies: { a, optional: {} },
          },
        },
      },
      directory,
    );
  };
  const first = make("/tmp/first"),
    second = make("/tmp/second");
  expect(first.nodes).toHaveLength(3);
  expect(first.edges).toContainEqual({
    from: "node_modules/b",
    name: "a",
    to: "node_modules/a",
  });
  expect(first.omissions).toEqual([
    {
      from: "node_modules/b",
      name: "optional",
      reason: "optional_not_reported",
    },
  ]);
  expect(first.fingerprint).toBe(second.fingerprint);
  expect(first.fingerprint).toMatch(/^[a-f0-9]{64}$/u);
});
it.each([
  {},
  { name: "a", version: "1.0.0", path: "/outside", integrity: sri },
])("preserves unresolved installed identities as unknown: %j", (child) => {
  const graph = dependencyGraph(
    {
      name: "rea-agents",
      version: "6.7.0",
      path: "/tmp/project",
      dependencies: { a: child },
    },
    "/tmp/project",
  );
  expect(graph.unknowns).toHaveLength(1);
  expect(graph.fingerprint).toBeNull();
});
it("rejects conflicting identities rather than choosing the last deduplicated record", () => {
  const directory = "/tmp/project",
    a = packageNode(directory, "a");
  const graph = dependencyGraph(
    {
      name: "rea-agents",
      version: "6.7.0",
      path: directory,
      dependencies: {
        a,
        b: {
          ...packageNode(directory, "b"),
          dependencies: { a: { ...a, version: "2.0.0" } },
        },
      },
    },
    directory,
  );
  expect(graph.unknowns).toContainEqual({
    id: "node_modules/a",
    reason: "conflicting_package_identity",
  });
  expect(graph.fingerprint).toBeNull();
});

async function scanFixture(
  options: {
    consumer?: boolean;
    changedVersion?: boolean;
    changedIntegrity?: boolean;
    mirror?: boolean;
    tarball?: boolean;
  } = {},
) {
  const root = await createTestTempDirectory("rea-security-evidence-");
  const directory = join(root, "project");
  await mkdir(directory);
  const reference = {
    lockfileVersion: 3,
    packages: {
      "": {},
      "node_modules/a": {
        name: "a",
        version: "1.0.0",
        resolved: `${registry}/a/-/a-1.0.0.tgz`,
        integrity: sri,
      },
    },
  };
  const referenceLockfile = join(root, "reference.json");
  await writeFile(referenceLockfile, JSON.stringify(reference));
  await writeFile(
    join(directory, "package-lock.json"),
    JSON.stringify(reference),
  );
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({ name: "rea-agents", version: "6.7.0" }),
  );
  const a = packageNode(
    directory,
    "a",
    options.changedVersion ? "2.0.0" : "1.0.0",
  );
  if (options.changedIntegrity)
    a.integrity = `sha512-${Buffer.alloc(64, 2).toString("base64")}`;
  if (options.mirror) a.resolved = "https://mirror.example/a.tgz";
  const dependencies: Record<string, unknown> = { a };
  let qualifiedTarball: string | undefined;
  if (options.consumer) {
    const product = packageNode(directory, "rea-agents", "6.7.0");
    await mkdir(product.path, { recursive: true });
    await writeFile(
      join(product.path, "package.json"),
      JSON.stringify({ name: "rea-agents", version: "6.7.0" }),
    );
    if (options.tarball) {
      qualifiedTarball = join(root, "package.tgz");
      const bytes = Buffer.from("qualified archive bytes");
      await writeFile(qualifiedTarball, bytes);
      product.integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
      // npm retains a file specifier relative to the consumer lock directory.
      product.resolved = "file:../package.tgz";
    }
    dependencies["rea-agents"] = product;
  }
  await writeFile(
    join(directory, "package-lock.json"),
    JSON.stringify({
      lockfileVersion: 3,
      packages: Object.fromEntries(
        Object.entries(dependencies).map(([name, record]) => [
          `node_modules/${name}`,
          record,
        ]),
      ),
    }),
  );
  const results = new Map([
    [
      "npm-version",
      {
        stdout: "11.16.0",
        stderr: "",
        exitCode: 0,
        elapsedMs: 1,
        failure: null,
      } satisfies NpmObservation,
    ],
    ["audit", observation(clean)],
    ["signatures", observation({ invalid: [], missing: [] })],
    [
      "tree",
      observation({
        name: "rea-agents",
        version: "6.7.0",
        path: directory,
        dependencies,
      }),
    ],
  ]);
  const calls: string[][] = [];
  const run = async (args: string[]) => {
    calls.push(args);
    const name =
      args[0] === "--version"
        ? "npm-version"
        : args[0] === "ls"
          ? "tree"
          : args[1] === "signatures"
            ? "signatures"
            : "audit";
    const value = results.get(name);
    if (!value) throw new Error(`Unexpected command ${name}`);
    return { ...value };
  };
  const scan = () =>
    checkDependencySecurity(
      {
        directory,
        referenceLockfile,
        evidenceDirectory: join(root, "evidence"),
        mode: options.consumer ? "consumer" : "source",
        expectedVersion: "6.7.0",
        ...(qualifiedTarball === undefined ? {} : { qualifiedTarball }),
        environment: { REA_TEST_AMBIENT_MARKER: "do-not-persist" },
      },
      run,
    );
  return { scan, results, calls, qualifiedTarball };
}
it("retains full evidence with compact facts, fresh unique runs, hashes and no ambient environment", async () => {
  const fixture = await scanFixture();
  const first = await fixture.scan(),
    second = await fixture.scan();
  expect(first.checks_passed).toBe(true);
  expect(first.signatures.verified).toBeNull();
  expect(first.evidence_directory).not.toBe(second.evidence_directory);
  expect(fixture.calls).toHaveLength(8);
  for (const args of fixture.calls) {
    expect(args).toContain("--ignore-scripts");
    expect(args).toContain("--registry=https://registry.npmjs.org");
    expect(args).toContain("--maxsockets=2");
  }
  const report = await readFile(
    join(first.evidence_directory, "report.json"),
    "utf8",
  );
  expect(report).not.toContain("do-not-persist");
  expect(report).toContain("stdout_sha256");
  expect(
    await readFile(join(first.evidence_directory, "audit.json"), "utf8"),
  ).toBe(JSON.stringify(clean));
});
it.each(["audit", "signatures", "tree"])(
  "fails closed for missing %s evidence without overwriting an earlier pass",
  async (name) => {
    const fixture = await scanFixture();
    const prior = await fixture.scan();
    fixture.results.set(name, {
      stdout: "not JSON",
      stderr: "network unavailable",
      exitCode: 1,
      elapsedMs: 1,
      failure: "1",
    });
    const report = await fixture.scan();
    expect(prior.checks_passed).toBe(true);
    expect(report.checks_passed).toBe(false);
    expect(report.evidence_directory).not.toBe(prior.evidence_directory);
  },
);
it("does not expose a complete tree fingerprint after a failed npm tree command", async () => {
  const fixture = await scanFixture(),
    tree = fixture.results.get("tree");
  if (!tree) throw new Error("Missing fixture tree");
  tree.exitCode = 1;
  const report = await fixture.scan();
  expect(report.tree).toMatchObject({
    status: "unavailable",
    content_graph_sha256: null,
  });
  expect(report.checks_passed).toBe(false);
});
it("bounds retained command output and marks overflow unavailable", async () => {
  const fixture = await scanFixture();
  fixture.results.set("audit", {
    stdout: "x".repeat(SECURITY_OUTPUT_BYTES + 1),
    stderr: "",
    exitCode: 0,
    elapsedMs: 1,
    failure: null,
  });
  const report = await fixture.scan();
  expect(report.checks_passed).toBe(false);
  expect(report.advisory.status).toBe("unavailable");
  expect(
    (await readFile(join(report.evidence_directory, "audit.json"))).length,
  ).toBe(SECURITY_OUTPUT_BYTES);
});
it("records floating consumer versions while rejecting changed bytes and unsupported registries", async () => {
  const floating = await (
    await scanFixture({ consumer: true, changedVersion: true })
  ).scan();
  expect(floating.checks_passed).toBe(true);
  expect(floating.tree.versions_outside_source_lock).toBe(1);
  expect(
    (await (await scanFixture({ changedVersion: true })).scan()).checks_passed,
  ).toBe(false);
  expect(
    (
      await (
        await scanFixture({ consumer: true, changedIntegrity: true })
      ).scan()
    ).checks_passed,
  ).toBe(false);
  expect((await (await scanFixture({ mirror: true })).scan()).tree.status).toBe(
    "unavailable",
  );
});
it("binds the local consumer exception to the selected archive's SHA-512 bytes", async () => {
  const fixture = await scanFixture({ consumer: true, tarball: true });
  expect((await fixture.scan()).checks_passed).toBe(true);
  if (!fixture.qualifiedTarball) throw new Error("Missing fixture tarball");
  await writeFile(fixture.qualifiedTarball, "changed bytes");
  expect((await fixture.scan()).checks_passed).toBe(false);
});

it("uses the selected lock for declared integrity when npm reads uncached package metadata", () => {
  const directory = "/tmp/project";
  const complete = packageNode(directory, "a");
  const { integrity: _reported, resolved: _origin, ...uncached } = complete;
  const root = (child: unknown) => ({
    name: "rea-agents",
    version: "6.7.0",
    path: directory,
    dependencies: { a: child },
  });
  const fromCache = dependencyGraph(root(complete), directory);
  const fromPackages = dependencyGraph(root(uncached), directory);
  expect(fromPackages.unknowns).toEqual([]);
  expect(fromPackages.fingerprint).toBe(fromCache.fingerprint);
  expect(fromPackages.nodes.find((node) => node.name === "a")?.integrity).toBe(
    sri,
  );
  expect(
    dependencyGraph(root({ ...uncached, version: "9.0.0" }), directory)
      .fingerprint,
  ).toBeNull();
});
