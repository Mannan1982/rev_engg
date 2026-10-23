export interface InstalledPackage {
  id: string;
  name: string;
  version: string;
  integrity: string | null;
  source_url: string | null;
}
export interface LockedPackage {
  path: string;
  name: string;
  version: string;
  resolved: string;
  integrity: string;
  dev: boolean;
  optional: boolean;
  license: unknown;
}
export function registryIdentity(
  resolved: unknown,
  integrity: unknown,
): boolean;
export function requireRegistryLock(packages: LockedPackage[]): void;
export function advisoryFacts(
  value: unknown,
  exitCode: number | null,
): {
  status: "unavailable" | "failed" | "passed";
  affected_packages: number | null;
};
export function signatureFacts(
  value: unknown,
  exitCode: number | null,
): {
  status: "unavailable" | "failed" | "passed";
  invalid: number | null;
  missing: number | null;
  verified: null;
};
export function dependencyGraph(
  value: unknown,
  directory: string,
  installedPackages: LockedPackage[],
): {
  nodes: InstalledPackage[];
  edges: { from: string; name: string; to: string }[];
  omissions: { from: string; name: string; reason: string }[];
  unknowns: { reason: string }[];
  fingerprint: string | null;
};
export function sourceIdentityDifferences(
  nodes: InstalledPackage[],
  reference: LockedPackage[],
  runtimeOnly: boolean,
): (InstalledPackage & {
  reason: "integrity_differs" | "version_not_locked";
})[];
