export const SECURITY_OUTPUT_BYTES: number;
export interface SecurityReport {
  checks_passed: boolean;
  evidence_directory: string;
  precondition?: { status: string; reason: string };
  advisory: { status: string; affected_packages?: number | null };
  signatures: { status: string; verified: null };
  tree: {
    status: string;
    content_graph_sha256?: string | null;
    versions_outside_source_lock?: number;
  };
}
export interface NpmObservation {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  elapsedMs: number;
  failure: string | null;
}
export function checkDependencySecurity(
  options: {
    directory: string;
    evidenceDirectory: string;
    referenceLockfile: string;
    mode?: "source" | "consumer";
    sourceSha?: string | null;
    expectedVersion?: string | null;
    qualifiedTarball?: string | null;
    environment?: NodeJS.ProcessEnv;
  },
  run?: (
    args: string[],
    options: { cwd: string; env: NodeJS.ProcessEnv },
  ) => Promise<NpmObservation>,
): Promise<SecurityReport>;
