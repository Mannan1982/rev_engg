import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { execNpm } from "./npm-command.mjs";

/** Install the selected archive or registry specifier before any protocol deadline. */
export async function installCanaryPackage(specifier, workspace, environment) {
  const prefix = join(workspace, "installed");
  await mkdir(prefix, { recursive: true });
  await writeFile(
    join(prefix, "package.json"),
    JSON.stringify({
      name: "rea-release-consumer-check",
      version: "0.0.0",
      private: true,
    }) + "\n",
    { flag: "wx", mode: 0o600 },
  );
  await execNpm(
    [
      "install",
      "--ignore-scripts",
      "--save-exact",
      "--package-lock=true",
      "--no-audit",
      "--no-fund",
      "--prefix",
      prefix,
      specifier,
    ],
    { cwd: workspace, env: environment, maxBuffer: 16 * 1024 * 1024 },
  );
  return join(prefix, "node_modules", "rea-agents");
}
