import { execFile } from "node:child_process";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);

/** Run npm through its JavaScript entry point so Windows command scripts are not required. */
export const execNpm = (arguments_, options = {}) => {
  const environment = options.env ?? process.env;
  const selectedEntry = environment.npm_execpath;
  if (
    selectedEntry !== undefined &&
    (typeof selectedEntry !== "string" || selectedEntry.length === 0)
  )
    throw new Error("npm_execpath must name the selected npm CLI entry point");
  const entry =
    selectedEntry ??
    (process.platform === "win32"
      ? join(dirname(process.execPath), "node_modules/npm/bin/npm-cli.js")
      : undefined);
  return entry === undefined
    ? exec("npm", arguments_, options)
    : exec(process.execPath, [entry, ...arguments_], options);
};
