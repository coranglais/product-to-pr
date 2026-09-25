// Every child process Product-to-PR starts (git, gh, npm, codex, claude,
// python) goes through this module.
//
// Why it exists: on Windows, npm-installed tools are `.cmd` shims rather than
// executables. Node does not append `.cmd` when it searches PATH, so a bare
// `spawn("npm")` fails with ENOENT, and since the BatBadBut fix
// (CVE-2024-27980, Node 18.20.2 / 20.12.2 / 21.7.3) Node refuses to spawn a
// `.cmd` or `.bat` file at all unless it is run through a shell with the
// arguments quoted for cmd.exe. `runCommand` and `spawnCommand` do that
// resolution and quoting here, and are plain passthroughs on other platforms.
// See https://nodejs.org/en/blog/vulnerability/april-2024-security-releases-2
import {
  execFile,
  spawn,
  type ChildProcess,
  type ChildProcessByStdio,
  type ExecFileException,
  type ExecFileOptions,
  type SpawnOptions,
  type SpawnOptionsWithStdioTuple,
  type StdioNull,
  type StdioPipe,
} from "node:child_process";
import { statSync } from "node:fs";
import { delimiter, extname, join, resolve } from "node:path";
import type { Readable, Writable } from "node:stream";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type CommandResult = { stdout: string; stderr: string };
export type CommandFailure = ExecFileException & {
  stdout?: string;
  stderr?: string;
};

export type LaunchOptions = {
  cwd?: string;
  environment?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
};

export type ResolvedLaunch = {
  file: string;
  args: string[];
  windowsVerbatimArguments: boolean;
};

// The quoting rules below follow cross-spawn (MIT,
// https://github.com/moxystudio/node-cross-spawn), which npm and yarn use for
// the same problem.
const shellScriptExtensions = new Set([".cmd", ".bat"]);
const metaCharacters = /([()\][%!^"`<>&|;, *?])/g;

function isFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function windowsPathEntries(environment: NodeJS.ProcessEnv): string[] {
  const value = environment.PATH ?? environment.Path ?? environment.path ?? "";
  return value.split(delimiter).filter(Boolean);
}

// Windows only runs a bare name through the PATHEXT extensions; an
// extension-less file of the same name (for example the `npm` shell script
// that ships beside `npm.cmd`) is not executable there.
function windowsExtensions(command: string, environment: NodeJS.ProcessEnv): string[] {
  if (extname(command)) return [""];
  return (environment.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean);
}

export function findWindowsExecutable(
  command: string,
  options: LaunchOptions = {},
): string | undefined {
  const environment = options.environment ?? process.env;
  const cwd = options.cwd ?? process.cwd();
  const hasDirectory = /[\\/]/.test(command);
  const directories = hasDirectory ? [cwd] : [cwd, ...windowsPathEntries(environment)];
  for (const directory of directories) {
    for (const extension of windowsExtensions(command, environment)) {
      const candidate = hasDirectory
        ? resolve(directory, `${command}${extension}`)
        : join(directory, `${command}${extension}`);
      if (isFile(candidate)) return candidate;
    }
  }
  return undefined;
}

function escapeShellCommand(value: string): string {
  return value.replace(metaCharacters, "^$1");
}

function escapeShellArgument(value: string): string {
  let escaped = value.replace(/(?=(\\+?)?)\1"/g, '$1$1\\"');
  escaped = escaped.replace(/(?=(\\+?)?)\1$/, "$1$1");
  escaped = `"${escaped}"`;
  return escaped.replace(metaCharacters, "^$1");
}

export function resolveLaunch(
  command: string,
  args: readonly string[],
  options: LaunchOptions = {},
): ResolvedLaunch {
  const platform = options.platform ?? process.platform;
  const passthrough = { file: command, args: [...args], windowsVerbatimArguments: false };
  if (platform !== "win32") return passthrough;

  const file = findWindowsExecutable(command, options);
  if (!file) return passthrough;
  if (!shellScriptExtensions.has(extname(file).toLowerCase())) {
    return { ...passthrough, file };
  }

  const environment = options.environment ?? process.env;
  const shellCommand = [
    escapeShellCommand(file),
    ...args.map(escapeShellArgument),
  ].join(" ");
  return {
    file: environment.ComSpec ?? environment.comspec ?? "cmd.exe",
    args: ["/d", "/s", "/c", `"${shellCommand}"`],
    windowsVerbatimArguments: true,
  };
}

export function spawnCommand(
  command: string,
  args: readonly string[],
  options: SpawnOptionsWithStdioTuple<StdioPipe, StdioPipe, StdioPipe>,
): ChildProcessByStdio<Writable, Readable, Readable>;
export function spawnCommand(
  command: string,
  args: readonly string[],
  options: SpawnOptionsWithStdioTuple<StdioPipe, StdioNull, StdioPipe>,
): ChildProcessByStdio<Writable, null, Readable>;
export function spawnCommand(
  command: string,
  args: readonly string[],
  options?: SpawnOptions,
): ChildProcess;
export function spawnCommand(
  command: string,
  args: readonly string[],
  options: SpawnOptions = {},
): ChildProcess {
  const launch = resolveLaunch(command, args, {
    cwd: typeof options.cwd === "string" ? options.cwd : undefined,
    environment: options.env,
  });
  return spawn(launch.file, launch.args, {
    ...options,
    windowsVerbatimArguments: launch.windowsVerbatimArguments,
  });
}

export async function runCommand(
  command: string,
  args: readonly string[],
  options: ExecFileOptions = {},
): Promise<CommandResult> {
  const launch = resolveLaunch(command, args, {
    cwd: typeof options.cwd === "string" ? options.cwd : undefined,
    environment: options.env,
  });
  const running = execFileAsync(launch.file, launch.args, {
    encoding: "utf8",
    ...options,
    windowsVerbatimArguments: launch.windowsVerbatimArguments,
  });
  // No caller writes to stdin; closing it prevents a child that reads stdin
  // from waiting forever.
  running.child.stdin?.end();
  try {
    const { stdout, stderr } = await running;
    return { stdout: String(stdout), stderr: String(stderr) };
  } catch (error) {
    throw describeFailure(error, command, args);
  }
}

// Node reports the command it actually ran. When that was cmd.exe wrapping a
// shim, users should still see the tool they asked for, not the wrapper.
function describeFailure(error: unknown, command: string, args: readonly string[]): unknown {
  if (!(error instanceof Error)) return error;
  const prefix = "Command failed: ";
  if (!error.message.startsWith(prefix)) return error;
  const newline = error.message.indexOf("\n");
  const rest = newline === -1 ? "" : error.message.slice(newline);
  error.message = `${prefix}${[command, ...args].join(" ")}${rest}`;
  return error;
}
