/**
 * Windows-only: what the native manager is actually running for one node.
 *
 * The launcher ownership pipe is the authority on who *supervises* a node, but
 * it is bound part-way through Node startup. A launcher that Task Scheduler has
 * already created, and that has not reached that line yet, is invisible to it.
 * That gap was measured at 649 ms in the failure this module exists to close:
 * an upgrade sampled ownership during it, concluded nothing was running, issued
 * `schtasks /End`, published a trial -- and the pending termination then killed
 * the launcher that had meanwhile picked the trial up, together with a
 * candidate that had already written a valid readiness marker.
 *
 * So the stop barrier needs evidence that exists *before* the pipe: the task's
 * own running instance, and the launcher process itself. Both are read-only
 * here. Nothing in this file terminates anything -- `schtasks /End` remains the
 * only way a managed generation is stopped, and this only proves when it landed.
 *
 * Task Scheduler's high-level `Ready` state is deliberately not used: it was
 * observed reporting `Ready` while a launcher it had started was alive and
 * about to become the supervisor.
 *
 * The command runner is injected rather than imported, both to keep this free
 * of a cycle with `autostart.ts` and so the barrier can be tested against
 * scripted native states instead of a real Task Scheduler.
 */
import path from 'node:path';

export type CommandRunner = (
  file: string,
  arguments_: string[],
  environment: Record<string, string>,
) => Promise<{ code: number; stdout: string; stderr: string }>;

/** One managed generation, as the native manager currently sees it. */
export type ManagedNativeGeneration = {
  /** Task Scheduler running-instance GUIDs for this exact registration. */
  instances: string[];
  /** PIDs of processes running this exact node's launcher. */
  launchers: number[];
};

const GUID = /^\{[0-9A-Fa-f-]{36}\}$/u;
const MAX_LINES = 256;

/**
 * A fixed script body. The registration name and launcher path arrive in the
 * environment, never as script text and never as command-line arguments, so
 * nothing the caller holds is ever parsed as PowerShell. (`$args` is not an
 * option here: it is populated by `-File`, not by `-Command`.)
 */
export const NATIVE_GENERATION_PROBE = `
$ErrorActionPreference = 'SilentlyContinue'
$taskName = $env:YSD_NATIVE_TASK
$launcher = $env:YSD_NATIVE_LAUNCHER
$out = @()
try {
  $service = New-Object -ComObject Schedule.Service
  $service.Connect()
  foreach ($task in $service.GetRunningTasks(1)) {
    if ($task.Path -eq $taskName -or $task.Path -eq ('\\' + $taskName)) {
      $out += 'instance ' + $task.InstanceGuid
    }
  }
} catch { }
try {
  foreach ($p in Get-CimInstance Win32_Process -Filter "Name='node.exe'") {
    if ($p.CommandLine -and $p.CommandLine.Contains($launcher)) {
      $out += 'launcher ' + $p.ProcessId
    }
  }
} catch { }
$out -join [Environment]::NewLine
`;

export function parseNativeGeneration(stdout: string): ManagedNativeGeneration {
  const generation: ManagedNativeGeneration = { instances: [], launchers: [] };
  for (const line of stdout.split('\n').slice(0, MAX_LINES)) {
    const [kind, value] = line.trim().split(' ');
    if (kind === 'instance' && value && GUID.test(value)) generation.instances.push(value);
    if (kind === 'launcher' && value && /^\d{1,10}$/u.test(value)) {
      generation.launchers.push(Number(value));
    }
  }
  return generation;
}

/**
 * Reads the managed generation for one registration.
 *
 * Scoped to this node by two exact values: the registration Task Scheduler
 * knows, and the absolute launcher path this install owns. A second managed
 * node on the same machine has its own launcher path under its own managed
 * directory, so it never appears here -- there is no machine-wide "some YSD
 * launcher is running" notion.
 */
export async function observeManagedNativeGeneration(input: {
  registrationId: string;
  launcherPath: string;
  powershell: string;
  run: CommandRunner;
}): Promise<ManagedNativeGeneration> {
  if (process.platform !== 'win32') return { instances: [], launchers: [] };
  const result = await input.run(
    input.powershell,
    ['-NoProfile', '-NonInteractive', '-Command', NATIVE_GENERATION_PROBE],
    {
      YSD_NATIVE_TASK: input.registrationId,
      YSD_NATIVE_LAUNCHER: path.resolve(input.launcherPath),
    },
  ).catch(() => null);
  if (!result || result.code !== 0) return { instances: [], launchers: [] };
  return parseNativeGeneration(result.stdout);
}

/**
 * Whether everything captured before the stop has gone.
 *
 * Only what was captured matters. A launcher started afterwards is the new
 * supervisor and must not be waited for, and a PID is only ever compared
 * against the live list -- never trusted as a durable identity.
 */
export function generationCleared(
  before: ManagedNativeGeneration,
  now: ManagedNativeGeneration,
): boolean {
  const instances = new Set(now.instances);
  const launchers = new Set(now.launchers);
  return before.instances.every((id) => !instances.has(id))
    && before.launchers.every((pid) => !launchers.has(pid));
}

/** Whether the manager currently runs anything at all for this node. */
export function generationPresent(generation: ManagedNativeGeneration): boolean {
  return generation.instances.length > 0 || generation.launchers.length > 0;
}
