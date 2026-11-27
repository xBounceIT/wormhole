import { spawnSync, type SpawnSyncOptions, type SpawnSyncReturns } from 'node:child_process';
import { isAbsolute } from 'node:path';

type Child = {
  readonly pid?: number;
  readonly exitCode?: number | null;
  readonly signalCode?: string | null;
};
type Runner = (
  exe: string,
  args: string[],
  options: SpawnSyncOptions,
) => Pick<SpawnSyncReturns<string | Buffer>, 'error' | 'status' | 'stdout'>;
const confirmed = new WeakMap<object, number>();
export function hasNativeProcessExitProof(child: Child): boolean {
  const pid = confirmed.get(child);
  return pid !== undefined && pid === child.pid;
}

// Only the Go Windows adapter may prove termination when libuv's notification
// is missing. process.kill(pid,0)/ESRCH can report an exit code before the process
// handle is signaled. The helper receives only a public PID, never vault data.
export function confirmNativeProcessExit(
  executable: string,
  child: Child,
  platform: NodeJS.Platform = process.platform,
  run: Runner = spawnSync,
): boolean {
  if (hasNativeProcessExitProof(child)) return true;
  const pid = child.pid;
  if (
    platform !== 'win32' ||
    !isAbsolute(executable) ||
    executable.length > 4096 ||
    !Number.isSafeInteger(pid) ||
    (pid as number) < 1 ||
    (pid as number) > 0xffffffff
  )
    return false;
  try {
    const result = run(
      executable,
      ['--operation', 'process-exit-proof', '--process-id', String(pid)],
      {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 2000,
        killSignal: 'SIGKILL',
        maxBuffer: 512,
      },
    );
    if (
      result.error ||
      result.status !== 0 ||
      (!Buffer.isBuffer(result.stdout) && typeof result.stdout !== 'string')
    )
      return false;
    const raw = result.stdout.toString();
    if (Buffer.byteLength(raw) > 512) return false;
    const value: unknown = JSON.parse(raw);
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
    const v = value as Record<string, unknown>;
    if (
      Object.keys(v).length !== 3 ||
      v.version !== 1 ||
      v.pid !== pid ||
      v.terminated !== true ||
      child.pid !== pid
    )
      return false;
    confirmed.set(child, pid as number);
    return true;
  } catch {
    return false;
  }
}
