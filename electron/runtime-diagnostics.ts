import {
  appendFileSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  renameSync,
  type BigIntStats,
} from 'node:fs';
import type { ChildProcess } from 'node:child_process';
import path from 'node:path';

type DiagnosticLevel = 'INF' | 'WRN' | 'ERR';
type Details = Record<string, number | boolean | string | null | undefined>;
export type RecordDiagnostic = (level: DiagnosticLevel, event: string, details?: Details) => void;

const repeatIntervalMs = 5_000;
const recentEventLimit = 256;
const fallbackLimitBytes = 1024 * 1024;
const unavailablePrefix = 'Wormhole diagnostic log unavailable: ';
const unavailableCause = /^(?:permission|not-found|invalid-path|os-\d+|syscall|unspecified)$/;
const expectedBackendExits = new WeakSet<object>();
const knownSystemCodes = new Set([
  'EACCES',
  'EAGAIN',
  'EBUSY',
  'ECONNABORTED',
  'ECONNREFUSED',
  'ECONNRESET',
  'EEXIST',
  'EINVAL',
  'EIO',
  'EISDIR',
  'EMFILE',
  'ENFILE',
  'ENOENT',
  'ENOSPC',
  'ENOTDIR',
  'EPERM',
  'EPIPE',
  'EROFS',
  'ETIMEDOUT',
  'ERR_STREAM_DESTROYED',
  'ERR_STREAM_PREMATURE_CLOSE',
]);

export function diagnosticErrorCode(error: unknown): string | undefined {
  // Never read message, stack or a user-supplied error code into a diagnostics record.
  try {
    if (!(error instanceof Error)) return undefined;
    const code = Object.getOwnPropertyDescriptor(error, 'code')?.value;
    return typeof code === 'string' && knownSystemCodes.has(code) ? code : undefined;
  } catch {
    return undefined;
  }
}

function safeAppend(file: string, line: string, rollAt?: number): void {
  const directory = path.dirname(file);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const originalDirectory = lstatSync(directory, { bigint: true });
  if (!originalDirectory.isDirectory()) throw new Error('Invalid diagnostic directory.');
  const existing = rollAt ? diagnosticFileInfo(file) : undefined;
  if (existing && rollAt && existing.size + BigInt(Buffer.byteLength(line)) > rollAt) {
    renameSync(file, file + '.previous');
  }
  const descriptor = openDiagnosticFile(file);
  try {
    if (!sameFile(originalDirectory, lstatSync(directory, { bigint: true }))) {
      throw new Error('Diagnostic directory changed.');
    }
    appendFileSync(descriptor, line);
  } finally {
    closeSync(descriptor);
  }
}

function diagnosticFileInfo(file: string): BigIntStats | undefined {
  const info = lstatSync(file, { bigint: true, throwIfNoEntry: false });
  if (info && !info.isFile()) throw new Error('Invalid diagnostic file type.');
  return info;
}

function sameFile(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function openDiagnosticFile(file: string): number {
  let existing = diagnosticFileInfo(file);
  const appendFlags = constants.O_WRONLY | constants.O_APPEND | (constants.O_NOFOLLOW ?? 0);
  if (!existing) {
    try {
      return openSync(file, appendFlags | constants.O_CREAT | constants.O_EXCL, 0o600);
    } catch (error) {
      if (diagnosticErrorCode(error) !== 'EEXIST') throw error;
      existing = diagnosticFileInfo(file);
      if (!existing) throw error;
    }
  }
  const descriptor = openSync(file, appendFlags);
  try {
    if (sameFile(existing, fstatSync(descriptor, { bigint: true }))) return descriptor;
    throw new Error('Diagnostic file changed.');
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
}

function localDay(now: Date): string {
  const year = String(now.getFullYear()).padStart(4, '0');
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  return year + month + day;
}

export function createRuntimeDiagnostics(options: {
  databasePath: () => string;
  fallbackPath: () => string;
  now?: () => Date;
}) {
  const recent = new Map<string, { at: number; day: string; repeated: number }>();
  let warned = false;

  return (level: DiagnosticLevel, event: string, details: Details = {}, alwaysPersist = false) => {
    const now = options.now?.() ?? new Date();
    const at = now.getTime();
    const day = localDay(now);
    const key = level + ' ' + event + ' ' + JSON.stringify(details);
    const previous = alwaysPersist ? undefined : recent.get(key);
    if (previous?.day === day && at >= previous.at && at - previous.at < repeatIntervalMs) {
      previous.repeated++;
      return true;
    }
    const metadata = JSON.stringify({ ...details, repeated: previous?.repeated || undefined });
    const line =
      now.toISOString() +
      ' [' +
      level +
      '] [electron pid=' +
      process.pid +
      '] ' +
      event +
      (metadata === '{}' ? '' : ' ' + metadata) +
      '\n';
    try {
      safeAppend(
        path.join(path.dirname(options.databasePath()), 'logs', 'wormhole-' + day + '.log'),
        line,
      );
      warned = false;
    } catch (error) {
      try {
        safeAppend(
          options.fallbackPath(),
          line.trimEnd() +
            ' [primary log unavailable: ' +
            (diagnosticErrorCode(error) ?? 'unknown') +
            ']\n',
          fallbackLimitBytes,
        );
      } catch {
        if (!warned) {
          warned = true;
          console.error('[Wormhole] Could not write the primary or fallback diagnostic log.');
        }
        return false;
      }
    }

    if (!alwaysPersist) {
      recent.delete(key);
      if (recent.size >= recentEventLimit) {
        const oldest = recent.keys().next();
        if (!oldest.done) recent.delete(oldest.value);
      }
      recent.set(key, { at, day, repeated: 0 });
    }
    return true;
  };
}

type BackendStderr = NonNullable<ChildProcess['stderr']>;

// Drain stderr while keeping only enough of each line to recognize Go's fixed sink warning.
function observeLogSink(stderr: BackendStderr, onUnavailable: (cause: string) => void): void {
  const maximum = 96;
  let prefix = '';
  let oversized = false;
  stderr.on('data', (chunk: Buffer | string) => {
    const text = typeof chunk === 'string' ? chunk : chunk.toString('utf8');
    let start = 0;
    for (let end = text.indexOf('\n'); end >= 0; end = text.indexOf('\n', start)) {
      if (!oversized && prefix.length + end - start <= maximum) {
        const cause = logSinkCause(prefix + text.slice(start, end));
        if (cause) onUnavailable(cause);
      }
      prefix = '';
      oversized = false;
      start = end + 1;
    }
    if (prefix.length + text.length - start > maximum) oversized = true;
    if (!oversized) prefix += text.slice(start);
  });
}

function logSinkCause(line: string): string | undefined {
  if (!line.startsWith(unavailablePrefix)) return undefined;
  const cause = line.slice(unavailablePrefix.length).trimEnd();
  return unavailableCause.test(cause) ? cause : undefined;
}

export function backendErrorText(stderr: string): string {
  return stderr
    .split('\n')
    .filter((line) => !logSinkCause(line))
    .join('\n')
    .trim();
}

export function withIpcDiagnostics<TArgs extends unknown[], TResult>(
  handler: (...args: TArgs) => TResult,
  channel: string,
  record: RecordDiagnostic,
) {
  return async (...args: TArgs) => {
    try {
      return await handler(...args);
    } catch (error) {
      record('ERR', 'IPC failed (' + channel + ')', { code: diagnosticErrorCode(error) });
      throw error;
    }
  };
}

export function observeBackendProcess(
  child: ChildProcess,
  service: string,
  record?: RecordDiagnostic,
  expectedExit: (code: number | null) => boolean = () => false,
): void {
  if (!record) {
    child.stderr?.resume();
    return;
  }
  const details = () => ({ service, childPid: child.pid });
  if (child.stderr) {
    observeLogSink(child.stderr, (cause) =>
      record('ERR', 'backend log unavailable (' + service + ')', { ...details(), cause }),
    );
  }
  child.once('error', (error) =>
    record('ERR', 'backend process error (' + service + ')', {
      ...details(),
      code: diagnosticErrorCode(error),
    }),
  );
  child.once('exit', (exitCode, signal) => {
    const requestedStop = expectedBackendExits.has(child) && (exitCode === 0 || signal !== null);
    if (!requestedStop && !expectedExit(exitCode)) {
      record('ERR', 'backend process exited (' + service + ')', {
        ...details(),
        exitCode,
        signal,
      });
    }
  });
}

export function expectBackendExit(child: object): void {
  expectedBackendExits.add(child);
}
