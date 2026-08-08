import { createHash, randomUUID } from 'node:crypto';
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  openSync,
  closeSync,
  opendirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
  type Stats,
} from 'node:fs';
import path from 'node:path';

const crashDumpDirectoryName = 'crashdumps';
const reportStateFileName = 'electron-crashdumps-reported.json';
const maintenanceLockFileName = 'electron-crashdumps-maintenance.lock';
const crashpadDumpDirectories = ['', 'completed', 'pending', 'reports', 'new'] as const;
const stateVersion = 1;
const staleMaintenanceLockMs = 5 * 60 * 1000;
const dumpKeyPattern = /^[a-f0-9]{64}$/;

export type CrashDiagnosticsPolicy = {
  maxDumps: number;
  maxTotalBytes: number;
  maxAgeMs: number;
  maxEntriesPerDirectory: number;
  maxCandidates: number;
  maxStateEntries: number;
  maxStateBytes: number;
};

export const defaultCrashDiagnosticsPolicy: CrashDiagnosticsPolicy = {
  maxDumps: 20,
  maxTotalBytes: 256 * 1024 * 1024,
  maxAgeMs: 30 * 24 * 60 * 60 * 1000,
  maxEntriesPerDirectory: 4_096,
  maxCandidates: 4_096,
  maxStateEntries: 256,
  maxStateBytes: 64 * 1024,
};

type CrashReporterStartOptions = {
  productName: string;
  uploadToServer: boolean;
  ignoreSystemCrashHandler: boolean;
  globalExtra: Record<string, string>;
};

type CrashDiagnosticsApp = {
  getPath(name: 'userData' | 'crashDumps'): string;
  setPath(name: 'crashDumps', value: string): void;
  getVersion(): string;
};

type CrashDiagnosticsReporter = {
  start(options: CrashReporterStartOptions): void;
};

type CrashDiagnosticsLogger = {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
};

export type CrashDiagnosticsPaths = {
  dataDirectory: string;
  dumpDirectory: string;
  statePath: string;
  lockPath: string;
};

export type CrashDiagnosticsResult = {
  enabled: boolean;
  dumpDirectory?: string;
  reportedDumps: number;
  prunedDumps: number;
  scanTruncated: boolean;
};

type InitializeCrashDiagnosticsOptions = {
  app: CrashDiagnosticsApp;
  reporter: CrashDiagnosticsReporter;
  platform: NodeJS.Platform;
  arch: string;
  electronVersion: string;
  processId: number;
  localAppData?: string;
  logger?: CrashDiagnosticsLogger;
  now?: number;
  policy?: CrashDiagnosticsPolicy;
};

type CrashDumpCandidate = {
  path: string;
  directoryName: (typeof crashpadDumpDirectories)[number];
  name: string;
  size: number;
  modifiedMs: number;
  key: string;
};

type ReportState = {
  keys: Set<string>;
  needsRewrite: boolean;
};

export function resolveCrashDiagnosticsPaths(options: {
  platform: NodeJS.Platform;
  userData: string;
  localAppData?: string;
}): CrashDiagnosticsPaths {
  const pathApi = options.platform === 'win32' ? path.win32 : path.posix;
  const localAppData = options.localAppData?.trim();
  const preferredRoot =
    options.platform === 'win32' && localAppData && path.win32.isAbsolute(localAppData)
      ? localAppData
      : options.userData;
  if (!preferredRoot || !pathApi.isAbsolute(preferredRoot)) {
    throw new Error('Crash diagnostics requires an absolute application-data path.');
  }

  const dataDirectory = pathApi.resolve(preferredRoot, 'Wormhole');
  const dumpDirectory = pathApi.resolve(dataDirectory, crashDumpDirectoryName);
  const statePath = pathApi.resolve(dataDirectory, reportStateFileName);
  const lockPath = pathApi.resolve(dataDirectory, maintenanceLockFileName);
  if (!isPathInside(pathApi, preferredRoot, dataDirectory)) {
    throw new Error('Crash diagnostics data directory escaped its application-data root.');
  }
  if (!isPathInside(pathApi, dataDirectory, dumpDirectory)) {
    throw new Error('Crash diagnostics dump directory escaped its data directory.');
  }
  if (!isPathInside(pathApi, dataDirectory, statePath)) {
    throw new Error('Crash diagnostics state file escaped its data directory.');
  }
  if (!isPathInside(pathApi, dataDirectory, lockPath)) {
    throw new Error('Crash diagnostics lock file escaped its data directory.');
  }
  return { dataDirectory, dumpDirectory, statePath, lockPath };
}

export function initializeLocalCrashDiagnostics(
  options: InitializeCrashDiagnosticsOptions,
): CrashDiagnosticsResult {
  const logger = options.logger ?? console;
  const policy = options.policy ?? defaultCrashDiagnosticsPolicy;
  const baseResult: CrashDiagnosticsResult = {
    enabled: false,
    reportedDumps: 0,
    prunedDumps: 0,
    scanTruncated: false,
  };

  let paths: CrashDiagnosticsPaths;
  try {
    paths = resolveCrashDiagnosticsPaths({
      platform: options.platform,
      userData: options.app.getPath('userData'),
      localAppData: options.localAppData,
    });
    ensurePrivateDirectory(paths.dataDirectory);
    ensurePrivateDirectory(paths.dumpDirectory);
    options.app.setPath('crashDumps', paths.dumpDirectory);
  } catch (error) {
    safeLog(
      logger,
      'warn',
      `[Wormhole] Crash diagnostics could not configure the bounded dump directory; local capture will use Electron defaults without startup scanning. code=${errorCode(error)}.`,
    );
    return startReporter(options, logger, baseResult);
  }

  const started = startReporter(options, logger, {
    ...baseResult,
    dumpDirectory: paths.dumpDirectory,
  });
  if (!started.enabled) return started;

  const lockDescriptor = acquireMaintenanceLock(paths.lockPath, options.now ?? Date.now());
  if (lockDescriptor === undefined) {
    safeLog(
      logger,
      'info',
      '[Wormhole] Crash diagnostics startup maintenance is already running in another process.',
    );
    return started;
  }

  try {
    const maintenance = maintainCrashDumps(paths, logger, options.now ?? Date.now(), policy);
    return { ...started, ...maintenance };
  } catch (error) {
    safeLog(
      logger,
      'warn',
      `[Wormhole] Crash diagnostics could not scan previous local dumps. code=${errorCode(error)}.`,
    );
    return started;
  } finally {
    releaseMaintenanceLock(paths.lockPath, lockDescriptor);
  }
}

function startReporter(
  options: InitializeCrashDiagnosticsOptions,
  logger: CrashDiagnosticsLogger,
  result: CrashDiagnosticsResult,
): CrashDiagnosticsResult {
  const version = safeAnnotation(safeAppVersion(options.app));
  const platform = safeAnnotation(options.platform);
  const arch = safeAnnotation(options.arch);
  const electronVersion = safeAnnotation(options.electronVersion);

  try {
    options.reporter.start({
      productName: 'Wormhole',
      uploadToServer: false,
      // Do not forward main-process failures to an OS handler that may have its own upload policy.
      ignoreSystemCrashHandler: true,
      globalExtra: {
        wormhole_shell: 'electron',
        wormhole_platform: platform,
        wormhole_arch: arch,
        wormhole_version: version,
      },
    });
  } catch (error) {
    safeLog(
      logger,
      'warn',
      `[Wormhole] Local crash capture could not be started. code=${errorCode(error)}.`,
    );
    return result;
  }

  safeLog(
    logger,
    'info',
    `[Wormhole] Crash diagnostics initialized: version=${version}, platform=${platform}, arch=${arch}, electron=${electronVersion}, processId=${safeProcessId(options.processId)}, upload=false.`,
  );
  return { ...result, enabled: true };
}

function maintainCrashDumps(
  paths: CrashDiagnosticsPaths,
  logger: CrashDiagnosticsLogger,
  now: number,
  policy: CrashDiagnosticsPolicy,
): Omit<CrashDiagnosticsResult, 'enabled' | 'dumpDirectory'> {
  validatePolicy(policy);
  const state = loadReportState(paths.statePath, policy);
  if (state.needsRewrite) {
    safeLog(
      logger,
      'warn',
      '[Wormhole] Crash diagnostics report state was invalid or outside bounds; existing dumps may be reported again.',
    );
  }
  const scan = scanCrashDumps(paths.dumpDirectory, logger, policy);
  const ordered = scan.dumps.sort(compareNewestFirst);
  const retained: CrashDumpCandidate[] = [];
  const pruned: CrashDumpCandidate[] = [];
  let retainedBytes = 0;

  for (const dump of ordered) {
    const ageMs = Math.max(0, now - dump.modifiedMs);
    const fits =
      ageMs <= policy.maxAgeMs &&
      retained.length < policy.maxDumps &&
      dump.size <= policy.maxTotalBytes - retainedBytes;
    if (fits) {
      retained.push(dump);
      retainedBytes += dump.size;
    } else {
      pruned.push(dump);
    }
  }

  let prunedDumps = 0;
  let pruneFailures = 0;
  for (const dump of pruned) {
    if (deleteRegularDump(paths.dumpDirectory, dump)) prunedDumps++;
    else pruneFailures++;
  }
  if (prunedDumps > 0) {
    safeLog(
      logger,
      'info',
      `[Wormhole] Crash diagnostics pruned ${prunedDumps} local dump(s) outside retention bounds.`,
    );
  }
  if (pruneFailures > 0) {
    safeLog(
      logger,
      'warn',
      `[Wormhole] Crash diagnostics could not prune ${pruneFailures} bounded local dump(s).`,
    );
  }

  let reportedDumps = 0;
  const retainedKeys = new Set<string>();
  for (const dump of retained) {
    if (state.keys.has(dump.key)) {
      retainedKeys.add(dump.key);
      continue;
    }
    if (
      safeLog(
        logger,
        'error',
        `[Wormhole] Previous crash dump detected: dumpId=${dump.key.slice(0, 12)}, modifiedUtc=${new Date(dump.modifiedMs).toISOString()}, sizeBytes=${dump.size}.`,
      )
    ) {
      retainedKeys.add(dump.key);
      reportedDumps++;
    }
  }

  const boundedKeys = new Set([...retainedKeys].slice(0, policy.maxStateEntries));
  if (scan.truncated) {
    for (const key of [...state.keys].sort()) {
      if (boundedKeys.size >= policy.maxStateEntries) break;
      boundedKeys.add(key);
    }
  }
  if (state.needsRewrite || !setsEqual(state.keys, boundedKeys)) {
    saveReportState(paths.statePath, boundedKeys);
  }
  if (scan.truncated) {
    safeLog(
      logger,
      'warn',
      '[Wormhole] Crash diagnostics reached its bounded startup scan limit; remaining dumps will be considered on a later launch.',
    );
  }

  return { reportedDumps, prunedDumps, scanTruncated: scan.truncated };
}

function scanCrashDumps(
  dumpDirectory: string,
  logger: CrashDiagnosticsLogger,
  policy: CrashDiagnosticsPolicy,
): { dumps: CrashDumpCandidate[]; truncated: boolean } {
  const dumps: CrashDumpCandidate[] = [];
  let truncated = false;

  for (const directoryName of crashpadDumpDirectories) {
    if (dumps.length >= policy.maxCandidates) {
      truncated = true;
      break;
    }
    const directoryPath = directoryName ? path.join(dumpDirectory, directoryName) : dumpDirectory;
    const directoryInfo = tryLstat(directoryPath);
    if (!directoryInfo) continue;
    if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) {
      safeLog(
        logger,
        'warn',
        `[Wormhole] Crash diagnostics skipped unsafe dump directory label=${directoryName || 'root'}.`,
      );
      continue;
    }

    let directory;
    try {
      directory = opendirSync(directoryPath);
      let entriesRead = 0;
      while (entriesRead < policy.maxEntriesPerDirectory) {
        const entry = directory.readSync();
        if (!entry) break;
        entriesRead++;
        if (!entry.isFile() || !entry.name.toLowerCase().endsWith('.dmp')) continue;
        if (dumps.length >= policy.maxCandidates) {
          truncated = true;
          break;
        }
        const dumpPath = path.join(directoryPath, entry.name);
        if (!isPathInside(path, dumpDirectory, dumpPath)) continue;
        const info = tryLstat(dumpPath);
        if (!isSafeDumpFile(info)) continue;
        dumps.push({
          path: dumpPath,
          directoryName,
          name: entry.name,
          size: info.size,
          modifiedMs: info.mtimeMs,
          key: crashDumpKey(entry.name, info),
        });
      }
      if (entriesRead === policy.maxEntriesPerDirectory && directory.readSync()) truncated = true;
    } catch (error) {
      safeLog(
        logger,
        'warn',
        `[Wormhole] Crash diagnostics could not inspect dump directory label=${directoryName || 'root'}, code=${errorCode(error)}.`,
      );
    } finally {
      try {
        directory?.closeSync();
      } catch {
        // Best-effort diagnostic scanning must never interfere with application startup.
      }
    }
  }

  return { dumps, truncated };
}

function loadReportState(statePath: string, policy: CrashDiagnosticsPolicy): ReportState {
  const info = tryLstat(statePath);
  if (!info) return { keys: new Set(), needsRewrite: false };
  if (!info.isFile() || info.isSymbolicLink() || info.size > policy.maxStateBytes) {
    return { keys: new Set(), needsRewrite: true };
  }
  if (process.platform !== 'win32') chmodSync(statePath, 0o600);

  try {
    const parsed = JSON.parse(readFileSync(statePath, 'utf8')) as unknown;
    if (!parsed || typeof parsed !== 'object') return { keys: new Set(), needsRewrite: true };
    const record = parsed as Record<string, unknown>;
    if (record.version !== stateVersion || !Array.isArray(record.reportedDumpKeys)) {
      return { keys: new Set(), needsRewrite: true };
    }
    const validKeys = record.reportedDumpKeys.filter(
      (value): value is string => typeof value === 'string' && dumpKeyPattern.test(value),
    );
    const boundedKeys = validKeys.slice(-policy.maxStateEntries);
    return {
      keys: new Set(boundedKeys),
      needsRewrite:
        validKeys.length !== record.reportedDumpKeys.length ||
        boundedKeys.length !== validKeys.length,
    };
  } catch {
    return { keys: new Set(), needsRewrite: true };
  }
}

function saveReportState(statePath: string, keys: Set<string>): void {
  ensureSafeStateTarget(statePath);
  const temporaryPath = `${statePath}.tmp-${process.pid}-${randomUUID()}`;
  const contents = JSON.stringify({
    version: stateVersion,
    reportedDumpKeys: [...keys].sort(),
  });
  let temporaryCreated = false;
  try {
    writeFileSync(temporaryPath, contents, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
    temporaryCreated = true;
    renameSync(temporaryPath, statePath);
    temporaryCreated = false;
  } finally {
    if (temporaryCreated) {
      try {
        unlinkSync(temporaryPath);
      } catch {
        // A stale temporary state file is harmless and contains only opaque dump keys.
      }
    }
  }
}

function acquireMaintenanceLock(lockPath: string, now: number): number | undefined {
  for (let attempt = 0; attempt < 2; attempt++) {
    let descriptor: number;
    try {
      descriptor = openSync(lockPath, 'wx', 0o600);
    } catch (error) {
      if (errorCode(error) !== 'EEXIST') return undefined;
      let info: Stats | undefined;
      try {
        info = tryLstat(lockPath);
      } catch {
        return undefined;
      }
      if (
        attempt > 0 ||
        !info?.isFile() ||
        info.isSymbolicLink() ||
        !Number.isFinite(info.mtimeMs) ||
        Math.max(0, now - info.mtimeMs) <= staleMaintenanceLockMs
      ) {
        return undefined;
      }
      try {
        unlinkSync(lockPath);
      } catch {
        return undefined;
      }
      continue;
    }

    try {
      writeFileSync(descriptor, String(process.pid));
      return descriptor;
    } catch {
      try {
        closeSync(descriptor);
        unlinkSync(lockPath);
      } catch {
        // A stale lock is reclaimed after a short timeout on a future launch.
      }
      return undefined;
    }
  }
  return undefined;
}

function releaseMaintenanceLock(lockPath: string, descriptor: number): void {
  try {
    closeSync(descriptor);
  } catch {
    // The exclusive file itself still prevents a second scanner from racing this one.
  }
  let info: Stats | undefined;
  try {
    info = tryLstat(lockPath);
  } catch {
    return;
  }
  if (!info?.isFile() || info.isSymbolicLink()) return;
  try {
    unlinkSync(lockPath);
  } catch {
    // A stale lock is reclaimed after a short timeout on a future launch.
  }
}

function deleteRegularDump(dumpDirectory: string, dump: CrashDumpCandidate): boolean {
  if (!isPathInside(path, dumpDirectory, dump.path)) return false;
  const current = tryLstat(dump.path);
  if (
    !isSafeDumpFile(current) ||
    current.size !== dump.size ||
    current.mtimeMs !== dump.modifiedMs
  ) {
    return false;
  }
  try {
    unlinkSync(dump.path);
    deleteSidecarIfSafe(dumpDirectory, dump);
    return true;
  } catch {
    return false;
  }
}

function deleteSidecarIfSafe(dumpDirectory: string, dump: CrashDumpCandidate): void {
  const sidecarName = `${path.parse(dump.name).name}_sidecar.json`;
  const parent = dump.directoryName ? path.join(dumpDirectory, dump.directoryName) : dumpDirectory;
  const sidecarPath = path.join(parent, sidecarName);
  if (!isPathInside(path, dumpDirectory, sidecarPath)) return;
  const info = tryLstat(sidecarPath);
  if (!info?.isFile() || info.isSymbolicLink()) return;
  try {
    unlinkSync(sidecarPath);
  } catch {
    // The minidump bound is the material disk bound; an unavailable metadata sidecar is harmless.
  }
}

function ensurePrivateDirectory(directoryPath: string): void {
  mkdirSync(directoryPath, { recursive: true, mode: 0o700 });
  const info = lstatSync(directoryPath);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error('Crash diagnostics directory is not a regular directory.');
  }
  if (process.platform !== 'win32') chmodSync(directoryPath, 0o700);
}

function ensureSafeStateTarget(statePath: string): void {
  const info = tryLstat(statePath);
  if (info && (!info.isFile() || info.isSymbolicLink())) {
    throw new Error('Crash diagnostics state target is not a regular file.');
  }
  if (info && process.platform !== 'win32') chmodSync(statePath, 0o600);
}

function isSafeDumpFile(info: Stats | undefined): info is Stats {
  return Boolean(
    info?.isFile() &&
    !info.isSymbolicLink() &&
    Number.isSafeInteger(info.size) &&
    info.size >= 0 &&
    Number.isFinite(info.mtimeMs) &&
    Math.abs(info.mtimeMs) <= 8.64e15,
  );
}

function tryLstat(candidate: string): Stats | undefined {
  try {
    return lstatSync(candidate);
  } catch (error) {
    if (errorCode(error) === 'ENOENT') return undefined;
    throw error;
  }
}

function crashDumpKey(name: string, info: Stats): string {
  return createHash('sha256')
    .update(name)
    .update('\0')
    .update(String(info.size))
    .update('\0')
    .update(String(info.mtimeMs))
    .digest('hex');
}

function compareNewestFirst(left: CrashDumpCandidate, right: CrashDumpCandidate): number {
  const byTime = right.modifiedMs - left.modifiedMs;
  if (byTime !== 0) return byTime;
  const byName = left.name.localeCompare(right.name);
  if (byName !== 0) return byName;
  return left.directoryName.localeCompare(right.directoryName);
}

function isPathInside(pathApi: typeof path, parent: string, candidate: string): boolean {
  const relative = pathApi.relative(parent, candidate);
  return (
    relative.length > 0 &&
    !relative.startsWith(`..${pathApi.sep}`) &&
    relative !== '..' &&
    !pathApi.isAbsolute(relative)
  );
}

function validatePolicy(policy: CrashDiagnosticsPolicy): void {
  for (const value of Object.values(policy)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new Error('Crash diagnostics policy values must be positive safe integers.');
    }
  }
}

function setsEqual(left: Set<string>, right: Set<string>): boolean {
  if (left.size !== right.size) return false;
  for (const value of left) if (!right.has(value)) return false;
  return true;
}

function safeAnnotation(value: string): string {
  return value.replace(/[^A-Za-z0-9._+-]/g, '_').slice(0, 120) || 'unknown';
}

function safeAppVersion(app: CrashDiagnosticsApp): string {
  try {
    return app.getVersion();
  } catch {
    return 'unknown';
  }
}

function safeProcessId(value: number): string {
  return Number.isSafeInteger(value) && value >= 0 ? String(value) : 'unknown';
}

function errorCode(error: unknown): string {
  if (!error || typeof error !== 'object') return 'unknown';
  const code = (error as NodeJS.ErrnoException).code;
  return typeof code === 'string' && /^[A-Z0-9_]{1,32}$/.test(code) ? code : 'unknown';
}

function safeLog(
  logger: CrashDiagnosticsLogger,
  level: keyof CrashDiagnosticsLogger,
  message: string,
): boolean {
  try {
    logger[level](message);
    return true;
  } catch {
    return false;
  }
}
