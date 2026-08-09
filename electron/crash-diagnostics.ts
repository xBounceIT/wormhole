import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync,
  constants as fsConstants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  opendirSync,
  readSync,
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
const maximumMaintenanceLockLifetimeMs = 24 * 60 * 60 * 1000;
const maximumFutureDumpSkewMs = 24 * 60 * 60 * 1000;
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
  directoryIdentity: FileIdentity;
  fileIdentity: FileIdentity;
  name: string;
  size: number;
  modifiedMs: number;
  key: string;
};

type FileIdentity = {
  dev: number;
  ino: number;
  birthtimeMs: number;
};

type MaintenanceLock = {
  descriptor: number;
  identity: FileIdentity;
};

type MaintenanceLockRecord = {
  pid: number;
  token: string;
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
    options.platform === 'win32' && localAppData && isWindowsLocalDrivePath(localAppData)
      ? localAppData
      : options.userData;
  const isSafeRoot =
    options.platform === 'win32'
      ? isWindowsLocalDrivePath(preferredRoot)
      : pathApi.isAbsolute(preferredRoot);
  if (!preferredRoot || !isSafeRoot) {
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

  const requestedNow = options.now ?? Date.now();
  const now = Number.isFinite(requestedNow) ? requestedNow : Date.now();
  const maintenanceLock = acquireMaintenanceLock(paths.lockPath, now);
  if (maintenanceLock === undefined) {
    safeLog(
      logger,
      'info',
      '[Wormhole] Crash diagnostics startup maintenance was skipped because its bounded lock is unavailable or held by another process.',
    );
    return started;
  }

  try {
    const maintenance = maintainCrashDumps(paths, logger, now, policy);
    return { ...started, ...maintenance };
  } catch (error) {
    safeLog(
      logger,
      'warn',
      `[Wormhole] Crash diagnostics could not scan previous local dumps. code=${errorCode(error)}.`,
    );
    return started;
  } finally {
    releaseMaintenanceLock(paths.lockPath, maintenanceLock);
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
      dump.modifiedMs <= now + maximumFutureDumpSkewMs &&
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

  let reportedDumps = 0;
  const retainedCandidateKeys = new Set(retained.map((dump) => dump.key));
  const retainedKeys = new Set<string>();
  const newlyReportedKeys = new Set<string>();
  for (const dump of retained) {
    if (retainedKeys.has(dump.key)) continue;
    if (state.keys.has(dump.key)) {
      retainedKeys.add(dump.key);
      continue;
    }
    if (
      safeLog(
        logger,
        'error',
        `[Wormhole] Previous crash dump detected: modifiedUtc=${new Date(dump.modifiedMs).toISOString()}, sizeBytes=${dump.size}.`,
      )
    ) {
      retainedKeys.add(dump.key);
      newlyReportedKeys.add(dump.key);
      reportedDumps++;
    }
  }

  const newPrunedKeys = new Set<string>();
  for (const dump of pruned) {
    if (
      !state.keys.has(dump.key) &&
      !retainedCandidateKeys.has(dump.key) &&
      !newlyReportedKeys.has(dump.key)
    ) {
      newPrunedKeys.add(dump.key);
    }
  }
  if (
    newPrunedKeys.size > 0 &&
    safeLog(
      logger,
      'error',
      `[Wormhole] ${newPrunedKeys.size} additional previous crash dump(s) were detected outside retention bounds and will be pruned locally.`,
    )
  ) {
    for (const key of newPrunedKeys) newlyReportedKeys.add(key);
    reportedDumps += newPrunedKeys.size;
  }

  let prunedDumps = 0;
  let pruneFailures = 0;
  let deferredPrunes = 0;
  const failedPruneKeys = new Set<string>();
  for (const dump of pruned) {
    if (!state.keys.has(dump.key) && !newlyReportedKeys.has(dump.key)) {
      deferredPrunes++;
      continue;
    }
    if (deleteRegularDump(paths.dumpDirectory, dump)) prunedDumps++;
    else {
      pruneFailures++;
      if (state.keys.has(dump.key) || newlyReportedKeys.has(dump.key)) {
        failedPruneKeys.add(dump.key);
      }
    }
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
  if (deferredPrunes > 0) {
    safeLog(
      logger,
      'warn',
      `[Wormhole] Crash diagnostics deferred pruning ${deferredPrunes} dump(s) because their detection could not be reported safely.`,
    );
  }

  const boundedKeys = new Set([...retainedKeys].slice(0, policy.maxStateEntries));
  for (const key of failedPruneKeys) {
    if (boundedKeys.size >= policy.maxStateEntries) break;
    boundedKeys.add(key);
  }
  if (scan.truncated || scan.incomplete) {
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
): { dumps: CrashDumpCandidate[]; truncated: boolean; incomplete: boolean } {
  const dumps: CrashDumpCandidate[] = [];
  let truncated = false;
  let incomplete = false;
  let skippedDumpEntries = 0;

  for (const directoryName of crashpadDumpDirectories) {
    if (dumps.length >= policy.maxCandidates) {
      truncated = true;
      break;
    }
    const directoryPath = directoryName ? path.join(dumpDirectory, directoryName) : dumpDirectory;
    const directoryInfo = tryLstat(directoryPath);
    if (!directoryInfo) continue;
    if (!isSafeDirectory(directoryInfo)) {
      incomplete = true;
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
      const openedDirectoryInfo = tryLstat(directoryPath);
      if (
        !isSafeDirectory(openedDirectoryInfo) ||
        !sameFileIdentity(fileIdentity(directoryInfo), fileIdentity(openedDirectoryInfo))
      ) {
        incomplete = true;
        safeLog(
          logger,
          'warn',
          `[Wormhole] Crash diagnostics skipped a dump directory that changed during inspection, label=${directoryName || 'root'}.`,
        );
        continue;
      }
      const directoryIdentity = fileIdentity(openedDirectoryInfo);
      let entriesRead = 0;
      while (entriesRead < policy.maxEntriesPerDirectory) {
        const entry = directory.readSync();
        if (!entry) break;
        entriesRead++;
        if (!entry.name.toLowerCase().endsWith('.dmp')) continue;
        if (!entry.isFile()) {
          incomplete = true;
          skippedDumpEntries++;
          continue;
        }
        if (dumps.length >= policy.maxCandidates) {
          truncated = true;
          break;
        }
        const dumpPath = path.join(directoryPath, entry.name);
        if (!isPathInside(path, dumpDirectory, dumpPath)) continue;
        let info: Stats | undefined;
        try {
          info = tryLstat(dumpPath);
        } catch {
          incomplete = true;
          skippedDumpEntries++;
          continue;
        }
        if (!isSafeDumpFile(info)) {
          incomplete = true;
          skippedDumpEntries++;
          continue;
        }
        dumps.push({
          path: dumpPath,
          directoryName,
          directoryIdentity,
          fileIdentity: fileIdentity(info),
          name: entry.name,
          size: info.size,
          modifiedMs: info.mtimeMs,
          key: crashDumpKey(entry.name, info),
        });
      }
      if (entriesRead === policy.maxEntriesPerDirectory && directory.readSync()) truncated = true;
    } catch (error) {
      incomplete = true;
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

  if (skippedDumpEntries > 0) {
    safeLog(
      logger,
      'warn',
      `[Wormhole] Crash diagnostics skipped ${skippedDumpEntries} unsafe or unstable dump entry/entries.`,
    );
  }

  return { dumps, truncated, incomplete };
}

function loadReportState(statePath: string, policy: CrashDiagnosticsPolicy): ReportState {
  const info = safeLstat(statePath);
  if (!info) return { keys: new Set(), needsRewrite: false };
  if (!info.isFile() || info.isSymbolicLink() || info.size > policy.maxStateBytes) {
    return { keys: new Set(), needsRewrite: true };
  }

  try {
    const contents = readBoundedRegularFile(statePath, policy.maxStateBytes, true);
    if (contents === undefined) return { keys: new Set(), needsRewrite: true };
    const parsed = JSON.parse(contents) as unknown;
    if (!parsed || typeof parsed !== 'object') return { keys: new Set(), needsRewrite: true };
    const record = parsed as Record<string, unknown>;
    if (record.version !== stateVersion || !Array.isArray(record.reportedDumpKeys)) {
      return { keys: new Set(), needsRewrite: true };
    }
    const hasExactSchema =
      Object.keys(record).length === 2 &&
      Object.hasOwn(record, 'version') &&
      Object.hasOwn(record, 'reportedDumpKeys');
    const validKeys = record.reportedDumpKeys.filter(
      (value): value is string => typeof value === 'string' && dumpKeyPattern.test(value),
    );
    const normalizedKeys = [...new Set(validKeys)].sort();
    const boundedKeys = normalizedKeys.slice(-policy.maxStateEntries);
    return {
      keys: new Set(boundedKeys),
      needsRewrite:
        !hasExactSchema ||
        validKeys.length !== record.reportedDumpKeys.length ||
        boundedKeys.length !== validKeys.length ||
        boundedKeys.some((key, index) => key !== validKeys[index]),
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
  let descriptor: number | undefined;
  try {
    descriptor = openSync(temporaryPath, 'wx', 0o600);
    temporaryCreated = true;
    writeFileSync(descriptor, contents, { encoding: 'utf8' });
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporaryPath, statePath);
    temporaryCreated = false;
    syncDirectory(path.dirname(statePath));
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // The temporary file cleanup below remains safe even if close reports an error.
      }
    }
    if (temporaryCreated) {
      try {
        unlinkSync(temporaryPath);
      } catch {
        // A stale temporary state file is harmless and contains only opaque dump keys.
      }
    }
  }
}

function acquireMaintenanceLock(lockPath: string, now: number): MaintenanceLock | undefined {
  for (let attempt = 0; attempt < 2; attempt++) {
    let descriptor: number;
    try {
      descriptor = openSync(lockPath, 'wx', 0o600);
    } catch (error) {
      if (errorCode(error) !== 'EEXIST') return undefined;
      const info = safeLstat(lockPath);
      if (attempt > 0 || !isReclaimableMaintenanceLock(lockPath, info, now)) {
        return undefined;
      }
      if (!unlinkIfIdentityMatches(lockPath, fileIdentity(info), true)) {
        return undefined;
      }
      continue;
    }

    let identity: FileIdentity | undefined;
    try {
      identity = fileIdentity(fstatSync(descriptor));
      writeFileSync(
        descriptor,
        JSON.stringify({ pid: process.pid, token: randomUUID() } satisfies MaintenanceLockRecord),
      );
      return { descriptor, identity };
    } catch {
      try {
        closeSync(descriptor);
      } catch {
        // Identity-checked cleanup below remains safe if close reports an error.
      }
      if (identity) unlinkIfIdentityMatches(lockPath, identity);
      return undefined;
    }
  }
  return undefined;
}

function releaseMaintenanceLock(lockPath: string, lock: MaintenanceLock): void {
  try {
    closeSync(lock.descriptor);
  } catch {
    // Re-check the path identity before attempting cleanup below.
  }
  unlinkIfIdentityMatches(lockPath, lock.identity);
}

function deleteRegularDump(dumpDirectory: string, dump: CrashDumpCandidate): boolean {
  if (!isPathInside(path, dumpDirectory, dump.path)) return false;
  if (!dumpDirectoryIdentityMatches(dumpDirectory, dump)) return false;
  const current = safeLstat(dump.path);
  if (
    !isSafeDumpFile(current) ||
    !sameFileIdentity(dump.fileIdentity, fileIdentity(current)) ||
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
  if (!dumpDirectoryIdentityMatches(dumpDirectory, dump)) return;
  const info = safeLstat(sidecarPath);
  if (!info?.isFile() || info.isSymbolicLink()) return;
  try {
    unlinkSync(sidecarPath);
  } catch {
    // The minidump bound is the material disk bound; an unavailable metadata sidecar is harmless.
  }
}

function dumpDirectoryIdentityMatches(dumpDirectory: string, dump: CrashDumpCandidate): boolean {
  const directoryPath = dump.directoryName
    ? path.join(dumpDirectory, dump.directoryName)
    : dumpDirectory;
  const info = safeLstat(directoryPath);
  return Boolean(
    isSafeDirectory(info) && sameFileIdentity(dump.directoryIdentity, fileIdentity(info)),
  );
}

function ensurePrivateDirectory(directoryPath: string): void {
  mkdirSync(directoryPath, { recursive: true, mode: 0o700 });
  const info = lstatSync(directoryPath);
  if (!isSafeDirectory(info)) {
    throw new Error('Crash diagnostics directory is not a regular directory.');
  }
  if (process.platform === 'win32') return;

  const descriptor = openDirectoryNoFollow(directoryPath);
  try {
    const opened = fstatSync(descriptor);
    if (!opened.isDirectory()) {
      throw new Error('Crash diagnostics directory changed during validation.');
    }
    fchmodSync(descriptor, 0o700);
  } finally {
    closeSync(descriptor);
  }
}

function ensureSafeStateTarget(statePath: string): void {
  const info = tryLstat(statePath);
  if (info?.isSymbolicLink()) {
    if (unlinkIfIdentityMatches(statePath, fileIdentity(info), true)) return;
    throw new Error('Crash diagnostics state symlink changed during validation.');
  }
  if (info && !info.isFile()) {
    throw new Error('Crash diagnostics state target is not a regular file.');
  }
}

function isSafeDirectory(info: Stats | undefined): info is Stats {
  return Boolean(info?.isDirectory() && !info.isSymbolicLink());
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

function fileIdentity(info: Stats): FileIdentity {
  return { dev: info.dev, ino: info.ino, birthtimeMs: info.birthtimeMs };
}

function sameFileIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.birthtimeMs === right.birthtimeMs;
}

function tryLstat(candidate: string): Stats | undefined {
  try {
    return lstatSync(candidate);
  } catch (error) {
    if (errorCode(error) === 'ENOENT') return undefined;
    throw error;
  }
}

function safeLstat(candidate: string): Stats | undefined {
  try {
    return tryLstat(candidate);
  } catch {
    return undefined;
  }
}

function readBoundedRegularFile(
  filePath: string,
  maxBytes: number,
  makePrivate: boolean,
): string | undefined {
  const before = safeLstat(filePath);
  if (!before?.isFile() || before.isSymbolicLink()) return undefined;

  let descriptor: number | undefined;
  try {
    const noFollow = process.platform === 'win32' ? 0 : (fsConstants.O_NOFOLLOW ?? 0);
    descriptor = openSync(filePath, fsConstants.O_RDONLY | noFollow);
    const opened = fstatSync(descriptor);
    if (
      !opened.isFile() ||
      (makePrivate && (before.nlink !== 1 || opened.nlink !== 1)) ||
      opened.size > maxBytes ||
      !sameFileIdentity(fileIdentity(before), fileIdentity(opened))
    ) {
      return undefined;
    }
    if (makePrivate && process.platform !== 'win32') fchmodSync(descriptor, 0o600);

    const buffer = Buffer.allocUnsafe(maxBytes + 1);
    let total = 0;
    while (total < buffer.length) {
      const bytesRead = readSync(descriptor, buffer, total, buffer.length - total, null);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    const after = fstatSync(descriptor);
    if (
      total > maxBytes ||
      total !== after.size ||
      opened.size !== after.size ||
      opened.mtimeMs !== after.mtimeMs ||
      !sameFileIdentity(fileIdentity(opened), fileIdentity(after))
    ) {
      return undefined;
    }
    return buffer.subarray(0, total).toString('utf8');
  } catch {
    return undefined;
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // Bounded reads are best effort and never block application startup.
      }
    }
  }
}

function openDirectoryNoFollow(directoryPath: string): number {
  return openSync(
    directoryPath,
    fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY ?? 0) | (fsConstants.O_NOFOLLOW ?? 0),
  );
}

function syncDirectory(directoryPath: string): void {
  if (process.platform === 'win32') return;
  const descriptor = openDirectoryNoFollow(directoryPath);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function isReclaimableMaintenanceLock(
  lockPath: string,
  info: Stats | undefined,
  now: number,
): info is Stats {
  if (!info || !Number.isFinite(info.mtimeMs)) return false;
  if (info.isSymbolicLink()) return true;
  if (!info.isFile()) return false;
  const ageMs = now - info.mtimeMs;
  if (ageMs < -staleMaintenanceLockMs || ageMs > maximumMaintenanceLockLifetimeMs) return true;

  const record = readMaintenanceLockRecord(lockPath);
  if (record) return !isProcessAlive(record.pid);

  return ageMs > staleMaintenanceLockMs;
}

function readMaintenanceLockRecord(lockPath: string): MaintenanceLockRecord | undefined {
  const contents = readBoundedRegularFile(lockPath, 512, false);
  if (contents === undefined) return undefined;
  try {
    const parsed = JSON.parse(contents) as unknown;
    if (!parsed || typeof parsed !== 'object') return undefined;
    const record = parsed as Record<string, unknown>;
    if (
      typeof record.pid !== 'number' ||
      !Number.isSafeInteger(record.pid) ||
      record.pid <= 0 ||
      typeof record.token !== 'string' ||
      !/^[a-f0-9-]{36}$/i.test(record.token)
    ) {
      return undefined;
    }
    return { pid: record.pid, token: record.token };
  } catch {
    return undefined;
  }
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return errorCode(error) !== 'ESRCH';
  }
}

function unlinkIfIdentityMatches(
  candidate: string,
  expected: FileIdentity,
  allowSymbolicLink = false,
): boolean {
  const current = safeLstat(candidate);
  if (
    (!current?.isFile() && !(allowSymbolicLink && current?.isSymbolicLink())) ||
    !sameFileIdentity(expected, fileIdentity(current))
  ) {
    return false;
  }
  try {
    unlinkSync(candidate);
    return true;
  } catch {
    return false;
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
  const byName = compareOrdinal(left.name, right.name);
  if (byName !== 0) return byName;
  return compareOrdinal(left.directoryName, right.directoryName);
}

function compareOrdinal(left: string, right: string): number {
  if (left === right) return 0;
  return left < right ? -1 : 1;
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

function isWindowsLocalDrivePath(candidate: string): boolean {
  return /^[A-Za-z]:[\\/]/.test(candidate) && path.win32.isAbsolute(candidate);
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
