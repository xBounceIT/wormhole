import assert from 'node:assert/strict';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  defaultCrashDiagnosticsPolicy,
  initializeLocalCrashDiagnostics,
  resolveCrashDiagnosticsPaths,
  type CrashDiagnosticsPolicy,
} from '../electron/crash-diagnostics.ts';

type LogCapture = {
  info: string[];
  warn: string[];
  error: string[];
};

function createLogger(capture: LogCapture) {
  return {
    info: (message: string) => capture.info.push(message),
    warn: (message: string) => capture.warn.push(message),
    error: (message: string) => capture.error.push(message),
  };
}

function createHarness(root: string) {
  const events: string[] = [];
  const starts: Array<Record<string, unknown>> = [];
  const logs: LogCapture = { info: [], warn: [], error: [] };
  const platform = process.platform;
  const userData = path.join(root, 'electron-profile');
  const localAppData = platform === 'win32' ? root : undefined;
  const paths = resolveCrashDiagnosticsPaths({ platform, userData, localAppData });
  const app = {
    getPath(name: 'userData' | 'crashDumps') {
      return name === 'userData' ? userData : path.join(userData, 'Crashpad');
    },
    setPath(name: 'crashDumps', value: string) {
      events.push(`set:${name}:${value}`);
    },
    getVersion: () => '2.0.0-test',
  };
  const reporter = {
    start(options: Record<string, unknown>) {
      events.push('start');
      starts.push(options);
    },
  };
  return { app, events, localAppData, logs, paths, platform, reporter, starts };
}

function initializeHarness(
  harness: ReturnType<typeof createHarness>,
  policy?: CrashDiagnosticsPolicy,
) {
  return initializeLocalCrashDiagnostics({
    app: harness.app,
    reporter: harness.reporter,
    platform: harness.platform,
    arch: process.arch,
    electronVersion: '43.2.0',
    processId: 42,
    localAppData: harness.localAppData,
    logger: createLogger(harness.logs),
    now: Date.UTC(2026, 7, 8),
    policy,
  });
}

test('crash diagnostics starts local-only capture before scanning and records safe context', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    const result = initializeHarness(harness);

    assert.equal(result.enabled, true);
    assert.equal(result.dumpDirectory, harness.paths.dumpDirectory);
    assert.equal(harness.events[0], `set:crashDumps:${harness.paths.dumpDirectory}`);
    assert.equal(harness.events[1], 'start');
    assert.equal(existsSync(harness.paths.dumpDirectory), true);
    assert.deepEqual(harness.starts, [
      {
        productName: 'Wormhole',
        uploadToServer: false,
        ignoreSystemCrashHandler: true,
        globalExtra: {
          wormhole_shell: 'electron',
          wormhole_platform: process.platform,
          wormhole_arch: process.arch,
          wormhole_version: '2.0.0-test',
        },
      },
    ]);
    assert.match(harness.logs.info[0], /upload=false/);
    assert.equal(harness.logs.info[0].includes(root), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('the main process initializes crash capture before Electron readiness', () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const initialization = source.indexOf('initializeLocalCrashDiagnostics({');
  const readiness = source.indexOf('app.whenReady()');

  assert.notEqual(initialization, -1);
  assert.notEqual(readiness, -1);
  assert.equal(initialization < readiness, true);
});

test('Windows diagnostics use the shared bounded LocalAppData directory', () => {
  const resolved = resolveCrashDiagnosticsPaths({
    platform: 'win32',
    userData: 'C:\\Users\\operator\\AppData\\Roaming\\wormhole-electron',
    localAppData: 'C:\\Users\\operator\\AppData\\Local',
  });

  assert.equal(resolved.dumpDirectory, 'C:\\Users\\operator\\AppData\\Local\\Wormhole\\crashdumps');
  assert.equal(
    resolved.statePath,
    'C:\\Users\\operator\\AppData\\Local\\Wormhole\\electron-crashdumps-reported.json',
  );
});

test('previous root and Crashpad dumps are reported once across launches', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const first = createHarness(root);
    mkdirSync(path.join(first.paths.dumpDirectory, 'pending'), { recursive: true });
    writeFileSync(path.join(first.paths.dumpDirectory, 'Wormhole.exe.1234.dmp'), 'wer');
    writeFileSync(path.join(first.paths.dumpDirectory, 'pending', 'crashpad-1.dmp'), 'crashpad');

    const firstResult = initializeHarness(first);
    assert.equal(firstResult.reportedDumps, 2);
    assert.equal(first.logs.error.length, 2);
    assert.equal(existsSync(first.paths.statePath), true);

    const second = createHarness(root);
    const secondResult = initializeHarness(second);
    assert.equal(secondResult.reportedDumps, 0);
    assert.deepEqual(second.logs.error, []);
    const state = JSON.parse(readFileSync(second.paths.statePath, 'utf8')) as {
      version: number;
      reportedDumpKeys: string[];
    };
    assert.equal(state.version, 1);
    assert.equal(state.reportedDumpKeys.length, 2);
    assert.equal(
      state.reportedDumpKeys.every((key) => /^[a-f0-9]{64}$/.test(key)),
      true,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('retention removes old and excess dumps plus matching sidecars within approved folders', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    const pending = path.join(harness.paths.dumpDirectory, 'pending');
    mkdirSync(pending, { recursive: true });
    const now = Date.UTC(2026, 7, 8);
    const newest = path.join(pending, 'newest.dmp');
    const excess = path.join(pending, 'excess.dmp');
    const old = path.join(pending, 'old.dmp');
    for (const dump of [newest, excess, old]) writeFileSync(dump, '123');
    writeFileSync(path.join(pending, 'excess_sidecar.json'), '{}');
    writeFileSync(path.join(pending, 'old_sidecar.json'), '{}');
    utimesSync(newest, new Date(now - 100), new Date(now - 100));
    utimesSync(excess, new Date(now - 200), new Date(now - 200));
    utimesSync(old, new Date(now - 2_000), new Date(now - 2_000));

    const policy: CrashDiagnosticsPolicy = {
      ...defaultCrashDiagnosticsPolicy,
      maxDumps: 2,
      maxTotalBytes: 5,
      maxAgeMs: 1_000,
    };
    const result = initializeHarness(harness, policy);

    assert.equal(result.prunedDumps, 2);
    assert.deepEqual(readdirSync(pending).sort(), ['newest.dmp']);
    assert.equal(result.reportedDumps, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('scanning ignores nested and unapproved directories', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    const nested = path.join(harness.paths.dumpDirectory, 'pending', 'nested');
    const unapproved = path.join(harness.paths.dumpDirectory, 'other');
    mkdirSync(nested, { recursive: true });
    mkdirSync(unapproved, { recursive: true });
    writeFileSync(path.join(nested, 'nested.dmp'), 'ignored');
    writeFileSync(path.join(unapproved, 'other.dmp'), 'ignored');
    writeFileSync(path.join(harness.paths.dumpDirectory, 'root.dmp'), 'reported');

    const result = initializeHarness(harness);

    assert.equal(result.reportedDumps, 1);
    assert.match(harness.logs.error[0], /dumpId=[a-f0-9]{12}/);
    assert.equal(harness.logs.error[0].includes('root.dmp'), false);
    assert.equal(existsSync(path.join(nested, 'nested.dmp')), true);
    assert.equal(existsSync(path.join(unapproved, 'other.dmp')), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('invalid configured paths degrade to Electron local capture without breaking startup', () => {
  const logs: LogCapture = { info: [], warn: [], error: [] };
  let starts = 0;
  let setPaths = 0;
  const result = initializeLocalCrashDiagnostics({
    app: {
      getPath: () => 'relative-profile',
      setPath: () => setPaths++,
      getVersion: () => '2.0.0',
    },
    reporter: {
      start: (options) => {
        starts++;
        assert.equal(options.uploadToServer, false);
      },
    },
    platform: 'linux',
    arch: 'x64',
    electronVersion: '43.2.0',
    processId: 42,
    logger: createLogger(logs),
  });

  assert.equal(result.enabled, true);
  assert.equal(starts, 1);
  assert.equal(setPaths, 0);
  assert.equal(result.dumpDirectory, undefined);
  assert.equal(logs.warn.length, 1);
});

test('a fresh maintenance lock avoids concurrent duplicate reporting without disabling capture', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    mkdirSync(harness.paths.dumpDirectory, { recursive: true });
    writeFileSync(path.join(harness.paths.dumpDirectory, 'previous.dmp'), 'dump');
    writeFileSync(harness.paths.lockPath, 'another-process');

    const result = initializeHarness(harness);

    assert.equal(result.enabled, true);
    assert.equal(result.reportedDumps, 0);
    assert.deepEqual(harness.logs.error, []);
    assert.match(harness.logs.info.at(-1) ?? '', /already running in another process/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a stale maintenance lock is reclaimed after an interrupted startup', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    mkdirSync(harness.paths.dumpDirectory, { recursive: true });
    writeFileSync(path.join(harness.paths.dumpDirectory, 'previous.dmp'), 'dump');
    writeFileSync(harness.paths.lockPath, 'stale-process');
    const stale = new Date(Date.UTC(2026, 7, 8) - 10 * 60 * 1000);
    utimesSync(harness.paths.lockPath, stale, stale);

    const result = initializeHarness(harness);

    assert.equal(result.reportedDumps, 1);
    assert.equal(existsSync(harness.paths.lockPath), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('oversized report state is replaced with bounded opaque keys', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    mkdirSync(harness.paths.dumpDirectory, { recursive: true });
    writeFileSync(path.join(harness.paths.dumpDirectory, 'previous.dmp'), 'dump');
    writeFileSync(harness.paths.statePath, 'x'.repeat(200));
    const policy: CrashDiagnosticsPolicy = {
      ...defaultCrashDiagnosticsPolicy,
      maxStateBytes: 100,
      maxStateEntries: 2,
    };

    const result = initializeHarness(harness, policy);
    const state = JSON.parse(readFileSync(harness.paths.statePath, 'utf8')) as {
      version: number;
      reportedDumpKeys: string[];
    };

    assert.equal(result.reportedDumps, 1);
    assert.equal(state.version, 1);
    assert.equal(state.reportedDumpKeys.length, 1);
    assert.match(state.reportedDumpKeys[0], /^[a-f0-9]{64}$/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
