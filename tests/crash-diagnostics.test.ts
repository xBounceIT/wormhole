import assert from 'node:assert/strict';
import {
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  truncateSync,
  unlinkSync,
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
  runtime: { arch?: string } = {},
) {
  return initializeLocalCrashDiagnostics({
    app: harness.app,
    reporter: harness.reporter,
    platform: harness.platform,
    arch: runtime.arch ?? process.arch,
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
  const firstWindow = source.indexOf('new BrowserWindow({');

  assert.notEqual(initialization, -1);
  assert.notEqual(readiness, -1);
  assert.notEqual(firstWindow, -1);
  assert.equal(initialization < readiness, true);
  assert.equal(initialization < firstWindow, true);
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

test('Windows diagnostics reject UNC and device roots instead of writing to a remote namespace', () => {
  for (const nonLocalRoot of [
    '\\\\server\\profile',
    '\\\\?\\UNC\\server\\profile',
    '\\\\.\\pipe\\wormhole',
  ]) {
    const resolved = resolveCrashDiagnosticsPaths({
      platform: 'win32',
      userData: 'C:\\Users\\operator\\AppData\\Roaming\\wormhole-electron',
      localAppData: nonLocalRoot,
    });
    assert.equal(
      resolved.dumpDirectory,
      'C:\\Users\\operator\\AppData\\Roaming\\wormhole-electron\\Wormhole\\crashdumps',
    );
  }

  assert.throws(() =>
    resolveCrashDiagnosticsPaths({
      platform: 'win32',
      userData: '\\\\server\\profile',
    }),
  );
});

test('non-Windows diagnostics stay within the Electron user-data directory', () => {
  const resolved = resolveCrashDiagnosticsPaths({
    platform: 'linux',
    userData: '/home/operator/.config/wormhole-electron',
    localAppData: 'C:\\ignored',
  });

  assert.equal(
    resolved.dumpDirectory,
    '/home/operator/.config/wormhole-electron/Wormhole/crashdumps',
  );
});

test('ARM64 is recorded as bounded crash context without changing capture behavior', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    initializeHarness(harness, undefined, { arch: 'arm64' });

    assert.equal((harness.starts[0].globalExtra as Record<string, string>).wormhole_arch, 'arm64');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
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

    writeFileSync(path.join(second.paths.dumpDirectory, 'later.dmp'), 'later');
    const third = createHarness(root);
    assert.equal(initializeHarness(third).reportedDumps, 1);
    const replacedState = JSON.parse(readFileSync(third.paths.statePath, 'utf8')) as {
      reportedDumpKeys: string[];
    };
    assert.equal(replacedState.reportedDumpKeys.length, 3);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('the same logical dump present in two Crashpad locations is reported once', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    const pending = path.join(harness.paths.dumpDirectory, 'pending');
    mkdirSync(pending, { recursive: true });
    const rootDump = path.join(harness.paths.dumpDirectory, 'same.dmp');
    const pendingDump = path.join(pending, 'same.dmp');
    writeFileSync(rootDump, 'same');
    writeFileSync(pendingDump, 'same');
    const modified = new Date(Date.UTC(2026, 7, 7));
    utimesSync(rootDump, modified, modified);
    utimesSync(pendingDump, modified, modified);

    const result = initializeHarness(harness);

    assert.equal(result.reportedDumps, 1);
    assert.equal(harness.logs.error.length, 1);
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
    assert.equal(result.reportedDumps, 3);
    assert.equal(harness.logs.error.length, 2);
    assert.match(harness.logs.error[1], /2 additional previous crash dump/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('retention breaks equal-time ties with locale-independent ordinal names', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    mkdirSync(harness.paths.dumpDirectory, { recursive: true });
    const ordinalFirst = path.join(harness.paths.dumpDirectory, 'z.dmp');
    const localeFirst = path.join(harness.paths.dumpDirectory, 'ä.dmp');
    writeFileSync(ordinalFirst, 'one');
    writeFileSync(localeFirst, 'two');
    const modified = new Date(Date.UTC(2026, 7, 7));
    utimesSync(ordinalFirst, modified, modified);
    utimesSync(localeFirst, modified, modified);

    const result = initializeHarness(harness, {
      ...defaultCrashDiagnosticsPolicy,
      maxDumps: 1,
    });

    assert.equal(result.reportedDumps, 2);
    assert.deepEqual(
      readdirSync(harness.paths.dumpDirectory).filter((name) => name.endsWith('.dmp')),
      ['z.dmp'],
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('an implausibly future-dated dump cannot displace a current crash from retention', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    mkdirSync(harness.paths.dumpDirectory, { recursive: true });
    const current = path.join(harness.paths.dumpDirectory, 'current.dmp');
    const future = path.join(harness.paths.dumpDirectory, 'future.dmp');
    writeFileSync(current, 'current');
    writeFileSync(future, 'future');
    const now = Date.UTC(2026, 7, 8);
    utimesSync(current, new Date(now), new Date(now));
    utimesSync(
      future,
      new Date(now + 2 * 24 * 60 * 60 * 1000),
      new Date(now + 2 * 24 * 60 * 60 * 1000),
    );

    const result = initializeHarness(harness, {
      ...defaultCrashDiagnosticsPolicy,
      maxDumps: 1,
    });

    assert.equal(result.reportedDumps, 2);
    assert.equal(result.prunedDumps, 1);
    assert.equal(existsSync(current), true);
    assert.equal(existsSync(future), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('oversized sparse dumps are signaled and pruned without reading their contents', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    mkdirSync(harness.paths.dumpDirectory, { recursive: true });
    const dumpPath = path.join(harness.paths.dumpDirectory, 'sparse-secret.dmp');
    writeFileSync(dumpPath, '');
    truncateSync(dumpPath, 1024 * 1024);

    const result = initializeHarness(harness, {
      ...defaultCrashDiagnosticsPolicy,
      maxTotalBytes: 1024,
    });

    assert.equal(result.reportedDumps, 1);
    assert.equal(result.prunedDumps, 1);
    assert.equal(existsSync(dumpPath), false);
    assert.equal(
      harness.logs.error.some((message) => message.includes('sparse-secret')),
      false,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('symlink and junction dump directories are never scanned or pruned', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    const outside = path.join(root, 'outside');
    mkdirSync(harness.paths.dumpDirectory, { recursive: true });
    mkdirSync(outside);
    const outsideDump = path.join(outside, 'outside-secret.dmp');
    writeFileSync(outsideDump, 'outside');
    symlinkSync(
      outside,
      path.join(harness.paths.dumpDirectory, 'pending'),
      process.platform === 'win32' ? 'junction' : 'dir',
    );

    const result = initializeHarness(harness);

    assert.equal(result.reportedDumps, 0);
    assert.equal(result.prunedDumps, 0);
    assert.equal(existsSync(outsideDump), true);
    assert.match(harness.logs.warn.join('\n'), /unsafe dump directory label=pending/);
    assert.equal(harness.logs.warn.join('\n').includes('outside-secret'), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a symlinked dump entry is skipped with bounded path-free diagnostics', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    const outside = path.join(root, 'outside-secret');
    mkdirSync(harness.paths.dumpDirectory, { recursive: true });
    writeFileSync(outside, 'do-not-touch');
    symlinkSync(outside, path.join(harness.paths.dumpDirectory, 'credential-secret.dmp'), 'file');

    const result = initializeHarness(harness);

    assert.equal(result.reportedDumps, 0);
    assert.equal(result.prunedDumps, 0);
    assert.equal(readFileSync(outside, 'utf8'), 'do-not-touch');
    assert.match(harness.logs.warn.join('\n'), /skipped 1 unsafe or unstable dump/);
    assert.equal(harness.logs.warn.join('\n').includes('credential-secret'), false);
    assert.equal(harness.logs.warn.join('\n').includes(root), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('an incomplete reparse-point scan preserves prior report state', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const first = createHarness(root);
    const pending = path.join(first.paths.dumpDirectory, 'pending');
    const hidden = path.join(first.paths.dumpDirectory, 'pending-hidden');
    const outside = path.join(root, 'outside');
    mkdirSync(pending, { recursive: true });
    mkdirSync(outside);
    writeFileSync(path.join(pending, 'previous.dmp'), 'dump');
    assert.equal(initializeHarness(first).reportedDumps, 1);

    renameSync(pending, hidden);
    symlinkSync(outside, pending, process.platform === 'win32' ? 'junction' : 'dir');
    const incomplete = createHarness(root);
    assert.equal(initializeHarness(incomplete).reportedDumps, 0);

    unlinkSync(pending);
    renameSync(hidden, pending);
    const recovered = createHarness(root);
    assert.equal(initializeHarness(recovered).reportedDumps, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a reparse point at the diagnostics data directory degrades without touching its target', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    const outside = path.join(root, 'outside-data');
    mkdirSync(outside);
    writeFileSync(path.join(outside, 'keep.txt'), 'keep');
    symlinkSync(
      outside,
      harness.paths.dataDirectory,
      process.platform === 'win32' ? 'junction' : 'dir',
    );

    const result = initializeHarness(harness);

    assert.equal(result.enabled, true);
    assert.equal(result.dumpDirectory, undefined);
    assert.equal(
      harness.events.some((event) => event.startsWith('set:crashDumps:')),
      false,
    );
    assert.deepEqual(readdirSync(outside), ['keep.txt']);
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
    writeFileSync(path.join(harness.paths.dumpDirectory, 'credential-supersecret.dmp'), 'reported');

    const result = initializeHarness(harness);

    assert.equal(result.reportedDumps, 1);
    assert.match(harness.logs.error[0], /modifiedUtc=.*sizeBytes=/);
    assert.equal(harness.logs.error[0].includes('dumpId='), false);
    assert.equal(harness.logs.error[0].includes('credential-supersecret'), false);
    assert.equal(existsSync(path.join(nested, 'nested.dmp')), true);
    assert.equal(existsSync(path.join(unapproved, 'other.dmp')), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('startup scanning stops at its candidate bound and reports truncation', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    mkdirSync(harness.paths.dumpDirectory, { recursive: true });
    for (const name of ['one.dmp', 'two.dmp', 'three.dmp']) {
      writeFileSync(path.join(harness.paths.dumpDirectory, name), name);
    }

    const result = initializeHarness(harness, {
      ...defaultCrashDiagnosticsPolicy,
      maxCandidates: 2,
    });

    assert.equal(result.scanTruncated, true);
    assert.equal(result.reportedDumps, 2);
    assert.match(harness.logs.warn.join('\n'), /bounded startup scan limit/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('cleanup never unlinks a same-metadata file swapped in after reporting', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    mkdirSync(harness.paths.dumpDirectory, { recursive: true });
    const dump = path.join(harness.paths.dumpDirectory, 'swap.dmp');
    writeFileSync(dump, 'old!');
    const modified = new Date(Date.UTC(2026, 7, 7));
    utimesSync(dump, modified, modified);
    let swapped = false;

    const result = initializeLocalCrashDiagnostics({
      app: harness.app,
      reporter: harness.reporter,
      platform: harness.platform,
      arch: process.arch,
      electronVersion: '43.2.0',
      processId: 42,
      localAppData: harness.localAppData,
      logger: {
        info: (message) => harness.logs.info.push(message),
        warn: (message) => harness.logs.warn.push(message),
        error: (message) => {
          harness.logs.error.push(message);
          if (swapped) return;
          swapped = true;
          unlinkSync(dump);
          writeFileSync(dump, 'new!');
          utimesSync(dump, modified, modified);
        },
      },
      now: Date.UTC(2026, 7, 8),
      policy: { ...defaultCrashDiagnosticsPolicy, maxTotalBytes: 1 },
    });

    assert.equal(result.reportedDumps, 1);
    assert.equal(result.prunedDumps, 0);
    assert.equal(readFileSync(dump, 'utf8'), 'new!');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('cleanup never crosses a dump directory swapped after reporting', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    const pending = path.join(harness.paths.dumpDirectory, 'pending');
    const moved = path.join(harness.paths.dumpDirectory, 'pending-moved');
    mkdirSync(pending, { recursive: true });
    const dump = path.join(pending, 'swap.dmp');
    writeFileSync(dump, 'old');
    let swapped = false;

    const result = initializeLocalCrashDiagnostics({
      app: harness.app,
      reporter: harness.reporter,
      platform: harness.platform,
      arch: process.arch,
      electronVersion: '43.2.0',
      processId: 42,
      localAppData: harness.localAppData,
      logger: {
        info: (message) => harness.logs.info.push(message),
        warn: (message) => harness.logs.warn.push(message),
        error: (message) => {
          harness.logs.error.push(message);
          if (swapped) return;
          swapped = true;
          renameSync(pending, moved);
          mkdirSync(pending);
          writeFileSync(path.join(pending, 'swap.dmp'), 'unrelated');
        },
      },
      now: Date.UTC(2026, 7, 8),
      policy: { ...defaultCrashDiagnosticsPolicy, maxTotalBytes: 1 },
    });

    assert.equal(result.reportedDumps, 1);
    assert.equal(result.prunedDumps, 0);
    assert.equal(readFileSync(path.join(pending, 'swap.dmp'), 'utf8'), 'unrelated');
    assert.equal(readFileSync(path.join(moved, 'swap.dmp'), 'utf8'), 'old');
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
    const current = new Date(Date.UTC(2026, 7, 8));
    utimesSync(harness.paths.lockPath, current, current);

    const result = initializeHarness(harness);

    assert.equal(result.enabled, true);
    assert.equal(result.reportedDumps, 0);
    assert.deepEqual(harness.logs.error, []);
    assert.match(harness.logs.info.at(-1) ?? '', /lock is unavailable or held/);
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

test('a future-dated invalid lock cannot disable maintenance indefinitely', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    mkdirSync(harness.paths.dumpDirectory, { recursive: true });
    writeFileSync(path.join(harness.paths.dumpDirectory, 'previous.dmp'), 'dump');
    writeFileSync(harness.paths.lockPath, 'invalid-lock');
    const future = new Date(Date.UTC(2026, 7, 9));
    utimesSync(harness.paths.lockPath, future, future);

    const result = initializeHarness(harness);

    assert.equal(result.reportedDumps, 1);
    assert.equal(existsSync(harness.paths.lockPath), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a symlink at the reserved lock path is removed without touching its target', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    mkdirSync(harness.paths.dumpDirectory, { recursive: true });
    const outside = path.join(root, 'outside-lock-target');
    writeFileSync(outside, 'do-not-touch');
    symlinkSync(outside, harness.paths.lockPath, 'file');
    writeFileSync(path.join(harness.paths.dumpDirectory, 'previous.dmp'), 'dump');

    const result = initializeHarness(harness);

    assert.equal(result.reportedDumps, 1);
    assert.equal(existsSync(harness.paths.lockPath), false);
    assert.equal(readFileSync(outside, 'utf8'), 'do-not-touch');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('an old lock owned by a live process is not stolen by another instance', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    mkdirSync(harness.paths.dumpDirectory, { recursive: true });
    writeFileSync(path.join(harness.paths.dumpDirectory, 'previous.dmp'), 'dump');
    writeFileSync(
      harness.paths.lockPath,
      JSON.stringify({ pid: process.pid, token: '00000000-0000-4000-8000-000000000000' }),
    );
    const old = new Date(Date.UTC(2026, 7, 8) - 10 * 60 * 1000);
    utimesSync(harness.paths.lockPath, old, old);

    const result = initializeHarness(harness);

    assert.equal(result.reportedDumps, 0);
    assert.equal(existsSync(harness.paths.lockPath), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('an implausibly old live-PID lock cannot suppress maintenance indefinitely', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    mkdirSync(harness.paths.dumpDirectory, { recursive: true });
    writeFileSync(path.join(harness.paths.dumpDirectory, 'previous.dmp'), 'dump');
    writeFileSync(
      harness.paths.lockPath,
      JSON.stringify({ pid: process.pid, token: '00000000-0000-4000-8000-000000000000' }),
    );
    const implausiblyOld = new Date(Date.UTC(2026, 7, 8) - 25 * 60 * 60 * 1000);
    utimesSync(harness.paths.lockPath, implausiblyOld, implausiblyOld);

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

test('malformed bounded state formats are replaced without exposing their contents', () => {
  for (const contents of [
    '{',
    'null',
    JSON.stringify({ version: 1, reportedDumpKeys: 'not-an-array' }),
    JSON.stringify({ version: 1, reportedDumpKeys: ['credential-secret'] }),
  ]) {
    const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
    try {
      const harness = createHarness(root);
      mkdirSync(harness.paths.dumpDirectory, { recursive: true });
      writeFileSync(path.join(harness.paths.dumpDirectory, 'previous.dmp'), 'dump');
      writeFileSync(harness.paths.statePath, contents);

      const result = initializeHarness(harness);
      const state = JSON.parse(readFileSync(harness.paths.statePath, 'utf8')) as {
        reportedDumpKeys: string[];
      };

      assert.equal(result.reportedDumps, 1);
      assert.equal(state.reportedDumpKeys.length, 1);
      assert.equal(
        [...harness.logs.info, ...harness.logs.warn, ...harness.logs.error].some((message) =>
          message.includes('credential-secret'),
        ),
        false,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

test('non-canonical state is sanitized even when there are no dumps', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    mkdirSync(harness.paths.dumpDirectory, { recursive: true });
    writeFileSync(
      harness.paths.statePath,
      JSON.stringify({ version: 1, reportedDumpKeys: [], credential: 'do-not-persist' }),
    );

    const result = initializeHarness(harness);
    const state = JSON.parse(readFileSync(harness.paths.statePath, 'utf8')) as Record<
      string,
      unknown
    >;

    assert.equal(result.reportedDumps, 0);
    assert.deepEqual(state, { version: 1, reportedDumpKeys: [] });
    assert.equal(
      [...harness.logs.info, ...harness.logs.warn, ...harness.logs.error].some((message) =>
        message.includes('do-not-persist'),
      ),
      false,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('unsafe state links are replaced locally without reading or modifying their targets', () => {
  for (const linkKind of ['symbolic', 'hard'] as const) {
    const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
    try {
      const harness = createHarness(root);
      mkdirSync(harness.paths.dumpDirectory, { recursive: true });
      const outside = path.join(root, `${linkKind}-state-target`);
      const outsideContents = '{"credential":"do-not-touch"}';
      writeFileSync(outside, outsideContents);
      if (linkKind === 'symbolic') symlinkSync(outside, harness.paths.statePath, 'file');
      else linkSync(outside, harness.paths.statePath);
      writeFileSync(path.join(harness.paths.dumpDirectory, 'previous.dmp'), 'dump');

      const result = initializeHarness(harness);
      const state = JSON.parse(readFileSync(harness.paths.statePath, 'utf8')) as {
        reportedDumpKeys: string[];
      };

      assert.equal(result.reportedDumps, 1);
      assert.equal(state.reportedDumpKeys.length, 1);
      assert.equal(readFileSync(outside, 'utf8'), outsideContents);
      assert.equal(
        [...harness.logs.info, ...harness.logs.warn, ...harness.logs.error].some((message) =>
          message.includes('credential'),
        ),
        false,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

test('pruning is deferred when a new crash cannot be reported', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const first = createHarness(root);
    mkdirSync(first.paths.dumpDirectory, { recursive: true });
    writeFileSync(path.join(first.paths.dumpDirectory, 'new.dmp'), 'new');
    writeFileSync(path.join(first.paths.dumpDirectory, 'old.dmp'), 'old');
    const policy = { ...defaultCrashDiagnosticsPolicy, maxDumps: 1 };
    const failed = initializeLocalCrashDiagnostics({
      app: first.app,
      reporter: first.reporter,
      platform: first.platform,
      arch: process.arch,
      electronVersion: '43.2.0',
      processId: 42,
      localAppData: first.localAppData,
      logger: {
        info: () => undefined,
        warn: () => undefined,
        error: () => {
          throw new Error('logger unavailable');
        },
      },
      now: Date.UTC(2026, 7, 8),
      policy,
    });

    assert.equal(failed.reportedDumps, 0);
    assert.equal(failed.prunedDumps, 0);
    assert.equal(
      readdirSync(first.paths.dumpDirectory).filter((name) => name.endsWith('.dmp')).length,
      2,
    );

    const second = createHarness(root);
    const recovered = initializeHarness(second, policy);
    assert.equal(recovered.reportedDumps, 2);
    assert.equal(recovered.prunedDumps, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a duplicate outside retention is preserved when its retained copy cannot be reported', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const first = createHarness(root);
    const pending = path.join(first.paths.dumpDirectory, 'pending');
    mkdirSync(pending, { recursive: true });
    const retained = path.join(first.paths.dumpDirectory, 'same.dmp');
    const duplicate = path.join(pending, 'same.dmp');
    writeFileSync(retained, 'same');
    writeFileSync(duplicate, 'same');
    const modified = new Date(Date.UTC(2026, 7, 7));
    utimesSync(retained, modified, modified);
    utimesSync(duplicate, modified, modified);
    const policy = { ...defaultCrashDiagnosticsPolicy, maxDumps: 1 };

    const failed = initializeLocalCrashDiagnostics({
      app: first.app,
      reporter: first.reporter,
      platform: first.platform,
      arch: process.arch,
      electronVersion: '43.2.0',
      processId: 42,
      localAppData: first.localAppData,
      logger: {
        info: () => undefined,
        warn: () => undefined,
        error: () => {
          throw new Error('logger unavailable');
        },
      },
      now: Date.UTC(2026, 7, 8),
      policy,
    });

    assert.equal(failed.reportedDumps, 0);
    assert.equal(failed.prunedDumps, 0);
    assert.equal(existsSync(retained), true);
    assert.equal(existsSync(duplicate), true);

    const second = createHarness(root);
    const recovered = initializeHarness(second, policy);
    assert.equal(recovered.reportedDumps, 1);
    assert.equal(recovered.prunedDumps, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('crash reporter startup failures degrade without logging exception details', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-crashdiag-'));
  try {
    const harness = createHarness(root);
    harness.reporter.start = () => {
      throw new Error('credential-secret');
    };

    const result = initializeHarness(harness);

    assert.equal(result.enabled, false);
    assert.equal(harness.logs.warn.length, 1);
    assert.equal(harness.logs.warn[0].includes('credential-secret'), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
