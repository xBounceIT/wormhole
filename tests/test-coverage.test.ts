import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

import {
  discoverGoModules,
  discoverTypeScriptTests,
  meetsCoverageThreshold,
  mergeGoCoverage,
  mergeVaultCoverageMatrix,
  parseGoCoverage,
  runGoCoverage,
} from '../scripts/test-coverage.ts';

test('Go coverage across runners counts portable blocks once and retains native files', () => {
  const windows = 'mode: atomic\r\nshared.go:1.1,2.2 3 0\r\nwindows.go:3.1,3.2 1 0\r\n';
  const linux = 'mode: set\nshared.go:1.1,2.2 3 1\nlinux.go:4.1,4.2 2 1\n';
  const merged = mergeGoCoverage([windows, linux]);
  assert.deepEqual(parseGoCoverage(merged), { covered: 5, total: 6 });
  assert.equal(merged, mergeGoCoverage([linux, windows, linux]));
  assert.equal(merged, mergeGoCoverage([merged]));
  assert.throws(() => mergeGoCoverage([]), /No Go coverage/);
  assert.throws(() => mergeGoCoverage([windows, 'mode: set\n']), /no statements/);
  assert.throws(() => mergeGoCoverage([windows, linux.replace('2.2 3', '2.2 4')]), /Inconsistent/);
});

test('the vault coverage gate uses the exact statement ratio', () => {
  assert.equal(meetsCoverageThreshold({ covered: 4, total: 5 }, 80), true);
  assert.equal(meetsCoverageThreshold({ covered: 7999, total: 10000 }, 80), false);
  assert.throws(() => meetsCoverageThreshold({ covered: 0, total: 0 }, 80));
});

test('the vault matrix requires results from native PostgreSQL and the desktop wizard', () => {
  const root = mkdtempSync(join(tmpdir(), 'vault-matrix-'));
  const profile = 'mode: set\nportable.go:1.1,2.1 1 0\n';
  try {
    for (const os of ['Linux', 'Windows', 'macOS']) {
      const runner = join(root, `vault-go-${os}-fixture`);
      mkdirSync(runner);
      for (const file of ['vault.coverage', 'vault-entry.coverage'])
        writeFileSync(join(runner, file), profile);
      if (os === 'Linux') {
        for (const major of [16, 17, 18]) {
          writeFileSync(
            join(runner, `vault-postgres-${major}.coverage`),
            profile.replace('portable.go', `pg${major}.go`),
          );
        }
        assert.throws(() => mergeVaultCoverageMatrix(root), /Missing vault coverage from Windows/);
      }
      if (os === 'Windows') {
        writeFileSync(join(runner, 'vault-postgres.coverage'), profile);
        writeFileSync(join(runner, 'vault-desktop.coverage'), profile.replace('1 0', '1 1'));
      }
    }
    assert.deepEqual(parseGoCoverage(mergeVaultCoverageMatrix(root)), { covered: 1, total: 4 });
    rmSync(join(root, 'vault-go-Windows-fixture', 'vault-desktop.coverage'));
    assert.throws(() => mergeVaultCoverageMatrix(root), /vault-desktop\.coverage/);
    rmSync(join(root, 'vault-go-Linux-fixture', 'vault-postgres-17.coverage'));
    assert.throws(() => mergeVaultCoverageMatrix(root), /vault-postgres-17\.coverage/);
  } finally {
    assert.equal(dirname(root), resolve(tmpdir()));
    rmSync(root, { recursive: true, force: true });
  }
});

test('Go coverage parsing is exact and fails closed', () => {
  const coverage = parseGoCoverage(
    [
      'mode: set',
      'example.go:1.1,2.2 8 1',
      'example.go:3.1,4.2 2 0',
      'example.go:5.1,5.1 0 0',
      '',
    ].join('\n'),
  );
  assert.deepEqual(coverage, { covered: 8, total: 10 });

  assert.throws(() => parseGoCoverage(''), /invalid header/);
  assert.throws(() => parseGoCoverage('mode: set\n'), /no statements/);
  assert.throws(() => parseGoCoverage('mode: set\nmalformed'), /invalid block/);
  assert.throws(() => parseGoCoverage('mode: set\ngarbage 1 1'), /invalid block/);
  assert.throws(
    () => parseGoCoverage('mode: set\nexample.go:1.1,2.2 9007199254740992 1'),
    /invalid counters/,
  );
});

test('coverage discovery includes nested tests and every Go module', () => {
  const root = mkdtempSync(join(tmpdir(), 'wormhole-coverage-discovery-'));
  try {
    mkdirSync(join(root, 'tests', 'nested'), { recursive: true });
    mkdirSync(join(root, 'tools', 'one'), { recursive: true });
    mkdirSync(join(root, 'tools', 'nested', 'two'), { recursive: true });
    mkdirSync(join(root, 'tools', 'vendor', 'ignored'), { recursive: true });
    writeFileSync(join(root, 'tests', 'top.test.ts'), '');
    writeFileSync(join(root, 'tests', 'nested', 'child.test.mjs'), '');
    writeFileSync(join(root, 'tests', 'nested', 'fixture.ts'), '');
    writeFileSync(join(root, 'tools', 'one', 'go.mod'), 'module one');
    writeFileSync(join(root, 'tools', 'nested', 'two', 'go.mod'), 'module two');
    writeFileSync(join(root, 'tools', 'vendor', 'ignored', 'go.mod'), 'module ignored');

    assert.deepEqual(discoverTypeScriptTests(root), [
      join(root, 'tests', 'nested', 'child.test.mjs'),
      join(root, 'tests', 'top.test.ts'),
    ]);
    assert.deepEqual(discoverGoModules(root), [
      join(root, 'tools', 'nested', 'two'),
      join(root, 'tools', 'one'),
    ]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('Go coverage reports low percentages and propagates test failures', (context) => {
  const output: string[] = [];
  context.mock.method(console, 'log', (line: string) => output.push(line));
  const root = mkdtempSync(join(tmpdir(), 'wormhole-coverage-runner-'));
  const modules = ['wormhole-backend', 'adapter'].map((name) => join(root, 'tools', name));
  const calls: string[] = [];
  const profiles: string[] = [];
  let failCommand = false;
  const runCommand = (command: string, args: string[], cwd: string) => {
    assert.equal(command, 'go');
    assert.deepEqual(
      args.slice(0, -1),
      cwd === modules[0]
        ? ['test', '-count=1', '-timeout=35m', './...']
        : ['test', '-timeout=10m', './...'],
    );
    assert.ok(modules.includes(cwd));
    calls.push(cwd);
    const profile = args.find((arg) => arg.startsWith('-coverprofile='))!.slice(14);
    profiles.push(profile);
    if (failCommand) throw new Error('go test failed');
    writeFileSync(profile, `mode: set\nexample.go:1.1,2.2 7 1\nexample.go:3.1,4.2 3 0\n`);
  };
  try {
    for (const modulePath of modules) {
      mkdirSync(modulePath, { recursive: true });
      writeFileSync(join(modulePath, 'go.mod'), 'module fixture');
    }
    runGoCoverage(root, runCommand);
    assert.equal(calls.length, 2);
    assert.ok(profiles.every((profile) => !existsSync(dirname(profile))));

    assert.ok(output.includes('  aggregate: 70.00% (14/20)'));

    failCommand = true;
    const previousCalls = calls.length;
    assert.throws(() => runGoCoverage(root, runCommand), /go test failed/);
    assert.equal(calls.length, previousCalls + 1, 'Stop after a failed module');
    assert.ok(profiles.every((profile) => !existsSync(dirname(profile))));

    const emptyRoot = join(root, 'empty');
    mkdirSync(join(emptyRoot, 'tools'), { recursive: true });
    assert.throws(() => runGoCoverage(emptyRoot, runCommand), /No Go modules/);
  } finally {
    assert.equal(resolve(root, '..'), resolve(tmpdir()));
    rmSync(root, { recursive: true, force: true });
  }
});

test('the coverage command reports low TypeScript and Go coverage without failing', () => {
  const root = mkdtempSync(join(tmpdir(), 'wormhole-coverage-smoke-'));
  try {
    mkdirSync(join(root, 'src'));
    mkdirSync(join(root, 'tests'));
    const modulePath = join(root, 'tools', 'example');
    mkdirSync(modulePath, { recursive: true });
    writeFileSync(join(root, 'package.json'), '{"type":"module"}');
    writeFileSync(
      join(root, 'src', 'pick.ts'),
      `export function pick(value: number): number {
  if (value === 1) {
    return 1;
  }
  if (value === 2) {
    return 2;
  }
  return 3;
}
`,
    );
    writeFileSync(
      join(root, 'tests', 'pick.test.mjs'),
      `import assert from 'node:assert/strict';
import test from 'node:test';
import { pick } from '../src/pick.ts';
test('pick', () => assert.equal(pick(1), 1));
`,
    );
    writeFileSync(join(modulePath, 'go.mod'), 'module example.test/coverage\n\ngo 1.23.0\n');
    writeFileSync(
      join(modulePath, 'pick.go'),
      `package example

func Pick(value int) int {
  if value == 1 {
    return 1
  }
  if value == 2 {
    return 2
  }
  return 3
}
`,
    );
    writeFileSync(
      join(modulePath, 'pick_test.go'),
      `package example

import "testing"

func TestPick(t *testing.T) {
  if Pick(1) != 1 {
    t.Fatal("wrong result")
  }
}
`,
    );
    const script = new URL('../scripts/test-coverage.ts', import.meta.url).href;
    const {
      NODE_TEST_CONTEXT: _parentTestContext,
      NODE_V8_COVERAGE: _parentCoverage,
      ...env
    } = process.env;
    const report = execFileSync(
      process.execPath,
      [
        '--experimental-strip-types',
        '--input-type=module',
        '--eval',
        `import { main } from ${JSON.stringify(script)}; main(process.cwd());`,
      ],
      { cwd: root, env, encoding: 'utf8', timeout: 60_000, windowsHide: true },
    );
    const typeScriptLines = /^.*all files\s+\|\s+([\d.]+)\s+\|/m.exec(report)?.[1];
    assert.ok(typeScriptLines && Number(typeScriptLines) < 80, report);
    assert.match(report, /aggregate: 40\.00% \(2\/5\)/);
  } finally {
    assert.equal(resolve(root, '..'), resolve(tmpdir()));
    rmSync(root, { recursive: true, force: true });
  }
});
