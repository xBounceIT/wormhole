import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  discoverGoModules,
  discoverTypeScriptTests,
  meetsCoverageThreshold,
  parseGoCoverage,
} from '../scripts/test-coverage.ts';

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
  assert.equal(meetsCoverageThreshold(coverage, 80), true);
  assert.equal(meetsCoverageThreshold({ covered: 799, total: 1000 }, 80), false);

  assert.throws(() => parseGoCoverage(''), /invalid header/);
  assert.throws(() => parseGoCoverage('mode: set\n'), /no statements/);
  assert.throws(() => parseGoCoverage('mode: set\nmalformed'), /invalid block/);
  assert.throws(() => parseGoCoverage('mode: set\ngarbage 1 1'), /invalid block/);
  assert.throws(
    () => parseGoCoverage('mode: set\nexample.go:1.1,2.2 9007199254740992 1'),
    /invalid counters/,
  );
  assert.throws(() => meetsCoverageThreshold({ covered: 0, total: 0 }, 80), /must be valid/);
  assert.throws(() => meetsCoverageThreshold({ covered: 2, total: 1 }, 80), /must be valid/);
  assert.throws(() => meetsCoverageThreshold({ covered: 1, total: 1 }, 101), /must be valid/);
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
