import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

for (const suite of ['wire', 'surface'])
  test(`native FreeRDP ${suite} contracts`, (t) => {
    const compiler = ['gcc', 'cc', 'clang'].find(
      (name) => spawnSync(name, ['--version'], { windowsHide: true }).status === 0,
    );
    if (!compiler) {
      t.skip('Native wire tests need a C compiler; run on the native build host.');
      return;
    }
    const directory = mkdtempSync(join(tmpdir(), 'rdp-wire-'));
    const source = fileURLToPath(new URL('../tools/wormhole-freerdp-host/', import.meta.url));
    const binary = join(directory, `${suite}-test${process.platform === 'win32' ? '.exe' : ''}`);
    const run = (command, args) => {
      const result = spawnSync(command, args, {
        cwd: directory,
        encoding: 'utf8',
        windowsHide: true,
      });
      assert.equal(result.status, 0, result.stderr || result.error?.message);
      return result.stdout;
    };
    try {
      const coverage =
        compiler === 'gcc' && spawnSync('gcov', ['--version'], { windowsHide: true }).status === 0;
      run(compiler, [
        '-std=c11',
        '-Wall',
        '-Wextra',
        '-Werror',
        ...(coverage ? ['--coverage', '-O0'] : []),
        join(source, `${suite}.c`),
        join(source, `${suite}_test.c`),
        '-o',
        binary,
      ]);
      assert.ok(run(binary, []).includes('tests passed'));
      if (coverage) {
        const output = run('gcov', [`${suite}-test-${suite}.gcno`]);
        const percent = Number(/Lines executed:([\d.]+)%/.exec(output)?.[1]);
        t.diagnostic(`Native C ${suite} line coverage: ${percent}%`);
        assert.ok(percent >= 80);
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
