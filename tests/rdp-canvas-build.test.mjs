import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { buildRdpCanvasHost } from '../scripts/build-rdp-canvas-host.mjs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

test('real CMake registers the adapter after FreeRDP targets exist', (t) => {
  if (spawnSync('cmake', ['--version']).status !== 0) {
    t.skip('CMake is required on the native build host.');
    return;
  }
  if (
    process.platform === 'win32' &&
    ['gcc', 'mingw32-make'].some((tool) => spawnSync(tool, ['--version']).status !== 0)
  ) {
    t.skip(
      'The Windows configure fixture requires the MinGW C toolchain; macOS uses its native toolchain.',
    );
    return;
  }
  const directory = mkdtempSync(join(tmpdir(), 'rdp-cmake-'));
  const source = fileURLToPath(
    new URL('../tools/wormhole-freerdp-host', import.meta.url),
  ).replaceAll('\\', '/');
  try {
    writeFileSync(
      join(directory, 'CMakeLists.txt'),
      `
cmake_minimum_required(VERSION 3.20)
project(FreeRDP C)
add_library(freerdp-client INTERFACE)
add_library(freerdp INTERFACE)
add_library(winpr INTERFACE)
`,
    );
    const result = spawnSync(
      'cmake',
      [
        '-S',
        directory,
        '-B',
        join(directory, 'build'),
        ...(process.platform === 'win32' ? ['-G', 'MinGW Makefiles'] : []),
        `-DCMAKE_PROJECT_FreeRDP_INCLUDE=${source}/register.cmake`,
        `-DWORMHOLE_RDP_SURFACE_SOURCE=${source}`,
      ],
      { encoding: 'utf8', windowsHide: true },
    );
    assert.equal(result.status, 0, result.stdout + result.stderr);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('canvas adapter reuses the provisioned FreeRDP build and stages both Mac slices', () => {
  const repoRoot = mkdtempSync(join(tmpdir(), 'rdp-build-'));
  try {
    assert.equal(buildRdpCanvasHost({ repoRoot, platform: 'win32' }), undefined);
    assert.throws(() => buildRdpCanvasHost({ repoRoot, platform: 'darwin' }), /Build the macOS/);
    for (const arch of ['x64', 'arm64']) {
      const build = join(repoRoot, 'obj', 'macos-freerdp', `${arch}-osx`);
      mkdirSync(build, { recursive: true });
      writeFileSync(join(build, 'CMakeCache.txt'), '');
    }
    const commands = [];
    const output = buildRdpCanvasHost({
      repoRoot,
      platform: 'darwin',
      spawn(command, args) {
        commands.push({ command, args });
        return { status: 0 };
      },
    });
    assert.equal(output, join(repoRoot, 'dist-electron', 'wormhole-freerdp-host'));
    assert.deepEqual(
      commands.map((item) => item.command),
      ['cmake', 'cmake', 'cmake', 'cmake', 'lipo', 'lipo', 'codesign'],
    );
    assert.ok(commands[4].args.some((arg) => arg.includes('x64-osx')));
    assert.ok(commands[4].args.some((arg) => arg.includes('arm64-osx')));
    assert.deepEqual(commands[0].args.slice(0, 2), ['-S', join(repoRoot, 'obj', 'freerdp-source')]);
    assert.deepEqual(commands[5].args.slice(1), ['-verify_arch', 'x86_64', 'arm64']);
    assert.throws(
      () => buildRdpCanvasHost({ repoRoot, platform: 'darwin', spawn: () => ({ status: 1 }) }),
      /build failed/,
    );
    assert.throws(
      () =>
        buildRdpCanvasHost({
          repoRoot,
          platform: 'darwin',
          spawn: () => ({ error: new Error('missing compiler') }),
        }),
      /missing compiler/,
    );
  } finally {
    rmSync(repoRoot, { recursive: true, force: true });
  }
});
