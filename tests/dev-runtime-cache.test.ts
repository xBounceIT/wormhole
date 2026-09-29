import assert from 'node:assert/strict';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  devRuntimeCacheAllowed,
  devRuntimeEnvironment,
  devRuntimeGoEnvironment,
  devRuntimeGoModuleDirectories,
  runCachedDevRuntimeBuild,
} from '../scripts/dev-runtime-cache.ts';
import type { DevRuntimeBuildStep } from '../scripts/dev-runtime-plan.ts';

function fixture(t: test.TestContext) {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-dev-runtime-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const write = (file: string, contents = 'source') => {
    mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    writeFileSync(path.join(root, file), contents);
  };
  const remove = (file: string) => rmSync(path.join(root, file), { recursive: true, force: true });
  const step: DevRuntimeBuildStep = {
    name: 'backend',
    command: 'go',
    args: ['build'],
    inputs: ['source', 'optional.config'],
    outputs: ['dist/backend'],
  };
  write('source/main.go');
  const builds: string[] = [];
  const logs: string[] = [];
  const options = {
    root,
    plan: [step],
    context: { architecture: 'x64' },
    log: (message: string) => logs.push(message),
    execute(build: DevRuntimeBuildStep) {
      builds.push(build.name);
      for (const output of build.outputs) {
        write(output, build.name);
        chmodSync(path.join(root, output), 0o755);
      }
    },
  };
  return {
    root,
    write,
    remove,
    step,
    builds,
    logs,
    options,
    run: () => runCachedDevRuntimeBuild(options),
  };
}

test('nested npm scripts share a stable cache without losing compiler search order', () => {
  assert.deepEqual(
    devRuntimeEnvironment(
      {
        Path: 'C:\\repo\\.bin;C:\\REPO\\.bin;C:\\Go;C:\\Go',
        GOFLAGS: '-race',
        npm_lifecycle_event: 'dev',
        TOKEN: 'secret',
      },
      'win32',
    ),
    { PATH: 'C:\\repo\\.bin;C:\\Go', GOFLAGS: '-race' },
  );
  assert.deepEqual(devRuntimeEnvironment({ PATH: '/bin:/BIN:/bin::', CC: 'clang' }, 'linux'), {
    PATH: '/bin:/BIN:',
    CC: 'clang',
  });
  assert.deepEqual(devRuntimeEnvironment({ PATH: '', CXX: undefined }, 'darwin'), {
    PATH: '',
    CXX: undefined,
  });
  assert.equal(
    devRuntimeEnvironment(
      { SDKROOT: '/sdk', MACOSX_DEPLOYMENT_TARGET: '14.0', CFLAGS: '-O3' },
      'darwin',
    ).SDKROOT,
    '/sdk',
  );
});

test('a fresh native source bootstrap is cached on the first successful build', (t) => {
  const f = fixture(t);
  f.step.bootstrap = {
    command: 'git',
    args: ['submodule', 'update'],
    outputs: ['source/submodule/header.h'],
  };
  const original = f.options.execute;
  let bootstraps = 0;
  f.options.execute = (step) => {
    if (step.command === 'git') {
      bootstraps++;
      f.write('source/submodule/header.h');
      return;
    }
    // The real OpenVPN script also hydrates missing submodules during compilation.
    if (!existsSync(path.join(f.root, 'source/submodule/header.h')))
      f.write('source/submodule/header.h');
    original(step);
  };
  f.run();
  f.run();
  assert.equal(bootstraps, 1);
  assert.deepEqual(f.builds, ['backend']);
});

test('source folders named build, bin and obj are hashed unless explicitly excluded', (t) => {
  const f = fixture(t);
  for (const dir of ['build', 'bin', 'obj']) f.write(`source/${dir}/live.go`);
  f.run();
  for (const dir of ['build', 'bin', 'obj']) {
    f.write(`source/${dir}/live.go`, 'edited');
    f.run();
  }
  assert.equal(f.builds.length, 4);
});

test(
  'POSIX executables that lose their execute bit are rebuilt',
  { skip: process.platform === 'win32' },
  (t) => {
    const f = fixture(t);
    const original = f.options.execute;
    f.options.execute = (step) => {
      original(step);
      for (const output of step.outputs) chmodSync(path.join(f.root, output), 0o755);
    };
    f.run();
    chmodSync(path.join(f.root, 'dist/backend'), 0o644);
    f.run();
    assert.equal(f.builds.length, 2);
  },
);

test('unchanged builds are reused without invoking any compiler', (t) => {
  const f = fixture(t);
  f.run();
  f.run();
  assert.deepEqual(f.builds, ['backend']);
  assert.match(f.logs.at(-1)!, /Reuse backend/);
});

test('edits with preserved timestamps, additions and deletions rebuild', (t) => {
  const f = fixture(t);
  f.run();
  f.write('source/main.go', 'edited');
  utimesSync(path.join(f.root, 'source/main.go'), new Date(0), new Date(0));
  f.run();
  f.write('source/migration.sql');
  f.run();
  f.remove('source/migration.sql');
  f.run();
  f.write('optional.config');
  f.run();
  f.remove('optional.config');
  f.run();
  assert.equal(f.builds.length, 6);
});

test('missing, empty, replaced or invalid executable outputs rebuild', (t) => {
  const f = fixture(t);
  f.run();
  f.remove('dist/backend');
  f.run();
  f.write('dist/backend', '');
  f.run();
  f.write('dist/backend', 'other architecture');
  f.run();
  f.remove('dist/backend');
  mkdirSync(path.join(f.root, 'dist/backend'));
  assert.throws(f.run);
  f.remove('dist/backend');
  f.run();
  assert.equal(f.builds.length, 6);
});

test('generated trees and shim stamps do not cause rebuild loops', (t) => {
  const f = fixture(t);
  f.step.excludedInputs = ['source/bin', 'source/obj', 'source/build', 'source/shim_buildinfo.go'];
  f.run();
  for (const dir of ['.git', 'bin', 'obj', 'build', 'node_modules'])
    f.write(`source/${dir}/generated`);
  f.write('source/shim_buildinfo.go');
  f.run();
  assert.equal(f.builds.length, 1);
});

test('generated-path exclusions follow the host filesystem case rules', (t) => {
  const f = fixture(t);
  f.step.excludedInputs = ['source/build'];
  f.write('source/BUILD/generated');
  f.run();
  f.write('source/BUILD/generated', 'new build output');
  f.run();
  assert.equal(f.builds.length, process.platform === 'win32' ? 1 : 2);
});

test('external Go inputs bypass cache; invalid query results never enable stale reuse', () => {
  for (const GOWORK of ['', 'off'])
    assert.equal(devRuntimeCacheAllowed(JSON.stringify({ GOWORK, GOFLAGS: '-race' })), true);
  assert.equal(
    devRuntimeCacheAllowed(JSON.stringify({ GOWORK: '/external/go.work', GOFLAGS: '' })),
    false,
  );
  for (const flag of [
    '-overlay=external.json',
    '-modfile=external.mod',
    '-toolexec=wrapper',
    '-overlay external.json',
    '--overlay=external.json',
    '"-overlay=external.json"',
    "'-modfile=external.mod'",
    '-a',
  ]) {
    assert.equal(
      devRuntimeCacheAllowed(JSON.stringify({ GOWORK: '', GOFLAGS: `-race ${flag}` })),
      false,
    );
  }
  for (const malformed of ['', '{broken', '{}', 'null', '{"GOWORK":"","GOFLAGS":42}'])
    assert.equal(devRuntimeCacheAllowed(malformed), false);
});

test('bootstrap failures stop the build and cannot create a cache stamp', (t) => {
  const f = fixture(t);
  f.step.bootstrap = { command: 'git', args: [], outputs: ['source/submodule/header.h'] };
  assert.throws(
    () => runCachedDevRuntimeBuild({ ...f.options, execute() {} }),
    /bootstrap did not produce/,
  );
  assert.throws(
    () =>
      runCachedDevRuntimeBuild({
        ...f.options,
        execute() {
          throw new Error('clone failed');
        },
      }),
    /clone failed/,
  );
  assert.deepEqual(readdirSync(path.join(f.root, 'obj/dev-runtime')), []);
  assert.deepEqual(f.builds, []);
});

test('Go contexts are queried in every actual build module, including nested workspace discovery', (t) => {
  const f = fixture(t);
  f.write('source/go.mod');
  f.write('tools/helper/go.mod');
  f.write('tools/go.work', 'go workspace above helper');
  f.options.plan.push({ ...f.step, inputs: ['tools/helper', 'source', 'not-a-module'] });
  assert.deepEqual(devRuntimeGoModuleDirectories(f.root, f.options.plan), [
    path.join(f.root, 'source'),
    path.join(f.root, 'tools/helper'),
  ]);
});

test('volatile Go work directories do not invalidate cache; actual compiler settings still do', (t) => {
  const f = fixture(t);
  const context = (temporary: string, flags = '-O2') => ({
    go: devRuntimeGoEnvironment(
      JSON.stringify({
        GOWORK: '',
        GOFLAGS: '',
        CGO_CFLAGS: flags,
        GOGCCFLAGS: `-ffile-prefix-map=${temporary}=/tmp/go-build`,
      }),
    ),
  });
  runCachedDevRuntimeBuild({ ...f.options, context: context('go-build-111') });
  runCachedDevRuntimeBuild({ ...f.options, context: context('go-build-222') });
  assert.equal(f.builds.length, 1);
  assert.equal(devRuntimeCacheAllowed(context('go-build-333').go), true);
  runCachedDevRuntimeBuild({ ...f.options, context: context('go-build-444', '-O3') });
  assert.equal(f.builds.length, 2);
  for (const malformed of ['', '{broken', 'null', '42', '[]'])
    assert.equal(devRuntimeGoEnvironment(malformed), '');
});

test('toolchain, command and architecture changes invalidate cache; force always rebuilds', (t) => {
  const f = fixture(t);
  f.run();
  runCachedDevRuntimeBuild({ ...f.options, context: { architecture: 'arm64', go: 'new version' } });
  f.step.args.push('-new-flag');
  f.run();
  runCachedDevRuntimeBuild({ ...f.options, force: true });
  assert.equal(f.builds.length, 4);
});

test('corrupt stamps are rebuilt and failures never leave a reusable stamp', (t) => {
  const f = fixture(t);
  f.run();
  const cache = path.join(f.root, 'obj/dev-runtime');
  const stamp = path.join(cache, readdirSync(cache)[0]);
  writeFileSync(stamp, '{broken');
  f.run();
  f.write('source/main.go', 'changed');
  assert.throws(
    () =>
      runCachedDevRuntimeBuild({
        ...f.options,
        execute() {
          throw new Error('compiler failed');
        },
      }),
    /compiler failed/,
  );
  assert.deepEqual(readdirSync(cache), []);
  f.run();
  f.run();
  assert.equal(f.builds.length, 3);
});

test('successful exit without all nonempty outputs is an error', (t) => {
  const f = fixture(t);
  assert.throws(() => runCachedDevRuntimeBuild({ ...f.options, execute() {} }), /ENOENT/);
  f.write('dist/backend', '');
  assert.throws(() => runCachedDevRuntimeBuild({ ...f.options, execute() {} }), /did not produce/);
  assert.deepEqual(readdirSync(path.join(f.root, 'obj/dev-runtime')), []);
});

test('sources changed during a build are not cached', (t) => {
  const f = fixture(t);
  runCachedDevRuntimeBuild({
    ...f.options,
    execute(step) {
      f.options.execute(step);
      f.write('source/main.go', 'edit during build');
    },
  });
  assert.deepEqual(readdirSync(path.join(f.root, 'obj/dev-runtime')), []);
  f.run();
  f.run();
  assert.equal(f.builds.length, 2);
});

test('upstream executable changes rebuild consumers in dependency order', (t) => {
  const f = fixture(t);
  const downstream = {
    ...f.step,
    name: 'consumer',
    inputs: f.step.outputs,
    outputs: ['dist/consumer'],
  };
  f.options.plan.push(downstream);
  f.run();
  f.run();
  assert.deepEqual(f.builds, ['backend', 'consumer']);
  f.write('dist/backend', 'changed upstream');
  // A new upstream build can produce identical bytes, so consumers correctly reuse their output.
  f.run();
  assert.deepEqual(f.builds, ['backend', 'consumer', 'backend']);
  f.step.name = 'new backend';
  f.run();
  assert.deepEqual(f.builds, ['backend', 'consumer', 'backend', 'new backend', 'consumer']);
});

test('filesystem errors reading sources fail visibly instead of reusing stale binaries', (t) => {
  const f = fixture(t);
  f.run();
  f.step.inputs = ['\0invalid-path'];
  assert.throws(f.run, { code: 'ERR_INVALID_ARG_VALUE' });
});
