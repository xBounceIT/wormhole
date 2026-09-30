import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
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
  devRuntimeCacheEnvironmentAllowed,
  devRuntimeCompilerIdentity,
  devRuntimeEnvironment,
  devRuntimeGoEnvironment,
  devRuntimeGoModuleDirectories,
  devRuntimeReplacementsAllowed,
  devRuntimeVcpkgInputs,
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

test('native dependency inputs are captured and mutable external roots disable reuse', (t) => {
  for (const name of [
    'CMAKE_PREFIX_PATH',
    'CMAKE_INCLUDE_PATH',
    'CMAKE_LIBRARY_PATH',
    'CMAKE_FIND_ROOT_PATH',
    'CMAKE_TOOLCHAIN_FILE',
    'ASIO_ROOT',
    'jsoncpp_DIR',
    'LZ4_ROOT',
    'XXHASH_DIR',
    'VCPKG_OVERLAY_PORTS',
    'VCPKG_OVERLAY_TRIPLETS',
    'CGO_CFLAGS',
    'CGO_CPPFLAGS',
    'CGO_CXXFLAGS',
    'CGO_FFLAGS',
    'CGO_LDFLAGS',
    'CFLAGS',
    'CPPFLAGS',
    'CXXFLAGS',
    'LDFLAGS',
    'CPATH',
    'C_INCLUDE_PATH',
    'CPLUS_INCLUDE_PATH',
    'OBJC_INCLUDE_PATH',
    'LIBRARY_PATH',
    'COMPILER_PATH',
    'GCC_EXEC_PREFIX',
    'SDKROOT',
  ]) {
    const environment = devRuntimeEnvironment(
      { [name]: '/external/native-input' },
      process.platform,
    );
    assert.equal(environment[name], '/external/native-input');
    assert.equal(devRuntimeCacheEnvironmentAllowed(environment), false);
  }
  assert.equal(devRuntimeCacheEnvironmentAllowed({}), true);
  assert.equal(
    devRuntimeCacheEnvironmentAllowed({
      CMAKE_PREFIX_PATH: '',
      ASIO_ROOT: undefined,
      VCPKG_OVERLAY_PORTS: '',
      VCPKG_OVERLAY_TRIPLETS: undefined,
    }),
    true,
  );
  assert.equal(
    devRuntimeCacheEnvironmentAllowed({ CMAKE_BUILD_PARALLEL_LEVEL: '4', PATH: '/bin' }),
    true,
  );
  assert.equal(devRuntimeCacheEnvironmentAllowed({ CGO_CFLAGS: '-O2 -g', CGO_CPPFLAGS: '' }), true);
  for (const flag of ['CGO_CFLAGS', 'CGO_CPPFLAGS', 'CGO_LDFLAGS']) {
    assert.equal(
      devRuntimeCacheAllowed(
        JSON.stringify({ GOWORK: '', GOFLAGS: '', [flag]: '-I/external/include -L/external/lib' }),
      ),
      false,
    );
  }
  assert.equal(
    devRuntimeCacheAllowed(
      JSON.stringify({ GOWORK: '', GOFLAGS: '', CGO_CFLAGS: '-O2 -g', CGO_LDFLAGS: '-O2 -g' }),
    ),
    true,
  );
  const f = fixture(t);
  const environment = devRuntimeEnvironment(
    { CMAKE_INCLUDE_PATH: 'external/include' },
    process.platform,
  );
  f.write('external/include/library.h', 'original library');
  const run = () =>
    runCachedDevRuntimeBuild({
      ...f.options,
      context: { environment },
      force: !devRuntimeCacheEnvironmentAllowed(environment),
    });
  run();
  f.write('external/include/library.h', 'changed library under the same search path');
  run();
  assert.equal(f.builds.length, 2);
  assert.notDeepEqual(
    environment,
    devRuntimeEnvironment({ CMAKE_INCLUDE_PATH: 'external/other' }, process.platform),
  );
  for (const name of [
    'VCPKG_OVERLAY_PORTS',
    'VCPKG_OVERLAY_TRIPLETS',
    'CGO_CFLAGS',
    'CGO_CPPFLAGS',
    'CGO_LDFLAGS',
    'CPATH',
    'C_INCLUDE_PATH',
    'CPLUS_INCLUDE_PATH',
    'LIBRARY_PATH',
  ]) {
    const environment = devRuntimeEnvironment({ [name]: 'external/overlay' }, process.platform);
    const run = () =>
      runCachedDevRuntimeBuild({
        ...f.options,
        context: { environment },
        force: !devRuntimeCacheEnvironmentAllowed(environment),
      });
    const before: number = f.builds.length;
    run();
    f.write('external/overlay/portfile.cmake', 'changed overlay at the same path');
    run();
    assert.equal(f.builds.length, before + 2);
  }
});

test('vcpkg checkout and manifest-installed dependency contents invalidate native reuse', (t) => {
  const f = fixture(t);
  const vcpkgRoot = path.join(f.root, 'external/vcpkg');
  f.step.inputs.push(...devRuntimeVcpkgInputs(f.root, vcpkgRoot));
  f.step.generatedInputs = ['tools/wormhole-ovpnproxy/ovpn_shim/build/x64/vcpkg_installed'];
  f.step.excludedInputs = ['tools/wormhole-ovpnproxy/ovpn_shim/build'];
  const inputs = [
    'external/vcpkg/scripts/buildsystems/vcpkg.cmake',
    'external/vcpkg/ports/asio/portfile.cmake',
    'external/vcpkg/versions/baseline.json',
    'external/vcpkg/triplets/x64-mingw-static.cmake',
    'external/vcpkg/vcpkg.exe',
    'external/vcpkg/.vcpkg-root',
    'external/vcpkg/vcpkg-configuration.json',
    'tools/wormhole-ovpnproxy/ovpn_shim/build/x64/vcpkg_installed/include/asio.hpp',
    'tools/wormhole-ovpnproxy/ovpn_shim/build/x64/vcpkg_installed/lib/jsoncpp.a',
  ];
  for (const input of inputs) f.write(input);
  runCachedDevRuntimeBuild(f.options);
  runCachedDevRuntimeBuild(f.options);
  assert.equal(f.builds.length, 1);
  for (const input of inputs) {
    const before: number = f.builds.length;
    f.write(input, 'upgraded dependency at the same path');
    runCachedDevRuntimeBuild(f.options);
    assert.equal(f.builds.length, before + 1, input);
  }
  f.write('external/vcpkg/downloads/archive.zip');
  f.write('external/vcpkg/buildtrees/intermediate.obj');
  const before = f.builds.length;
  runCachedDevRuntimeBuild(f.options);
  assert.equal(f.builds.length, before);
  f.remove('tools/wormhole-ovpnproxy/ovpn_shim/build/x64/vcpkg_installed');
  runCachedDevRuntimeBuild(f.options);
  assert.equal(f.builds.length, before + 1);
});

test('the first successful dependency restore is cached while real source races remain invalid', (t) => {
  const f = fixture(t);
  f.step.generatedInputs = ['generated/dependencies'];
  const options = {
    ...f.options,
    execute(step: DevRuntimeBuildStep) {
      f.options.execute(step);
      f.write('generated/dependencies/lib.a', 'restored dependency');
    },
  };
  runCachedDevRuntimeBuild(options);
  runCachedDevRuntimeBuild(options);
  assert.equal(f.builds.length, 1);
  f.write('generated/dependencies/lib.a', 'updated dependency');
  runCachedDevRuntimeBuild(options);
  assert.equal(f.builds.length, 2);
  f.write('source/main.go', 'new source');
  runCachedDevRuntimeBuild({
    ...options,
    execute(step) {
      options.execute(step);
      f.write('source/main.go', 'source changed concurrently during restore');
      f.write('generated/dependencies/lib.a', 'new restore');
    },
  });
  runCachedDevRuntimeBuild(options);
  assert.equal(f.builds.length, 4);
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
  for (const flag of ['-pgo=auto', '-pgo=off', '--pgo=auto', '"-pgo=off"', "'-pgo=auto'"])
    assert.equal(devRuntimeCacheAllowed(JSON.stringify({ GOWORK: '', GOFLAGS: flag })), true);
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
    '-pkgdir=/external/packages',
    '--pkgdir=/external/packages',
    '"-pkgdir=/external/packages"',
    '-pkgdir /external/packages',
    '-pgo=/external/profile.pprof',
    '--pgo=/external/profile.pprof',
    '"-pgo=/external/profile.pprof"',
    "'-pgo=/external/profile.pprof'",
    '-pgo=auto.pprof',
    '-pgo=auto/profile.pprof',
    '-pgo=off/profile.pprof',
    '-pgo /external/profile.pprof',
    '-pgo=',
    '-pgo',
    '-pgo=off -pgo=/external/profile.pprof',
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

test('changed external PGO profiles and package directories cannot reuse stale builds', (t) => {
  for (const flag of ['-pgo=external/profile.pprof', '-pkgdir=external/packages']) {
    const f = fixture(t);
    const environment = JSON.stringify({ GOWORK: '', GOFLAGS: flag });
    const externalInput = flag.includes('pgo')
      ? 'external/profile.pprof'
      : 'external/packages/pkg.a';
    f.write(externalInput, 'original external input');
    const run = () =>
      runCachedDevRuntimeBuild({
        ...f.options,
        context: { go: environment },
        force: !devRuntimeCacheAllowed(environment),
      });
    run();
    f.write(externalInput, 'changed external input');
    run();
    assert.equal(f.builds.length, 2);
  }
});

test('automatic PGO reuses unchanged builds and tracks the main-package profile', (t) => {
  const f = fixture(t);
  const environment = JSON.stringify({ GOWORK: '', GOFLAGS: '-pgo=auto' });
  f.write('source/default.pgo', 'original profile');
  const run = () =>
    runCachedDevRuntimeBuild({
      ...f.options,
      context: { go: environment },
      force: !devRuntimeCacheAllowed(environment),
    });
  run();
  run();
  assert.equal(f.builds.length, 1);
  f.write('source/default.pgo', 'changed profile');
  run();
  assert.equal(f.builds.length, 2);
});

test('local Go replacements are reusable only within each consumer tracked inputs', (t) => {
  const f = fixture(t);
  const cwd = path.join(f.root, 'source');
  const module = (target: string, version?: string) =>
    JSON.stringify({
      Module: { Path: 'example.test/main' },
      Replace: [{ New: { Path: target, Version: version } }],
    });
  f.write('tools/internal/dep/main.go');
  f.step.inputs.push('tools/internal');
  assert.equal(
    devRuntimeReplacementsAllowed(f.root, cwd, module('../tools/internal/dep'), f.options.plan),
    true,
  );
  assert.equal(
    devRuntimeReplacementsAllowed(
      f.root,
      cwd,
      module('example.test/dep', 'v1.0.0'),
      f.options.plan,
    ),
    true,
  );
  f.write('external/dep/main.go');
  assert.equal(
    devRuntimeReplacementsAllowed(f.root, cwd, module('../external/dep'), f.options.plan),
    false,
  );
  assert.equal(
    devRuntimeReplacementsAllowed(
      f.root,
      cwd,
      module(path.join(f.root, 'external/dep')),
      f.options.plan,
    ),
    false,
  );
  const other = { ...f.step, inputs: ['external/dep'], outputs: ['dist/other'] };
  assert.equal(
    devRuntimeReplacementsAllowed(f.root, cwd, module('../external/dep'), [f.step, other]),
    false,
  );
  f.write('source/obj/dep/main.go');
  f.step.excludedInputs = ['source/obj'];
  assert.equal(
    devRuntimeReplacementsAllowed(f.root, cwd, module('obj/dep'), f.options.plan),
    false,
  );
  f.write('source/node_modules/dep/main.go');
  assert.equal(
    devRuntimeReplacementsAllowed(f.root, cwd, module('node_modules/dep'), f.options.plan),
    false,
  );
  f.write('source-other/dep/main.go');
  assert.equal(
    devRuntimeReplacementsAllowed(f.root, cwd, module('../source-other/dep'), f.options.plan),
    false,
  );
  assert.equal(
    devRuntimeReplacementsAllowed(f.root, cwd, module('../missing'), f.options.plan),
    false,
  );
  assert.equal(devRuntimeReplacementsAllowed(f.root, cwd, module('.'), []), false);
  for (const malformed of [
    '',
    '{}',
    'null',
    '{broken',
    '{"Module":{"Path":"x"},"Replace":42}',
    '{"Module":{"Path":"x"},"Replace":[{}]}',
  ])
    assert.equal(devRuntimeReplacementsAllowed(f.root, cwd, malformed, f.options.plan), false);
  assert.equal(
    devRuntimeReplacementsAllowed(f.root, cwd, '{"Module":{"Path":"x"}}', f.options.plan),
    true,
  );
  assert.equal(
    devRuntimeReplacementsAllowed(
      f.root,
      cwd,
      '{"Module":{"Path":"x"},"Replace":null}',
      f.options.plan,
    ),
    true,
  );
});

test('external replacements force rebuilding after edits; tracked replacements invalidate normally', (t) => {
  const f = fixture(t);
  const cwd = path.join(f.root, 'source');
  f.write('external/dep/main.go');
  const module = JSON.stringify({
    Module: { Path: 'main' },
    Replace: [{ New: { Path: '../external/dep' } }],
  });
  const run = () =>
    runCachedDevRuntimeBuild({
      ...f.options,
      context: { module },
      force: !devRuntimeReplacementsAllowed(f.root, cwd, module, f.options.plan),
    });
  run();
  f.write('external/dep/main.go', 'edited external replacement');
  run();
  assert.equal(f.builds.length, 2);
  f.step.inputs.push('external/dep');
  run();
  run();
  assert.equal(f.builds.length, 3);
  f.write('external/dep/main.go', 'edited tracked replacement');
  run();
  assert.equal(f.builds.length, 4);
});

test('selected compiler identities detect same-path upgrades and preserve PATH search order', (t) => {
  const f = fixture(t);
  f.write('first/clang', 'compiler one');
  f.write('second/clang', 'compiler two');
  chmodSync(path.join(f.root, 'first/clang'), 0o755);
  chmodSync(path.join(f.root, 'second/clang'), 0o755);
  const identity = () =>
    devRuntimeCompilerIdentity('clang', f.root, { PATH: 'missing:first:second' }, 'darwin');
  assert.equal(identity()?.executable, path.join(f.root, 'first/clang'));
  const run = () => runCachedDevRuntimeBuild({ ...f.options, context: identity() });
  run();
  run();
  assert.equal(f.builds.length, 1);
  f.write('first/clang', 'upgraded compiler at same path');
  run();
  assert.equal(f.builds.length, 2);
  f.write('compiler with spaces', 'custom compiler');
  chmodSync(path.join(f.root, 'compiler with spaces'), 0o755);
  assert.ok(
    devRuntimeCompilerIdentity(
      `"${path.join(f.root, 'compiler with spaces')}"`,
      f.root,
      {},
      'darwin',
    ),
  );
  for (const unsupported of [
    '',
    'ccache clang',
    'clang -arch arm64',
    '"unterminated',
    'unavailable',
  ])
    assert.equal(devRuntimeCompilerIdentity(unsupported, f.root, {}), null);
  f.write('windows/gcc.exe', 'Windows compiler');
  assert.ok(devRuntimeCompilerIdentity('gcc', f.root, { Path: 'missing;windows' }, 'win32'));
  assert.equal(devRuntimeCompilerIdentity('first', f.root, { PATH: '.' }, 'darwin'), null);
});

test(
  'OpenVPN context probes the compiler selected after PATH filtering without building',
  { skip: process.platform !== 'win32' },
  (t) => {
    const f = fixture(t);
    f.write('overlay/msys-2.0.dll');
    f.write('overlay/gcc.cmd', '@echo ignored compiler\r\n');
    f.write('selected/gcc.cmd', '@echo selected compiler\r\n');
    f.write('selected/g++.cmd', '@echo selected C++ compiler\r\n');
    f.write('vcpkg/scripts/buildsystems/vcpkg.cmake');
    const probe = () => {
      const result = spawnSync(
        'powershell.exe',
        [
          '-NoProfile',
          '-ExecutionPolicy',
          'Bypass',
          '-File',
          path.resolve('scripts/Fetch-OvpnProxy.ps1'),
          '-Arch',
          'x64',
          '-PrintBuildContext',
        ],
        {
          encoding: 'utf8',
          windowsHide: true,
          env: {
            ...process.env,
            VCPKG_ROOT: path.join(f.root, 'vcpkg'),
            PATH: [
              path.join(f.root, 'overlay'),
              path.join(f.root, 'selected'),
              process.env.PATH,
            ].join(';'),
          },
        },
      );
      assert.equal(result.status, 0, result.stderr);
      return JSON.parse(result.stdout);
    };
    const original = probe();
    assert.equal(original.Cacheable, true);
    assert.equal(original.Tools[0].Path, path.join(f.root, 'selected/gcc.cmd'));
    f.write('selected/gcc.cmd', '@echo selected compiler upgraded\r\n');
    assert.notEqual(probe().Tools[0].Sha256, original.Tools[0].Sha256);
    f.remove('vcpkg/scripts/buildsystems/vcpkg.cmake');
    assert.equal(probe().Cacheable, false);
    f.remove('vcpkg');
    assert.equal(probe().Cacheable, false);
  },
);

test(
  'OpenVPN compiler migrations reset CMake with the complete toolchain arguments',
  { skip: process.platform !== 'win32' },
  (t) => {
    const f = fixture(t);
    const cc = path.join(f.root, 'gcc.exe');
    const cxx = path.join(f.root, 'g++.exe');
    const probe = () => {
      const result = spawnSync(
        'powershell.exe',
        [
          '-NoProfile',
          '-ExecutionPolicy',
          'Bypass',
          '-Command',
          '. $env:WORMHOLE_TEST_SCRIPT -PrintBuildContext | Out-Null; $actual = Get-OvpnCmakeCompilerArguments $env:WORMHOLE_TEST_CACHE $env:WORMHOLE_TEST_CC $env:WORMHOLE_TEST_CXX; ConvertTo-Json -InputObject @($actual) -Compress',
        ],
        {
          encoding: 'utf8',
          windowsHide: true,
          env: {
            ...process.env,
            WORMHOLE_TEST_SCRIPT: path.resolve('scripts/Fetch-OvpnProxy.ps1'),
            WORMHOLE_TEST_CACHE: path.join(f.root, 'CMakeCache.txt'),
            WORMHOLE_TEST_CC: cc,
            WORMHOLE_TEST_CXX: cxx,
          },
        },
      );
      assert.equal(result.status, 0, result.stderr);
      return JSON.parse(result.stdout);
    };
    const selected = [`-DCMAKE_C_COMPILER=${cc}`, `-DCMAKE_CXX_COMPILER=${cxx}`];
    f.write('CMakeFiles/compiler-check.txt');
    f.write('vcpkg_installed/include/asio.hpp');
    f.write('libovpn_shim.a');
    assert.deepEqual(probe(), selected);
    f.write(
      'CMakeCache.txt',
      `CMAKE_C_COMPILER:FILEPATH=${cc.toUpperCase()}\nCMAKE_CXX_COMPILER:STRING=${cxx}\n`,
    );
    assert.deepEqual(probe(), selected);
    assert.ok(existsSync(path.join(f.root, 'CMakeFiles/compiler-check.txt')));
    for (const kind of ['FILEPATH', 'STRING', 'UNINITIALIZED']) {
      f.write('CMakeCache.txt', `CMAKE_CXX_COMPILER:${kind}=${path.join(f.root, 'old-g++.exe')}\n`);
      f.write('CMakeFiles/compiler-check.txt');
      assert.deepEqual(probe(), selected);
      assert.equal(existsSync(path.join(f.root, 'CMakeCache.txt')), false);
      assert.equal(existsSync(path.join(f.root, 'CMakeFiles')), false);
      assert.ok(existsSync(path.join(f.root, 'vcpkg_installed/include/asio.hpp')));
      assert.ok(existsSync(path.join(f.root, 'libovpn_shim.a')));
    }
  },
);

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
  const context = (temporary: string, flags = '-O2 -g') => ({
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
