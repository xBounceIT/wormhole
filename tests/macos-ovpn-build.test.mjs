import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import vm from 'node:vm';
import test from 'node:test';
import { parse } from 'yaml';
import { buildMacOvpnProxy } from '../scripts/build-macos-ovpnproxy.mjs';

test('relative vcpkg roots are resolved before CMake changes its search base', (t) => {
  const f = fixture(t);
  const root = path.join(f.root, 'vcpkg');
  f.args.environment.VCPKG_ROOT = path.relative(process.cwd(), root);
  buildMacOvpnProxy(f.args);
  const configure = f.calls.find((call) => call.command === 'cmake');
  assert.ok(
    configure.args.includes(
      `-DCMAKE_TOOLCHAIN_FILE=${path.join(root, 'scripts/buildsystems/vcpkg.cmake')}`,
    ),
  );
  assert.equal(configure.config.env.VCPKG_ROOT, root);
});

test('real Git patch application preserves a pre-existing patch and restores build-only changes', (t) => {
  const f = fixture(t, {
    override(cmd, args, config) {
      if (cmd === 'git')
        return spawnSync(cmd, args, { ...config, stdio: 'pipe', windowsHide: true });
      if (cmd === 'cmake') {
        assert.equal(readFileSync(header, 'utf8'), 'patched for build\n');
      }
    },
  });
  const source = path.join(f.root, 'tools/wormhole-ovpnproxy');
  const upstream = path.join(source, 'third_party/openvpn3');
  const header = path.join(upstream, 'client/ovpncli.hpp');
  writeFileSync(header, 'original\n');
  const patch = (before, after) =>
    `diff --git a/client/ovpncli.hpp b/client/ovpncli.hpp\n--- a/client/ovpncli.hpp\n+++ b/client/ovpncli.hpp\n@@ -1 +1 @@\n-${before}\n+${after}\n`;
  writeFileSync(path.join(source, 'patches/001.patch'), patch('original', 'developer patch'));
  writeFileSync(
    path.join(source, 'patches/002.patch'),
    patch('developer patch', 'patched for build'),
  );
  const git = (args) => {
    const result = spawnSync('git', ['-C', upstream, ...args], {
      encoding: 'utf8',
      windowsHide: true,
    });
    assert.equal(result.status, 0, result.stderr);
  };
  git(['init', '--quiet']);
  git(['config', 'core.autocrlf', 'false']);
  git(['apply', path.join(source, 'patches/001.patch')]);
  buildMacOvpnProxy(f.args);
  assert.equal(readFileSync(header, 'utf8'), 'developer patch\n');
});

test('partial submodule checkout initializes the missing mbedTLS framework', (t) => {
  const f = fixture(t);
  rmSync(
    path.join(f.root, 'tools/wormhole-ovpnproxy/third_party/mbedtls/framework/CMakeLists.txt'),
  );
  buildMacOvpnProxy(f.args);
  assert.ok(f.calls.some((call) => call.command === 'git' && call.args.includes('submodule')));
});

test('a failed build releases the lock and allows a retry in the same checkout', (t) => {
  let fail = true;
  const f = fixture(t, { override: (cmd) => cmd === 'cmake' && fail && { status: 2 } });
  assert.throws(() => buildMacOvpnProxy(f.args), /cmake failed/);
  fail = false;
  assert.equal(buildMacOvpnProxy(f.args), f.output);
});

test('overlapping builds cannot reverse patches or remove another build output', (t) => {
  let attempted = false;
  const f = fixture(t, {
    override(cmd) {
      if (cmd === 'cmake' && !attempted) {
        attempted = true;
        f.write('dist-electron/wormhole-ovpnproxy', 'owned by active build');
        assert.throws(() => buildMacOvpnProxy(f.args), /OpenVPN build.*lock/i);
        assert.equal(readFileSync(f.output, 'utf8'), 'owned by active build');
        rmSync(f.output);
      }
    },
  });
  buildMacOvpnProxy(f.args);
  assert.equal(attempted, true);
  buildMacOvpnProxy(f.args); // Normal completion releases the lock.
});

test('failed final rename leaves no temporary binary eligible for packaging', (t) => {
  let temporary;
  const f = fixture(t, {
    override(cmd, args) {
      if (cmd === 'go') temporary = args[args.indexOf('-o') + 1];
      if (cmd.endsWith('.building')) mkdirSync(f.output); // Force rename to fail after verification.
    },
  });
  assert.throws(() => buildMacOvpnProxy(f.args));
  assert.ok(!temporary.startsWith(path.join(f.root, 'dist-electron')));
  assert.equal(existsSync(temporary), false);
  rmSync(f.output, { recursive: true });
  assert.equal(existsSync(path.join(f.root, 'obj/macos-ovpn-build.lock')), false);
});

function fixture(t, options = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole mac ovpn '));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const write = (name, contents = 'fixture') => {
    const target = path.join(root, name);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, contents);
  };
  const source = 'tools/wormhole-ovpnproxy';
  const output = path.join(root, 'dist-electron/wormhole-ovpnproxy');
  write('vcpkg/scripts/buildsystems/vcpkg.cmake');
  const headers = () => {
    write(`${source}/third_party/openvpn3/client/ovpncli.hpp`);
    write(`${source}/third_party/mbedtls/include/mbedtls/ssl.h`);
    write(`${source}/third_party/mbedtls/framework/CMakeLists.txt`);
  };
  if (!options.missingHeaders) headers();
  write(`${source}/patches/001.patch`);
  write(`${source}/patches/002.patch`);
  write('dist-electron/wormhole-ovpnproxy', 'stale stub');
  const calls = [];
  const args = {
    repoRoot: root,
    architecture: 'arm64',
    platform: 'darwin',
    hostArchitecture: 'arm64',
    environment: {
      VCPKG_ROOT: path.join(root, 'vcpkg'),
      CGO_ENABLED: '0',
      GOOS: 'windows',
      GOARCH: 'amd64',
    },
  };
  args.spawn = (command, commandArgs, config) => {
    calls.push({ command, args: commandArgs, config: { ...config, env: { ...config.env } } });
    const override = options.override?.(command, commandArgs, config);
    if (override) return override;
    if (command === 'git' && commandArgs.includes('submodule')) {
      if (!options.bootstrapMissing) headers();
    }
    if (command === 'git' && commandArgs.includes('--reverse') && commandArgs.includes('--check')) {
      return { status: options.prepatched ? 0 : 1 };
    }
    if (command === 'xcrun') return { status: 0, stdout: '/SDK with spaces' };
    if (command === 'cmake' && commandArgs.includes('--build')) {
      const build = `${source}/ovpn_shim/build/darwin-${args.architecture}`;
      for (const file of [
        'libovpn_shim.a',
        ...['mbedtls', 'mbedx509', 'mbedcrypto'].map(
          (name) => `third_party_mbedtls/library/lib${name}.a`,
        ),
        ...['lz4', 'jsoncpp'].map(
          (name) => `vcpkg_installed/${args.architecture}-osx/lib/lib${name}.a`,
        ),
      ]) {
        write(`${build}/${file}`, options.archiveContent ?? file);
      }
    }
    if (command === 'go')
      writeFileSync(
        commandArgs[commandArgs.indexOf('-o') + 1],
        options.stub ? 'binding not linked' : 'native engine',
      );
    if (command === 'otool')
      return {
        status: 0,
        stdout: `${output}:\n\t/usr/lib/libc++.1.dylib (compatibility version 1.0.0)\n\t/System/Library/Frameworks/IOKit.framework/IOKit (compatibility version 1.0.0)\n`,
      };
    if (command.endsWith('.building'))
      return { status: 1, stderr: 'fatal: openvpn start: ovpn_load_profile failed (code 1)' };
    return { status: 0, stdout: '' };
  };
  return { root, output, args, calls, write };
}

for (const architecture of ['x64', 'arm64']) {
  test(`builds and verifies real macOS OpenVPN for ${architecture}`, (t) => {
    const f = fixture(t);
    f.args.architecture = architecture;
    assert.equal(buildMacOvpnProxy(f.args), f.output);
    assert.equal(readFileSync(f.output, 'utf8'), 'native engine');
    const cmake = f.calls.find((call) => call.command === 'cmake');
    assert.ok(cmake.args.includes('-DWORMHOLE_REQUIRE_OPENVPN3=ON'));
    assert.ok(
      cmake.args.includes(
        `-DCMAKE_OSX_ARCHITECTURES=${architecture === 'x64' ? 'x86_64' : 'arm64'}`,
      ),
    );
    assert.ok(cmake.args.includes(`-DVCPKG_TARGET_TRIPLET=${architecture}-osx`));
    const go = f.calls.find((call) => call.command === 'go');
    assert.deepEqual(go.args.slice(0, 4), ['build', '-trimpath', '-tags', 'ovpn3']);
    assert.equal(go.config.env.CGO_ENABLED, '1');
    assert.equal(go.config.env.GOOS, 'darwin');
    assert.equal(go.config.env.GOARCH, architecture === 'x64' ? 'amd64' : 'arm64');
    assert.equal(go.config.env.CC, 'clang');
    assert.equal(go.config.env.SDKROOT, '/SDK with spaces');
    assert.equal(f.args.environment.CGO_ENABLED, '0');
    const restore = f.calls.filter(
      (call) => call.args.includes('--reverse') && !call.args.includes('--check'),
    );
    assert.deepEqual(
      restore.map((call) => path.basename(call.args.at(-1))),
      ['002.patch', '001.patch'],
    );
    assert.equal(
      f.calls.some((call) => call.command.endsWith('.building')),
      architecture === 'arm64',
    );
    const stamp = readFileSync(
      path.join(f.root, 'tools/wormhole-ovpnproxy/shim_buildinfo.go'),
      'utf8',
    );
    assert.match(stamp, /const shimArchiveHash = "[a-f0-9]{64}"/);
  });
}

test('bootstraps missing sources and preserves pre-existing patches', (t) => {
  const f = fixture(t, { missingHeaders: true, prepatched: true });
  f.args.environment.VCPKG_INSTALLATION_ROOT = f.args.environment.VCPKG_ROOT;
  delete f.args.environment.VCPKG_ROOT;
  buildMacOvpnProxy(f.args);
  assert.ok(
    f.calls.some((call) => call.args.includes('submodule') && call.args.includes('--recursive')),
  );
  assert.equal(
    f.calls.filter((call) => call.args.includes('apply') && !call.args.includes('--check')).length,
    0,
  );
});

test('changing native archives invalidates the Go link cache stamp', (t) => {
  const first = fixture(t, { archiveContent: 'first library' });
  const second = fixture(t, { archiveContent: 'updated library' });
  buildMacOvpnProxy(first.args);
  buildMacOvpnProxy(second.args);
  const stamp = (f) =>
    readFileSync(path.join(f.root, 'tools/wormhole-ovpnproxy/shim_buildinfo.go'), 'utf8');
  assert.notEqual(stamp(first), stamp(second));
});

const failures = [
  [
    'missing toolchain',
    {},
    (f) => {
      delete f.args.environment.VCPKG_ROOT;
    },
    /VCPKG_ROOT/,
  ],
  [
    'invalid toolchain',
    {},
    (f) => {
      f.args.environment.VCPKG_ROOT = path.join(f.root, 'absent');
    },
    /VCPKG_ROOT/,
  ],
  [
    'missing sources after bootstrap',
    { missingHeaders: true, bootstrapMissing: true },
    null,
    /sources are missing/,
  ],
  [
    'missing patch set',
    {},
    (f) => {
      rmSync(path.join(f.root, 'tools/wormhole-ovpnproxy/patches/001.patch'));
      rmSync(path.join(f.root, 'tools/wormhole-ovpnproxy/patches/002.patch'));
    },
    /patches are missing/,
  ],
  ['Go-only stub', { stub: true }, null, /mock-only/],
  [
    'empty SDK',
    { override: (cmd) => cmd === 'xcrun' && { status: 0, stdout: '\n' } },
    null,
    /macOS SDK/,
  ],
  [
    'missing compiler process',
    { override: (cmd) => cmd === 'cmake' && { error: new Error('ENOENT') } },
    null,
    /Could not start cmake/,
  ],
  [
    'failed native build',
    { override: (cmd, args) => cmd === 'cmake' && args.includes('--build') && { status: 2 } },
    null,
    /cmake failed/,
  ],
  [
    'killed Go build',
    { override: (cmd) => cmd === 'go' && { status: null } },
    null,
    /exit unknown/,
  ],
  [
    'wrong architecture',
    { override: (cmd) => cmd === 'lipo' && { status: 1 } },
    null,
    /lipo failed/,
  ],
  [
    'Homebrew dependency',
    {
      override: (cmd) =>
        cmd === 'otool' && {
          status: 0,
          stdout: 'binary:\n\t/opt/homebrew/lib/liblz4.dylib (version 1)\n',
        },
    },
    null,
    /system libraries/,
  ],
  [
    'empty library list',
    { override: (cmd) => cmd === 'otool' && { status: 0, stdout: 'binary:\n' } },
    null,
    /system libraries/,
  ],
  [
    'C++ stub',
    {
      override: (cmd) =>
        cmd.endsWith('.building') && { status: 1, stderr: 'ovpn_new returned null' },
    },
    null,
    /smoke test/,
  ],
  [
    'probe timeout',
    { override: (cmd) => cmd.endsWith('.building') && { error: new Error('ETIMEDOUT') } },
    null,
    /smoke test/,
  ],
  [
    'probe unexpectedly succeeds',
    { override: (cmd) => cmd.endsWith('.building') && { status: 0, stderr: '' } },
    null,
    /smoke test/,
  ],
  [
    'patch conflict',
    {
      override: (cmd, args) =>
        cmd === 'git' &&
        args.includes('--check') &&
        !args.includes('--reverse') &&
        args.at(-1).endsWith('002.patch') && { status: 1 },
    },
    null,
    /git failed/,
  ],
  [
    'patch restore fails',
    {
      override: (cmd, args) =>
        cmd === 'git' && args.includes('--reverse') && !args.includes('--check') && { status: 1 },
    },
    null,
    /Could not restore/,
  ],
];
for (const [name, options, mutate, expected] of failures) {
  test(`${name} fails closed without leaving a packageable sidecar`, (t) => {
    const f = fixture(t, options);
    mutate?.(f);
    assert.throws(() => buildMacOvpnProxy(f.args), expected);
    assert.equal(existsSync(f.output), false);
    assert.equal(existsSync(path.join(f.root, 'obj/macos-ovpn-build.lock')), false);
    const applied = f.calls.filter(
      (call) =>
        call.command === 'git' &&
        call.args.includes('apply') &&
        !call.args.includes('--reverse') &&
        !call.args.includes('--check'),
    );
    const restored = f.calls.filter(
      (call) =>
        call.command === 'git' && call.args.includes('--reverse') && !call.args.includes('--check'),
    );
    assert.equal(restored.length, applied.length);
  });
}

test('rejects unsupported hosts and architectures before deleting build outputs', (t) => {
  const f = fixture(t);
  for (const override of [{ platform: 'win32' }, { architecture: 'ia32' }]) {
    assert.throws(() => buildMacOvpnProxy({ ...f.args, ...override }), /require macOS/);
    assert.equal(readFileSync(f.output, 'utf8'), 'stale stub');
  }
});

test('macOS backend delegates OpenVPN to the native builder and never runs its portable build', () => {
  const source = readFileSync(
    new URL('../scripts/Build-ElectronBackend.mjs', import.meta.url),
    'utf8',
  )
    .replace(/^import .*;\r?\n/gm, '')
    .replaceAll(
      'import.meta.url',
      JSON.stringify(pathToFileURL(path.resolve('scripts/Build-ElectronBackend.mjs')).href),
    );
  const calls = [];
  const native = [];
  vm.runInNewContext(source, {
    path,
    fileURLToPath: (url) => new URL(url).pathname,
    mkdirSync() {},
    rmSync() {},
    process: {
      argv: ['node', 'script', '--arch', 'arm64'],
      platform: 'darwin',
      arch: 'arm64',
      env: {},
    },
    console: { log() {} },
    spawnSync(command, args, options) {
      calls.push({ command, args, options });
      return { status: 0 };
    },
    buildMacOvpnProxy(options) {
      native.push(options);
    },
  });
  assert.equal(native.length, 1);
  assert.equal(native[0].architecture, 'arm64');
  assert.equal(calls.length, 5);
  assert.ok(calls.every((call) => !call.options.cwd.endsWith('wormhole-ovpnproxy')));
});

test('release and CI provision native dependencies before building universal macOS binaries', () => {
  const jobs = (file) =>
    parse(readFileSync(new URL(`../.github/workflows/${file}`, import.meta.url), 'utf8')).jobs;
  for (const steps of [jobs('release.yml').packages.steps, jobs('ci.yml')['macos-openvpn'].steps]) {
    const setup = steps.findIndex((step) => step.uses === './.github/actions/setup-macos-ovpn');
    const build = steps.findIndex((step) =>
      /build:backend:universal|Build-ElectronUniversalBackend/.test(step.run),
    );
    assert.ok(setup >= 0 && build > setup);
  }
  const manifest = JSON.parse(
    readFileSync(new URL('../tools/wormhole-ovpnproxy/ovpn_shim/vcpkg.json', import.meta.url)),
  );
  assert.deepEqual(
    manifest.dependencies.find((dep) => dep.name === 'tap-windows6'),
    { name: 'tap-windows6', platform: 'windows' },
  );
  const cmake = readFileSync(
    new URL('../tools/wormhole-ovpnproxy/ovpn_shim/CMakeLists.txt', import.meta.url),
    'utf8',
  );
  assert.match(cmake, /if\(WORMHOLE_REQUIRE_OPENVPN3\)\s+message\(FATAL_ERROR/);
  const binding = readFileSync(
    new URL('../tools/wormhole-ovpnproxy/ovpn_cgo.go', import.meta.url),
    'utf8',
  );
  for (const [goarch, arch] of [
    ['amd64', 'x64'],
    ['arm64', 'arm64'],
  ]) {
    const flags = binding
      .split('\n')
      .find((line) => line.startsWith(`#cgo darwin,${goarch} LDFLAGS:`));
    assert.ok(flags.includes(`build/darwin-${arch}`));
    assert.ok(flags.includes(`vcpkg_installed/${arch}-osx/lib`));
  }
  const flags = binding.split('\n').find((line) => line.startsWith('#cgo darwin LDFLAGS:'));
  assert.ok(flags.includes('-lc++'));
  assert.ok(!flags.includes('-lstdc++'));
});
