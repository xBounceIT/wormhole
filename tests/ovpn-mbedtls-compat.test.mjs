import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { createDevRuntimeBuildPlan } from '../scripts/dev-runtime-plan.ts';

// Unmodified header from OpenVPN3 3.11.8, commit 4f3bdef73245d4ee9e8216c5d65baccc9568f6ef.
const original = readFileSync(
  new URL('fixtures/openvpn3-mbedtls-compat.hpp', import.meta.url),
  'utf8',
).replace(/\r\n/g, '\n');
const compiler = process.env.CXX || (process.platform === 'win32' ? 'g++' : 'c++');
const compilerProbe = spawnSync(compiler, ['--version'], { windowsHide: true });

function temporaryDirectory(t, parent = tmpdir()) {
  const root = mkdtempSync(join(parent, 'wormhole-mbedtls-'));
  assert.equal(dirname(root), resolve(parent));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

// Run the production bootstrap with real local Git repositories. V8 coverage cannot
// instrument PowerShell; these integration cases cover its changed RequireReal guard.
function submoduleFixture(t) {
  const root = temporaryDirectory(t);
  const upstream = join(root, 'upstream');
  const repo = join(root, 'checkout');
  const relativeSource = 'tools/wormhole-ovpnproxy/third_party';
  const openvpn = join(repo, relativeSource, 'openvpn3');
  const mbedtls = join(repo, relativeSource, 'mbedtls');
  const git = (cwd, ...args) =>
    execFileSync('git', ['-c', 'protocol.file.allow=always', '-C', cwd, ...args], {
      encoding: 'utf8',
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
  const commit = (cwd, message) => {
    git(cwd, 'add', '.');
    git(
      cwd,
      '-c',
      'user.name=Test',
      '-c',
      'user.email=test@example.com',
      'commit',
      '--no-gpg-sign',
      '-qm',
      message,
    );
    return git(cwd, 'rev-parse', 'HEAD');
  };
  mkdirSync(upstream);
  mkdirSync(repo);
  git(upstream, 'init', '--quiet');
  git(upstream, 'config', 'core.autocrlf', 'false');
  // Exercise signing-enabled user setups without invoking a personal key or agent.
  git(upstream, 'config', 'commit.gpgsign', 'true');
  git(upstream, 'config', 'gpg.program', 'wormhole-test-missing-gpg');
  for (const file of ['client/ovpncli.hpp', 'include/mbedtls/ssl.h']) {
    mkdirSync(dirname(join(upstream, file)), { recursive: true });
    writeFileSync(join(upstream, file), 'old headers\n');
  }
  const old = commit(upstream, 'old native sources');
  for (const file of ['client/ovpncli.hpp', 'include/mbedtls/ssl.h']) {
    writeFileSync(join(upstream, file), 'pinned headers\n');
  }
  const pinned = commit(upstream, 'pinned native sources');
  git(repo, 'init', '--quiet');
  for (const name of ['openvpn3', 'mbedtls']) {
    git(repo, 'submodule', 'add', '--quiet', upstream, `${relativeSource}/${name}`);
  }
  commit(repo, 'pin both native submodules');

  const source = readFileSync(
    new URL('../scripts/Fetch-OvpnProxy.ps1', import.meta.url),
    'utf8',
  ).replaceAll('\r\n', '\n');
  const bootstrap = source.match(
    /(\$haveOvpn3Src = \(Test-Path \$openvpn3\)[\s\S]+?)^\$compilerPair = Get-OvpnCompilerPair/m,
  )?.[1];
  assert.ok(bootstrap, 'production native source bootstrap must be exercised');
  const script = join(root, 'bootstrap.ps1');
  writeFileSync(
    script,
    `param([string]$repoRoot, [switch]$RequireReal)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sourceDir = Join-Path $repoRoot 'tools/wormhole-ovpnproxy'
$openvpn3 = Join-Path $sourceDir 'third_party/openvpn3/client/ovpncli.hpp'
$mbedtls = Join-Path $sourceDir 'third_party/mbedtls/include/mbedtls/ssl.h'
function Write-Info($message) { Write-Host $message }
function Remove-StagedBinary { [IO.File]::Delete((Join-Path $repoRoot 'staged.exe')) }
${bootstrap}
if (-not $haveOvpn3Src) { throw 'Native headers are missing.' }
if ($ErrorActionPreference -ne 'Stop') { throw 'Error preference was not restored.' }
Write-Host 'BOOTSTRAP_READY'
`,
  );
  return {
    repo,
    openvpn,
    mbedtls,
    old,
    pinned,
    git,
    run(requireReal = true, environment = {}) {
      return spawnSync(
        join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe'),
        [
          '-NoProfile',
          '-ExecutionPolicy',
          'Bypass',
          '-File',
          script,
          repo,
          ...(requireReal ? ['-RequireReal'] : []),
        ],
        { encoding: 'utf8', windowsHide: true, env: { ...process.env, ...environment } },
      );
    },
  };
}

test(
  'real Windows OpenVPN builds update populated stale submodules to the gitlinks',
  { skip: process.platform !== 'win32' },
  (t) => {
    const f = submoduleFixture(t);
    for (const directory of [f.openvpn, f.mbedtls]) f.git(directory, 'checkout', '--quiet', f.old);
    const result = f.run();
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /BOOTSTRAP_READY/);
    for (const directory of [f.openvpn, f.mbedtls]) {
      assert.equal(f.git(directory, 'rev-parse', 'HEAD'), f.pinned);
    }
  },
);

test(
  'real OpenVPN bootstrap overrides submodule update policies that skip the pinned revision',
  { skip: process.platform !== 'win32' },
  (t) => {
    const f = submoduleFixture(t);
    for (const name of ['openvpn3', 'mbedtls']) {
      const directory = join(f.repo, 'tools/wormhole-ovpnproxy/third_party', name);
      f.git(directory, 'checkout', '--quiet', f.old);
      f.git(
        f.repo,
        'config',
        `submodule.tools/wormhole-ovpnproxy/third_party/${name}.update`,
        'none',
      );
    }
    const result = f.run();
    assert.equal(result.status, 0, result.stderr);
    for (const directory of [f.openvpn, f.mbedtls]) {
      assert.equal(f.git(directory, 'rev-parse', 'HEAD'), f.pinned);
    }
  },
);

test(
  'Windows development pre-bootstrap initializes skipped submodules before the real builder',
  { skip: process.platform !== 'win32' },
  (t) => {
    const f = submoduleFixture(t);
    const paths = ['openvpn3', 'mbedtls'].map(
      (name) => `tools/wormhole-ovpnproxy/third_party/${name}`,
    );
    for (const architecture of ['x64', 'arm64']) {
      f.git(f.repo, 'submodule', 'deinit', '--', ...paths);
      for (const submodule of paths)
        f.git(f.repo, 'config', `submodule.${submodule}.update`, 'none');
      const bootstrap = createDevRuntimeBuildPlan({
        platform: 'win32',
        architecture,
        scriptDirectory: join(f.repo, 'scripts'),
        nodeExecutable: process.execPath,
      })[0].bootstrap;
      const result = spawnSync(bootstrap.command, bootstrap.args, {
        encoding: 'utf8',
        windowsHide: true,
      });
      assert.equal(result.status, 0, result.stderr);
      for (const output of bootstrap.outputs) {
        assert.equal(
          readFileSync(join(f.repo, output), 'utf8').replaceAll('\r\n', '\n'),
          'pinned headers\n',
        );
      }
    }
  },
);

test(
  'required OpenVPN bootstrap fails closed when Git is unavailable despite populated sources',
  { skip: process.platform !== 'win32' },
  (t) => {
    const f = submoduleFixture(t);
    const staged = join(f.repo, 'staged.exe');
    writeFileSync(staged, 'stale binary');
    const result = f.run(true, { PATH: '' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /git.*not on PATH/i);
    assert.doesNotMatch(result.stdout, /BOOTSTRAP_READY/);
    assert.throws(() => readFileSync(staged), { code: 'ENOENT' });
  },
);

test(
  'real Windows OpenVPN builds initialize empty submodules',
  { skip: process.platform !== 'win32' },
  (t) => {
    const f = submoduleFixture(t);
    f.git(
      f.repo,
      'submodule',
      'deinit',
      '--',
      'tools/wormhole-ovpnproxy/third_party/openvpn3',
      'tools/wormhole-ovpnproxy/third_party/mbedtls',
    );
    const result = f.run();
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /BOOTSTRAP_READY/);
    for (const directory of [f.openvpn, f.mbedtls]) {
      assert.equal(f.git(directory, 'rev-parse', 'HEAD'), f.pinned);
    }
  },
);

test(
  'repeated real OpenVPN bootstraps preserve edits to pinned sources',
  { skip: process.platform !== 'win32' },
  (t) => {
    const f = submoduleFixture(t);
    const header = join(f.openvpn, 'client/ovpncli.hpp');
    writeFileSync(header, 'developer edit\n');
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = f.run();
      assert.equal(result.status, 0, result.stderr);
      assert.equal(readFileSync(header, 'utf8'), 'developer edit\n');
    }
  },
);

test(
  'conflicting submodule edits fail closed and remove a stale staged sidecar',
  { skip: process.platform !== 'win32' },
  (t) => {
    const f = submoduleFixture(t);
    f.git(f.openvpn, 'checkout', '--quiet', f.old);
    const header = join(f.openvpn, 'client/ovpncli.hpp');
    const staged = join(f.repo, 'staged.exe');
    writeFileSync(header, 'developer edit\n');
    writeFileSync(staged, 'stale binary');
    const result = f.run();
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Could not initialize the pinned OpenVPN3\/mbedTLS submodules/);
    assert.doesNotMatch(result.stdout, /BOOTSTRAP_READY/);
    assert.equal(readFileSync(header, 'utf8'), 'developer edit\n');
    assert.equal(f.git(f.openvpn, 'rev-parse', 'HEAD'), f.old);
    assert.throws(() => readFileSync(staged), { code: 'ENOENT' });
  },
);

test(
  'optional OpenVPN builds skip synchronization even when Git is unavailable',
  { skip: process.platform !== 'win32' },
  (t) => {
    const f = submoduleFixture(t);
    for (const directory of [f.openvpn, f.mbedtls]) f.git(directory, 'checkout', '--quiet', f.old);
    const result = f.run(false, { PATH: '' });
    assert.equal(result.status, 0, result.stderr);
    assert.doesNotMatch(result.stdout, /INIT/);
    for (const directory of [f.openvpn, f.mbedtls]) {
      assert.equal(f.git(directory, 'rev-parse', 'HEAD'), f.old);
    }
  },
);

test('OpenVPN3 factory preserves DATA_V2 through its new virtual capability contract', (t) => {
  if (compilerProbe.error?.code === 'ENOENT') {
    t.skip('A C++ compiler is required for the native factory contract.');
    return;
  }
  const source = readFileSync(
    new URL('../tools/wormhole-ovpnproxy/ovpn_shim/shim.cc', import.meta.url),
    'utf8',
  );
  const method = source.match(/bool supports_epoch_data\(\) override \{[^}]+\}/)?.[0];
  assert.ok(method);
  const root = temporaryDirectory(t);
  writeFileSync(
    join(root, 'capability.hpp'),
    `
    struct TunClientFactory { virtual ~TunClientFactory() = default; virtual bool supports_epoch_data() = 0; };
    struct Factory final : TunClientFactory { ${method} };
  `,
  );
  writeFileSync(
    join(root, 'capability.cc'),
    `
    #include "capability.hpp"
    #include <cassert>
    int main() { Factory factory; TunClientFactory& base = factory; assert(!base.supports_epoch_data()); }
  `,
  );
  const coverage =
    /Free Software Foundation/.test(String(compilerProbe.stdout)) &&
    spawnSync('gcov', ['--version'], { windowsHide: true }).status === 0;
  const binary = join(root, process.platform === 'win32' ? 'capability.exe' : 'capability');
  const run = (command, args) =>
    execFileSync(command, args, { cwd: root, windowsHide: true, encoding: 'utf8' });
  run(compiler, [
    '-std=c++17',
    '-Wall',
    '-Wextra',
    '-Werror',
    ...(coverage ? ['--coverage', '-O0'] : []),
    'capability.cc',
    '-o',
    binary,
  ]);
  run(binary, []);
  if (coverage) {
    const output = run('gcov', ['capability.gcno']);
    const percent = Number(/File 'capability.hpp'\r?\nLines executed:([\d.]+)%/.exec(output)?.[1]);
    t.diagnostic(`Native OpenVPN factory capability line coverage: ${percent}%`);
    assert.ok(percent >= 80, output);
  }
});

function fixture(t, parent) {
  const root = temporaryDirectory(t, parent);
  const header = join(root, 'openvpn/mbedtls/mbedtls_compat.hpp');
  mkdirSync(dirname(header), { recursive: true });
  mkdirSync(join(root, 'mbedtls'));
  writeFileSync(header, original);
  return { root, header };
}

test(
  'OpenVPN mbedTLS compatibility preserves extension masks with either header order',
  { skip: compilerProbe.error?.code === 'ENOENT' && 'C++ compiler is unavailable' },
  async (t) => {
    assert.equal(compilerProbe.status, 0, compilerProbe.error?.message);
    const { root } = fixture(t);

    const writeHeader = (name, contents) =>
      writeFileSync(join(root, 'mbedtls', name), `#pragma once\n${contents}\n`);
    writeHeader('ctr_drbg.h', '');
    writeHeader(
      'pem.h',
      '#include <cstddef>\nstruct mbedtls_pem_context { unsigned char *buf; size_t buflen; };',
    );
    writeHeader(
      'md.h',
      'struct mbedtls_md_info_t {};\nstruct mbedtls_md_context_t { const mbedtls_md_info_t *md_info; };',
    );
    writeHeader(
      'x509_crt.h',
      '#include <mbedtls/x509.h>\nstruct mbedtls_x509_crt { int ext_types; };',
    );

    for (const legacy of [false, true]) {
      // mbedTLS 3.6 defines OID masks in oid.h. Older 2.x releases expose them
      // through x509.h. Upstream 3.11.8 removed the incorrect EKU-to-KU fallback,
      // so the local OID include backport is no longer needed.
      writeHeader(
        'version.h',
        `#define MBEDTLS_VERSION_NUMBER ${legacy ? '0x02100c00' : '0x03060700'}`,
      );
      writeHeader(
        'x509.h',
        legacy
          ? '#define MBEDTLS_X509_EXT_KEY_USAGE (1 << 2)\n#define MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE (1 << 11)'
          : '#define MBEDTLS_X509_EXT_KEY_USAGE MBEDTLS_OID_X509_EXT_KEY_USAGE\n#define MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE',
      );
      writeHeader(
        'oid.h',
        legacy
          ? '#include <mbedtls/x509.h>'
          : '#define MBEDTLS_OID_X509_EXT_KEY_USAGE (1 << 2)\n#define MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE (1 << 11)',
      );
      for (const oidFirst of [false, true]) {
        await t.test(
          `mbedTLS ${legacy ? '2.x' : '3.6'}, oid.h ${oidFirst ? 'first' : 'last'}`,
          () => {
            const source = join(root, 'check.cc');
            writeFileSync(
              source,
              [
                '#include <mbedtls/md.h>',
                '#include <mbedtls/x509_crt.h>',
                oidFirst ? '#include <mbedtls/oid.h>' : '',
                '#include <openvpn/mbedtls/mbedtls_compat.hpp>',
                '#include <mbedtls/oid.h>',
                'static_assert(MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE == (1 << 11));',
                'static_assert(MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE != MBEDTLS_X509_EXT_KEY_USAGE);',
                '',
              ].join('\n'),
            );
            const compile = () =>
              spawnSync(
                compiler,
                ['-std=c++17', '-Wall', '-Werror', '-fsyntax-only', '-I', root, source],
                { encoding: 'utf8', windowsHide: true },
              );
            const result = compile();
            assert.equal(result.status, 0, result.stderr || result.error?.message);
          },
        );
      }
    }
  },
);
