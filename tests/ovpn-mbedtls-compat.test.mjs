import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

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
