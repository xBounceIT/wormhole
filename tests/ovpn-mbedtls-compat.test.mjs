import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const patch = fileURLToPath(
  new URL(
    '../tools/wormhole-ovpnproxy/patches/0003-mbedtls-include-oid-before-compat-fallback.patch',
    import.meta.url,
  ),
);
// Unmodified header from the pinned OpenVPN3 commit 10c6a56cb17fd015a2d24953c3c42145bbcdea58.
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

function fixture(t, parent) {
  const root = temporaryDirectory(t, parent);
  const header = join(root, 'openvpn/mbedtls/mbedtls_compat.hpp');
  mkdirSync(dirname(header), { recursive: true });
  mkdirSync(join(root, 'mbedtls'));
  writeFileSync(header, original);
  const git = (args) =>
    execFileSync('git', ['-c', 'core.autocrlf=false', ...args], { cwd: root, windowsHide: true });
  git(['init', '--quiet']);
  return { root, header, git };
}

test('OpenVPN mbedTLS patch applies and reverses inside another Git worktree without C++', (t) => {
  const parent = temporaryDirectory(t);
  execFileSync('git', ['init', '--quiet', parent], { windowsHide: true });
  const { header, git } = fixture(t, parent);
  git(['apply', '--check', patch]);
  git(['apply', patch]);
  assert.notEqual(readFileSync(header, 'utf8'), original, 'Patch must change the header');
  git(['apply', '--reverse', '--check', patch]);
  git(['apply', '--reverse', patch]);
  assert.equal(readFileSync(header, 'utf8'), original);
});

test(
  'OpenVPN mbedTLS compatibility preserves extension masks with either header order',
  { skip: compilerProbe.error?.code === 'ENOENT' && 'C++ compiler is unavailable' },
  async (t) => {
    assert.equal(compilerProbe.status, 0, compilerProbe.error?.message);
    const { root, header, git } = fixture(t);
    git(['apply', patch]);
    const patched = readFileSync(header, 'utf8');

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
      // through x509.h, which their oid.h includes. Preserve the existing legacy
      // fallback: upstream uses that alias in both KU and EKU certificate checks.
      writeHeader(
        'version.h',
        `#define MBEDTLS_VERSION_NUMBER ${legacy ? '0x02100c00' : '0x03060600'}`,
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
                `static_assert(MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE == (1 << ${legacy ? 2 : 11}));`,
                `static_assert(MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE ${legacy ? '==' : '!='} MBEDTLS_X509_EXT_KEY_USAGE);`,
                '',
              ].join('\n'),
            );
            const compile = () =>
              spawnSync(
                compiler,
                ['-std=c++17', '-Wall', '-Werror', '-fsyntax-only', '-I', root, source],
                { encoding: 'utf8', windowsHide: true },
              );
            if (!legacy && !oidFirst) {
              writeFileSync(header, original);
              const regression = compile();
              assert.notEqual(
                regression.status,
                0,
                'Unpatched header must reproduce the regression',
              );
              assert.match(regression.stderr, /redefined/);
              writeFileSync(header, patched);
            }
            const result = compile();
            assert.equal(result.status, 0, result.stderr || result.error?.message);
          },
        );
      }
    }
    git(['apply', '--reverse', patch]);
    assert.equal(readFileSync(header, 'utf8'), original);
  },
);
