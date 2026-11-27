import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import {
  parseVaultVncBundle,
  parseVaultRoutedVncBundle,
  parseVaultRoutedVncRequest,
} from '../electron/vault-vnc.ts';
import { vncRequest, vncBundle, routedVncRequest, routedVncBundle } from './fixtures/vault-vnc.ts';

test('VNC ciphertext contracts bind direct authority and bound the binary payload', () => {
  const q = vncRequest(),
    value = vncBundle(q);
  assert.deepEqual(parseVaultVncBundle(value, q), value);
  for (const field of Object.keys(value.binding)) {
    const changed = structuredClone(value) as any;
    changed.binding[field] =
      field === 'host'
        ? 'bad host'
        : field === 'port'
          ? 0
          : field === 'epoch'
            ? 2
            : field === 'useExternalClient'
              ? true
              : randomUUID();
    assert.equal(parseVaultVncBundle(changed, q), undefined, field);
  }
  for (const path of ['root', 'binding', 'bundle']) {
    const changed = structuredClone(value) as any;
    (path === 'root' ? changed : changed[path]).extra = true;
    assert.equal(parseVaultVncBundle(changed, q), undefined);
  }
  for (const change of [
    (v: any) => (v.binding.host = '\ud800'),
    (v: any) => (v.binding.host = ''),
    (v: any) => (v.binding.port = 65536),
    (v: any) => (v.bundle.enc = 'bad'),
    (v: any) => (v.bundle.suiteId = 3),
    (v: any) => (v.bundle.formatVersion = 2),
    (v: any) => (v.bundle.ciphertext = ''),
  ]) {
    const changed = structuredClone(value);
    change(changed);
    assert.equal(parseVaultVncBundle(changed, q), undefined);
  }
  for (const v of [null, [], {}, 1]) assert.equal(parseVaultVncBundle(v, q), undefined);
  for (const bad of [
    { ...q, publicKey: 'bad' },
    { ...q, epoch: 0 },
    { ...q, password: 'injected' },
  ])
    assert.equal(parseVaultVncBundle(value, bad), undefined);
  for (const length of [21, 22, 16406, 16407]) {
    value.bundle.ciphertext = Buffer.alloc(length).toString('base64');
    assert.equal(!!parseVaultVncBundle(value, q), length >= 22 && length <= 16406);
  }
  const copy = parseVaultVncBundle(vncBundle(q), q)!;
  copy.binding.host = 'changed';
  assert.equal(vncBundle(q).binding.host, 'host.example');
});
test('routed VNC contracts bind exact VPN revision and endpoint without allowing another protocol', () => {
  const q = routedVncRequest(),
    value = routedVncBundle(q);
  assert.deepEqual(parseVaultRoutedVncRequest(q), q);
  assert.deepEqual(parseVaultRoutedVncBundle(value, q), value);
  for (const bad of [
    null,
    {},
    { ...q, endpoint: 'localhost:2345' },
    { ...q, password: 'secret' },
    { ...q, route: { ...q.route, protocol: 'ssh' } },
    { ...q, epoch: 0 },
  ])
    assert.equal(parseVaultRoutedVncRequest(bad), undefined);
  for (const bad of [
    null,
    {},
    { ...value, endpoint: '127.0.0.1:2346' },
    { ...value, extra: true },
    { ...value, binding: { ...value.binding, rowVersion: '3' } },
    { ...value, binding: { ...value.binding, protocol: 'ssh' } },
    { ...value, bundle: { ...value.bundle, ciphertext: Buffer.alloc(16407).toString('base64') } },
  ])
    assert.equal(parseVaultRoutedVncBundle(bad, q), undefined);
  assert.equal(parseVaultRoutedVncBundle(value, { ...q, publicKey: 'bad' }), undefined);
  const copy = parseVaultRoutedVncBundle(value, q)!;
  copy.binding.host = 'changed';
  assert.equal(value.binding.host, 'host.example');
});
