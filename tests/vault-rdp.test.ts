import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import {
  parseVaultRdpBundle,
  parseVaultRoutedRdpBundle,
  parseVaultRoutedRdpRequest,
} from '../electron/vault-rdp.ts';
import { rdpRequest, rdpBundle, routedRdpRequest, routedRdpBundle } from './fixtures/vault-rdp.ts';

test('RDP ciphertext contracts bind direct authority and bound the binary payload', () => {
  const q = rdpRequest(),
    value = rdpBundle(q);
  assert.deepEqual(parseVaultRdpBundle(value, q), value);
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
    assert.equal(parseVaultRdpBundle(changed, q), undefined, field);
  }
  for (const path of ['root', 'binding', 'bundle']) {
    const changed = structuredClone(value) as any;
    (path === 'root' ? changed : changed[path]).extra = true;
    assert.equal(parseVaultRdpBundle(changed, q), undefined);
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
    assert.equal(parseVaultRdpBundle(changed, q), undefined);
  }
  for (const v of [null, [], {}, 1]) assert.equal(parseVaultRdpBundle(v, q), undefined);
  for (const bad of [
    { ...q, publicKey: 'bad' },
    { ...q, epoch: 0 },
    { ...q, password: 'injected' },
  ])
    assert.equal(parseVaultRdpBundle(value, bad), undefined);
  for (const length of [41, 42, 65552, 65553]) {
    value.bundle.ciphertext = Buffer.alloc(length).toString('base64');
    assert.equal(!!parseVaultRdpBundle(value, q), length >= 42 && length <= 65552);
  }
  const copy = parseVaultRdpBundle(rdpBundle(q), q)!;
  copy.binding.host = 'changed';
  assert.equal(rdpBundle(q).binding.host, 'host.example');
});
test('routed RDP contracts bind exact VPN revision and endpoint without allowing another protocol', () => {
  const q = routedRdpRequest(),
    value = routedRdpBundle(q);
  assert.deepEqual(parseVaultRoutedRdpRequest(q), q);
  assert.deepEqual(parseVaultRoutedRdpBundle(value, q), value);
  for (const bad of [
    null,
    {},
    { ...q, endpoint: 'localhost:2345' },
    { ...q, password: 'secret' },
    { ...q, route: { ...q.route, protocol: 'ssh' } },
    { ...q, epoch: 0 },
  ])
    assert.equal(parseVaultRoutedRdpRequest(bad), undefined);
  for (const bad of [
    null,
    {},
    { ...value, endpoint: '127.0.0.1:2346' },
    { ...value, extra: true },
    { ...value, binding: { ...value.binding, rowVersion: '3' } },
    { ...value, binding: { ...value.binding, protocol: 'ssh' } },
    { ...value, bundle: { ...value.bundle, ciphertext: Buffer.alloc(65553).toString('base64') } },
  ])
    assert.equal(parseVaultRoutedRdpBundle(bad, q), undefined);
  assert.equal(parseVaultRoutedRdpBundle(value, { ...q, publicKey: 'bad' }), undefined);
  const copy = parseVaultRoutedRdpBundle(value, q)!;
  copy.binding.host = 'changed';
  assert.equal(value.binding.host, 'host.example');
});
