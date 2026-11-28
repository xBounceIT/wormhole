import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Script } from 'node:vm';
import { buildVaultBitwardenBridge } from '../scripts/Build-VaultBitwardenBridge.mjs';
import { create, version } from '../src/vault-bitwarden-extension-entry.ts';
import type { BitwardenExtensionBridge } from '../electron/vault-bitwarden-bridge-contract.ts';
const id = 'a'.repeat(32),
  owner = () => ({ workspaceId: randomUUID(), profileId: randomUUID(), epoch: 2 });
function world() {
  const values: Record<string, unknown> = {},
    memory: Record<string, string> = {};
  return {
    isSecureContext: true,
    location: { protocol: 'chrome-extension:', hostname: id },
    chrome: {
      runtime: { id, getManifest: () => ({ manifest_version: 2 }) },
      storage: {
        local: {
          get: (_key: unknown, done: (v: unknown) => void) =>
            queueMicrotask(() => done({ ...values })),
          set: (next: Record<string, unknown>, done: () => void) => {
            Object.assign(values, next);
            queueMicrotask(done);
          },
          remove: (key: string, done: () => void) => {
            delete values[key];
            queueMicrotask(done);
          },
        },
      },
    },
    bitwardenMain: {
      memoryStorageForStateProviders: {
        store: memory,
        save: async (key: string, value: unknown) => {
          memory[key] = JSON.stringify(value);
        },
        remove: async (key: string) => {
          delete memory[key];
        },
      },
    },
  };
}
test('packaged entry refuses ordinary, insecure, foreign and unready extension worlds', async (t) => {
  assert.equal(version, 1);
  assert.throws(() => create(owner()), /background is unavailable/);
  const descriptors = new Map<string, PropertyDescriptor | undefined>();
  const install = (value: Record<string, unknown>) => {
    for (const [key, v] of Object.entries(value)) {
      if (!descriptors.has(key))
        descriptors.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
      Object.defineProperty(globalThis, key, { value: v, configurable: true, writable: true });
    }
  };
  t.after(() => {
    for (const [key, descriptor] of descriptors)
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete (globalThis as any)[key];
  });
  for (const delta of [
    { isSecureContext: false },
    { location: { protocol: 'https:', hostname: id } },
    { location: { protocol: 'chrome-extension:', hostname: 'b'.repeat(32) } },
    { chrome: undefined },
    { chrome: { runtime: { id: 'bad' }, storage: { local: {} } } },
    {
      chrome: {
        runtime: { id, getManifest: () => ({ manifest_version: 1 }) },
        storage: { local: {} },
      },
    },
    { bitwardenMain: undefined },
  ]) {
    install({ ...world(), ...delta });
    assert.throws(() => create(owner()), /background is unavailable/);
  }
  install(world());
  assert.throws(() => create(null), /background is unavailable/);
  const bridge = create(owner());
  try {
    const q = await bridge.prepare();
    assert.equal(q.action, 'hydrate');
    const key = (await crypto.subtle.generateKey({ name: 'X25519' }, false, [
      'deriveBits',
    ])) as CryptoKeyPair;
    await bridge.bind({
      ...q,
      fileId: randomUUID(),
      transferId: randomUUID(),
      policySequence: '3',
      capturePublicKey: Buffer.from(await crypto.subtle.exportKey('raw', key.publicKey)).toString(
        'base64',
      ),
    });
    assert.equal((await bridge.next()).manifest.bytes, 14);
  } finally {
    await bridge.dispose();
  }
});
test('build emits a standalone sandbox browser asset and preserves existing app artifacts', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wormhole-bitwarden-bundle-'));
  try {
    await writeFile(join(directory, 'preserve.txt'), 'existing artifact');
    const path = await buildVaultBitwardenBridge(directory),
      code = await readFile(path, 'utf8');
    assert.equal(await readFile(join(directory, 'preserve.txt'), 'utf8'), 'existing artifact');
    assert.ok(code.length > 1000);
    assert.doesNotMatch(code, /sourceMappingURL/);
    const env = world(),
      context = {
        ...env,
        crypto: globalThis.crypto,
        Uint8Array,
        ArrayBuffer,
        DataView,
        TextEncoder,
        TextDecoder,
        AbortController,
        setTimeout,
        clearTimeout,
        queueMicrotask,
        atob,
        btoa,
      } as any;
    new Script(code, { filename: 'vault-bitwarden-extension.js' }).runInNewContext(context);
    assert.equal(context.process, undefined);
    assert.equal(context.require, undefined);
    assert.equal(context.WormholeVaultBitwarden.version, 1);
    const q = owner(),
      bridge = context.WormholeVaultBitwarden.create(q) as BitwardenExtensionBridge;
    try {
      const request = await bridge.prepare();
      assert.equal(request.workspaceId, q.workspaceId);
      assert.equal(request.profileId, q.profileId);
      assert.equal(request.sourceRevision, '0');
      assert.deepEqual(
        Object.keys(request).sort(),
        [
          'workspaceId',
          'profileId',
          'requestId',
          'epoch',
          'action',
          'sourceRevision',
          'restorePublicKey',
        ].sort(),
      );
      const key = (await crypto.subtle.generateKey({ name: 'X25519' }, false, [
        'deriveBits',
      ])) as CryptoKeyPair;
      await bridge.bind({
        ...request,
        fileId: randomUUID(),
        transferId: randomUUID(),
        policySequence: '3',
        capturePublicKey: Buffer.from(await crypto.subtle.exportKey('raw', key.publicKey)).toString(
          'base64',
        ),
      });
      const packet = await bridge.next();
      assert.equal(packet.direction, 'capture');
      assert.equal(packet.manifest.bytes, 14);
    } finally {
      await bridge.dispose();
    }
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 });
  }
});
