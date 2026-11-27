import { VaultBackendClient } from '../electron/vault-client.ts';
import assert from 'node:assert/strict';
import test from 'node:test';
import { rdpRequest, rdpBundle, routedRdpRequest } from './fixtures/vault-rdp.ts';
import {
  parseVaultRdpPlan,
  parseVaultRdpManualRequest,
  parseVaultRdpManualBundle,
  rdpPlanPayload,
  rdpManualPayload,
} from '../electron/vault-rdp-manual.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
const tick = () => new Promise(setImmediate);
function fixture(route = false) {
  const q = routedRdpRequest(),
    binding = route ? q.route : rdpBundle(q).binding;
  const context = { binding, publicKey: q.publicKey, ...(route ? { endpoint: q.endpoint } : {}) };
  const manual = rdpBundle(q).bundle;
  const request = { context, credentialOverride: q.credentialOverride, manual };
  const result = {
    binding,
    bundle: { ...manual, ciphertext: Buffer.alloc(75).toString('base64') },
    ...(route ? { endpoint: q.endpoint } : {}),
  };
  const { publicKey: _, route: __, endpoint: ___, ...plan } = q;
  return { q, plan, binding, request, result };
}
test('manual RDP contracts bind metadata-only plans and opaque authorization to one exact request', () => {
  const { plan, binding } = fixture();
  assert.deepEqual(parseVaultRdpPlan({ binding }, plan), binding);
  assert.equal(rdpPlanPayload(plan).epoch, '1');
  for (const value of [
    null,
    {},
    { binding, extra: true },
    { binding: { ...binding, host: 'bad host' } },
    { binding: { ...binding, nodeId: rdpRequest().nodeId } },
    { binding: { ...binding, epoch: 2 } },
  ])
    assert.equal(parseVaultRdpPlan(value, plan), undefined);
  assert.equal(parseVaultRdpPlan({ binding }, { ...plan, epoch: 0 }), undefined);
  for (const route of [false, true]) {
    const f = fixture(route);
    assert.deepEqual(parseVaultRdpManualRequest(f.request), f.request);
    assert.deepEqual(parseVaultRdpManualBundle(f.result, f.request), f.result);
    const copy = parseVaultRdpManualRequest(f.request)!;
    copy.context.binding.host = 'changed';
    copy.manual.enc = '';
    assert.equal(f.request.context.binding.host, 'host.example');
    assert.notEqual(f.request.manual.enc, '');
    const payload = rdpManualPayload(f.request);
    assert.equal('workspaceId' in payload, false);
    assert.equal(payload.epoch, '1');
    assert.equal('route' in payload, route);
    assert.equal('binding' in payload, !route);
    for (const value of [
      null,
      {},
      { ...f.request, extra: true },
      { ...f.request, password: 'secret' },
      { ...f.request, credentialOverride: 'bad' },
      { ...f.request, context: null },
      { ...f.request, manual: null },
    ])
      assert.equal(parseVaultRdpManualRequest(value), undefined);
    assert.equal(
      parseVaultRdpManualRequest({ ...f.request, credentialOverride: rdpRequest().nodeId }),
      undefined,
    );
    for (const size of [41, 42, 65552, 65553]) {
      const value = {
        ...f.result,
        bundle: { ...f.result.bundle, ciphertext: Buffer.alloc(size).toString('base64') },
      };
      assert.equal(!!parseVaultRdpManualBundle(value, f.request), size >= 42 && size <= 65552);
    }
    for (const value of [
      null,
      { ...f.result, extra: true },
      { ...f.result, binding: { ...f.binding, host: 'redirect.example' } },
      { ...f.result, binding: { ...f.binding, port: 5901 } },
      ...(route ? [{ ...f.result, endpoint: '127.0.0.1:2346' }] : []),
    ])
      assert.equal(parseVaultRdpManualBundle(value, f.request), undefined);
  }
});
test('manual RDP host rejects lock, stale owner/client/workspace and malformed native replies', async () => {
  for (const operation of ['plan', 'manual']) {
    const f = fixture();
    let allowed = true,
      delayed = false,
      release!: () => void,
      malformed = false;
    const client: any = {
      describe: async () => ({
        vaultId: f.q.workspaceId,
        slots: [{ id: f.q.nodeId, kind: 'recovery' }],
      }),
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      security: async () => ({ effective: 'default' }),
      lock: async () => {},
      stop: async () => {},
      rdpPlan: async () => {
        if (delayed) await new Promise<void>((r) => (release = r));
        return malformed ? {} : f.binding;
      },
      rdpManualBundle: async () => {
        if (delayed) await new Promise<void>((r) => (release = r));
        return malformed ? {} : f.result;
      },
    };
    const host = new VaultBackendHost(
      () => client,
      () => true,
    );
    const input = operation === 'plan' ? f.plan : f.request;
    const invoke = (value: unknown = input) =>
      operation === 'plan'
        ? host.rdpPlan(value, () => allowed)
        : host.rdpManualBundle(value, () => allowed);
    await assert.rejects(invoke(null), /Invalid/);
    await assert.rejects(invoke(), /locked/);
    const unlock = async () => {
      await host.describe();
      await host.unlock({
        vaultId: f.q.workspaceId,
        slotId: f.q.nodeId,
        kind: 'recovery',
        factor: new Uint8Array(32),
      });
    };
    await unlock();
    assert.deepEqual(await invoke(), operation === 'plan' ? f.binding : f.result);
    allowed = false;
    await assert.rejects(invoke(), /locked/);
    allowed = true;
    malformed = true;
    await assert.rejects(invoke(), /Invalid/);
    malformed = false;
    for (const invalidate of ['owner', 'stop']) {
      delayed = true;
      const pending = invoke();
      await tick();
      if (invalidate === 'owner') allowed = false;
      else await host.stop();
      release();
      await assert.rejects(pending, /locked/);
      delayed = false;
      allowed = true;
      if (invalidate !== 'owner') await unlock();
    }
    await host.stop();
  }
});

test('manual RDP client rejects malformed metadata before spawning a vault owner', async () => {
  let spawned = 0;
  const client = new VaultBackendClient(
    { executable: 'never-start', databasePath: 'never-open.db' },
    () => {
      spawned++;
      throw Error('unexpected process');
    },
  );
  const f = fixture();
  for (const value of [
    null,
    {},
    { ...f.plan, epoch: 0 },
    { ...f.plan, password: 'must-not-relay' },
  ])
    await assert.rejects(client.rdpPlan(value), /Invalid/);
  for (const value of [
    null,
    {},
    { ...f.request, credentialOverride: f.q.nodeId },
    { ...f.request, username: 'must-not-relay' },
  ])
    await assert.rejects(client.rdpManualBundle(value), /Invalid/);
  assert.equal(spawned, 0);
  await client.stop();
});
