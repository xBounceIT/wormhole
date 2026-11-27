import assert from 'node:assert/strict';
import test from 'node:test';
import { vncRequest, vncBundle, routedVncRequest } from './fixtures/vault-vnc.ts';
import {
  parseVaultVncPlan,
  parseVaultVncManualRequest,
  parseVaultVncManualBundle,
  vncPlanPayload,
  vncManualPayload,
} from '../electron/vault-vnc-manual.ts';
import {
  parseVaultVncBundle,
  parseVaultRoutedVncBundle,
  parseVaultManualVncBundle,
  parseVaultManualRoutedVncBundle,
} from '../electron/vault-vnc.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
const tick = () => new Promise(setImmediate);
function fixture(route = false) {
  const q = routedVncRequest(),
    binding = route ? q.route : vncBundle(q).binding;
  const context = { binding, publicKey: q.publicKey, ...(route ? { endpoint: q.endpoint } : {}) };
  const manual = vncBundle(q).bundle;
  const request = { context, credentialOverride: q.credentialOverride, manual };
  const result = {
    binding,
    bundle: { ...manual, ciphertext: Buffer.alloc(75).toString('base64') },
    ...(route ? { endpoint: q.endpoint } : {}),
  };
  const { publicKey: _, route: __, endpoint: ___, ...plan } = q;
  return { q, plan, binding, request, result };
}
test('manual VNC contracts bind metadata-only plans and opaque authorization to one exact request', () => {
  const { plan, binding } = fixture();
  assert.deepEqual(parseVaultVncPlan({ binding }, plan), binding);
  assert.equal(vncPlanPayload(plan).epoch, '1');
  for (const value of [
    null,
    {},
    { binding, extra: true },
    { binding: { ...binding, host: 'bad host' } },
    { binding: { ...binding, nodeId: vncRequest().nodeId } },
    { binding: { ...binding, epoch: 2 } },
  ])
    assert.equal(parseVaultVncPlan(value, plan), undefined);
  assert.equal(parseVaultVncPlan({ binding }, { ...plan, epoch: 0 }), undefined);
  for (const route of [false, true]) {
    const f = fixture(route);
    assert.deepEqual(parseVaultVncManualRequest(f.request), f.request);
    assert.deepEqual(parseVaultVncManualBundle(f.result, f.request), f.result);
    const copy = parseVaultVncManualRequest(f.request)!;
    copy.context.binding.host = 'changed';
    copy.manual.enc = '';
    assert.equal(f.request.context.binding.host, 'host.example');
    assert.notEqual(f.request.manual.enc, '');
    const payload = vncManualPayload(f.request);
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
      assert.equal(parseVaultVncManualRequest(value), undefined);
    assert.ok(
      parseVaultVncManualRequest({ ...f.request, credentialOverride: vncRequest().nodeId }),
    );
    for (const size of [74, 75, 16459, 16460]) {
      const value = {
        ...f.result,
        bundle: { ...f.result.bundle, ciphertext: Buffer.alloc(size).toString('base64') },
      };
      assert.equal(!!parseVaultVncManualBundle(value, f.request), size >= 75 && size <= 16459);
      if (size === 16459)
        assert.equal(
          route ? parseVaultRoutedVncBundle(value, f.q) : parseVaultVncBundle(value, f.q),
          undefined,
        );
    }
    for (const value of [
      null,
      { ...f.result, extra: true },
      { ...f.result, bundle: f.request.manual },
      { ...f.result, binding: { ...f.binding, host: 'redirect.example' } },
      { ...f.result, binding: { ...f.binding, port: 5901 } },
      ...(route ? [{ ...f.result, endpoint: '127.0.0.1:2346' }] : []),
    ])
      assert.equal(parseVaultVncManualBundle(value, f.request), undefined);
    assert.equal(
      route ? parseVaultManualRoutedVncBundle(null, f.q) : parseVaultManualVncBundle(null, f.q),
      undefined,
    );
  }
});
test('manual VNC host rejects lock, stale owner/client/workspace and malformed native replies', async () => {
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
      vncPlan: async () => {
        if (delayed) await new Promise<void>((r) => (release = r));
        return malformed ? {} : f.binding;
      },
      vncManualBundle: async () => {
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
        ? host.vncPlan(value, () => allowed)
        : host.vncManualBundle(value, () => allowed);
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
