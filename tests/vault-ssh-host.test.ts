import assert from 'node:assert/strict';
import test from 'node:test';
import { sshRequest, sshBundle } from './fixtures/vault-ssh.ts';
import { VaultBackendHost, registerVaultIpc } from '../electron/vault-host.ts';
import {
  parseVaultSshHostRequest,
  parseVaultSshHostPlan,
  parseVaultSshHostTrust,
  validVaultSshFingerprint,
  vaultSshHostPayload,
} from '../electron/vault-ssh-host.ts';

const base = sshRequest();
const { publicKey: _, ...context } = base;
const request = { ...context, route: null };
const plan = {
  binding: sshBundle(base).binding,
  fileId: base.workspaceId,
  revision: 'a'.repeat(64),
  fingerprint: '',
};
const received = 'SHA256:' + Buffer.alloc(32, 1).toString('base64').slice(0, -1);
const trust = { ...request, expected: plan, received };

test('SSH host contracts snapshot full context and accept only canonical fingerprints', () => {
  assert.deepEqual(parseVaultSshHostRequest(request), request);
  assert.deepEqual(parseVaultSshHostPlan(plan, request), plan);
  assert.deepEqual(parseVaultSshHostTrust(trust), trust);
  assert.ok(validVaultSshFingerprint(received));
  for (const bad of [
    null,
    '',
    'MD5:bad',
    received + '=',
    received.slice(0, -1),
    'SHA256:' + 'A'.repeat(44),
  ])
    assert.equal(validVaultSshFingerprint(bad), false);
  for (const bad of [
    null,
    {},
    { ...request, extra: true },
    { ...request, route: undefined },
    { ...request, route: {} },
    { ...request, epoch: 0 },
  ])
    assert.equal(parseVaultSshHostRequest(bad), undefined);
  for (const bad of [
    null,
    {},
    { ...plan, extra: true },
    { ...plan, fileId: 'bad' },
    { ...plan, revision: 'A'.repeat(64) },
    { ...plan, fingerprint: 'bad' },
    { ...plan, binding: null },
    { ...plan, binding: { ...plan.binding, extra: true } },
    ...Object.keys(plan.binding).map((key) => ({
      ...plan,
      binding: { ...plan.binding, [key]: key === 'port' ? 0 : key === 'host' ? '' : 'wrong' },
    })),
    { ...plan, binding: { ...plan.binding, host: 'bad host' } },
    { ...plan, binding: { ...plan.binding, port: 65536 } },
  ])
    assert.equal(parseVaultSshHostPlan(bad, request), undefined);
  assert.equal(parseVaultSshHostPlan(plan, { ...request, epoch: 0 }), undefined);
  for (const bad of [
    null,
    {},
    { ...trust, extra: true },
    { ...trust, expected: null },
    { ...trust, received: 'bad' },
    { ...trust, expected: { ...plan, fingerprint: received } },
  ])
    assert.equal(parseVaultSshHostTrust(bad), undefined);
  const original = structuredClone(trust),
    copy = parseVaultSshHostTrust(original)!;
  original.expected.binding.host = 'changed';
  assert.equal(copy.expected.binding.host, plan.binding.host);
  assert.deepEqual(vaultSshHostPayload(request), {
    nodeId: base.nodeId,
    credentialOverride: '',
    sessionId: base.sessionId,
    requestId: base.requestId,
    epoch: '1',
    route: null,
  });
  assert.equal(vaultSshHostPayload(trust).received, received);
});

test('SSH host plan must describe the exact main-owned route', () => {
  const route = {
    ...plan.binding,
    fileId: plan.fileId,
    tunnelConfigId: base.nodeId,
    kind: 6,
    rowVersion: '1',
    configurationVersion: '1',
  };
  const q = { ...context, route },
    p = { ...plan, binding: { ...plan.binding, tunnelConfigId: route.tunnelConfigId } };
  assert.deepEqual(parseVaultSshHostRequest(q), q);
  assert.deepEqual(parseVaultSshHostPlan(p, q), p);
  assert.equal(parseVaultSshHostRequest({ ...q, route: { ...route, protocol: 'rdp' } }), undefined);
  for (const changed of [
    { ...p, fileId: base.requestId },
    { ...p, binding: { ...p.binding, host: 'changed' } },
    { ...p, binding: { ...p.binding, port: 23 } },
  ])
    assert.equal(parseVaultSshHostPlan(changed, q), undefined);
});

test('main host rechecks ownership, confines trust to one fresh action and exposes no renderer method', async () => {
  for (const operation of ['plan', 'trust'] as const) {
    let allowed = true,
      delayed = false,
      release!: () => void,
      standard = false,
      calls = 0;
    const result = { nodeId: base.nodeId, rowVersion: '2', updated: true };
    const client: any = {
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      security: async () => ({ effective: standard ? 'standard' : 'default' }),
      describe: async () => ({
        vaultId: base.workspaceId,
        slots: [{ id: base.nodeId, kind: 'password' }],
      }),
      lock: async () => {},
      sshHostPlan: async (q: unknown) => {
        calls++;
        assert.deepEqual(q, request);
        if (delayed) await new Promise<void>((r) => (release = r));
        return plan;
      },
      trustSshHost: async (q: unknown, factor?: any) => {
        calls++;
        assert.deepEqual(q, trust);
        assert.equal(Boolean(factor), standard);
        if (delayed) await new Promise<void>((r) => (release = r));
        return result;
      },
    };
    const host = new VaultBackendHost(
      () => client,
      () => true,
    );
    const invoke = (value: unknown, confirm?: any) =>
      operation === 'plan'
        ? host.sshHostPlan(value, () => allowed)
        : host.trustSshHost(value, confirm, () => allowed);
    const input = operation === 'plan' ? request : trust;
    await assert.rejects(invoke(null), /Invalid/);
    await assert.rejects(invoke(input), /locked/);
    await host.unlock({
      vaultId: base.workspaceId,
      slotId: base.nodeId,
      kind: 'password',
      factor: new Uint8Array([1]),
    });
    allowed = false;
    await assert.rejects(invoke(input), /locked/);
    allowed = true;
    assert.equal(calls, 0);
    assert.deepEqual(await invoke(input), operation === 'plan' ? plan : result);
    if (operation === 'trust') {
      standard = true;
      await assert.rejects(invoke(input), /Fresh authentication/);
      let factor!: Uint8Array;
      assert.deepEqual(
        await invoke(input, async (name: string, descriptor: any, submit: any) => {
          assert.equal(name, 'ssh-host-trust');
          assert.equal(descriptor.vaultId, base.workspaceId);
          factor = new Uint8Array([2]);
          return submit({
            vaultId: base.workspaceId,
            slotId: base.nodeId,
            kind: 'password',
            factor,
          });
        }),
        result,
      );
      assert.ok(factor.every((x) => x === 0));
      standard = false;
    }
    const channels: string[] = [];
    registerVaultIpc({ handle: (name: string) => channels.push(name) } as any, host, () => true);
    assert.ok(!channels.some((name) => /ssh-host/.test(name)));
    delayed = true;
    for (const stop of [false, true]) {
      allowed = true;
      const mutable = structuredClone(input),
        pending = invoke(mutable);
      mutable.nodeId = 'mutated';
      if ('expected' in mutable) mutable.expected.binding.host = 'mutated';
      await new Promise(setImmediate);
      if (stop) await host.stop();
      else allowed = false;
      release();
      await assert.rejects(pending, /locked/);
    }
  }
});
test('SFTP bundles preserve their protocol and reject cross-protocol routed host plans', () => {
  const direct = { ...plan, binding: { ...plan.binding, protocol: 'sftp' as const } };
  assert.deepEqual(parseVaultSshHostPlan(direct, request), direct);
  const route = {
    ...direct.binding,
    fileId: plan.fileId,
    tunnelConfigId: base.nodeId,
    kind: 6,
    rowVersion: '1',
    configurationVersion: '1',
  };
  const q = { ...context, route };
  const p = { ...direct, binding: { ...direct.binding, tunnelConfigId: route.tunnelConfigId } };
  assert.deepEqual(parseVaultSshHostRequest(q), q);
  assert.deepEqual(parseVaultSshHostPlan(p, q), p);
  assert.equal(
    parseVaultSshHostPlan({ ...p, binding: { ...p.binding, protocol: 'ssh' } }, q),
    undefined,
  );
  assert.equal(parseVaultSshHostPlan(p, { ...q, route: { ...route, protocol: 'ssh' } }), undefined);
});
