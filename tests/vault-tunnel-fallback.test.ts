import assert from 'node:assert/strict';
import test from 'node:test';
import { Session } from 'node:inspector/promises';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import {
  parseVaultTunnelFallbackPlanRequest,
  parseVaultTunnelFallbackBinding,
  parseVaultTunnelFallbackRequest,
  parseVaultTunnelFallbackBundle,
} from '../electron/vault-tunnel-fallback.ts';
import { VaultBackendHost, registerVaultIpc } from '../electron/vault-host.ts';
import {
  fallbackPlan as plan,
  fallbackRequest as request,
  fallbackBundle as packet,
} from './fixtures/vault-tunnel-fallback.ts';

test('fallback contracts preserve two independent sources and snapshot every public field', () => {
  assert.deepEqual(parseVaultTunnelFallbackPlanRequest(plan), plan);
  assert.deepEqual(parseVaultTunnelFallbackBinding(request.binding, plan), request.binding);
  assert.deepEqual(parseVaultTunnelFallbackRequest(request), request);
  assert.deepEqual(parseVaultTunnelFallbackBundle(packet, request), packet);
  const input = structuredClone(request),
    response = structuredClone(packet);
  const q = parseVaultTunnelFallbackRequest(input)!;
  const p = parseVaultTunnelFallbackBundle(response, input)!;
  input.binding.primary.host = 'changed';
  input.binding.fallback.rowVersion = '99';
  input.publicKey = 'changed';
  response.binding.fallback.host = 'changed';
  response.bundle.enc = 'changed';
  assert.deepEqual(q, request);
  assert.deepEqual(p, packet);
  for (const protocol of ['ssh', 'sftp', 'rdp', 'vnc', 'http', 'https'] as const) {
    const pair = structuredClone(request.binding),
      source = structuredClone(plan);
    pair.primary.protocol = pair.fallback.protocol = source.primary.protocol = protocol;
    assert.ok(parseVaultTunnelFallbackBinding(pair, source));
  }
});

test('fallback plan and packet requests reject unknown, missing, malformed or replayed context', () => {
  for (const bad of [
    null,
    [],
    {},
    { ...plan, extra: 1 },
    { ...plan, publicKey: request.publicKey },
    { ...plan, primary: null },
    { ...plan, primary: { ...plan.primary, kind: 2 } },
    { ...plan, fallbackRequestId: plan.requestId },
    { ...plan, fallbackRequestId: 'bad' },
    { ...plan, epoch: Number.MAX_SAFE_INTEGER + 1 },
  ])
    assert.equal(parseVaultTunnelFallbackPlanRequest(bad), undefined);
  for (const key of Object.keys(plan)) {
    const missing: any = { ...plan };
    delete missing[key];
    assert.equal(parseVaultTunnelFallbackPlanRequest(missing), undefined, key);
  }
  for (const bad of [
    null,
    [],
    {},
    { ...request, extra: 1 },
    { ...request, primary: plan.primary },
    { ...request, binding: null },
    { ...request, binding: { primary: plan.primary } },
    { ...request, binding: { ...request.binding, extra: 1 } },
    { ...request, publicKey: Buffer.alloc(31).toString('base64') },
    {
      ...request,
      binding: {
        ...request.binding,
        fallback: { ...request.binding.fallback, requestId: plan.requestId },
      },
    },
  ])
    assert.equal(parseVaultTunnelFallbackRequest(bad), undefined);
  for (const key of Object.keys(request)) {
    const missing: any = { ...request };
    delete missing[key];
    assert.equal(parseVaultTunnelFallbackRequest(missing), undefined, key);
  }
});

test('pair parsing refuses source replacement, shared-field mismatch, invalid revisions and provider changes', () => {
  assert.equal(parseVaultTunnelFallbackBinding(request.binding, {} as any), undefined);
  for (const bad of [
    null,
    [],
    {},
    { ...request.binding, extra: 1 },
    { ...request.binding, primary: null },
  ])
    assert.equal(parseVaultTunnelFallbackBinding(bad, plan), undefined);
  for (const side of ['primary', 'fallback'] as const) {
    for (const key of Object.keys(request.binding[side])) {
      const pair: any = structuredClone(request.binding);
      pair[side][key] = typeof pair[side][key] === 'number' ? -1 : 'bad';
      assert.equal(parseVaultTunnelFallbackBinding(pair, plan), undefined, `${side}.${key}`);
    }
    for (const delta of [
      { workspaceId: request.nodeId },
      { nodeId: request.workspaceId },
      { sessionId: request.nodeId },
      { requestId: request.nodeId },
      { fileId: request.nodeId },
      { protocol: 'ssh' },
      { host: 'other.example' },
      { port: 22 },
      { epoch: 2 },
      { useExternalClient: true },
      { kind: side === 'primary' ? 2 : 9 },
      { rowVersion: '0' },
      { rowVersion: '01' },
      { rowVersion: '9223372036854775808' },
      { configurationVersion: '0' },
      { configurationVersion: '9223372036854775808' },
    ]) {
      const pair = structuredClone(request.binding);
      Object.assign(pair[side], delta);
      assert.equal(
        parseVaultTunnelFallbackBinding(pair, plan),
        undefined,
        `${side}:${JSON.stringify(delta)}`,
      );
    }
  }
  for (const delta of [
    { tunnelConfigId: plan.primary.tunnelConfigId },
    { requestId: plan.requestId },
    { rowVersion: '6' },
    { extra: 1 },
  ]) {
    const pair = structuredClone(request.binding);
    Object.assign(pair.fallback, delta);
    assert.equal(parseVaultTunnelFallbackBinding(pair, plan), undefined);
  }
  const changed = structuredClone(request.binding);
  changed.primary.rowVersion = '9223372036854775806'; // valid, but a different exact primary
  assert.equal(parseVaultTunnelFallbackBinding(changed, plan), undefined);
});

test('sealed fallback parsing requires the exact pair and bounded ordinary packet shape', () => {
  assert.equal(parseVaultTunnelFallbackBundle(packet, {} as any), undefined);
  for (const bad of [
    null,
    [],
    {},
    { ...packet, extra: 1 },
    { ...packet, binding: null },
    { ...packet, bundle: null },
  ])
    assert.equal(parseVaultTunnelFallbackBundle(bad, request), undefined);
  for (const side of ['primary', 'fallback'] as const) {
    for (const delta of [
      { rowVersion: '9223372036854775807' },
      { configurationVersion: '1' },
      { tunnelConfigId: request.nodeId },
    ]) {
      const changed = structuredClone(packet);
      Object.assign(changed.binding[side], delta);
      if (JSON.stringify(changed) === JSON.stringify(packet)) continue;
      assert.equal(parseVaultTunnelFallbackBundle(changed, request), undefined);
    }
  }
  for (const delta of [
    { formatVersion: 2 },
    { suiteId: 1 },
    { enc: 'bad' },
    { extra: 1 },
    { ciphertext: Buffer.alloc(16).toString('base64') },
    { ciphertext: Buffer.alloc(4 * 1024 * 1024 + 17).toString('base64') },
  ])
    assert.equal(
      parseVaultTunnelFallbackBundle(
        { ...packet, bundle: { ...packet.bundle, ...delta } },
        request,
      ),
      undefined,
    );
  assert.ok(
    parseVaultTunnelFallbackBundle(
      {
        ...packet,
        bundle: {
          ...packet.bundle,
          ciphertext: Buffer.alloc(4 * 1024 * 1024 + 16).toString('base64'),
        },
      },
      request,
    ),
  );
});

test('main fallback host retains workspace and owner authority around each native call without IPC exposure', async (t) => {
  // Native node coverage owns its profiler in coverage runs. The normal suite
  // measures the two changed host methods with the existing V8-block gate.
  const profiler =
    process.execArgv.includes('--experimental-test-coverage') || process.env.NODE_V8_COVERAGE
      ? undefined
      : new Session();
  if (profiler) {
    profiler.connect();
    t.after(() => profiler.disconnect());
    await profiler.post('Profiler.enable');
    await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  }
  for (const method of ['tunnelFallbackPlan', 'tunnelFallbackBundle'] as const) {
    const input = method === 'tunnelFallbackPlan' ? plan : request;
    const response = method === 'tunnelFallbackPlan' ? request.binding : packet;
    let calls = 0,
      allowed = true,
      delayed = false,
      bad = false;
    let resume!: () => void;
    const client: any = {
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      security: async () => ({ effective: 'default' }),
      lock: async () => {},
      [method]: async (q: unknown) => {
        calls++;
        assert.deepEqual(q, input);
        if (delayed)
          await new Promise<void>((resolve) => {
            resume = resolve;
          });
        return bad ? {} : response;
      },
    };
    const host = new VaultBackendHost(
      () => client,
      () => true,
    );
    await assert.rejects(host[method](null), /Invalid/);
    await assert.rejects(host[method](input), /locked/);
    await host.unlock({
      vaultId: plan.workspaceId,
      slotId: plan.nodeId,
      kind: 'password',
      factor: new Uint8Array([1]),
    });
    const foreign: any = structuredClone(input);
    foreign.workspaceId = plan.nodeId;
    if ('primary' in foreign) foreign.primary.workspaceId = plan.nodeId;
    else foreign.binding.primary.workspaceId = foreign.binding.fallback.workspaceId = plan.nodeId;
    await assert.rejects(host[method](foreign), /locked/);
    await assert.rejects(
      host[method](input, () => false),
      /locked/,
    );
    assert.equal(calls, 0);
    assert.deepEqual(await host[method](input), response);
    bad = true;
    await assert.rejects(host[method](input), /Invalid.*response/);
    bad = false;
    delayed = true;
    for (const stop of [false, true]) {
      allowed = true;
      const mutable = structuredClone(input),
        pending = host[method](mutable, () => allowed);
      mutable.nodeId = 'changed';
      await new Promise(setImmediate);
      if (stop) await host.stop();
      else allowed = false;
      resume();
      await assert.rejects(pending, /locked/);
    }
    const channels: string[] = [];
    registerVaultIpc({ handle: (name: string) => channels.push(name) } as any, host, () => true);
    assert.equal(
      channels.some((channel) => /fallback/.test(channel)),
      false,
    );
  }
  if (profiler) {
    const coverage = await profiler.post('Profiler.takePreciseCoverage');
    const ranges = coverage.result
      .filter((s) => s.url.endsWith('/electron/vault-host.ts'))
      .flatMap((s) => s.functions)
      .filter((f) => ['tunnelFallbackPlan', 'tunnelFallbackBundle'].includes(f.functionName))
      .flatMap((f) => f.ranges);
    assert.ok(ranges.length > 0);
    const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
    t.diagnostic(`fallback host: ${percent.toFixed(2)}% V8 blocks`);
    assert.ok(percent >= coverageThreshold);
  }
});
