import {
  parseVaultRoutedSshRequest,
  parseVaultRoutedSshBundle,
} from '../electron/vault-ssh-route.ts';
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseVaultConnectionRoute,
  validVaultRouteEndpoint,
  parseVaultRoutePlanRequest,
  parseVaultRouteBinding,
  parseVaultRouteRequest,
  parseVaultRouteBundle,
} from '../electron/vault-route.ts';
import { VaultBackendHost, registerVaultIpc } from '../electron/vault-host.ts';
const id = '11111111-1111-4111-8111-111111111111',
  other = '22222222-2222-4222-8222-222222222222';
const request = {
  workspaceId: id,
  nodeId: id,
  credentialOverride: '',
  sessionId: id,
  requestId: id,
  epoch: 1,
  publicKey: Buffer.alloc(32, 1).toString('base64'),
};
const binding = {
  workspaceId: id,
  fileId: other,
  nodeId: id,
  sessionId: id,
  requestId: id,
  epoch: 1,
  protocol: 'ssh',
  host: 'host.example',
  port: 22,
  tunnelConfigId: other,
  useExternalClient: false,
  kind: 1,
  rowVersion: '2',
  configurationVersion: '1',
};
const response = {
  binding,
  bundle: {
    formatVersion: 1,
    suiteId: 2,
    enc: request.publicKey,
    ciphertext: Buffer.alloc(32).toString('base64'),
  },
};
test('route handoff contract snapshots exact context and preserves full decimal revisions', () => {
  assert.deepEqual(parseVaultRouteRequest(request), request);
  assert.deepEqual(parseVaultRouteBundle(response, request), response);
  assert.ok(parseVaultRouteRequest({ ...request, credentialOverride: other }));
  for (const protocol of ['ssh', 'sftp', 'rdp', 'vnc', 'http', 'https'])
    for (let kind = 0; kind <= 8; kind++)
      assert.ok(
        parseVaultRouteBundle({ ...response, binding: { ...binding, protocol, kind } }, request),
      );
  const large = {
    ...response,
    binding: {
      ...binding,
      rowVersion: '9223372036854775807',
      configurationVersion: '9223372036854775807',
    },
  };
  assert.deepEqual(parseVaultRouteBundle(large, request), large);
  for (const bad of [
    null,
    {},
    [],
    { ...request, extra: 1 },
    ...[
      'workspaceId',
      'nodeId',
      'sessionId',
      'requestId',
      'credentialOverride',
      'publicKey',
      'epoch',
    ].map((key) => ({ ...request, [key]: 'bad' })),
    { ...request, epoch: 0 },
    { ...request, epoch: 2 ** 53 },
  ])
    assert.equal(parseVaultRouteRequest(bad), undefined);
  assert.equal(parseVaultRouteBundle(response, { ...request, epoch: 0 }), undefined);
  for (const bad of [
    null,
    [],
    {},
    { ...response, extra: 1 },
    { ...response, binding: null },
    { ...response, bundle: null },
    { ...response, binding: { ...binding, extra: 1 } },
    { ...response, bundle: { ...response.bundle, extra: 1 } },
  ])
    assert.equal(parseVaultRouteBundle(bad, request), undefined);
  for (const delta of [
    ...['workspaceId', 'nodeId', 'sessionId', 'requestId', 'fileId', 'tunnelConfigId'].map(
      (key) => ({ [key]: 'bad' }),
    ),
    { epoch: 2 },
    { protocol: 'serial' },
    { host: '' },
    { host: 'bad host' },
    { host: 'a\0b' },
    { host: 'x'.repeat(1025) },
    { port: 0 },
    { port: 65536 },
    { port: 1.5 },
    { port: '22' },
    { useExternalClient: true },
    { kind: -1 },
    { kind: 10 },
    { kind: 1.5 },
    { kind: '1' },
    { rowVersion: '0' },
    { rowVersion: '01' },
    { rowVersion: '9223372036854775808' },
    { rowVersion: 1 },
    { configurationVersion: '0' },
    { configurationVersion: '3' },
    { configurationVersion: 'bad' },
  ])
    assert.equal(
      parseVaultRouteBundle({ ...response, binding: { ...binding, ...delta } }, request),
      undefined,
      JSON.stringify(delta),
    );
  for (const delta of [
    { formatVersion: 2 },
    { suiteId: 1 },
    { enc: 'bad' },
    { ciphertext: Buffer.alloc(16).toString('base64') },
    { ciphertext: Buffer.alloc(4 * 1024 * 1024 + 17).toString('base64') },
    { ciphertext: 'bad' },
  ])
    assert.equal(
      parseVaultRouteBundle({ ...response, bundle: { ...response.bundle, ...delta } }, request),
      undefined,
    );
  assert.ok(
    parseVaultRouteBundle(
      {
        ...response,
        bundle: {
          ...response.bundle,
          ciphertext: Buffer.alloc(4 * 1024 * 1024 + 16).toString('base64'),
        },
      },
      request,
    ),
  );
  const value = structuredClone(response),
    parsed = parseVaultRouteBundle(value, request)!;
  value.binding.host = 'changed';
  value.bundle.enc = 'changed';
  assert.equal(parsed.binding.host, 'host.example');
  assert.equal(parsed.bundle.enc, request.publicKey);
});
test('main route host checks workspace and current authority before and after native release', async () => {
  let release!: () => void,
    delayed = false,
    allowed = true,
    calls = 0;
  const client: any = {
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    security: async () => ({ effective: 'default' }),
    lock: async () => {},
    tunnelBundle: async (value: any) => {
      calls++;
      assert.deepEqual(value, request);
      if (delayed) await new Promise<void>((r) => (release = r));
      return response;
    },
  };
  const host = new VaultBackendHost(
      () => client,
      () => true,
    ),
    factor = () => ({ vaultId: id, slotId: other, kind: 'password', factor: new Uint8Array([1]) });
  await assert.rejects(host.tunnelBundle(null), /Invalid/);
  await assert.rejects(host.tunnelBundle(request), /locked/);
  await host.unlock(factor());
  await assert.rejects(host.tunnelBundle({ ...request, workspaceId: other }), /locked/);
  await assert.rejects(
    host.tunnelBundle(request, () => false),
    /locked/,
  );
  assert.equal(calls, 0);
  assert.deepEqual(await host.tunnelBundle(request), response);
  const channels: string[] = [];
  registerVaultIpc({ handle: (name: string) => channels.push(name) } as any, host, () => true);
  assert.ok(!channels.includes('vault:tunnel-bundle'));
  delayed = true;
  for (const stop of [false, true]) {
    allowed = true;
    const input = { ...request },
      pending = host.tunnelBundle(input, () => allowed);
    input.nodeId = 'changed';
    await new Promise(setImmediate);
    if (stop) await host.stop();
    else allowed = false;
    release();
    await assert.rejects(pending, /locked/);
  }
});

test('route plans contain only current context and host checks authority around native resolution', async () => {
  const { publicKey: _, ...q } = request;
  assert.deepEqual(parseVaultRoutePlanRequest(q), q);
  assert.deepEqual(parseVaultRouteBinding(binding, q), binding);
  assert.equal(parseVaultRoutePlanRequest(request), undefined);
  assert.equal(parseVaultRouteBinding(binding, request), undefined);
  for (const bad of [
    null,
    {},
    { ...q, epoch: 0 },
    { ...q, epoch: 2 ** 53 },
    { ...q, credentialOverride: 'bad' },
    { ...q, nodeId: other, extra: 1 },
  ])
    assert.equal(parseVaultRoutePlanRequest(bad), undefined);
  let release!: () => void,
    delayed = false,
    allowed = true;
  const client: any = {
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    security: async () => ({ effective: 'default' }),
    lock: async () => {},
    tunnelPlan: async (value: any) => {
      assert.deepEqual(value, q);
      if (delayed) await new Promise<void>((r) => (release = r));
      return binding;
    },
  };
  const host = new VaultBackendHost(
    () => client,
    () => true,
  );
  const factor = () => ({
    vaultId: id,
    slotId: other,
    kind: 'password',
    factor: new Uint8Array([1]),
  });
  await assert.rejects(host.tunnelPlan(null), /Invalid/);
  await assert.rejects(host.tunnelPlan(q), /locked/);
  await host.unlock(factor());
  await assert.rejects(host.tunnelPlan({ ...q, workspaceId: other }), /locked/);
  await assert.rejects(
    host.tunnelPlan(q, () => false),
    /locked/,
  );
  assert.deepEqual(await host.tunnelPlan(q), binding);
  const channels: string[] = [];
  registerVaultIpc({ handle: (name: string) => channels.push(name) } as any, host, () => true);
  assert.ok(!channels.includes('vault:tunnel-plan'));
  delayed = true;
  for (const stop of [false, true]) {
    allowed = true;
    const input = { ...q },
      pending = host.tunnelPlan(input, () => allowed);
    input.nodeId = 'changed';
    await new Promise(setImmediate);
    if (stop) await host.stop();
    else allowed = false;
    release();
    await assert.rejects(pending, /locked/);
  }
});

test('routed SSH contract binds the exact VPN revision and canonical endpoint', () => {
  const q = { ...request, route: binding, endpoint: '127.0.0.1:12345' };
  const result = { ...response, endpoint: q.endpoint };
  assert.deepEqual(parseVaultRoutedSshRequest(q), q);
  assert.deepEqual(parseVaultRoutedSshBundle(result, q), result);
  for (const endpoint of [
    null,
    '',
    'localhost:12345',
    '127.0.0.1:0',
    '127.0.0.1:65536',
    '127.0.0.1:0123',
    '127.0.0.1:+123',
    '[::1]:123',
    '192.0.2.1:123',
  ]) {
    assert.equal(validVaultRouteEndpoint(endpoint), false);
    assert.equal(parseVaultRoutedSshRequest({ ...q, endpoint }), undefined);
  }
  for (const endpoint of ['127.0.0.1:1', '127.0.0.1:65535'])
    assert.equal(validVaultRouteEndpoint(endpoint), true);
  for (const bad of [
    null,
    {},
    { ...q, extra: 1 },
    { ...q, route: null },
    { ...q, route: { ...binding, protocol: 'rdp' } },
  ])
    assert.equal(parseVaultRoutedSshRequest(bad), undefined);
  for (const bad of [
    null,
    {},
    { ...result, extra: 1 },
    { ...result, endpoint: '127.0.0.1:23456' },
    { ...result, bundle: {} },
    ...['host', 'fileId', 'tunnelConfigId', 'kind', 'rowVersion', 'configurationVersion'].map(
      (field) => ({
        ...result,
        binding: {
          ...binding,
          [field]:
            field === 'kind'
              ? 2
              : field.endsWith('Version')
                ? '3'
                : field.endsWith('Id')
                  ? id
                  : 'changed.example',
        },
      }),
    ),
  ])
    assert.equal(parseVaultRoutedSshBundle(bad, q), undefined);
  assert.equal(parseVaultRoutedSshBundle(result, { ...q, epoch: 0 }), undefined);
  const source = structuredClone(q),
    snapshot = parseVaultRoutedSshRequest(source)!;
  source.route.host = 'changed.example';
  assert.equal(snapshot.route.host, 'host.example');
  const { publicKey: _, ...plan } = request;
  assert.equal(parseVaultConnectionRoute(null, plan), null);
  assert.equal(parseVaultConnectionRoute(undefined, plan), undefined);
  assert.equal(parseVaultConnectionRoute(null, request), undefined);
  assert.deepEqual(parseVaultConnectionRoute(binding, plan), binding);
});

test('main-only SSH route methods reject stale authority and snapshot nested context', async () => {
  const { publicKey: _, ...plan } = request;
  const q = { ...request, route: binding, endpoint: '127.0.0.1:12345' };
  for (const method of ['connectionRoute', 'routedSshBundle'] as const) {
    const input = method === 'connectionRoute' ? plan : q;
    const output = method === 'connectionRoute' ? binding : { ...response, endpoint: q.endpoint };
    let release!: () => void,
      delayed = false,
      allowed = true,
      calls = 0;
    const client: any = {
      unlock: async () => ({ unlocked: true, lockedMemory: true }),
      security: async () => ({ effective: 'default' }),
      lock: async () => {},
      [method]: async (value: any) => {
        calls++;
        if (delayed) await new Promise<void>((r) => (release = r));
        assert.deepEqual(value, input);
        return output;
      },
    };
    const host = new VaultBackendHost(
      () => client,
      () => true,
    );
    await assert.rejects(host[method](null), /Invalid/);
    await assert.rejects(host[method](input), /locked/);
    await host.unlock({
      vaultId: id,
      slotId: other,
      kind: 'password',
      factor: new Uint8Array([1]),
    });
    await assert.rejects(
      host[method]({
        ...input,
        workspaceId: other,
        ...('route' in input ? { route: { ...input.route, workspaceId: other } } : {}),
      }),
      /locked/,
    );
    await assert.rejects(
      host[method](input, () => false),
      /locked/,
    );
    assert.equal(calls, 0);
    assert.deepEqual(await host[method](input), output);
    const channels: string[] = [];
    registerVaultIpc({ handle: (name: string) => channels.push(name) } as any, host, () => true);
    assert.ok(!channels.some((name) => /connection-route|ssh-route-bundle/.test(name)));
    delayed = true;
    for (const stop of [false, true]) {
      allowed = true;
      const mutable = structuredClone(input),
        pending = host[method](mutable, () => allowed);
      mutable.nodeId = 'changed';
      if ('route' in mutable) mutable.route.host = 'changed';
      await new Promise(setImmediate);
      if (stop) await host.stop();
      else allowed = false;
      release();
      await assert.rejects(pending, /locked/);
    }
  }
});
test('routed SFTP ciphertext is bound to its exact protocol', () => {
  const route = { ...binding, protocol: 'sftp' as const };
  const q = { ...request, route, endpoint: '127.0.0.1:12345' };
  const result = { ...response, binding: route, endpoint: q.endpoint };
  assert.deepEqual(parseVaultRoutedSshRequest(q), q);
  assert.deepEqual(parseVaultRoutedSshBundle(result, q), result);
  assert.equal(parseVaultRoutedSshBundle({ ...result, binding }, q), undefined);
});
test('routed file mode survives parsing and cannot be injected or stripped', () => {
  const q = { ...request, route: binding, endpoint: '127.0.0.1:12345', sftpOnly: true as const };
  const result = { ...response, endpoint: q.endpoint, sftpOnly: true as const };
  assert.deepEqual(parseVaultRoutedSshRequest(q), q);
  assert.deepEqual(parseVaultRoutedSshBundle(result, q), result);
  for (const sftpOnly of [undefined, false, null, 'true', 1]) {
    assert.equal(parseVaultRoutedSshBundle({ ...result, sftpOnly }, q), undefined);
    if (sftpOnly !== undefined)
      assert.equal(parseVaultRoutedSshRequest({ ...q, sftpOnly }), undefined);
  }
  assert.equal(parseVaultRoutedSshBundle(result, { ...q, sftpOnly: undefined }), undefined);
});
