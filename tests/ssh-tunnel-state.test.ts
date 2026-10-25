import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { TunnelFailureRegistry, tunnelClosedMessage } from '../electron/tunnel-failure.ts';
import { sshJumpCandidates, type JumpNode } from '../src/ssh-tunnel-state.ts';
import {
  missingTunnelFields,
  normalizeTunnelEditorSettings,
  updateTunnelEditorSetting,
} from '../src/tunnel-state.ts';
import {
  parseSSHJumpSettings,
  parseTunnelDetailsResponse,
} from '../electron/tunnel-test-contract.ts';

const id = '11111111-1111-4111-8111-111111111111';
const credential = '22222222-2222-4222-8222-222222222222';
const pin = 'SHA256:' + 'A'.repeat(43);

test('tunnel failure dispatch disconnects current dependents once and ignores released or stale leases', () => {
  const registry = new TunnelFailureRegistry();
  const closed: string[] = [];
  for (const protocol of ['ssh', 'rdp', 'vnc', 'web'])
    registry.watch(protocol, () => closed.push(protocol));
  registry.watch('unused');
  registry.watch('throws', () => {
    throw new Error('closed owner');
  });
  registry.fail({ type: 'tunnel.failed', sessionId: 'throws' });
  registry.watch('throws-all', () => {
    throw new Error('closed owner');
  });
  for (const bad of [
    null,
    {},
    { type: 'bad', sessionId: 'ssh' },
    { type: 'tunnel.failed', sessionId: 'x'.repeat(129) },
    { type: 'tunnel.failed', sessionId: 'bad\n' },
  ])
    assert.equal(registry.fail(bad), false);
  assert.equal(
    registry.fail({ type: 'tunnel.failed', sessionId: 'ssh', message: 'untrusted' }),
    true,
  );
  registry.fail({ type: 'tunnel.failed', sessionId: 'ssh' });
  registry.forget('rdp');
  registry.fail({ type: 'tunnel.failed', sessionId: 'rdp' });
  registry.failAll();
  registry.failAll();
  assert.deepEqual(closed, ['ssh', 'vnc', 'web']);
  assert.match(tunnelClosedMessage, /disconnected/);
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  // Process entrypoints are covered by scoped source contracts, with the dispatcher executed above.
  for (const start of [
    'const tunnelRoute = await openingTunnelBackend.acquireTunnelRoute({',
    'socksEndpoint = await getNativeBackend().acquireTunnel({',
    'route = await getNativeBackend().acquireTunnelRoute({',
  ]) {
    const block = main.slice(main.indexOf(start), main.indexOf(start) + 2000);
    assert.match(block, /onExit:/);
    assert.match(block, /isActive\(/);
    assert.match(block, /tunnelClosedMessage/);
  }
});

test('SSH editor modes retain only references and reset trust on endpoint changes', () => {
  const manual = normalizeTunnelEditorSettings(7, {
    Mode: 'manual',
    Host: ' bastion.test ',
    Port: '22',
    Username: ' ops ',
    CredentialId: credential,
    HostKeySha256: ' ',
    KeepaliveSeconds: '30',
    Password: 'must-drop',
  });
  assert.deepEqual(manual, {
    Mode: 'manual',
    Host: 'bastion.test',
    Port: 22,
    Username: 'ops',
    CredentialId: credential,
    KeepaliveSeconds: 30,
  });
  assert.deepEqual(missingTunnelFields({ name: 'jump', kind: 7, settings: manual }), []);
  const connection = normalizeTunnelEditorSettings(7, {
    ...manual,
    Mode: 'connection',
    JumpConnectionId: ' ' + id + ' ',
    HostKeySha256: pin,
  });
  assert.deepEqual(connection, { Mode: 'connection', JumpConnectionId: id, KeepaliveSeconds: 30 });
  assert.deepEqual(missingTunnelFields({ name: 'jump', kind: 7, settings: connection }), []);
  for (const key of ['Host', 'Port', 'Username', 'CredentialId'])
    assert.equal(
      updateTunnelEditorSetting(7, { ...manual, HostKeySha256: pin }, key, 'new').HostKeySha256,
      undefined,
    );
  assert.equal(
    updateTunnelEditorSetting(7, { ...manual, HostKeySha256: pin }, 'Host', manual.Host)
      .HostKeySha256,
    pin,
  );
  assert.deepEqual(updateTunnelEditorSetting(7, manual, 'Mode', 'connection'), {
    Mode: 'connection',
    KeepaliveSeconds: 30,
  });
  assert.deepEqual(updateTunnelEditorSetting(7, {}, 'Mode', 'manual'), {
    Mode: 'manual',
    KeepaliveSeconds: 30,
    Port: 22,
  });
  assert.ok(
    missingTunnelFields({
      name: '',
      kind: 7,
      settings: { Mode: 'manual', Port: 0, KeepaliveSeconds: 0 },
    }).length >= 5,
  );
  assert.deepEqual(missingTunnelFields({ name: 'x', kind: 7, settings: { Mode: 'connection' } }), [
    'SSH connection',
  ]);
  assert.deepEqual(missingTunnelFields({ name: 'x', kind: 7, settings: {} }), ['SSH tunnel mode']);
});

test('SSH IPC rejects secrets, invalid references, endpoint bounds and incompatible modes', () => {
  const manual = {
    Mode: 'manual',
    Host: 'bastion.test',
    Port: 22,
    Username: 'ops',
    CredentialId: credential,
    HostKeySha256: pin,
  };
  assert.equal(parseSSHJumpSettings(manual), manual);
  assert.deepEqual(
    parseTunnelDetailsResponse({
      id,
      name: 'jump',
      kind: 7,
      settings: { Mode: 'connection', JumpConnectionId: credential },
      jumpHostKeySha256: pin,
    }).jumpHostKeySha256,
    pin,
  );
  for (const bad of [
    null,
    [],
    {},
    { Mode: 'connection', JumpConnectionId: 'bad' },
    { Mode: 'connection', JumpConnectionId: id, Host: 'override' },
    ...[
      { Password: 'secret' },
      { Host: 'bad\n' },
      { Port: 0 },
      { Port: 65536 },
      { Username: '' },
      { Username: '\0' },
      { CredentialId: 'bad' },
      { HostKeySha256: 'bad' },
      { KeepaliveSeconds: 0 },
      { KeepaliveSeconds: 3601 },
      { JumpConnectionId: id },
      { Host: 'x'.repeat(9000) },
    ].map((value) => ({ ...manual, ...value })),
  ])
    assert.throws(() => parseSSHJumpSettings(bad));
  assert.throws(() =>
    parseTunnelDetailsResponse({
      id,
      name: 'jump',
      kind: 7,
      settings: manual,
      jumpHostKeySha256: 'bad',
    }),
  );
});

test('blank optional SSH keepalive uses the default while invalid values remain blocked', () => {
  const connection = { Mode: 'connection', JumpConnectionId: id };
  for (const KeepaliveSeconds of [undefined, '', '   ']) {
    const settings = { ...connection, KeepaliveSeconds };
    assert.deepEqual(missingTunnelFields({ name: 'Jump', kind: 7, settings }), []);
    const normalized = normalizeTunnelEditorSettings(7, settings);
    assert.deepEqual(normalized, connection);
    assert.deepEqual(parseSSHJumpSettings(normalized), connection);
  }
  for (const KeepaliveSeconds of [0, 3601, 1.5, null, [], {}]) {
    assert.deepEqual(
      missingTunnelFields({ name: 'Jump', kind: 7, settings: { ...connection, KeepaliveSeconds } }),
      ['Keepalive (1-3600 seconds)'],
    );
  }
  for (const KeepaliveSeconds of [1, 3600]) {
    assert.deepEqual(
      missingTunnelFields({ name: 'Jump', kind: 7, settings: { ...connection, KeepaliveSeconds } }),
      [],
    );
  }
});

test('jump picker respects inheritance, rejects cycles, missing routes and excessive depth', () => {
  const nodes: JumpNode[] = [
    { id: 'direct', name: 'Direct', kind: 'connection', protocol: 'ssh' },
    {
      id: 'folder',
      name: 'Folder',
      kind: 'folder',
      protocol: 'ssh',
      tunnelEnabled: true,
      tunnelConfigId: 'vpn',
      children: [
        { id: 'inherited', name: 'Inherited', kind: 'connection' },
        { id: 'off', name: 'Off', kind: 'connection', tunnelEnabled: false },
      ],
    },
    {
      id: 'cycle',
      name: 'Cycle',
      kind: 'connection',
      protocol: 'ssh',
      tunnelEnabled: true,
      tunnelConfigId: 'editing',
    },
    {
      id: 'missing',
      name: 'Missing',
      kind: 'connection',
      protocol: 'ssh',
      tunnelEnabled: true,
      tunnelConfigId: 'gone',
    },
    { id: 'rdp', name: 'RDP', kind: 'connection', protocol: 'rdp' },
    {
      id: 'via',
      name: 'Via',
      kind: 'connection',
      protocol: 'ssh',
      tunnelEnabled: true,
      tunnelConfigId: 'jump',
    },
    {
      id: 'deep',
      name: 'Deep',
      kind: 'connection',
      protocol: 'ssh',
      tunnelEnabled: true,
      tunnelConfigId: 'nested',
    },
  ];
  const catalog = {
    vpn: null,
    jump: { Mode: 'connection', JumpConnectionId: 'inherited' },
    nested: { Mode: 'connection', JumpConnectionId: 'via' },
  };
  assert.deepEqual(
    sshJumpCandidates(nodes, 'editing', catalog).map((option) => option.value),
    ['direct', 'inherited', 'off', 'via'],
  );
  assert.deepEqual(
    sshJumpCandidates(nodes, 'editing', {
      ...catalog,
      jump: { Mode: 'connection', JumpConnectionId: 'via' },
    }).map((option) => option.value),
    ['direct', 'inherited', 'off'],
  );
  assert.equal(
    sshJumpCandidates(nodes, undefined, { ...catalog, jump: { Mode: 'manual' } }).some(
      (item) => item.value === 'via',
    ),
    true,
  );
  assert.equal(
    sshJumpCandidates(nodes, undefined, {
      ...catalog,
      jump: { Mode: 'connection', JumpConnectionId: 'rdp' },
    }).some((item) => item.value === 'via'),
    false,
  );
});

test('jump picker resolves route enablement and references independently like the backend', () => {
  const nodes: JumpNode[] = [
    {
      id: 'folder',
      name: 'Folder',
      kind: 'folder',
      protocol: 'ssh',
      tunnelEnabled: false,
      tunnelConfigId: 'editing',
      children: [
        { id: 'disabled', name: 'Disabled', kind: 'connection' },
        { id: 'cycle', name: 'Cycle', kind: 'connection', tunnelEnabled: true },
        { id: 'local', name: 'Local', kind: 'connection', tunnelConfigId: 'missing' },
        {
          id: 'enabled',
          name: 'Enabled',
          kind: 'connection',
          tunnelEnabled: true,
          tunnelConfigId: 'vpn',
        },
      ],
    },
    {
      id: 'invalid',
      name: 'Invalid',
      kind: 'connection',
      protocol: 'ssh',
      tunnelEnabled: true,
    },
  ];
  assert.deepEqual(
    sshJumpCandidates(nodes, 'editing', { vpn: null }).map(({ value }) => value),
    ['disabled', 'enabled', 'local'],
  );
});
