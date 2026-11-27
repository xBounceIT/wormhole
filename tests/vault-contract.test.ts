import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseVaultDescription,
  parseVaultDescriptor,
  parseVaultHeartbeat,
  parseVaultResponse,
  parseVaultCatalogEvent,
  parseVaultStatus,
  parseVaultCatalog,
  parseVaultStartup,
} from '../electron/vault-contract.ts';

const status = {
  formatVersion: 1,
  stage: 'foundation',
  protectionAvailable: false,
  sharedWorkspaceAvailable: false,
  unlocked: false,
  lockedMemory: false,
} as const;

test('catalog event envelope is canonical, bounded and contains no payload', () => {
  const valid = { version: 1, id: 0, event: 'shared-catalog-changed' };
  assert.equal(parseVaultCatalogEvent(JSON.stringify(valid)), true);
  for (const value of [
    null,
    {},
    { ...valid, id: 1 },
    { ...valid, version: 2 },
    { ...valid, event: 'other' },
    { ...valid, result: {} },
    { ...valid, error: 'secret' },
  ])
    assert.equal(parseVaultCatalogEvent(JSON.stringify(value)), undefined);
  for (const text of [
    'x'.repeat(129),
    ' {"version":1,"id":0,"event":"shared-catalog-changed"}',
    '{"version":1,"id":0,"id":0,"event":"shared-catalog-changed"}',
  ])
    assert.equal(parseVaultCatalogEvent(text), undefined);
});
const uuid = '11111111-1111-4111-8111-111111111111';
const recovery = '22222222-2222-4222-8222-222222222222';
const descriptor = {
  formatVersion: 1,
  vaultId: uuid,
  encrypted: false,
  slots: [
    { id: uuid, kind: 'password', preset: 'kdf-v1' },
    { id: recovery, kind: 'recovery' },
  ],
};

test('pending migration exposes only recovery slot hints and cannot select shared or empty mode', () => {
  const value = {
    slots: descriptor,
    cosmetics: { theme: 'dark' },
    newWorkspace: false,
    migration: { pending: true },
  };
  const parsed = parseVaultStartup(value)!;
  assert.deepEqual(parsed, value);
  assert.notEqual(parsed.migration, value.migration);
  for (const bad of [
    { ...value, slots: null },
    { ...value, slots: { ...descriptor, encrypted: true } },
    { ...value, newWorkspace: true },
    { ...value, shared: { lastLoginName: 'alice', serverDisplayName: 'Team' } },
    ...[null, undefined, {}, { pending: false }, { pending: true, path: 'private' }].map(
      (migration) => ({ ...value, migration }),
    ),
  ])
    assert.equal(parseVaultStartup(bad), undefined);
});

test('shared startup exposes only bounded login and server display hints', () => {
  const value = {
    slots: { ...descriptor, encrypted: true },
    cosmetics: { theme: 'system' },
    newWorkspace: false,
    shared: { lastLoginName: 'alice', serverDisplayName: 'Team workspace' },
  };
  const parsed = parseVaultStartup(value)!;
  assert.deepEqual(parsed, value);
  assert.notEqual(parsed.shared, value.shared);
  for (const shared of [
    null,
    undefined,
    {},
    { ...value.shared, policy: {} },
    { ...value.shared, lastLoginName: '' },
    { ...value.shared, serverDisplayName: '' },
    { ...value.shared, lastLoginName: 7 },
    { ...value.shared, serverDisplayName: 'é'.repeat(129) },
    { ...value.shared, lastLoginName: 'a'.repeat(257) },
    { ...value.shared, serverDisplayName: 'a\nname' },
    { ...value.shared, lastLoginName: 'a\u0085name' },
    { ...value.shared, serverDisplayName: '\ud800' },
  ]) {
    assert.equal(parseVaultStartup({ ...value, shared }), undefined);
  }
  for (const bad of [
    { ...value, slots: null },
    { ...value, slots: descriptor },
    { ...value, newWorkspace: true },
    { ...value, policy: {} },
  ]) {
    assert.equal(parseVaultStartup(bad), undefined);
  }
});

test('startup accepts only public slot hints and an exact cosmetic allowlist', () => {
  for (const theme of ['system', 'light', 'dark']) {
    for (const slots of [null, descriptor]) {
      const value = { slots, cosmetics: { theme }, newWorkspace: slots === null };
      const parsed = parseVaultStartup(value)!;
      assert.deepEqual(parsed, value);
      assert.notEqual(parsed.cosmetics, value.cosmetics);
      if (slots) assert.notEqual(parsed.slots, slots);
    }
  }
  for (const value of [
    { slots: descriptor, cosmetics: { theme: 'dark' }, newWorkspace: true },
    { slots: null, cosmetics: { theme: 'dark' }, newWorkspace: 'true' },
    null,
    [],
    {},
    { slots: null },
    { slots: {}, cosmetics: { theme: 'system' } },
    { slots: null, cosmetics: null },
    { slots: null, cosmetics: {} },
    { slots: null, cosmetics: { theme: 0 } },
    { slots: null, cosmetics: { theme: 'unknown' } },
    { slots: null, cosmetics: { theme: 'dark', idleTimeoutMinutes: 0 } },
    { slots: null, cosmetics: { theme: 'dark' }, workspace: {} },
    { slots: { ...descriptor, rootKey: 'private' }, cosmetics: { theme: 'dark' } },
  ]) {
    assert.equal(parseVaultStartup(value), undefined);
  }
});

test('vault status exposes only the supported capability and memory state', () => {
  assert.deepEqual(parseVaultStatus(status), status);
  assert.deepEqual(parseVaultStatus({ ...status, unlocked: true, lockedMemory: true }), {
    ...status,
    unlocked: true,
    lockedMemory: true,
  });
  for (const value of [
    null,
    [],
    {},
    { ...status, formatVersion: 2 },
    { ...status, stage: 'unknown' },
    { ...status, protectionAvailable: true },
    { ...status, sharedWorkspaceAvailable: true },
    { ...status, unlocked: 1 },
    { ...status, lockedMemory: 'yes' },
    { ...status, lockedMemory: true },
    { ...status, password: 'must-not-pass' },
  ])
    assert.equal(parseVaultStatus(value), undefined);
});

test('vault descriptors project only bounded public slot metadata', () => {
  assert.deepEqual(parseVaultDescriptor(descriptor), descriptor);
  assert.deepEqual(parseVaultDescription({ slots: descriptor }), descriptor);

  const v2 = { ...descriptor, formatVersion: 2 };
  assert.deepEqual(parseVaultDescriptor(v2), v2);
  assert.deepEqual(parseVaultDescription({ slots: v2 }), v2);
  const v3 = { ...descriptor, formatVersion: 3 };
  assert.deepEqual(parseVaultDescriptor(v3), v3);
  assert.deepEqual(parseVaultDescription({ slots: v3 }), v3);
  assert.equal(parseVaultDescriptor({ ...v2, vpnSso: [] }), undefined);
  assert.equal(parseVaultDescriptor({ ...v2, tunnels: [] }), undefined);
  assert.equal(parseVaultDescription({ slots: null }), null);
  assert.equal(parseVaultDescription({ slots: null, password: 'secret' }), undefined);
  assert.equal(parseVaultDescription([]), undefined);
  const projected = parseVaultDescriptor(descriptor)!;
  assert.notEqual(projected, descriptor);
  assert.notEqual(projected.slots, descriptor.slots);
  for (const preset of ['kdf-low', 'kdf-v1', 'kdf-v2', 'kdf-v3'])
    assert.ok(
      parseVaultDescriptor({ ...descriptor, slots: [{ id: uuid, kind: 'password', preset }] }),
    );
  for (const value of [
    undefined,
    [],
    {},
    { ...descriptor, formatVersion: 4 },
    { ...descriptor, vaultId: uuid.toUpperCase().replace('1', 'A') },
    { ...descriptor, vaultId: '00000000-0000-0000-0000-000000000000' },
    { ...descriptor, encrypted: 1 },
    { ...descriptor, slots: [] },
    { ...descriptor, slots: Array(17).fill(descriptor.slots[0]) },
    { ...descriptor, slots: [descriptor.slots[0], descriptor.slots[0]] },
    { ...descriptor, slots: [null] },
    { ...descriptor, slots: [{ id: uuid, kind: 'hello' }] },
    { ...descriptor, slots: [{ id: uuid, kind: 'password', preset: 'unknown' }] },
    { ...descriptor, slots: [{ id: recovery, kind: 'recovery', preset: '' }] },
    { ...descriptor, slots: [{ ...descriptor.slots[0], wrappedKey: 'secret' }] },
    { ...descriptor, rootKeyId: uuid },
  ])
    assert.equal(parseVaultDescriptor(value), undefined);
});

test('Hello slot hints preserve a software fallback and expose only the slot identifier', () => {
  const hello = { id: 'a2345678-1234-4234-8234-123456789abc', kind: 'hello' };
  const versioned = { ...descriptor, formatVersion: 5, slots: [...descriptor.slots, hello] };
  assert.deepEqual(parseVaultDescriptor(versioned), versioned);
  for (const candidate of [
    { ...versioned, formatVersion: 3 },
    { ...versioned, slots: [hello] },
    { ...versioned, slots: [...versioned.slots, { ...hello, id: descriptor.vaultId }] },
    { ...versioned, slots: [...descriptor.slots, { ...hello, publicKeyHash: 'unexpected' }] },
  ]) {
    assert.equal(parseVaultDescriptor(candidate), undefined);
  }
});

test('v6 and v7 slot hints support Touch ID and Windows Hello with a software fallback', () => {
  const hello = { id: 'a2345678-1234-4234-8234-123456789abc', kind: 'hello' };
  const touchID = { id: 'a2345678-1234-4234-8234-123456789abd', kind: 'touch-id' };
  const versioned = {
    ...descriptor,
    formatVersion: 6,
    slots: [...descriptor.slots, hello, touchID],
  };
  assert.deepEqual(parseVaultDescriptor(versioned), versioned);
  const current = { ...versioned, formatVersion: 7 };
  assert.deepEqual(parseVaultDescriptor(current), current);
  for (const candidate of [
    { ...versioned, formatVersion: 5 },
    { ...current, formatVersion: 8 },
    { ...current, slots: [...descriptor.slots, { ...hello, attestation: 'tpm-verified' }] },
    { ...versioned, slots: [hello, touchID] },
    { ...versioned, slots: [...versioned.slots, { ...touchID, id: descriptor.vaultId }] },
    { ...versioned, slots: [...descriptor.slots, { ...touchID, factor: 'unexpected' }] },
  ])
    assert.equal(parseVaultDescriptor(candidate), undefined);
});

test('pending root rotation exposes only new v3 slot hints and excludes other startup modes', () => {
  const value = {
    slots: { ...descriptor, formatVersion: 3 },
    cosmetics: { theme: 'system' },
    newWorkspace: false,
    rotation: { pending: true },
  };
  assert.deepEqual(parseVaultStartup(value), value);
  const encrypted = { ...value, slots: { ...value.slots, encrypted: true } };
  assert.deepEqual(parseVaultStartup(encrypted), encrypted);
  for (const bad of [
    { ...value, slots: null },
    { ...value, slots: { ...value.slots, formatVersion: 2 } },
    { ...value, newWorkspace: true },
    { ...value, migration: { pending: true } },
    { ...value, shared: { lastLoginName: 'user', serverDisplayName: 'server' } },
    { ...value, rotation: null },
    { ...value, rotation: { pending: false } },
    { ...value, rotation: { pending: true, sourcePath: 'private' } },
    { ...value, rootKey: new Uint8Array(32) },
  ])
    assert.equal(parseVaultStartup(bad), undefined);
});

test('vault framing rejects noncanonical IDs, duplicate keys and raw diagnostics', () => {
  assert.deepEqual(parseVaultResponse('{"version":1,"id":1,"result":null}'), {
    id: 1,
    result: null,
  });
  for (const error of [
    'vault_busy',
    'vault_cancelled',
    'vault_operation_failed',
    'vault_invalid_response',
  ])
    assert.deepEqual(parseVaultResponse(JSON.stringify({ version: 1, id: 2, error })), {
      id: 2,
      error,
    });
  for (const raw of [
    '{',
    'null',
    '[]',
    '{}',
    '{"version":2,"id":1,"result":null}',
    '{"version":1,"id":0,"result":null}',
    '{"version":1,"id":9007199254740992,"result":null}',
    '{"version":1,"id":1.00000000000000001,"result":null}',
    '{"version":1,"id":1,"id":2,"result":null}',
    '{"version":1,"id":1,"\\u0069d":2,"result":null}',
    '{"version":1,"id":1,"result":null,"error":"vault_busy"}',
    '{"version":1,"id":1,"error":"private path password=secret"}',
    '{"version":1,"id":1,"error":["vault_busy"]}',
    '{"version":1,"id":1,"result":null,"extra":true}',
  ])
    assert.equal(parseVaultResponse(raw), undefined);
  assert.equal(parseVaultHeartbeat({ alive: true }), true);
  for (const value of [null, {}, { alive: false }, { alive: true, key: 'secret' }])
    assert.equal(parseVaultHeartbeat(value), undefined);
});

const catalogNode = {
  id: uuid,
  parentId: null,
  name: 'Node <&> 日本語\u2028😀',
  kind: 1,
  sortOrder: '-9223372036854775808',
  protocol: null,
  host: null,
  port: null,
  username: null,
  rowVersion: '9223372036854775807',
  hasNotes: true,
  hasInlinePassword: false,
};
const catalogCredential = {
  id: uuid,
  name: 'Account',
  protocol: 'ssh',
  kind: 'password',
  username: '',
  domain: '',
  provider: 'local',
  rowVersion: '1',
};
const catalogTunnel = { id: uuid, name: 'VPN', kind: 8, rowVersion: '1' };
const catalog = {
  nodes: [catalogNode],
  credentials: [catalogCredential],
  tunnels: [catalogTunnel],
};

test('catalog projects independent records and preserves null inheritance and int64 precision', () => {
  const value = parseVaultCatalog(catalog)!;
  assert.deepEqual(value, catalog);
  assert.notEqual(value, catalog);
  assert.notEqual(value.nodes[0], catalogNode);
  assert.notEqual(value.credentials[0], catalogCredential);
  assert.notEqual(value.tunnels[0], catalogTunnel);
  assert.deepEqual(parseVaultCatalog({ nodes: [], credentials: [], tunnels: [] }), {
    nodes: [],
    credentials: [],
    tunnels: [],
  });
  for (const protocol of [0, 1, 3, 4, 5, 6, 7]) {
    assert.ok(
      parseVaultCatalog({
        ...catalog,
        nodes: [{ ...catalogNode, protocol, host: '', port: 65535, username: '', sortOrder: '0' }],
      }),
    );
  }
  for (const credential of [
    { ...catalogCredential, kind: 'sshKey' },
    { ...catalogCredential, protocol: 'rdp', provider: 'bitwarden' },
    { ...catalogCredential, protocol: 'vnc' },
  ])
    assert.ok(parseVaultCatalog({ ...catalog, credentials: [credential] }));
});

test('catalog rejects malformed, secret-bearing, excessive and noncanonical records', () => {
  for (const value of [
    null,
    [],
    {},
    { ...catalog, password: 'secret' },
    { ...catalog, nodes: null },
    { ...catalog, credentials: {} },
    { ...catalog, tunnels: null },
    { ...catalog, nodes: Array(50_001).fill(catalogNode) },
  ])
    assert.equal(parseVaultCatalog(value), undefined);
  const badNodes = [
    null,
    {},
    { ...catalogNode, password: 'secret' },
    ...Object.entries({
      id: ['bad', '00000000-0000-0000-0000-000000000000'],
      parentId: ['bad', uuid],
      name: [
        null,
        '',
        '  ',
        'x\0y',
        'x\ny',
        'x\u0085y',
        '\ud800',
        'x'.repeat(257),
        '界'.repeat(400),
        'x'.repeat(1025),
      ],
      kind: [-1, 2],
      sortOrder: [
        0,
        '-0',
        '00',
        '01',
        '-9223372036854775809',
        '9223372036854775808',
        '1'.repeat(21),
      ],
      rowVersion: [0, '0', '-1', '1.0', '9223372036854775808'],
      protocol: [2, '0', 8],
      host: [4, 'x\r', 'x'.repeat(16385)],
      port: ['22', -1, 65536, 1.5, NaN],
      username: [5, 'x\n', 'x'.repeat(2049)],
      hasNotes: [null],
      hasInlinePassword: [1],
    }).flatMap(([key, values]) => values.map((value) => ({ ...catalogNode, [key]: value }))),
  ];
  for (const n of badNodes)
    assert.equal(parseVaultCatalog({ ...catalog, nodes: [n] }), undefined, JSON.stringify(n));
  const badCredentials = [
    null,
    {},
    { ...catalogCredential, value: 'secret' },
    ...Object.entries({
      id: ['bad'],
      name: [''],
      username: [null],
      domain: ['x'.repeat(2049)],
      rowVersion: ['0'],
      protocol: ['http'],
      kind: ['key'],
      provider: ['other'],
    }).flatMap(([key, values]) => values.map((value) => ({ ...catalogCredential, [key]: value }))),
    { ...catalogCredential, kind: 'sshKey', protocol: 'rdp' },
    { ...catalogCredential, kind: 'sshKey', provider: 'bitwarden' },
  ];
  for (const c of badCredentials)
    assert.equal(parseVaultCatalog({ ...catalog, credentials: [c] }), undefined);
  for (const t of [
    null,
    {},
    { ...catalogTunnel, configuration: 'secret' },
    ...Object.entries({
      id: ['bad'],
      name: ['', 'x'.repeat(129), '😀'.repeat(129)],
      rowVersion: ['0'],
      kind: ['1', -1, 10, 1.5],
    }).flatMap(([key, values]) => values.map((value) => ({ ...catalogTunnel, [key]: value }))),
  ])
    assert.equal(parseVaultCatalog({ ...catalog, tunnels: [t] }), undefined);
  for (const field of ['nodes', 'credentials', 'tunnels'] as const) {
    assert.equal(
      parseVaultCatalog({ ...catalog, [field]: [catalog[field][0], catalog[field][0]] }),
      undefined,
    );
    assert.equal(
      parseVaultCatalog({
        ...catalog,
        [field]: [{ ...catalog[field][0], id: recovery }, catalog[field][0]],
      }),
      undefined,
    );
  }
});

test('catalog rejects missing parents, non-folder parents, cycles and excessive depth', () => {
  const parent = { ...catalogNode, kind: 0 };
  const child = { ...catalogNode, id: recovery, parentId: uuid };
  assert.ok(parseVaultCatalog({ ...catalog, nodes: [parent, child] }));
  for (const nodes of [
    [child],
    [catalogNode, child],
    [
      { ...parent, parentId: recovery },
      { ...child, kind: 0 },
    ],
  ])
    assert.equal(parseVaultCatalog({ ...catalog, nodes }), undefined);
  const nodes = Array.from({ length: 129 }, (_, i) => ({
    ...parent,
    id: (i + 1).toString(16).padStart(8, '0') + '-1111-4111-8111-111111111111',
    parentId: i === 0 ? null : i.toString(16).padStart(8, '0') + '-1111-4111-8111-111111111111',
  }));
  assert.ok(parseVaultCatalog({ ...catalog, nodes: nodes.slice(0, 128) }));
  assert.equal(parseVaultCatalog({ ...catalog, nodes }), undefined);
});

test('Go HTML escaping is accepted without accepting duplicate keys or numeric rounding', () => {
  const value = { version: 1, id: 1, result: catalog };
  const canonical = JSON.stringify(value);
  const native = canonical.replace(
    /[<>&\u2028\u2029]/g,
    (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'),
  );
  assert.notEqual(native, canonical);
  assert.deepEqual(parseVaultResponse(native), { id: 1, result: catalog });
  assert.deepEqual(parseVaultResponse(canonical), { id: 1, result: catalog });
  assert.equal(parseVaultResponse(native.replace('"id":1,', '"id":2,"id":1,')), undefined);
  assert.equal(
    parseVaultResponse(native.replace('"id":1,', '"id":1.0000000000000001,')),
    undefined,
  );
});

test('continuation hint is accepted only as true on pending shared selection', () => {
  const hints = { lastLoginName: 'alice', serverDisplayName: 'Team' };
  const value = {
    slots: {
      formatVersion: 1,
      vaultId: '11111111-1111-4111-8111-111111111111',
      encrypted: true,
      slots: [{ id: '22222222-2222-4222-8222-222222222222', kind: 'password', preset: 'kdf-v1' }],
    },
    cosmetics: { theme: 'system' },
    newWorkspace: false,
  };
  assert.equal(
    parseVaultStartup({ ...value, sharedJoin: { ...hints, canContinue: true } })?.sharedJoin
      ?.canContinue,
    true,
  );
  for (const canContinue of [false, null, undefined, 1, 'true'])
    assert.equal(parseVaultStartup({ ...value, sharedJoin: { ...hints, canContinue } }), undefined);
  assert.equal(parseVaultStartup({ ...value, shared: { ...hints, canContinue: true } }), undefined);
});

test('required metadata names follow Go Unicode whitespace, including NEL and BOM', () => {
  assert.equal(
    parseVaultCatalog({ ...catalog, credentials: [{ ...catalogCredential, name: '\u0085' }] }),
    undefined,
  );
  for (const field of ['nodes', 'credentials', 'tunnels'] as const)
    assert.ok(
      parseVaultCatalog({ ...catalog, [field]: [{ ...catalog[field][0], name: '\ufeff' }] }),
    );
});
