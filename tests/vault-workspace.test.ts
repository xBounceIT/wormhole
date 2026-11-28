import assert from 'node:assert/strict';
import test from 'node:test';
import { parseVaultWorkspace } from '../electron/vault-workspace.ts';

const id = (n: number) => `11111111-1111-4111-8111-${n.toString(16).padStart(12, '0')}`;
const credential = (n = 1, protocol = 'ssh') => ({
  id: id(n),
  name: 'Account 日本語',
  protocol,
  kind: 'password',
  username: 'user',
  provider: 'Local',
  canEdit: true,
  canDelete: true,
});
const node = (n = 2) => ({ id: id(n), name: 'Connection', kind: 'connection', persisted: true });
const empty = () => ({
  tree: [] as any[],
  credentials: [] as any[],
  credentialOptions: { ssh: [] as any[], rdp: [] as any[], vnc: [] as any[] },
  tunnels: [] as any[],
});
const rdp = () => ({
  domain: 'CONTOSO',
  screenSize: '1600x900',
  fullScreen: false,
  colorDepth: 32,
  useAllMonitors: true,
  audioMode: 0,
  audioCaptureMode: 1,
  keyboardHookMode: 2,
  redirectClipboard: true,
  redirectPrinters: true,
  redirectSmartCards: true,
  redirectPorts: false,
  redirectDevices: false,
  redirectDrives: 'C, D',
  connectionSpeed: 7,
  desktopBackground: true,
  fontSmoothing: true,
  desktopComposition: true,
  windowDrag: true,
  menuAnimation: true,
  visualStyles: true,
  bitmapCaching: true,
  autoReconnect: true,
  serverAuthentication: 2,
  gatewayUsageMethod: 1,
  gatewayHostname: 'gateway.example',
  gatewayCredentialId: id(3),
  gatewayBypassLocal: true,
  gatewayUseSameCreds: false,
  useExternalClient: false,
});
function populated() {
  const value = empty();
  value.credentials = [credential(), credential(3, 'rdp'), credential(4, 'vnc')];
  value.credentialOptions = {
    ssh: [value.credentials[0]],
    rdp: [value.credentials[1]],
    vnc: [value.credentials[2]],
  };
  value.tunnels = [{ id: id(5), name: 'VPN', kind: 'WireGuard' }];
  value.tree = [
    {
      ...node(6),
      kind: 'folder',
      children: [
        {
          ...node(),
          protocol: 'rdp',
          rdp: rdp(),
          credentialId: id(3),
          tunnelConfigId: id(5),
          port: 3389,
          credentialMode: 2,
          username: 'user',
          host: 'host',
          httpPath: '',
          hasInlineCredential: false,
          tunnelEnabled: true,
          sshAutoSudo: false,
          httpIgnoreCertErrors: false,
        },
      ],
    },
  ];
  return value;
}

test('vault workspace validates metadata without resolving or retaining native records', () => {
  assert.deepEqual(parseVaultWorkspace(empty()), empty());
  const value = populated();
  const parsed = parseVaultWorkspace(value)!;
  assert.deepEqual(parsed, value);
  assert.notEqual(parsed.tree, value.tree);
  assert.notEqual(parsed.tree[0].children![0].rdp, value.tree[0].children[0].rdp);
  assert.notEqual(parsed.credentials[0], value.credentials[0]);
  const key = {
    ...credential(),
    kind: 'sshKey',
    privateKeyFileName: 'key',
    certificateFileName: 'key-cert.pub',
    hasCertificate: true,
    domain: '',
    bitwardenItemId: '',
    bitwardenItemName: '',
  };
  value.credentials[0] = key;
  value.credentialOptions.ssh = [key];
  assert.ok(parseVaultWorkspace(value));
  key.kind = 'password';
  key.provider = 'Bitwarden';
  assert.ok(parseVaultWorkspace(value));
});

test('vault workspace rejects private fields, inconsistent options, duplicate or missing references', () => {
  const mutations: ((v: ReturnType<typeof populated>) => void)[] = [
    (v) => {
      (v as any).rootKey = 'private';
    },
    (v) => {
      v.credentials[0].password = 'private';
    },
    (v) => {
      v.credentials.push(v.credentials[0]);
    },
    (v) => {
      v.credentials[0].id = 'bad';
    },
    (v) => {
      v.credentials[0].kind = 'sshKey';
      v.credentials[0].provider = 'Bitwarden';
    },
    (v) => {
      v.credentials[0].name = '';
    },
    (v) => {
      v.credentials[0].domain = '\0';
    },
    (v) => {
      v.credentials[0].hasCertificate = 1;
    },
    (v) => {
      v.credentialOptions.ssh = [];
    },
    (v) => {
      v.credentialOptions.ssh = [credential(8)];
    },
    (v) => {
      v.credentialOptions.ssh = [{ ...credential(), username: 'changed' }];
    },
    (v) => {
      v.credentialOptions.ssh.push(credential());
    },
    (v) => {
      v.credentialOptions.ssh = [credential(3, 'rdp')];
    },
    (v) => {
      v.credentialOptions.ssh = null as any;
    },
    (v) => {
      v.tunnels.push(v.tunnels[0]);
    },
    (v) => {
      v.tunnels[0].configuration = 'private';
    },
    (v) => {
      v.tunnels[0].kind = 'Unknown';
    },
    (v) => {
      v.tunnels[0].name = 'a'.repeat(129);
    },
    (v) => {
      v.tree[0].children[0].credentialId = id(9);
    },
    (v) => {
      v.tree[0].children[0].tunnelConfigId = id(9);
    },
    (v) => {
      v.tree[0].children[0].rdp.gatewayCredentialId = id(9);
    },
    (v) => {
      v.tree[0].children[0].rdp.password = 'private';
    },
    (v) => {
      v.tree[0].children[0].rdp.audioMode = 4;
    },
    (v) => {
      v.tree[0].children[0].protocol = 'ssh';
    },
    (v) => {
      v.tree[0].children[0].children = [];
    },
    (v) => {
      v.tree[0].children = {};
    },
    (v) => {
      v.tree[0].children[0].id = v.tree[0].id;
    },
    (v) => {
      v.tree[0].children[0].seal = 'private';
    },
  ];
  for (const mutate of mutations) {
    const value = populated();
    mutate(value);
    assert.equal(parseVaultWorkspace(value), undefined, String(mutate));
  }
  for (const value of [
    null,
    [],
    {},
    { ...empty(), tree: null },
    { ...empty(), credentialOptions: {} },
    { ...empty(), tunnels: Array(50_001).fill(null) },
  ])
    assert.equal(parseVaultWorkspace(value), undefined);
});

test('vault workspace bounds node strings, optional types, serial fields and tree depth', () => {
  for (const [key, invalid] of Object.entries({
    id: 'bad',
    name: 'a\n',
    kind: 'invalid',
    persisted: false,
    protocol: 'unknown',
    host: 'x'.repeat(16385),
    username: '\0',
    httpPath: '\0',
    port: 65536,
    credentialMode: -1,
    serialBaudRate: 0,
    serialDataBits: 9,
    serialStopBits: 0,
    serialParity: 5,
    serialFlowControl: 4,
    hasInlineCredential: 1,
    httpIgnoreCertErrors: 'true',
    sshAutoSudo: null,
    tunnelEnabled: 0,
    credentialId: '',
    tunnelConfigId: '',
    rdp: null,
  })) {
    const v = empty();
    v.tree = [{ ...node(), [key]: invalid }];
    assert.equal(parseVaultWorkspace(v), undefined, key);
  }
  for (const protocol of ['ssh', 'sftp', 'rdp', 'vnc', 'http', 'https', 'serial']) {
    const v = empty();
    v.tree = [
      {
        ...node(),
        protocol,
        serialBaudRate: 9600,
        serialDataBits: 8,
        serialStopBits: 1,
        serialParity: 0,
        serialFlowControl: 0,
      },
    ];
    assert.ok(parseVaultWorkspace(v));
  }
  const v = empty();
  let children = v.tree;
  for (let n = 1; n <= 128; n++) {
    const folder = { ...node(n), kind: 'folder', children: [] as any[] };
    children.push(folder);
    children = folder.children;
  }
  // An omitted children array at the deepest leaf is legal; a further level is not.
  let leaf = v.tree[0];
  for (let n = 1; n < 128; n++) leaf = leaf.children[0];
  delete leaf.children;
  assert.ok(parseVaultWorkspace(v));
  leaf.children = [node(129)];
  assert.equal(parseVaultWorkspace(v), undefined);
  const wide = empty();
  wide.tree = Array.from({ length: 50_001 }, (_, n) => node(n + 1));
  assert.equal(parseVaultWorkspace(wide), undefined);
});

test('RDP display preserves native Unicode identities without applying editor normalization', () => {
  const v = populated();
  const settings = v.tree[0].children[0].rdp;
  settings.domain = '🧪'.repeat(512);
  settings.gatewayHostname = '🧪'.repeat(253);
  settings.screenSize = '\u0085fitToWindow\u0085';
  assert.deepEqual(parseVaultWorkspace(v)?.tree[0].children![0].rdp, settings);
  settings.domain = ' domain with spaces ';
  assert.equal(parseVaultWorkspace(v)?.tree[0].children![0].rdp?.domain, settings.domain);
  for (const [key, value] of Object.entries({
    domain: '🧪'.repeat(513),
    gatewayHostname: 'host\u0085example',
    screenSize: '\0',
    redirectDrives: '\ud800',
    gatewayCredentialId: '\ud800',
  })) {
    const old = settings[key];
    settings[key] = value;
    assert.equal(parseVaultWorkspace(v), undefined, key);
    settings[key] = old;
  }
});

test('credential revisions are canonical and identical in list and protocol options', () => {
  const value = populated();
  value.credentials[0].rowVersion = '7';
  assert.equal(parseVaultWorkspace(value)?.credentials[0].rowVersion, '7');
  for (const version of ['0', '01', '-1', '9223372036854775808', null, 1]) {
    value.credentials[0].rowVersion = version;
    assert.equal(parseVaultWorkspace(value), undefined);
  }
  value.credentials[0].rowVersion = '8';
  value.credentialOptions.ssh = [{ ...value.credentials[0], rowVersion: '7' }];
  assert.equal(parseVaultWorkspace(value), undefined);
});

test('tunnel revisions survive projection and malformed revisions fail closed', () => {
  const value = populated();
  value.tunnels[0].rowVersion = '7';
  assert.equal(parseVaultWorkspace(value)?.tunnels[0].rowVersion, '7');
  for (const version of ['0', '01', '-1', '9223372036854775808', 1, null]) {
    value.tunnels[0].rowVersion = version;
    assert.equal(parseVaultWorkspace(value), undefined);
  }
});
