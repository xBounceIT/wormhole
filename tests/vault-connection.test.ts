import assert from 'node:assert/strict';
import test from 'node:test';
import { consumeVaultConnectionInput } from '../electron/vault-connection.ts';
import {
  appRdpDefaults,
  connectionInput,
  connectionNodeId as id,
} from './fixtures/vault-connection.ts';
const defaultRdpSettings = appRdpDefaults();
import { VaultBackendHost, registerVaultIpc } from '../electron/vault-host.ts';
import { encodeVaultBytesFrame } from '../electron/vault-unlock.ts';

test('connection input consumes bytes and strictly snapshots only public metadata', () => {
  const input = connectionInput(),
    password = input.password.slice(),
    notes = input.notes.slice();
  const owned = consumeVaultConnectionInput(input);
  assert.ok(input.password.every((byte) => byte === 0) && input.notes.every((byte) => byte === 0));
  assert.deepEqual([...owned.password], [...password]);
  assert.deepEqual([...owned.notes], [...notes]);
  input.metadata.name = 'Mutated';
  assert.equal(owned.metadata.name, 'Connection');
  const frame = encodeVaultBytesFrame(
    1,
    'connection-save',
    { metadata: owned.metadata, rowVersion: owned.rowVersion, notesAction: owned.notesAction },
    [
      ['password', owned.password],
      ['notes', owned.notes],
    ],
  );
  const payload = JSON.parse(frame.toString()).payload;
  assert.equal(Buffer.from(payload.password, 'base64').toString(), 'password-fixture');
  assert.equal(Buffer.from(payload.notes, 'base64').toString(), 'notes-fixture');
  assert.equal(payload.metadata.inlinePassword, undefined);
  frame.fill(0);
  owned.password.fill(0);
  owned.notes.fill(0);
  for (const bad of [null, [], {}, { ...connectionInput(), extra: true }])
    assert.throws(() => consumeVaultConnectionInput(bad));
  for (const [key, values] of Object.entries({
    id: ['bad', id],
    name: ['', '\ud800'],
    protocol: ['unknown'],
    host: ['', 'line\nfeed'],
    port: [-1, 65536, 1.5],
    username: [null, 'line\nfeed'],
    inlinePasswordAction: ['unknown', 'clear'],
    httpIgnoreCertErrors: [0],
    serialBaudRate: [-1, 2147483648, 1.5],
    rdp: [{}],
    notes: ['forbidden'],
  })) {
    for (const value of values) {
      const bad: any = connectionInput();
      bad.metadata[key] = value;
      assert.throws(() => consumeVaultConnectionInput(bad), key);
      assert.ok(
        bad.password.every((v: number) => v === 0) && bad.notes.every((v: number) => v === 0),
      );
    }
  }
  for (const patch of [
    { rowVersion: '1' },
    { notesAction: 'bad' },
    { notesAction: 'preserve' },
    { password: [] },
    { notes: [] },
    { password: new Uint8Array(16385) },
    { notes: new Uint8Array(65537) },
    { password: new Uint8Array(new SharedArrayBuffer(1)) },
    { notes: new Uint8Array(new SharedArrayBuffer(1)) },
  ]) {
    const bad: any = { ...connectionInput(), ...patch };
    assert.throws(() => consumeVaultConnectionInput(bad));
    if (bad.password instanceof Uint8Array) assert.ok(bad.password.every((v) => v === 0));
    if (bad.notes instanceof Uint8Array) assert.ok(bad.notes.every((v) => v === 0));
  }
  for (const action of ['preserve', 'clear'] as const) {
    const input = connectionInput();
    input.password = new Uint8Array();
    input.notes = new Uint8Array();
    input.notesAction = action;
    input.metadata.inlinePasswordAction = action;
    assert.equal(consumeVaultConnectionInput(input).notesAction, action);
  }
  const edit = connectionInput();
  edit.metadata.id = id;
  edit.rowVersion = '7';
  assert.equal(consumeVaultConnectionInput(edit).rowVersion, '7');
});

test('RDP metadata is deeply copied, exact and gateway IDs remain canonical', () => {
  const input = connectionInput();
  input.metadata.protocol = 'rdp';
  input.metadata.rdp = { ...defaultRdpSettings };
  const owned = consumeVaultConnectionInput(input);
  input.metadata.rdp.domain = 'Changed';
  assert.equal(owned.metadata.rdp?.domain, defaultRdpSettings.domain);
  for (const rdp of [
    null,
    {},
    { ...defaultRdpSettings, extra: true },
    { ...defaultRdpSettings, gatewayCredentialId: 'BAD' },
    { ...defaultRdpSettings, colorDepth: 17 },
  ]) {
    const input: any = connectionInput();
    input.metadata.protocol = 'rdp';
    input.metadata.rdp = rdp;
    assert.throws(() => consumeVaultConnectionInput(input));
  }
  owned.password.fill(0);
  owned.notes.fill(0);
});

test('connection host and IPC erase factors on refusal, lock and document loss', async () => {
  let trusted = true,
    calls = 0,
    delayed = false,
    complete!: () => void,
    borrowed: any;
  const host = new VaultBackendHost(
    () =>
      ({
        unlock: async () => ({ unlocked: true, lockedMemory: true }),
        security: async () => ({
          sequence: '1',
          workspace: 'default',
          user: 'default',
          os: 'default',
          effective: 'default',
          source: 'workspace',
        }),
        lock: async () => {},
        saveConnection: async (input: any) => {
          calls++;
          borrowed = input;
          if (delayed)
            await new Promise<void>((resolve) => {
              complete = resolve;
            });
          return { nodeId: id, rowVersion: '1', updated: true };
        },
      }) as any,
    () => true,
  );
  const handlers = new Map<string, any>();
  registerVaultIpc(
    { handle: (name: string, fn: any) => handlers.set(name, fn) } as any,
    host,
    () => trusted,
  );
  const invoke = (input: any, ...extra: any[]) =>
    handlers.get('vault:save-connection')({}, input, ...extra);
  const locked = connectionInput();
  await assert.rejects(invoke(locked), /locked/);
  assert.ok(locked.password.every((v) => v === 0));
  assert.equal(calls, 0);
  await host.unlock({ vaultId: id, slotId: id, kind: 'password', factor: new Uint8Array([1]) });
  for (const extra of [false, true]) {
    trusted = extra;
    const input = connectionInput();
    await assert.rejects(extra ? invoke(input, {}) : invoke(input), /Invalid/);
    assert.ok(input.password.every((v) => v === 0) && input.notes.every((v) => v === 0));
  }
  trusted = true;
  assert.equal((await invoke(connectionInput())).nodeId, id);
  assert.ok(borrowed.password.every((v: number) => v === 0));
  delayed = true;
  const pending = invoke(connectionInput());
  await new Promise(setImmediate);
  trusted = false;
  complete();
  await assert.rejects(pending, /owner/);
  assert.ok(borrowed.notes.every((v: number) => v === 0));
  trusted = true;
  const locking = invoke(connectionInput());
  await new Promise(setImmediate);
  await host.stop();
  complete();
  await assert.rejects(locking, /locked/);
  assert.ok(borrowed.password.every((v: number) => v === 0));
});
