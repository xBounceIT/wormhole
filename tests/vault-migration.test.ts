import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseVaultMigrationSelection,
  parseVaultMigrationDecision,
  parseVaultMigrationReport,
} from '../electron/vault-migration.ts';
import { VaultBackendHost, registerVaultIpc } from '../electron/vault-host.ts';
import {
  migrationReport,
  migrationDecision,
  migrationSelection,
  migrationNode,
} from './fixtures/vault-migration.ts';

test('migration contracts retain only versioned public choices and reject private or inconsistent reports', () => {
  assert.deepEqual(parseVaultMigrationSelection(migrationSelection), migrationSelection);
  const input = migrationDecision(),
    snapshot = parseVaultMigrationDecision(input);
  input.choices[0].choice = 'keep';
  assert.equal(snapshot?.choices[0].choice, 'new');
  assert.deepEqual(
    parseVaultMigrationReport(migrationReport(), migrationSelection),
    migrationReport(),
  );
  const empty = { ...migrationSelection, fingerprint: null, entries: [], canDecide: false };
  assert.deepEqual(parseVaultMigrationReport(empty, migrationSelection), empty);
  for (const bad of [
    null,
    [],
    {},
    { ...migrationSelection, nodeId: 'bad' },
    { ...migrationSelection, rowVersion: '0' },
    { ...migrationSelection, rowVersion: '01' },
    { ...migrationSelection, rowVersion: '9223372036854775808' },
    { ...migrationSelection, password: 'private' },
  ])
    assert.equal(parseVaultMigrationSelection(bad), undefined);
  for (const [key, values] of Object.entries({
    nodeId: ['bad', null],
    rowVersion: ['0', '9223372036854775807'],
    fingerprint: ['A'.repeat(64), 'a'.repeat(63), null],
    choices: [
      null,
      [],
      [null],
      [1],
      Array(4).fill({ protocolPath: 'ssh', choice: 'new' }),
      [{ protocolPath: 'invalid', choice: 'new' }],
      [{ protocolPath: 'ssh', choice: 'invalid' }],
      [{ protocolPath: 'ssh', choice: 'new', username: 'private' }],
      [
        { protocolPath: 'ssh', choice: 'new' },
        { protocolPath: 'ssh', choice: 'keep' },
      ],
    ],
  }))
    for (const value of values)
      assert.equal(
        parseVaultMigrationDecision({ ...migrationDecision(), [key]: value }),
        undefined,
        key,
      );
  for (const bad of [null, { ...migrationDecision(), extra: 1 }])
    assert.equal(parseVaultMigrationDecision(bad), undefined);
  for (const [key, values] of Object.entries({
    nodeId: ['bad'],
    rowVersion: ['3'],
    fingerprint: [null, 'bad'],
    canDecide: [null, 1],
    entries: [
      null,
      Array(4).fill(migrationReport().entries[0]),
      [null],
      [migrationReport().entries[0], migrationReport().entries[0]],
    ],
  }))
    for (const value of values)
      assert.equal(
        parseVaultMigrationReport({ ...migrationReport(), [key]: value }, migrationSelection),
        undefined,
        key,
      );
  for (const [key, values] of Object.entries({
    nodeId: ['bad'],
    protocolPath: ['unknown'],
    oldCredentialId: ['bad', null],
    newCredentialId: ['bad', null],
    credentialChanged: [true, null],
    usernameChanged: [false, null],
    domainChanged: [null],
    sourceChanged: [null],
    choice: ['bad', null],
    username: ['private'],
  }))
    for (const value of values) {
      const report = migrationReport();
      report.entries = [{ ...report.entries[0], [key]: value } as any];
      assert.equal(parseVaultMigrationReport(report, migrationSelection), undefined, key);
    }
  assert.equal(
    parseVaultMigrationReport({ ...empty, fingerprint: 'a'.repeat(64) }, migrationSelection),
    undefined,
  );
  assert.equal(
    parseVaultMigrationReport({ ...migrationReport(), private: 'hidden' }, migrationSelection),
    undefined,
  );
  assert.equal(parseVaultMigrationReport(null, migrationSelection), undefined);
});

test('migration IPC binds current owner and sender before and after reads or choices', async () => {
  for (const operation of ['report', 'decide'] as const) {
    let trusted = true,
      delayed = false,
      release!: () => void,
      calls = 0,
      submitted: any;
    const answer =
      operation === 'report'
        ? migrationReport()
        : { nodeId: migrationNode, rowVersion: '3', updated: true };
    const client: any = {
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
    };
    client[operation === 'report' ? 'migrationReport' : 'decideMigration'] = async (input: any) => {
      calls++;
      submitted = input;
      if (delayed) await new Promise<void>((resolve) => (release = resolve));
      return answer;
    };
    const host = new VaultBackendHost(
        () => client,
        () => true,
      ),
      handlers = new Map<string, any>();
    registerVaultIpc(
      { handle: (name: string, fn: any) => handlers.set(name, fn) } as any,
      host,
      () => trusted,
    );
    const invoke = (...args: any[]) => handlers.get('vault:migration-' + operation)({}, ...args),
      input = () => (operation === 'report' ? { ...migrationSelection } : migrationDecision());
    await assert.rejects(invoke(null), /Invalid/);
    await assert.rejects(invoke(input()), /locked/);
    assert.equal(host.hasOwner, false);
    await host.unlock({
      vaultId: migrationNode,
      slotId: migrationNode,
      kind: 'password',
      factor: new Uint8Array([1]),
    });
    await assert.rejects(invoke());
    await assert.rejects(invoke(input(), 1));
    trusted = false;
    await assert.rejects(invoke(input()), /Invalid/);
    trusted = true;
    assert.deepEqual(await invoke(input()), answer);
    assert.equal(calls, 1);
    delayed = true;
    const value = input(),
      late = invoke(value);
    await new Promise(setImmediate);
    value.rowVersion = '99';
    assert.equal(submitted.rowVersion, '2');
    trusted = false;
    release();
    await assert.rejects(late, /owner/);
    trusted = true;
    const locked = invoke(input());
    await new Promise(setImmediate);
    await host.stop();
    release();
    await assert.rejects(locked, /locked/);
  }
});
