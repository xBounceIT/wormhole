import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { VaultSharedSetupDialog } from '../electron/vault-shared-setup-dialog.ts';
import {
  confirmedSlotDefault,
  parseSlotDefaultReply,
  parseSlotDefaultRequest,
} from '../electron/vault-shared-slot-default.ts';
import { parsePersonalRootRecoveryReply } from '../electron/vault-account-suspension.ts';
import {
  parseWorkspaceAccessReply,
  parseWorkspaceAccessRequest,
} from '../electron/vault-shared-access.ts';
import { pickSharedBackupDestination } from '../electron/vault-shared-backup-destination.ts';
import {
  parseSharedRecoveryBackup,
  type SharedRecoveryBackupInput,
  type SharedRecoveryBackupOperation,
} from '../electron/vault-shared-recovery-backup.ts';
import {
  parseSharedRecoveryInspection,
  parseSharedRecoveryInspectionReceipt,
  validSharedRecoveryRestore,
} from '../electron/vault-shared-restore.ts';
import {
  consumeSharedAccountResetIssue,
  parseSharedAccountResetIssue,
  type SharedAccountResetIssueInput,
  type SharedAccountResetIssueOperation,
} from '../electron/vault-shared-account-reset-issue.ts';
import {
  parseAccountResetMark,
  parseAccountResetMarkResult,
  parseAccountResetTargetPage,
} from '../electron/vault-shared-account-reset-queue.ts';

const url = 'file:///app/dist/vault-shared-setup.html';
const workspaceId = '11111111-1111-4111-8111-111111111111';

class TestWindow extends EventEmitter {
  destroyed = false;
  refusesDestroy = false;
  refusesLoad = false;
  shown = false;
  webContents = Object.assign(new EventEmitter(), {
    mainFrame: { url },
    setWindowOpenHandler() {},
    session: Object.assign(new EventEmitter(), {
      setPermissionRequestHandler() {},
      setPermissionCheckHandler() {},
      webRequest: { onBeforeRequest() {} },
    }),
  });

  isDestroyed() {
    return this.destroyed;
  }

  setMenu() {}

  destroy() {
    if (this.refusesDestroy) return;
    this.destroyed = true;
    this.emit('closed');
  }

  show() {
    this.shown = true;
  }

  async loadURL(destination: string) {
    assert.equal(destination, url);
    if (this.refusesLoad) throw Error('load failed');
    this.webContents.emit('dom-ready');
  }
}

function fixture(
  holdNative = false,
  recovery?: ConstructorParameters<typeof VaultSharedSetupDialog>[0]['recover'],
  restore?: ConstructorParameters<typeof VaultSharedSetupDialog>[0]['restore'],
) {
  const parent = new TestWindow();
  const child = new TestWindow();
  const handlers = new Map<string, (...args: any[]) => unknown>();
  const calls: unknown[] = [];
  let accepted = true;
  let finishPicker = (_path: string | null) => {};
  let finishNative = () => {};
  const dialog = new VaultSharedSetupDialog({
    ipc: { handle: (channel, handler) => handlers.set(channel, handler) },
    host: {
      sharedSetup: async (request, current) => {
        assert.equal(current?.(), true);
        calls.push(request);
        if (holdNative)
          await new Promise<void>((resolve) => {
            finishNative = resolve;
          });
        if (!current?.()) throw Error('Shared workspace setup was interrupted.');
        return { plan: null };
      },
    },
    createWindow: (options) => {
      assert.equal(options.webPreferences?.sandbox, true);
      assert.equal(options.webPreferences?.nodeIntegration, false);
      return child as any;
    },
    pickExport: () => new Promise((resolve) => (finishPicker = resolve)),
    pickRecovery: () => new Promise((resolve) => (finishPicker = resolve)),
    pickBackup: () => new Promise((resolve) => (finishPicker = resolve)),
    pickAccountReset: () => new Promise((resolve) => (finishPicker = resolve)),
    recover: recovery,
    restore,
    platform: 'linux',
    preload: '/app/preload.cjs',
    url,
  });
  return {
    parent,
    child,
    dialog,
    calls,
    open: (recover = false) =>
      dialog.open(
        parent as any,
        () => accepted,
        recover ? () => accepted : undefined,
        false,
        recover ? 'recovery' : 'setup',
      ),
    revoke: () => (accepted = false),
    finishPicker: (path: string | null) => finishPicker(path),
    finishNative: () => finishNative(),
    event: { sender: child.webContents, senderFrame: child.webContents.mainFrame },
    request: (...args: any[]) => handlers.get('vault-shared-setup:request')!(...args),
    close: (...args: any[]) => handlers.get('vault-shared-setup:close')!(...args),
    recover: (...args: any[]) => handlers.get('vault-shared-setup:recover-admin')!(...args),
    mode: (...args: any[]) => handlers.get('vault-shared-setup:mode')!(...args),
    openBackup: (operation: SharedRecoveryBackupOperation) =>
      dialog.openBackup(parent as any, () => accepted, operation),
    backupContext: (...args: any[]) => handlers.get('vault-shared-setup:backup-context')!(...args),
    exportBackup: (...args: any[]) => handlers.get('vault-shared-setup:export-backup')!(...args),
    openAccountReset: (operation: SharedAccountResetIssueOperation) =>
      dialog.openAccountReset(parent as any, () => accepted, operation),
    openAdministration: (
      read: Parameters<typeof dialog.openAdministration>[2]['read'],
      access?: Parameters<typeof dialog.openAdministration>[2]['access'],
      suspension?: Parameters<typeof dialog.openAdministration>[2]['suspension'],
      accountRotation?: Parameters<typeof dialog.openAdministration>[2]['accountRotation'],
      personalRecovery?: Parameters<typeof dialog.openAdministration>[2]['personalRecovery'],
      reenrollment?: Parameters<typeof dialog.openAdministration>[2]['reenrollment'],
    ) =>
      dialog.openAdministration(parent as any, () => accepted, {
        read,
        access,
        suspension,
        accountRotation,
        personalRecovery,
        reenrollment,
      }),
    inventory: (...args: any[]) => handlers.get('vault-shared-setup:admin-inventory')!(...args),
    slotDefault: (...args: any[]) => handlers.get('vault-shared-setup:slot-default')!(...args),
    personalSlot: (...args: any[]) => handlers.get('vault-shared-setup:personal-slot')!(...args),
    access: (...args: any[]) => handlers.get('vault-shared-setup:workspace-access')!(...args),
    suspension: (...args: any[]) => handlers.get('vault-shared-setup:account-suspension')!(...args),
    accountRotation: (...args: any[]) =>
      handlers.get('vault-shared-setup:account-boundary-rotation')!(...args),
    personalRecovery: (...args: any[]) =>
      handlers.get('vault-shared-setup:personal-root-recovery')!(...args),
    resetContext: (...args: any[]) => handlers.get('vault-shared-setup:reset-context')!(...args),
    issueReset: (...args: any[]) => handlers.get('vault-shared-setup:issue-reset')!(...args),
    resetTargets: (...args: any[]) => handlers.get('vault-shared-setup:reset-targets')!(...args),
    markResetHandover: (...args: any[]) =>
      handlers.get('vault-shared-setup:mark-reset-handover')!(...args),
    leaveResetPending: (...args: any[]) =>
      handlers.get('vault-shared-setup:leave-reset-pending')!(...args),
    inspectBackup: (...args: any[]) => handlers.get('vault-shared-setup:inspect-backup')!(...args),
    applyBackup: (...args: any[]) => handlers.get('vault-shared-setup:apply-backup')!(...args),
  };
}

const resetRequestId = '22222222-2222-4222-8222-222222222222';
const offerId = '33333333-3333-4333-8333-333333333333';

test('slot defaults require one matching review in the protected administrator window', async () => {
  const f = fixture();
  const input = { slotId: offerId, credentialName: 'Desktop' };
  const confirmation = {
    workspaceId: offerId,
    slotRevision: '2',
    credentialId: resetRequestId,
    credentialRevision: '7',
  };
  const commit = { ...input, confirmation };
  let saves = 0;
  const opened = f.dialog.openAdministration(f.parent as any, () => true, {
    read: async () => ({ status: 'unavailable' }),
    slotDefault: async (request, factors, current) => {
      assert.ok(current());
      if (!request.confirmation)
        return {
          status: 'review',
          workspaceId: offerId,
          authenticationRequired: true,
          choice: {
            ...input,
            slotName: 'Operations',
            protocol: 'rdp',
            slotRevision: '2',
            credentialId: resetRequestId,
            credentialRevision: '7',
            hasDefault: false,
          },
        };
      assert.deepEqual(request, commit);
      assert.ok(factors?.password.length);
      saves++;
      return { status: 'saved' };
    },
  });
  try {
    const factors = () => ({ password: new Uint8Array([1]), ask: new Uint8Array(32).fill(9) });
    await assert.rejects(f.slotDefault(f.event, commit, factors()), /review/i);
    await assert.rejects(
      f.slotDefault({ ...f.event, senderFrame: { url } }, input),
      /unavailable/i,
    );
    await f.slotDefault(f.event, input);
    const rejected = factors();
    await assert.rejects(
      f.slotDefault(
        f.event,
        { ...commit, confirmation: { ...confirmation, credentialId: offerId } },
        rejected,
      ),
      /review/i,
    );
    assert.ok(rejected.password.every((v) => v === 0) && rejected.ask.every((v) => v === 0));
    await assert.rejects(f.slotDefault(f.event, commit, factors()), /review/i);
    await f.slotDefault(f.event, input);
    await assert.rejects(f.slotDefault(f.event, commit), /review/i);
    await f.slotDefault(f.event, input);
    const correct = factors();
    assert.deepEqual(await f.slotDefault(f.event, commit, correct), { status: 'saved' });
    assert.ok(correct.password.every((v) => v === 0) && correct.ask.every((v) => v === 0));
    await assert.rejects(f.slotDefault(f.event, commit, factors()), /review/i);
    assert.equal(saves, 1);
  } finally {
    await f.dialog.cancel();
    await opened;
  }
});

test('a personal slot review binds the account and the assignment revision in its own protected window', async () => {
  const f = fixture();
  const input = { slotId: offerId, credentialName: 'My desktop' };
  const choice = {
    ...input,
    slotName: 'Operations',
    slotRevision: '9223372036854775807',
    protocol: 'rdp' as const,
    userId: resetRequestId,
    valueRevision: '0',
    hasDefault: true,
    credentialId: offerId,
    credentialRevision: '2',
    provider: 'bitwarden' as const,
  };
  const review = { status: 'review' as const, workspaceId, choice };
  const commit = confirmedSlotDefault(review);
  assert.deepEqual(parseSlotDefaultRequest(commit, true), commit);
  assert.deepEqual(parseSlotDefaultReply(review, input, true), review);
  assert.equal(parseSlotDefaultRequest(commit), undefined);
  assert.equal(parseSlotDefaultReply(review, input), undefined);
  for (const invalid of [
    { userId: 'other' },
    { valueRevision: '00' },
    { valueRevision: '9223372036854775807' },
    { provider: 'unknown' },
    { hasAssignment: true },
    { bitwardenItemId: 'private' },
  ])
    assert.equal(
      parseSlotDefaultReply({ ...review, choice: { ...choice, ...invalid } }, input, true),
      undefined,
    );
  let saves = 0;
  const opened = f.dialog.openAdministration(f.parent as any, () => true, {
    ownDevicesOnly: true,
    read: async () => ({ status: 'unavailable' }),
    personalSlot: async (request) => {
      if (!request.confirmation) return review;
      assert.deepEqual(request, commit);
      saves++;
      return { status: 'saved' };
    },
  });
  try {
    await f.personalSlot(f.event, input);
    await assert.rejects(f.slotDefault(f.event, commit), /review/i);
    await assert.rejects(f.personalSlot(f.event, commit), /review/i);
    await f.personalSlot(f.event, input);
    await assert.rejects(
      f.personalSlot(f.event, {
        ...input,
        confirmation: { ...commit.confirmation, userId: workspaceId },
      }),
      /review/i,
    );
    await f.personalSlot(f.event, input);
    assert.deepEqual(await f.personalSlot(f.event, commit), { status: 'saved' });
    await assert.rejects(f.personalSlot(f.event, commit), /review/i);
    assert.equal(saves, 1);
  } finally {
    await f.dialog.cancel();
    await opened;
  }
});

test('protected personal key recovery consumes one review and wipes factors on every exit', async () => {
  const f = fixture();
  const request = { accountId: resetRequestId, suspension: '17' };
  const review = 'be'.repeat(32);
  const confirm = { ...request, review };
  const draft = { status: 'review', review, enrollment: offerId } as const;
  const factors = () => ({ password: new Uint8Array([1, 2, 3]), ask: new Uint8Array(32).fill(7) });
  const wiped = (owned: ReturnType<typeof factors>) => {
    assert.deepEqual(owned.password, new Uint8Array(3));
    assert.deepEqual(owned.ask, new Uint8Array(32));
  };
  let consumed: ReturnType<typeof factors> | undefined;
  let commits = 0;
  let checked: (() => boolean) | undefined;
  let settle: (() => void) | undefined;
  const opened = f.openAdministration(
    async () => ({ status: 'unavailable' }),
    undefined,
    undefined,
    undefined,
    async (input, auth, accepted) => {
      assert.equal(accepted(), true);
      if (!input.review) {
        assert.deepEqual(input, request);
        assert.equal(auth, undefined);
        return draft;
      }
      assert.deepEqual(input, confirm);
      assert.ok(auth?.ask);
      assert.deepEqual(auth.password, new Uint8Array([1, 2, 3]));
      consumed = { password: auth.password, ask: auth.ask };
      commits++;
      if (commits === 2) {
        checked = accepted;
        await new Promise<void>((resolve) => {
          settle = resolve;
        });
      }
      return { status: 'changed' };
    },
  );
  const unreviewed = factors();
  await assert.rejects(f.personalRecovery(f.event, confirm, unreviewed), /review/i);
  wiped(unreviewed);
  const untrusted = factors();
  await assert.rejects(
    f.personalRecovery({ ...f.event, senderFrame: { url } }, confirm, untrusted),
    /unavailable/i,
  );
  wiped(untrusted);
  await assert.rejects(f.personalRecovery(f.event, { ...request, suspension: '017' }), /review/i);
  assert.deepEqual(await f.personalRecovery(f.event, request), draft);
  const wrongScope = factors();
  await assert.rejects(
    f.personalRecovery(f.event, { ...confirm, suspension: '18' }, wrongScope),
    /review/i,
  );
  wiped(wrongScope);
  const stale = factors();
  await assert.rejects(f.personalRecovery(f.event, confirm, stale), /review/i);
  wiped(stale);
  assert.deepEqual(await f.personalRecovery(f.event, request), draft);
  const input = factors();
  assert.deepEqual(await f.personalRecovery(f.event, confirm, input), { status: 'changed' });
  assert.ok(consumed);
  wiped(consumed);
  wiped(input);
  assert.deepEqual(await f.personalRecovery(f.event, request), draft);
  const interrupted = factors();
  const pending = f.personalRecovery(f.event, confirm, interrupted);
  assert.equal(checked?.(), true);
  const concurrent = factors();
  await assert.rejects(f.personalRecovery(f.event, confirm, concurrent), /unavailable/i);
  wiped(concurrent);
  f.revoke();
  assert.equal(checked?.(), false);
  settle?.();
  await assert.rejects(pending, /interrupted/i);
  wiped(interrupted);
  assert.ok(consumed);
  wiped(consumed);
  assert.equal(commits, 2);
  await f.dialog.cancel();
  await opened;
});
const resetInput = () => ({
  targetLogin: 'fixture-user',
  requestId: resetRequestId,
  recipient: new Uint8Array(32).fill(8),
  password: Uint8Array.of(7),
  ask: new Uint8Array(32).fill(9),
});
const wipedReset = (input: SharedAccountResetIssueInput) =>
  [input.password, input.ask, input.recipient].every((bytes) => bytes?.every((b) => b === 0));
const resetReceipt = {
  status: 'issued',
  handover: {
    workspaceId,
    requestId: resetRequestId,
    offerId,
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: Buffer.alloc(32, 7).toString('base64'),
      ciphertext: Buffer.alloc(64, 4).toString('base64'),
    },
  },
};

test('reset queue accepts bounded pages and exact account and offer pairs', () => {
  const page = (targets: unknown[], next?: string) => ({
    status: 'ready',
    page: { targets, ...(next ? { next } : {}) },
  });
  const id = (i: number) => `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`;
  const target = {
    userId: id(1),
    loginName: 'active-account',
    status: 'awaiting-handover',
    eligible: true,
    offerId,
    expiresAt: 1800000000,
  };
  assert.deepEqual(parseAccountResetTargetPage(page([]), null), page([]));
  assert.deepEqual(parseAccountResetTargetPage(page([target]), null), page([target]));
  for (const status of ['handed-over', 'redeemed', 'expired', 'inactive'])
    assert.ok(parseAccountResetTargetPage(page([{ ...target, status }]), null));
  assert.ok(
    parseAccountResetTargetPage(
      page([{ userId: id(1), loginName: 'active-account', status: 'not-issued', eligible: false }]),
      null,
    ),
  );
  const fifty = Array.from({ length: 50 }, (_, i) => ({ ...target, userId: id(i + 1) }));
  assert.deepEqual(parseAccountResetTargetPage(page(fifty, id(50)), null), page(fifty, id(50)));
  for (const invalid of [
    page(fifty, id(51)),
    page([target], id(1)),
    page([...fifty, { ...target, userId: id(51) }]),
    page([target, target]),
    page([{ ...target, loginName: 'bad\nname' }]),
    page([{ ...target, status: 'undeclared' }]),
    page([{ ...target, expiresAt: 0 }]),
    page([{ ...target, offerId: 'bad-id' }]),
    page([{ ...target, eligible: 'true' }]),
    page([{ ...target, status: 'not-issued' }]),
    { status: 'ready', page: { targets: null } },
  ])
    assert.equal(parseAccountResetTargetPage(invalid, null), undefined);
  assert.equal(parseAccountResetTargetPage(page([target]), id(1)), undefined);
  assert.equal(parseAccountResetMark({ userId: id(1), offerId, loginName: 'ignored' }), undefined);
  assert.deepEqual(parseAccountResetMark({ userId: id(1), offerId }), { userId: id(1), offerId });
  for (const status of ['handed-over', 'redeemed', 'unsupported', 'unavailable', 'busy'])
    assert.deepEqual(parseAccountResetMarkResult({ status }), { status });
  assert.equal(parseAccountResetMarkResult({ status: 'unknown' }), undefined);
});

test('the reset window keeps a displayed offer bound until that handover is resolved', async () => {
  const f = fixture();
  const confirmed: unknown[] = [];
  const done = f.openAccountReset({
    workspaceId,
    targets: async (after, accepted) => {
      assert.ok(accepted());
      assert.equal(after, null);
      return { status: 'ready', page: { targets: [] } };
    },
    mark: async (mark, accepted) => {
      assert.ok(accepted());
      confirmed.push(mark);
      return { status: 'handed-over' };
    },
    submit: async () => parseSharedAccountResetIssue(resetReceipt)!,
  });
  assert.deepEqual(await f.resetTargets(f.event, null), { status: 'ready', page: { targets: [] } });
  assert.throws(() => f.resetTargets(f.event, 'invalid'), /unavailable/);
  assert.throws(() => f.markResetHandover(f.event, { userId: workspaceId }), /unavailable/);
  const issue = async () => {
    const pending = f.issueReset(f.event, resetInput());
    f.finishPicker('/owner/reset.whreset');
    assert.deepEqual(await pending, resetReceipt);
  };
  await issue();
  await assert.rejects(
    f.markResetHandover(f.event, { userId: workspaceId, offerId: resetRequestId }),
    /unavailable/,
  );
  assert.throws(() => f.leaveResetPending(f.event, resetRequestId), /unavailable/);
  assert.deepEqual(await f.markResetHandover(f.event, { userId: workspaceId, offerId }), {
    status: 'handed-over',
  });
  assert.deepEqual(confirmed, [{ userId: workspaceId, offerId }]);
  await issue();
  assert.equal(f.leaveResetPending(f.event, offerId), true);
  assert.equal(confirmed.length, 1);
  assert.equal(f.close(f.event), true);
  await done;
});

test('reset issuance validates exact borrowed inputs and returns only a fixed ciphertext receipt', () => {
  for (const patch of [
    { path: '/untrusted/offer.whreset' },
    { requestId: 'not-a-uuid' },
    { targetLogin: 'a'.repeat(257) },
    { targetLogin: 'invalid\nuser' },
    { password: new Uint8Array() },
    { recipient: new Uint8Array(31).fill(7) },
    { ask: new Uint8Array(31).fill(7) },
    { suspension: '17' },
    { targetUserId: offerId, suspension: '017' },
    { targetUserId: offerId, suspension: '9223372036854775808' },
  ]) {
    const input = { ...resetInput(), ...patch };
    assert.throws(() => consumeSharedAccountResetIssue(input), /Invalid/);
    assert.ok(wipedReset(input));
  }
  const overlap = new Uint8Array(32).fill(9);
  const consumed = consumeSharedAccountResetIssue({
    ...resetInput(),
    recipient: overlap,
    ask: overlap,
    password: overlap.subarray(0, 1),
  });
  assert.ok(overlap.every((b) => b === 0));
  assert.deepEqual([consumed.recipient[0], consumed.password[0], consumed.ask?.[0]], [9, 9, 9]);
  assert.deepEqual(parseSharedAccountResetIssue(resetReceipt), resetReceipt);
  assert.equal(parseSharedAccountResetIssue({ ...resetReceipt, code: 'unsafe' }), undefined);
  assert.equal(
    parseSharedAccountResetIssue({
      ...resetReceipt,
      handover: {
        ...resetReceipt.handover,
        bundle: { ...resetReceipt.handover.bundle, ciphertext: '' },
      },
    }),
    undefined,
  );
  for (const status of [
    'unavailable',
    'invalid-login',
    'invalid-authentication',
    'invalid-recipient',
    'publication-disabled',
    'save-failed',
  ])
    assert.deepEqual(parseSharedAccountResetIssue({ status }), { status });
});

test('custodian re-enrollment is bound to the latest eligible suspension review', async () => {
  const f = fixture();
  const scope = { accountId: offerId, suspension: '17' };
  const eligible = { status: 'enrollment-required', canReenroll: true } as const;
  assert.deepEqual(parsePersonalRootRecoveryReply(eligible, scope), eligible);
  assert.equal(
    parsePersonalRootRecoveryReply({ ...eligible, canReenroll: false }, scope),
    undefined,
  );
  assert.equal(
    parsePersonalRootRecoveryReply(eligible, { ...scope, review: 'be'.repeat(32) }),
    undefined,
  );

  const input = () => ({
    ...resetInput(),
    targetUserId: scope.accountId,
    suspension: scope.suspension,
  });
  let publications = 0;
  let borrowed: SharedAccountResetIssueInput | undefined;
  const closed = f.openAdministration(
    async () => ({ status: 'unavailable' }),
    undefined,
    undefined,
    undefined,
    async ({ accountId, suspension }) =>
      accountId === scope.accountId && suspension === scope.suspension
        ? eligible
        : { status: 'stale' },
    {
      workspaceId,
      submit: async (path, value, accepted) => {
        assert.equal(path, '/owner/replacement.whreset');
        assert.ok(accepted());
        assert.deepEqual(value, input());
        borrowed = value;
        publications++;
        return resetReceipt;
      },
    },
  );
  const reject = async (request: ReturnType<typeof input>) => {
    await assert.rejects(f.issueReset(f.event, request));
    assert.ok(wipedReset(request));
  };
  assert.throws(() => f.resetContext(f.event), /unavailable/);
  await reject(input());
  assert.deepEqual(await f.personalRecovery(f.event, scope), eligible);
  assert.equal(f.resetContext(f.event), workspaceId);
  await reject({ ...input(), targetUserId: resetRequestId });
  await reject({ ...input(), suspension: '18' });
  await f.personalRecovery(f.event, { ...scope, suspension: '18' });
  await reject(input());

  await f.personalRecovery(f.event, scope);
  const picking = f.issueReset(f.event, input());
  await assert.rejects(f.personalRecovery(f.event, scope), /unavailable/);
  assert.throws(() => f.close(f.event), /busy/);
  f.finishPicker(null);
  assert.equal(await picking, null);
  assert.equal(publications, 0);

  const issuing = f.issueReset(f.event, input());
  f.finishPicker('/owner/replacement.whreset');
  assert.deepEqual(await issuing, resetReceipt);
  assert.ok(borrowed && wipedReset(borrowed));
  assert.equal(publications, 1);
  await reject(input());
  assert.throws(() => f.resetContext(f.event), /unavailable/);

  await f.personalRecovery(f.event, scope);
  const interrupted = f.issueReset(f.event, input());
  f.parent.webContents.emit('did-start-navigation', {}, '', false, true);
  await closed;
  f.finishPicker('/owner/replacement.whreset');
  await assert.rejects(interrupted, /interrupted/);
  assert.equal(f.dialog.active, false);
  assert.equal(publications, 1);
});

test('custodian reset uses only the native picker and wipes factors when its owner leaves', async () => {
  const f = fixture();
  const denied = resetInput();
  await assert.rejects(f.issueReset(f.event, denied), /unavailable/);
  assert.ok(wipedReset(denied));
  let submitted: SharedAccountResetIssueInput | undefined;
  let finish: (() => void) | undefined;
  const done = f.openAccountReset({
    workspaceId,
    submit: async (path, input, accepted) => {
      assert.equal(path, '/owner/reset.whreset');
      assert.ok(accepted());
      assert.deepEqual(input, resetInput());
      submitted = input;
      await new Promise<void>((resolve) => {
        finish = resolve;
      });
      return parseSharedAccountResetIssue(resetReceipt)!;
    },
    targets: async () => ({ status: 'unsupported' }),
    mark: async () => ({ status: 'unsupported' }),
  });
  assert.equal(f.mode(f.event), 'account-reset');
  assert.equal(f.resetContext(f.event), workspaceId);
  assert.throws(() => f.resetContext(f.event, null), /unavailable/);
  assert.throws(() => f.resetContext({ ...f.event, senderFrame: { url } }), /unavailable/);
  const scoped = { ...resetInput(), targetUserId: offerId, suspension: '17' };
  await assert.rejects(f.issueReset(f.event, scoped), /review/);
  assert.ok(wipedReset(scoped));

  const picker = f.issueReset(f.event, resetInput());
  await assert.rejects(f.issueReset(f.event, resetInput()), /unavailable/);
  assert.throws(() => f.close(f.event), /busy/);
  f.finishPicker(null);
  assert.equal(await picker, null);
  const issue = f.issueReset(f.event, resetInput());
  f.finishPicker('/owner/reset.whreset');
  await Promise.resolve();
  assert.ok(submitted);
  finish!();
  assert.deepEqual(await issue, resetReceipt);
  assert.ok(wipedReset(submitted));
  await assert.rejects(f.issueReset(f.event, resetInput()), /unavailable/);
  assert.equal(f.close(f.event), true);
  await done;

  const stale = fixture();
  const closed = stale.openAccountReset({
    workspaceId,
    submit: async () => assert.fail('Untrusted parent dispatched a reset.'),
    targets: async () => ({ status: 'unsupported' }),
    mark: async () => ({ status: 'unsupported' }),
  });
  const pending = stale.issueReset(stale.event, resetInput());
  stale.parent.webContents.emit('did-start-navigation', {}, '', false, true);
  await closed;
  assert.equal(stale.dialog.active, true);
  stale.finishPicker('/owner/reset.whreset');
  await assert.rejects(pending, /interrupted/);
  assert.equal(stale.dialog.active, false);
});

const inspectedArchive = {
  workspaceId,
  roleTag: 'archivetag',
  sourceSchemaVersion: 49 as const,
  profile: 'default' as const,
  accounts: 1,
  nodes: 3,
};
const archiveDigest = 'e'.repeat(64);

test('restore receipt exposes only bounded display and deployment identity', () => {
  const current = { ...inspectedArchive, sourceSchemaVersion: 100 };
  assert.deepEqual(parseSharedRecoveryInspection({ status: 'ready', summary: current }), {
    status: 'ready',
    summary: current,
  });
  for (const status of ['ready', 'saved', 'save-failed']) {
    assert.deepEqual(parseSharedRecoveryInspection({ status, summary: inspectedArchive }), {
      status,
      summary: inspectedArchive,
    });
  }
  for (const status of ['invalid-backup', 'invalid-password']) {
    assert.deepEqual(parseSharedRecoveryInspection({ status }), { status });
    assert.equal(parseSharedRecoveryInspection({ status, summary: inspectedArchive }), undefined);
  }
  for (const summary of [
    null,
    {},
    { ...inspectedArchive, path: 'private' },
    { ...inspectedArchive, roleTag: 'not-valid' },
    { ...inspectedArchive, nodes: -1 },
    { ...inspectedArchive, accounts: 100001 },
    { ...inspectedArchive, sourceSchemaVersion: 48 },
    { ...inspectedArchive, sourceSchemaVersion: 101 },
    { ...inspectedArchive, sourceSchemaVersion: 55.5 },
    { ...inspectedArchive, sourceSchemaVersion: '85' },
    { ...inspectedArchive, profile: 'hardened' },
    { ...inspectedArchive, workspaceId: 'bad' },
  ]) {
    assert.equal(parseSharedRecoveryInspection({ status: 'ready', summary }), undefined);
  }
  assert.equal(parseSharedRecoveryInspection(null), undefined);
  assert.equal(parseSharedRecoveryInspection({ status: 'unexpected' }), undefined);
  const ready = { status: 'ready', summary: inspectedArchive };
  for (let version = 49; version <= 89; version++) {
    const receipt = {
      ...ready,
      summary: { ...inspectedArchive, sourceSchemaVersion: version },
      archiveDigest,
    };
    assert.deepEqual(parseSharedRecoveryInspectionReceipt(receipt), receipt);
  }
  assert.equal(parseSharedRecoveryInspectionReceipt(ready), undefined);
  assert.equal(
    parseSharedRecoveryInspectionReceipt({ ...ready, archiveDigest: 'private' }),
    undefined,
  );
  assert.equal(
    parseSharedRecoveryInspectionReceipt({ status: 'invalid-backup', archiveDigest }),
    undefined,
  );
});

test('restore mode chooses archive and deployment paths and clears the password on lock', async () => {
  const fresh = () => new Uint8Array(76).fill(65);
  let source: string | null = '/owner/backup.json';
  let selected = 0;
  let published = 0;
  let submitted;
  let finishNative: (() => void) | undefined;
  let hold = false;
  const f = fixture(false, undefined, {
    choose: async () => {
      selected++;
      return source;
    },
    inspect: async (input, current) => {
      assert.ok(current());
      submitted = input;
      assert.deepEqual(input.password, fresh());
      assert.equal(input.path, '/owner/backup.json');
      if (hold)
        await new Promise<void>((resolve) => {
          finishNative = resolve;
        });
      if (input.scriptPath) published++;
      return {
        status: input.scriptPath ? 'saved' : 'ready',
        summary: inspectedArchive,
        archiveDigest,
      };
    },
  });
  const invalid = { password: fresh(), saveScript: false };
  await assert.rejects(f.inspectBackup(f.event, invalid), /unavailable/);
  assert.deepEqual(invalid.password, new Uint8Array(76));
  const parent = f.parent as any;
  const opening = f.dialog.open(parent, () => true, undefined, false, 'restore');
  assert.equal(f.mode(f.event), 'restore');
  await assert.rejects(
    f.inspectBackup(f.event, { ...invalid, password: fresh(), path: 'renderer.json' }),
    /Invalid/,
  );
  assert.equal(selected, 0);
  source = null;
  assert.equal(await f.inspectBackup(f.event, { password: fresh(), saveScript: true }), null);
  source = '/owner/backup.json';
  const ready = await f.inspectBackup(f.event, { password: fresh(), saveScript: false });
  assert.equal(ready.status, 'ready');
  assert.equal(ready.archiveDigest, undefined);
  assert.deepEqual(submitted.password, new Uint8Array(76));
  const saving = f.inspectBackup(f.event, { password: fresh(), saveScript: true });
  await Promise.resolve();
  f.finishPicker('/owner/restore.sql');
  assert.equal((await saving).status, 'saved');
  assert.equal(submitted.scriptPath, '/owner/restore.sql');
  assert.equal(published, 1);
  hold = true;
  const late = f.inspectBackup(f.event, { password: fresh(), saveScript: false });
  await Promise.resolve();
  assert.throws(() => f.close(f.event), /busy/);
  await f.dialog.cancel();
  await opening;
  assert.deepEqual(submitted.password, new Uint8Array(76));
  assert.equal(f.dialog.active, true);
  finishNative!();
  await assert.rejects(late, /interrupted/);
  assert.equal(f.dialog.active, false);
});

test('restore pins the inspected archive, consumes both factors and invalidates changed input', async () => {
  const path = resolve('archive.json');
  const request = () => ({
    host: 'db.example.test',
    port: 5432,
    database: 'recovered',
    confirmed: true,
    password: new Uint8Array(76).fill(2),
    deployerPassword: Uint8Array.of(3),
  });
  let status = 'uncertain' as 'uncertain' | 'archive-changed' | 'restored';
  let submitted;
  const f = fixture(false, undefined, {
    choose: async () => path,
    inspect: async () => ({ status: 'ready', summary: inspectedArchive, archiveDigest }),
    apply: async (input, current) => {
      assert.ok(current());
      assert.equal(input.path, path);
      assert.equal(input.workspaceId, workspaceId);
      assert.equal(input.roleTag, inspectedArchive.roleTag);
      assert.equal(input.archiveDigest, archiveDigest);
      assert.equal(input.host, request().host);
      submitted = input;
      return status;
    },
  });
  const closed = f.dialog.open(f.parent as any, () => true, undefined, false, 'restore');
  const assertClear = (value: ReturnType<typeof request>) => {
    assert.ok(value.password.every((byte) => byte === 0));
    assert.ok(value.deployerPassword.every((byte) => byte === 0));
  };
  const attempt = request();
  await assert.rejects(f.applyBackup(f.event, attempt), /unavailable/);
  assertClear(attempt);
  const inspect = () =>
    f.inspectBackup(f.event, { password: request().password, saveScript: false });
  await inspect();
  for (const invalid of [
    { path: '/forged.json' },
    { confirmed: false },
    { port: 65536 },
    { host: 'https://input' },
    { database: 'bad name' },
  ]) {
    const bad = { ...request(), ...invalid };
    await assert.rejects(f.applyBackup(f.event, bad), /Invalid/);
    assertClear(bad);
  }
  assert.equal(await f.applyBackup(f.event, request()), 'uncertain');
  assertClear(submitted);
  assert.ok(
    validSharedRecoveryRestore({
      ...submitted,
      password: request().password,
      deployerPassword: request().deployerPassword,
    }),
  );
  status = 'archive-changed';
  assert.equal(await f.applyBackup(f.event, request()), status);
  await assert.rejects(f.applyBackup(f.event, request()), /unavailable/);
  await inspect();
  status = 'restored';
  assert.equal(await f.applyBackup(f.event, request()), status);
  await assert.rejects(f.applyBackup(f.event, request()), /unavailable/);
  assert.equal(f.close(f.event), true);
  await closed;
});

const backupReceipt = {
  status: 'exported',
  vaultId: workspaceId,
  exportId: '22222222-2222-4222-8222-222222222222',
  bundle: {
    formatVersion: 1,
    suiteId: 2,
    enc: Buffer.alloc(32, 53).toString('base64'),
    ciphertext: Buffer.alloc(92, 54).toString('base64'),
  },
};

test('workspace backup receipts have a bounded ciphertext and exact shape', () => {
  const { status, vaultId, exportId, bundle } = backupReceipt;
  assert.deepEqual(parseSharedRecoveryBackup(backupReceipt), {
    status,
    receipt: { vaultId, enrollmentId: exportId, bundle },
  });
  for (const value of [
    'unavailable',
    'authentication-required',
    'invalid-authentication',
    'too-large',
    'save-failed',
  ])
    assert.deepEqual(parseSharedRecoveryBackup({ status: value }), { status: value });
  for (const value of [
    null,
    [],
    { status: 'future' },
    { status, password: 'private' },
    { ...backupReceipt, password: 'private' },
    { ...backupReceipt, exportId: 'invalid' },
    { ...backupReceipt, bundle: { ...bundle, ciphertext: 'a==a' } },
  ])
    assert.equal(parseSharedRecoveryBackup(value), undefined);
});

test('backup mode owns the path, consumes factors, and closes safely across cancellations', async () => {
  const input = () => ({
    recipient: new Uint8Array(32).fill(1),
    password: Uint8Array.of(7),
    ask: new Uint8Array(32).fill(9),
  });
  const cleared = (value: SharedRecoveryBackupInput) =>
    Object.values(value).every((factor) => factor.every((byte: number) => byte === 0));
  const f = fixture();
  const invalid = input();
  await assert.rejects(f.exportBackup(f.event, invalid), /unavailable/);
  assert.ok(cleared(invalid));
  const result = parseSharedRecoveryBackup(backupReceipt)!;
  let sent: SharedRecoveryBackupInput | undefined;
  let complete: (() => void) | undefined;
  const closed = f.openBackup({
    authenticationRequired: true,
    submit: async (path, factors, accepted) => {
      assert.equal(path, '/owner/backup.json');
      assert.ok(accepted());
      assert.deepEqual(factors, input());
      sent = factors;
      await new Promise<void>((resolve) => {
        complete = resolve;
      });
      return result;
    },
  });
  assert.equal(f.mode(f.event), 'backup');
  assert.equal(f.backupContext(f.event), true);
  assert.throws(() => f.backupContext(f.event, null), /unavailable/);
  const forged = { path: '/forged.json', ...input() };
  await assert.rejects(f.exportBackup(f.event, forged), /Invalid/);
  assert.ok(cleared({ recipient: forged.recipient, password: forged.password, ask: forged.ask }));
  const cancelled = input();
  const picking = f.exportBackup(f.event, cancelled);
  assert.ok(cleared(cancelled));
  await assert.rejects(f.exportBackup(f.event, input()), /unavailable/);
  assert.throws(() => f.close(f.event), /busy/);
  f.finishPicker(null);
  assert.equal(await picking, null);
  const exporting = f.exportBackup(f.event, input());
  f.finishPicker('/owner/backup.json');
  await Promise.resolve();
  assert.ok(sent);
  complete!();
  assert.deepEqual(await exporting, result);
  assert.ok(cleared(sent));
  await assert.rejects(f.exportBackup(f.event, input()), /unavailable/);
  assert.equal(f.close(f.event), true);
  await closed;
  assert.equal(f.dialog.active, false);

  const interrupted = fixture();
  const exiting = interrupted.openBackup({
    authenticationRequired: false,
    submit: async () => assert.fail('Revoked dialog dispatched a native export.'),
  });
  const supplied = input();
  await assert.rejects(interrupted.exportBackup(interrupted.event, supplied), /Invalid/);
  assert.ok(cleared(supplied));
  const pending = interrupted.exportBackup(interrupted.event, { recipient: input().recipient });
  interrupted.parent.webContents.emit('did-start-navigation', {}, '', false, true);
  await exiting;
  assert.equal(interrupted.dialog.active, true);
  interrupted.finishPicker('/owner/backup.json');
  await assert.rejects(pending, /interrupted/);
  assert.equal(interrupted.dialog.active, false);
});

test('backup picker distinguishes likely sync folders and respects owner changes', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'wormhole-backup-picker-'));
  try {
    const cloud = join(folder, 'OneDrive - Team');
    await mkdir(cloud);
    const offline = join(folder, 'backup.json');
    const synchronized = join(cloud, 'backup.json');
    for (const response of [0, 1, 2, 'closed', 'cancelled'] as const) {
      let opens = 0;
      let warnings = 0;
      let current = true;
      const chosen = await pickSharedBackupDestination(
        {
          showSaveDialog: (async () => {
            const first = ++opens === 1;
            return { canceled: response === 'cancelled', filePath: first ? synchronized : offline };
          }) as any,
          showMessageBox: (async (_parent, options) => {
            warnings++;
            assert.equal(options.cancelId, 2);
            assert.match(options.message, /appears to sync/);
            if (response === 'closed') current = false;
            return { response, checkboxChecked: false };
          }) as any,
        },
        {} as any,
        () => current,
      );
      assert.equal(chosen, response === 0 ? offline : response === 1 ? synchronized : null);
      assert.equal(opens, response === 0 ? 2 : 1);
      assert.equal(warnings, response === 'cancelled' ? 0 : 1);
    }
  } finally {
    await rm(folder, { recursive: true, force: true });
  }
});

test('the recovery window owns both paths and wipes factors, including on cancellation', async () => {
  const input = () => ({
    workspaceId,
    host: 'db.example.test',
    port: 5432,
    database: 'workspace',
    role: 'wh_testrole_deployer',
    loginName: 'new-admin',
    deviceName: 'device',
    confirmed: true,
    recoveryCode: new Uint8Array(76).fill(65),
    deployerPassword: Uint8Array.of(32),
    accountPassword: Uint8Array.of(42),
    ask: new Uint8Array(32).fill(7),
  });
  for (const kind of ['cancel', 'complete', 'forged-path', 'wrong-mode', 'after-navigation']) {
    const picked: string[] = [];
    let f: ReturnType<typeof fixture>;
    let borrowed: ReturnType<typeof input> | undefined;
    f = fixture(false, {
      choose: async (_, artifact) => {
        picked.push(artifact);
        if (kind === 'after-navigation')
          f.parent.webContents.emit('did-start-navigation', {}, '', false, true);
        if (kind === 'cancel') return null;
        return artifact === 'kit' ? '/files/team.whrecovery' : '/files/team.whtls';
      },
      submit: async (value, accepted) => {
        assert.ok(accepted());
        assert.equal(value.kitPath, '/files/team.whrecovery');
        assert.equal(value.trustPath, '/files/team.whtls');
        borrowed = value;
        return { admitted: true, lockedMemory: true, orgEscrow: true, tls: 'verified' };
      },
    });
    const opened = f.open(kind !== 'wrong-mode');
    assert.equal(f.mode(f.event), kind === 'wrong-mode' ? 'setup' : 'recovery');
    const value = input();
    const action = f.recover(
      f.event,
      kind === 'forged-path' ? Object.assign(value, { kitPath: '/forged' }) : value,
    );
    if (kind === 'forged-path' || kind === 'wrong-mode')
      await assert.rejects(action as Promise<unknown>);
    else assert.equal(await action, kind === 'complete');
    assert.ok(value.recoveryCode.every((n) => n === 0) && value.ask.every((n) => n === 0));
    if (kind === 'complete') {
      assert.deepEqual(picked, ['kit', 'trust']);
      assert.ok(borrowed?.deployerPassword.every((n) => n === 0));
      assert.equal(((await opened) as any).admitted, true);
    } else {
      assert.equal(borrowed, undefined);
      await f.dialog.cancel();
      assert.equal(await opened, undefined);
    }
  }
});

test('accepts the protected main frame and wipes transient DBA input from every sender', async () => {
  const f = fixture();
  const opened = f.open();
  await assert.rejects(f.open(), /setup is unavailable/);
  const badSenders = [
    { ...f.event, sender: f.parent.webContents },
    { ...f.event, senderFrame: { url } },
    { ...f.event, sender: null },
  ];
  for (const event of badSenders) {
    const password = new Uint8Array([1, 2]);
    await assert.rejects(
      f.request(event, { action: 'check', workspaceId, role: 'dba', password }) as Promise<unknown>,
      /setup is unavailable/,
    );
    assert.deepEqual([...password], [0, 0]);
  }
  assert.equal(f.calls.length, 0);
  const password = new Uint8Array([1, 2]);
  assert.deepEqual(
    await f.request(f.event, { action: 'check', workspaceId, role: 'dba', password }),
    { plan: null },
  );
  assert.deepEqual(f.calls, [
    { action: 'check', workspaceId, role: 'dba', password: new Uint8Array(2) },
  ]);
  assert.equal(f.child.shown, true);
  assert.equal(f.close(f.event), true);
  await opened;
  assert.equal(f.child.destroyed, true);
});

test('administration pages require the isolated main frame and never survive modal close', async () => {
  const f = fixture();
  const request = { kind: 'audit' } as const;
  let calls = 0;
  let release = () => {};
  const opened = f.openAdministration(async (value) => {
    calls++;
    assert.deepEqual(value, request);
    if (calls === 2) await new Promise<void>((resolve) => (release = resolve));
    return { status: 'ready', page: { kind: 'audit', entries: [] } };
  });
  await assert.rejects(f.inventory({ ...f.event, senderFrame: { url } }, request));
  await assert.rejects(f.inventory(f.event, { kind: 'audit', password: 'unexpected' }));
  await assert.rejects(f.inventory(f.event, request, request));
  assert.equal(calls, 0);
  assert.equal((await f.inventory(f.event, request)).status, 'ready');
  const pending = f.inventory(f.event, request);
  const refused = assert.rejects(pending, /interrupted/i);
  await assert.rejects(f.inventory(f.event, request));
  await f.dialog.cancel();
  release();
  await refused;
  await opened;
  assert.equal(calls, 2);
});

test('workspace access can confirm only the review from the current protected window', async () => {
  const f = fixture();
  const request = { action: 'disable-account', targetId: workspaceId } as const;
  const confirmation = { ...request, revision: '1' };
  let changes = 0;
  const opened = f.openAdministration(
    async () => ({ status: 'unavailable' }),
    async (value) => {
      if (value.revision) {
        changes++;
        assert.deepEqual(value, confirmation);
        return { status: 'changed' };
      }
      return {
        status: 'review',
        review: { ...confirmation, login: 'member', name: '', currentDevice: false },
      };
    },
  );
  await assert.rejects(f.access(f.event, confirmation), /review/i);
  await assert.rejects(f.access({ ...f.event, senderFrame: { url } }, request), /unavailable/i);
  await assert.rejects(f.access(f.event, { ...request, revision: '01' }), /review/i);
  assert.equal((await f.access(f.event, request)).status, 'review');
  await assert.rejects(f.access(f.event, { ...confirmation, action: 'enable-account' }), /review/i);
  await assert.rejects(f.access(f.event, confirmation), /review/i);
  assert.equal((await f.access(f.event, request)).status, 'review');
  assert.equal((await f.access(f.event, confirmation)).status, 'changed');
  await assert.rejects(f.access(f.event, confirmation), /review/i);
  assert.equal(changes, 1);
  await f.dialog.cancel();
  await opened;
});

test('workspace access bridge binds reviews and receipts to the reviewed action and revision', () => {
  const request = { action: 'revoke-device', targetId: workspaceId } as const;
  const confirmation = { ...request, revision: '9223372036854775807' };
  const review = { ...confirmation, login: 'member', name: '', currentDevice: true };
  assert.deepEqual(parseWorkspaceAccessRequest(request), request);
  assert.deepEqual(parseWorkspaceAccessRequest(confirmation), confirmation);
  for (const value of [
    null,
    { ...request, targetId: 'invalid' },
    { ...request, action: 'delete-account' },
    { ...request, revision: '9223372036854775808' },
    { ...request, revision: null },
    { ...request, password: 'unexpected' },
  ])
    assert.equal(parseWorkspaceAccessRequest(value), undefined);
  assert.deepEqual(parseWorkspaceAccessReply({ status: 'review', review }, request), {
    status: 'review',
    review,
  });
  assert.deepEqual(
    parseWorkspaceAccessReply({ status: 'changed', currentDevice: true }, confirmation),
    { status: 'changed', currentDevice: true },
  );
  assert.deepEqual(parseWorkspaceAccessReply({ status: 'changed' }, confirmation), {
    status: 'changed',
  });
  assert.equal(parseWorkspaceAccessReply({ status: 'changed' }, request), undefined);
  assert.equal(parseWorkspaceAccessReply({ status: 'review', review }, confirmation), undefined);
  assert.equal(
    parseWorkspaceAccessReply(
      { status: 'changed', currentDevice: true },
      {
        ...confirmation,
        action: 'enable-account',
      },
    ),
    undefined,
  );
  for (const fields of [
    { action: 'enable-account' },
    { targetId: '00000000-0000-0000-0000-000000000002' },
    { currentDevice: 'true' },
    { login: 'member\u0000' },
    { login: '🦉'.repeat(100) },
    { revision: '0' },
    { name: 'x'.repeat(4097) },
    { grant: true },
  ])
    assert.equal(
      parseWorkspaceAccessReply({ status: 'review', review: { ...review, ...fields } }, request),
      undefined,
    );
  for (const status of ['unchanged', 'stale', 'busy', 'unavailable', 'unsupported']) {
    assert.deepEqual(parseWorkspaceAccessReply({ status }, request), { status });
    assert.equal(parseWorkspaceAccessReply({ status, review }, request), undefined);
  }
  const personalRecovery = { status: 'personal-recovery-required' };
  const enable = { ...request, action: 'enable-account' } as const;
  assert.deepEqual(parseWorkspaceAccessReply(personalRecovery, enable), personalRecovery);
  assert.deepEqual(
    parseWorkspaceAccessReply(personalRecovery, { ...enable, revision: '5' }),
    personalRecovery,
  );
  assert.equal(parseWorkspaceAccessReply(personalRecovery, request), undefined);
  assert.equal(parseWorkspaceAccessReply({ ...personalRecovery, review }, enable), undefined);
  assert.equal(parseWorkspaceAccessReply(null, request), undefined);
  assert.equal(parseWorkspaceAccessReply({ status: 'invalid' }, request), undefined);
});

test('suspension rotation confirmation requires the reviewed root in the protected window', async () => {
  const f = fixture();
  const request = {
    accountId: workspaceId,
    suspension: '8',
    boundaryId: workspaceId,
    purpose: 'secret',
    rootId: '32345678-1234-4234-8234-123456789abc',
    rootVersion: '9',
  } as const;
  const review = '12'.repeat(32);
  const confirm = { ...request, review };
  let commits = 0;
  const opened = f.openAdministration(
    async () => ({ status: 'unavailable' }),
    undefined,
    undefined,
    async (value) => {
      if (value.review) {
        assert.deepEqual(value, confirm);
        commits++;
        return { status: 'changed' };
      }
      assert.deepEqual(value, request);
      return { status: 'review', review };
    },
  );
  await assert.rejects(f.accountRotation(f.event, confirm), /review/i);
  await assert.rejects(
    f.accountRotation({ ...f.event, senderFrame: { url } }, request),
    /unavailable/i,
  );
  assert.equal((await f.accountRotation(f.event, request)).status, 'review');
  await assert.rejects(f.accountRotation(f.event, { ...confirm, suspension: '9' }), /review/i);
  await assert.rejects(f.accountRotation(f.event, confirm), /review/i);
  assert.equal((await f.accountRotation(f.event, request)).status, 'review');
  assert.equal((await f.accountRotation(f.event, confirm)).status, 'changed');
  await assert.rejects(f.accountRotation(f.event, confirm), /review/i);
  assert.equal(commits, 1);
  await f.dialog.cancel();
  await opened;
});

test('a cancelled or interrupted save picker cannot authorize a write', async () => {
  const f = fixture();
  const opened = f.open();
  const pending = f.request(f.event, { action: 'export', workspaceId }) as Promise<unknown>;
  assert.throws(() => f.close(f.event), /setup is busy/);
  const event = {
    prevented: false,
    preventDefault() {
      this.prevented = true;
    },
  };
  f.child.emit('close', event);
  assert.equal(event.prevented, true);
  f.finishPicker(null);
  assert.equal(await pending, null);
  const interrupted = f.request(f.event, { action: 'export', workspaceId }) as Promise<unknown>;
  f.revoke();
  f.finishPicker('C:/vault.sql');
  await assert.rejects(interrupted, /was interrupted/);
  assert.deepEqual(f.calls, []);
  await f.dialog.cancel();
  await opened;
});

test('passes only the chooser path, and closes when the parent navigates', async () => {
  const f = fixture();
  const opened = f.open();
  const pending = f.request(f.event, { action: 'export', workspaceId });
  f.finishPicker('C:/picked.sql');
  assert.deepEqual(await pending, { plan: null });
  assert.deepEqual(f.calls, [{ action: 'export', workspaceId, path: 'C:/picked.sql' }]);
  f.parent.webContents.emit('did-start-navigation', {}, '/other', false, false);
  assert.equal(f.child.destroyed, false);
  f.parent.webContents.emit('did-start-navigation', {}, '/next', false, true);
  await opened;
  assert.equal(f.child.destroyed, true);
  assert.equal(f.parent.listenerCount('closed'), 0);
});

test('locking during recovery kit selection retires the dialog and refuses late picker results', async () => {
  const f = fixture();
  const opened = f.open();
  assert.equal(f.dialog.active, true);
  const accountPassword = Uint8Array.of(7);
  const ask = new Uint8Array(32).fill(4);
  const pending = f.request(f.event, {
    action: 'admin-recovery',
    workspaceId,
    accountPassword,
    ask,
    recipient: new Uint8Array(32),
  }) as Promise<unknown>;
  await f.dialog.cancel();
  await opened;
  assert.equal(f.child.destroyed, true);
  f.finishPicker('C:/offline.whrecovery');
  await assert.rejects(pending, /was interrupted/);
  assert.equal(f.dialog.active, false);
  assert.equal(f.calls.length, 0);
  assert.equal(accountPassword[0], 0);
  assert.ok(ask.every((byte) => byte === 0));
});

test('locking wipes the wizard factors while the native response is still pending', async () => {
  const f = fixture(true);
  const opened = f.open();
  const pending = f.request(f.event, {
    action: 'admin-open',
    workspaceId,
    accountPassword: Uint8Array.of(7),
    ask: new Uint8Array(32).fill(4),
  }) as Promise<unknown>;
  const borrowed = f.calls[0] as { accountPassword: Uint8Array; ask: Uint8Array };
  assert.equal(borrowed.accountPassword[0], 7);
  await f.dialog.cancel();
  await opened;
  assert.equal(borrowed.accountPassword[0], 0);
  assert.ok(borrowed.ask.every((byte) => byte === 0));
  f.finishNative();
  await assert.rejects(pending, /was interrupted/);
  assert.equal(f.dialog.active, false);
});

test('a failed teardown keeps the window reserved for native cleanup', async () => {
  const f = fixture();
  const opened = f.open();
  f.child.refusesDestroy = true;
  assert.throws(() => f.close(f.event), /could not be closed/);
  await assert.rejects(opened, /could not be closed/);
  await assert.rejects(f.dialog.cancel(), /could not be closed/);
  await assert.rejects(f.open(), /setup is unavailable/);
  f.child.refusesDestroy = false;
  f.child.destroy();
  assert.equal(f.child.destroyed, true);
  assert.equal(f.parent.listenerCount('closed'), 0);
  await f.dialog.cancel();
});

test('load refusal retires the isolated window and rejects the open request', async () => {
  const f = fixture();
  f.child.refusesLoad = true;
  await assert.rejects(f.open(), /window could not be loaded/);
  assert.equal(f.child.destroyed, true);
});
