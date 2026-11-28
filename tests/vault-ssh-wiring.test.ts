import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { randomUUID } from 'node:crypto';
import { Session } from 'node:inspector/promises';
import { runInNewContext } from 'node:vm';
import { stripTypeScriptTypes } from 'node:module';
import { declarations } from './fixtures/main-source.ts';
import { mainSshHarness, mainSshSource } from './fixtures/vault-ssh-main.ts';
import { VaultSshIpc } from '../electron/vault-ssh-ipc.ts';

let profiler: Session;
before(async () => {
  profiler = new Session();
  profiler.connect();
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
});
after(async () => {
  try {
    const report = await profiler.post('Profiler.takePreciseCoverage');
    const names = new Set([
      'hasProtectedReservation',
      'ownsProtected',
      'captureOwner',
      'admitProtected',
      'closeProtected',
      'retireProtected',
    ]);
    const blocks = new Map<string, number>();
    for (const s of report.result.filter((s) => s.url === 'wormhole-vault-ssh-main.js')) {
      const scopes = s.functions.filter((f) => names.has(f.functionName)).map((f) => f.ranges[0]);
      for (const f of s.functions)
        if (
          scopes.some(
            (r) => f.ranges[0].startOffset >= r.startOffset && f.ranges[0].endOffset <= r.endOffset,
          )
        )
          for (const r of f.ranges) {
            const key = r.startOffset + ':' + r.endOffset;
            blocks.set(key, (blocks.get(key) ?? 0) + r.count);
          }
    }
    const percent = (100 * [...blocks.values()].filter((n) => n > 0).length) / blocks.size;
    console.log(`Main protected SSH admission methods: V8 block coverage ${percent.toFixed(2)}%`);
    assert.ok(percent >= 80);
    const nativeCode = stripTypeScriptTypes(
      mainSshSource.slice(
        mainSshSource.indexOf('class NativeSshBackend {'),
        mainSshSource.indexOf('function serializeAuthOperation'),
      ) + '\nNativeSshBackend;',
    );
    const manualStart = nativeCode.indexOf('manual: {'),
      manualEnd = nativeCode.indexOf('    route:', manualStart);
    assert.ok(manualStart > 0 && manualEnd > manualStart);
    const manualBlocks = new Map<string, number>();
    for (const script of report.result.filter((s) => s.url === 'wormhole-vault-ssh-main.js'))
      for (const fn of script.functions) {
        const extent = fn.ranges[0];
        if (extent.startOffset < manualStart || extent.endOffset > manualEnd) continue;
        for (const r of fn.ranges) {
          const key = `${r.startOffset}:${r.endOffset}`;
          manualBlocks.set(key, (manualBlocks.get(key) ?? 0) + r.count);
        }
      }
    assert.ok(manualBlocks.size);
    const manualPercent =
      (100 * [...manualBlocks.values()].filter((n) => n > 0).length) / manualBlocks.size;
    console.log(
      `Main private SSH credential callbacks: V8 block coverage ${manualPercent.toFixed(2)}%`,
    );
    assert.ok(manualPercent >= 80);
  } finally {
    profiler.disconnect();
  }
});

function fixture() {
  let options: any,
    failNative = false,
    accepted = true;
  const sessions = new Map<string, any>(),
    sent: any[] = [],
    trusts: string[] = [];
  const find = (id: string) => [...sessions.values()].find((s) => s.id === id || s.members.has(id));
  const event = (s: any, id: string, type: string) =>
    options.onLine(
      JSON.stringify({
        type,
        session_id: id,
        host: 'ssh.example',
        port: 22,
        username: 'native',
        fingerprint: 'pin',
      }),
    );
  const retire = async (s: any) => {
    if (!s) return;
    s.retiring = true;
    if (failNative) throw Error('SSH shutdown could not be confirmed.');
    const members = [...s.members];
    s.members.clear();
    try {
      await s.retired?.();
    } catch {
      throw Error('SSH shutdown could not be confirmed.');
    }
    sessions.delete(s.id);
    for (const id of members) event(s, id, 'closed');
  };
  class Sealed {
    constructor(q: any) {
      options = q;
    }
    has(id: string) {
      return Boolean(find(id)?.members.has(id));
    }
    hasReservation(id: string) {
      return Boolean(find(id));
    }
    admit(q: any, epoch: number, current: any, retired: any) {
      if (!accepted) return { accepted: false, result: Promise.reject(Error('refused')) };
      const s = {
        id: q.sessionId,
        q,
        epoch,
        current,
        retired,
        members: new Set([q.sessionId]),
        retiring: false,
      };
      sessions.set(s.id, s);
      return {
        accepted: true,
        result: Promise.resolve().then(() => {
          event(s, s.id, 'connected');
          return {
            sessionId: s.id,
            host: 'ssh.example',
            port: 22,
            username: 'native',
            fingerprint: 'pin',
          };
        }),
      };
    }
    open(q: any, epoch: number, current: any) {
      return this.admit(q, epoch, current, undefined).result;
    }
    connectedSessionIds() {
      return [...sessions.values()].filter((s) => !s.retiring).flatMap((s) => [...s.members]);
    }
    async shareSftp(source: string, id: string, current: any) {
      const s = find(source);
      assert.equal(current(), true);
      s.members.add(id);
      event(s, id, 'connected');
      return {
        sessionId: id,
        host: 'ssh.example',
        port: 22,
        username: 'native',
        fingerprint: 'pin',
      };
    }
    async close(id: string) {
      const s = find(id);
      if (!s) return;
      if (!s.retiring && !s.members.has(id)) return;
      if (s.retiring || s.members.size <= 1) return retire(s);
      if (s.members.delete(id)) event(s, id, 'closed');
    }
    async closeCohorts(ids: string[]) {
      const groups = new Set(ids.map(find).filter(Boolean));
      await Promise.all([...groups].map(retire));
    }
    async closeAll() {
      await Promise.all([...sessions.values()].map(retire));
    }
    send(id: string, packet: any) {
      assert.ok(this.has(id));
      sent.push(packet);
    }
  }
  const backend: any = {
    isVaultWorkspace: true,
    unlockedWorkspaceId: randomUUID(),
    sshBundle: async (q: any) => q,
    sshHostPlan: async (q: any) => q,
    trustSshHost: async () => {
      trusts.push('saved');
    },
    trustQuickSshHost: async () => {
      trusts.push('quick');
    },
    connectionRoute: async () => null,
    tunnelPlan: async (q: any) => q,
    tunnelBundle: async (q: any) => q,
    routedSshBundle: async (q: any) => q,
  };
  const h = mainSshHarness(Sealed, backend);
  const q = { sessionId: randomUUID(), nodeId: randomUUID(), columns: 80, rows: 24 };
  const admit = (retired: () => Promise<void> = async () => {}) =>
    h.native.admitProtected(h.owner, q, 5, () => true, retired);
  return {
    ...h,
    q,
    backend,
    sessions,
    sent,
    trusts,
    admit,
    get options() {
      return options;
    },
    failNative: (value: boolean) => {
      failNative = value;
    },
    accept: (value: boolean) => {
      accepted = value;
    },
  };
}

test('actual main transfers target retirement to its original native cohort and preserves ownership across SFTP aliases', async () => {
  const h = fixture();
  let retired = 0,
    failRetirement = true;
  const receipt = h.admit(async () => {
    if (failRetirement) throw Error('private target diagnostic');
    retired++;
  });
  assert.equal(receipt.accepted, true);
  await receipt.result;
  const current = h.native.captureOwner(h.event, h.q.sessionId);
  current();
  const alias = randomUUID();
  await h.native.shareSftp(h.q.sessionId, alias, h.owner);
  assert.equal(h.native.ownsProtected(h.owner, alias), true);
  await h.native.closeProtected(h.owner, h.q.sessionId);
  assert.throws(current, /unavailable/);
  assert.equal(h.native.hasProtectedReservation(h.q.sessionId), true);
  assert.equal(retired, 0);
  await assert.rejects(
    h.native.retireProtected(h.owner, [h.q.sessionId]),
    /could not be confirmed/,
  );
  assert.equal(h.native.ownsProtected(h.owner, alias), true);
  failRetirement = false;
  await h.native.retireProtected(h.owner, [], true);
  assert.equal(retired, 1);
  assert.equal(h.native.hasProtectedReservation(alias), false);
  assert.equal(h.native.protectedMembers.size, 0);
  await h.native.closeProtected(h.owner, alias);
});

test('actual main rejects invalid native handoffs and retains failed close owners for a positive retry', async () => {
  const h = fixture();
  for (const delta of [
    { manualCredentials: true, manualKeyPassphrase: true },
    { manualCredentials: true, credentialId: randomUUID() },
  ]) {
    const r = h.native.admitProtected(
      h.owner,
      { ...h.q, ...delta },
      5,
      () => true,
      async () => {},
    );
    assert.equal(r.accepted, false);
    await assert.rejects(r.result);
  }
  h.backend.unlockedWorkspaceId = undefined;
  let r = h.admit();
  assert.equal(r.accepted, false);
  await assert.rejects(r.result);
  h.backend.unlockedWorkspaceId = randomUUID();
  h.setAllowed(false);
  r = h.admit();
  await assert.rejects(r.result);
  h.setAllowed(true);
  h.setDestroyed(true);
  r = h.admit();
  await assert.rejects(r.result);
  h.setDestroyed(false);
  r = h.native.admitProtected(
    h.owner,
    h.q,
    5,
    () => false,
    async () => {},
  );
  await assert.rejects(r.result);
  h.accept(false);
  r = h.admit();
  await assert.rejects(r.result);
  assert.equal(h.native.protectedMembers.size, 0);
  assert.equal(h.native.terminalOwners.size, 0);
  h.accept(true);
  r = h.admit();
  await r.result;
  const duplicate = h.admit();
  assert.equal(duplicate.accepted, false);
  await assert.rejects(duplicate.result);
  await assert.rejects(h.native.closeProtected({} as any, h.q.sessionId), /owner/);
  await assert.rejects(h.native.retireProtected({} as any, [h.q.sessionId]), /owner/);
  h.failNative(true);
  await assert.rejects(h.native.closeProtected(h.owner, h.q.sessionId));
  assert.equal(h.native.terminalOwners.get(h.q.sessionId), h.owner);
  h.failNative(false);
  await h.native.closeProtected(h.owner, h.q.sessionId);
});

test('actual main captures member generation and document ownership before asynchronous commands', async () => {
  const h = fixture();
  await h.admit().result;
  const old = h.native.captureOwner(h.event, h.q.sessionId);
  assert.throws(() => h.native.captureOwner({ sender: {} }, h.q.sessionId), /owner/);
  assert.throws(
    () => h.native.captureOwner({ ...h.event, trusted: false }, h.q.sessionId),
    /owner/,
  );
  h.setAllowed(false);
  assert.throws(old, /unavailable/);
  h.setAllowed(true);
  h.setDestroyed(true);
  assert.throws(old, /owner/);
  h.setDestroyed(false);
  await h.native.closeProtected(h.owner, h.q.sessionId);
  await h.admit().result;
  assert.throws(old, /unavailable/);
  h.native.captureOwner(h.event, h.q.sessionId)();
  const emptyId = randomUUID(),
    retired = h.native.captureOwner(h.event, emptyId, true);
  const newReceipt = h.native.admitProtected(
    h.owner,
    { ...h.q, sessionId: emptyId },
    5,
    () => true,
    async () => {},
  );
  await newReceipt.result;
  assert.throws(retired, /unavailable/);
  await h.native.retireProtected(h.owner, [], true);
  h.backend.isVaultWorkspace = false;
  h.backend.unlockedWorkspaceId = undefined;
  h.native.captureOwner({ sender: {} }, 'legacy')();
});

test('actual main chooses temporary host trust only for the captured Quick target scope', async () => {
  const h = fixture();
  await h.admit().result;
  const request = { sessionId: h.q.sessionId, nodeId: h.q.nodeId },
    signal = new AbortController().signal;
  await h.options.host.confirm(
    request,
    { fingerprint: '', binding: { host: 'ssh.example', port: 22 } },
    'pin',
    () => true,
    signal,
  );
  h.context.vaultSshIpc = { isQuickTarget: () => true };
  await h.options.host.confirm(
    request,
    { fingerprint: 'old', binding: { host: 'ssh.example', port: 22 } },
    'new',
    () => true,
    signal,
  );
  assert.deepEqual(h.trusts, ['saved', 'quick']);
  assert.equal(h.dialogs[1].type, 'warning');
  await h.native.retireProtected(h.owner, [], true);
});

test('actual main keeps manual planning, document ownership and scoped shutdown on private native callbacks', async () => {
  const h = fixture(),
    calls: any[] = [];
  h.backend.sshManualPlan = async (q: any) => {
    calls.push(['plan', q]);
    return 'planned';
  };
  h.backend.sshManualBundle = async (q: any) => {
    calls.push(['bundle', q]);
    return 'sealed';
  };
  h.context.vaultSshCredentialsDialog = {
    open: async (parent: any, current: () => boolean, context: any, signal: AbortSignal) => {
      assert.equal(parent, h.parent);
      assert.ok(current());
      assert.equal(signal.aborted, false);
      calls.push(['document', context]);
      return 'opaque';
    },
    cancelSession: async (id: string) => {
      calls.push(['close', id]);
    },
    cancel: async () => {
      calls.push(['all']);
    },
  };
  await h.admit().result;
  const manual = h.options.manual,
    request = { private: 'metadata-only' },
    context = { plan: { host: { binding: { sessionId: h.q.sessionId } } } },
    signal = new AbortController().signal;
  assert.equal(await manual.plan(request), 'planned');
  assert.equal(await manual.bundle(request), 'sealed');
  assert.equal(await manual.prompt(context, () => true, signal), 'opaque');
  await assert.rejects(
    manual.prompt({ plan: { host: { binding: { sessionId: randomUUID() } } } }, () => true, signal),
    /owner unavailable/,
  );
  await manual.close(h.q.sessionId);
  await h.native.stopSealedSessions();
  assert.deepEqual(calls, [
    ['plan', request],
    ['bundle', request],
    ['document', context],
    ['close', h.q.sessionId],
    ['all'],
  ]);
});

test('queued terminal and file IPC cannot reach a replacement native generation in the same document', async () => {
  const h = fixture();
  await h.admit().result;
  let release!: () => void;
  let gate: Promise<void> | undefined;
  const calls: string[] = [];
  Object.assign(h.context, {
    isSshSessionId: (id: any) => typeof id === 'string',
    isSshInput: () => true,
    isSftpPath: () => true,
    isSftpRequestId: () => true,
    serializeAuthOperation: async (run: any) => {
      await gate;
      return run();
    },
    requireWorkspaceAuth: async () => {},
  });
  h.native.sendInput = () => calls.push('input');
  h.native.resize = () => calls.push('resize');
  h.native.listSftp = () => calls.push('list');
  const handlers = h.register(['ssh:input', 'ssh:resize', 'ssh:sftp-list']);
  const args: Record<string, any[]> = {
    'ssh:input': [h.q.sessionId, 'YQ==', false],
    'ssh:resize': [h.q.sessionId, 80, 24],
    'ssh:sftp-list': [h.q.sessionId, '/', 'request'],
  };
  for (const [name, handler] of handlers) {
    gate = new Promise((r) => {
      release = r;
    });
    const pending = handler(h.event, ...args[name]);
    void pending.catch(() => {});
    await h.native.closeProtected(h.owner, h.q.sessionId);
    await h.admit().result;
    release();
    await assert.rejects(pending, /unavailable/);
    assert.equal(calls.length, 0);
  }
  gate = undefined;
  await handlers.get('ssh:input')(h.event, ...args['ssh:input']);
  assert.deepEqual(calls, ['input']);
  await h.native.retireProtected(h.owner, [], true);
});

test('actual SSH initializer and IPC admit Quick targets, share a cohort and reject ordinary private payloads', async () => {
  const h = fixture(),
    registrations: any[] = [];
  let releases = 0,
    running = true;
  h.backend.beginQuickTarget = async (q: any, current: any) => {
    assert.equal(current(), true);
    const reference = {
      workspaceId: q.workspaceId,
      sessionId: q.sessionId,
      epoch: q.epoch,
      id: randomUUID(),
    };
    registrations.push({ q, reference, current });
    let released = false;
    return {
      reference,
      release: async () => {
        if (!released) {
          releases++;
          released = true;
        }
      },
    };
  };
  Object.assign(h.context, {
    VaultSshIpc,
    requireNativeResourcesRunning: () => {
      if (!running) throw Error('stopping');
    },
    runAuthorizedOperation: async (run: any) => run(4),
    isRecord: (v: any) => v !== null && typeof v === 'object',
    isSshOpenRequest: () => true,
    isSshHostKeyTrustRequest: () => true,
    isSshSessionId: (v: any) => typeof v === 'string',
  });
  const init = runInNewContext(
    stripTypeScriptTypes(
      declarations(mainSshSource, ['sshBackend', 'vaultSshIpc']) + '\n({sshBackend,vaultSshIpc});',
    ),
    h.context,
    { filename: 'wormhole-vault-ssh-init.js' },
  );
  const native = init.sshBackend,
    ipc = init.vaultSshIpc;
  const handlers = h.register(['ssh:open', 'ssh:sftp-share', 'ssh:close', 'ssh:trust-host-key']);
  const quick = {
    sessionId: randomUUID(),
    columns: 80,
    rows: 24,
    mode: 'terminal',
    quickTarget: {
      protocol: 'ssh',
      host: 'ssh.example',
      port: 22,
      credentialId: randomUUID(),
      tunnelId: '',
      sshAutoSudo: false,
      httpPath: '',
      ignoreCertificateErrors: false,
      rdp: null,
    },
  };
  const open = (q: any, ...extra: any[]) => handlers.get('ssh:open')(h.event, q, ...extra);
  try {
    for (const q of [
      { ...quick, password: 'private' },
      { ...quick, username: 'private' },
      { ...quick, keyPassphrase: 'private' },
      { ...quick, quickTarget: { ...quick.quickTarget, publicKey: 'forged' } },
    ])
      await assert.rejects(open(q), /Invalid vault SSH request/);
    await assert.rejects(open(quick, 'extra'), /owner/);
    await assert.rejects(handlers.get('ssh:open')({ ...h.event, trusted: false }, quick), /owner/);
    const response = await open(quick);
    assert.equal(response.sessionId, quick.sessionId);
    const lease = registrations[0];
    assert.equal(lease.q.workspaceId, h.backend.unlockedWorkspaceId);
    assert.equal(lease.q.epoch, 5);
    assert.equal(lease.q.sessionId, quick.sessionId);
    assert.equal(h.sessions.get(quick.sessionId).q.nodeId, lease.reference.id);
    assert.equal(h.sessions.get(quick.sessionId).q.credentialId, undefined);
    assert.equal(JSON.stringify(response).includes(lease.reference.id), false);
    const alias = randomUUID();
    await handlers.get('ssh:sftp-share')(h.event, quick.sessionId, alias);
    await assert.rejects(
      handlers.get('ssh:sftp-share')(h.event, quick.sessionId, randomUUID(), 'extra'),
      /owner/,
    );
    await assert.rejects(handlers.get('ssh:close')(h.event, quick.sessionId, 'extra'), /owner/);
    await handlers.get('ssh:close')(h.event, quick.sessionId);
    assert.equal(releases, 0);
    await handlers.get('ssh:close')(h.event, alias);
    assert.equal(releases, 1);
    assert.equal(native.protectedMembers.size, 0);
    await assert.rejects(
      handlers.get('ssh:trust-host-key')(h.event, { sessionId: quick.sessionId }),
      /protected/,
    );
    running = false;
    await assert.rejects(open({ ...quick, sessionId: randomUUID() }), /stopping/);
    running = true;
    h.backend.unlockedWorkspaceId = undefined;
    await assert.rejects(open({ ...quick, sessionId: randomUUID() }));
    h.backend.unlockedWorkspaceId = randomUUID();
    await open({ ...quick, sessionId: randomUUID() });
    await ipc.closeAll();
    h.backend.isVaultWorkspace = false;
    h.backend.unlockedWorkspaceId = undefined;
    native.open = async () => 'legacy';
    assert.equal(
      await open({ sessionId: 'legacy', host: 'legacy.example', columns: 80, rows: 24 }),
      'legacy',
    );
  } finally {
    await ipc.closeAll();
  }
});
