import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { SealedSshBackend } from '../electron/sealed-ssh.ts';
import type { VaultSshRequest, VaultSshBundle } from '../electron/vault-ssh.ts';
import type { VaultRouteBinding, VaultRoutePlanRequest } from '../electron/vault-route.ts';
import type { VaultRoutedSshRequest } from '../electron/vault-ssh-route.ts';
import { sshBundle } from './fixtures/vault-ssh.ts';

const tick = async () => {
  for (let i = 0; i < 8; i++) await Promise.resolve();
  await new Promise<void>((resolve) => setImmediate(resolve));
};

test('manual SSH relay binds isolated entry to the probed identity and aborts stale or invalid handoffs', async (t) => {
  for (const scenario of [
    'account',
    'passphrase',
    'files',
    'invalid-plan',
    'wrong-fingerprint',
    'wrong-host',
    'invalid-envelope',
    'prompt-error',
    'cancel-prompt',
    'invalid-bundle',
    'failed-document-close',
  ]) {
    const fingerprint = 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
      fileId = randomUUID();
    let promptSignal: AbortSignal | undefined,
      promptDone: ((v: any) => void) | undefined,
      planInput: any,
      promptContext: any;
    let planCalls = 0,
      bundleCalls = 0;
    let failDocumentClose = scenario === 'failed-document-close';
    const host = {
      plan: async (q: any) => ({
        binding: sshBundle({ ...q, publicKey: '' }).binding,
        fileId,
        revision: 'a'.repeat(64),
        fingerprint,
      }),
      confirm: async () => {},
    };
    const manual = {
      close: async () => {
        if (failDocumentClose) throw Error('document shutdown unconfirmed');
      },
      plan: async (q: any) => {
        planCalls++;
        planInput = q;
        const result: any = {
          host: await host.plan(q),
          mode: q.mode,
          autoSudo: !q.sftpOnly,
          sftpOnly: q.sftpOnly,
        };
        if (scenario === 'invalid-plan') return {} as any;
        if (scenario === 'wrong-fingerprint')
          result.host.fingerprint = 'SHA256:' + Buffer.alloc(32, 2).toString('base64').slice(0, -1);
        if (scenario === 'wrong-host') result.host.binding.host = 'changed.example';
        return result;
      },
      prompt: async (c: any, current: () => boolean, signal: AbortSignal) => {
        promptSignal = signal;
        promptContext = c;
        assert.ok(current());
        if (scenario === 'prompt-error') throw Error('private document error');
        if (scenario === 'cancel-prompt')
          return new Promise<any>((resolve) => {
            promptDone = resolve;
          });
        return scenario === 'invalid-envelope'
          ? ({} as any)
          : {
              formatVersion: 1,
              suiteId: 2,
              enc: Buffer.alloc(32).toString('base64'),
              ciphertext: Buffer.alloc(40).toString('base64'),
            };
      },
      bundle: async (q: any) => {
        bundleCalls++;
        assert.ok(promptContext);
        assert.deepEqual(q.context, promptContext);
        assert.equal(q.credentialOverride, '');
        assert.equal(q.manual.ciphertext.length, 56);
        return scenario === 'invalid-bundle'
          ? ({} as any)
          : sshBundle({
              ...q.context.plan.host.binding,
              publicKey: q.context.publicKey,
              credentialOverride: '',
              ...(planInput.sftpOnly ? { sftpOnly: true as const } : {}),
            });
      },
    };
    const f = fixture(
      t,
      5000,
      undefined,
      host,
      undefined,
      manual,
      scenario === 'passphrase' ? 'passphrase' : 'account',
    );
    const x = f.open(
      undefined,
      () => true,
      scenario === 'passphrase'
        ? { manualKeyPassphrase: true }
        : { manualCredentials: true, ...(scenario === 'files' ? { mode: 'sftp' as const } : {}) },
    );
    await tick();
    const probe = f.children[0];
    probe.line({ requestId: probe.requests[0].requestId, fingerprint });
    probe.exit();
    await tick();
    const child = f.children[1];
    assert.ok(child);
    f.recipient(child);
    await tick();
    if (scenario === 'cancel-prompt') {
      assert.ok(promptDone);
      await f.broker.close(x.request.sessionId);
      assert.equal(promptSignal!.aborted, true);
      promptDone!({
        formatVersion: 1,
        suiteId: 2,
        enc: Buffer.alloc(32).toString('base64'),
        ciphertext: Buffer.alloc(40).toString('base64'),
      });
      await tick();
    }
    if (['account', 'passphrase', 'files', 'failed-document-close'].includes(scenario)) {
      child.line({
        type: 'connected',
        session_id: x.request.sessionId,
        host: 'host.example',
        port: 22,
        username: 'manual-user',
        fingerprint,
      });
      assert.equal((await x.result).username, 'manual-user');
      assert.equal(bundleCalls, 1);
      assert.equal(planCalls, 1);
      assert.equal(promptContext.plan.mode, scenario === 'passphrase' ? 'passphrase' : 'account');
      if (failDocumentClose) {
        await assert.rejects(f.broker.closeAll(), /shutdown could not be confirmed/);
        assert.equal(f.broker.hasReservation(x.request.sessionId), true);
        failDocumentClose = false;
      }
      await f.broker.closeAll();
      assert.equal(promptSignal!.aborted, true);
    } else {
      await assert.rejects(x.result);
      await f.broker.closeAll();
    }
    assert.equal(
      f.requests.length,
      0,
      'manual mode must never call the saved credential bundle API',
    );
    assert.doesNotMatch(JSON.stringify(f.events), /private document error|ciphertext|publicKey/);
  }
  const f = fixture(t);
  for (const flags of [
    { manualCredentials: true },
    { manualKeyPassphrase: true },
    { manualCredentials: false },
    { manualKeyPassphrase: false },
    { manualCredentials: true, manualKeyPassphrase: true },
    { manualCredentials: true, credentialId: randomUUID() },
  ]) {
    const r = f.broker.admit(
      { sessionId: randomUUID(), nodeId: randomUUID(), columns: 80, rows: 24, ...flags } as any,
      1,
    );
    assert.equal(r.accepted, false);
    await assert.rejects(r.result);
  }
});
class Child extends EventEmitter {
  exitCode: number | null = null;
  signalCode: string | null = null;
  stdout = new PassThrough();
  stderr = new PassThrough();
  requests: any[] = [];
  exitOnEnd = true;
  kills = 0;
  stdin = new Writable({
    write: (chunk, _encoding, callback) => {
      this.requests.push(JSON.parse(chunk.toString()));
      callback();
    },
  });
  constructor() {
    super();
    this.stdin.on('finish', () => {
      if (this.exitOnEnd) queueMicrotask(() => this.exit());
    });
  }
  exit() {
    if (this.exitCode !== null) return;
    this.exitCode = 0;
    this.emit('close');
  }
  kill() {
    this.kills++;
    this.exit();
    return true;
  }
  line(value: unknown) {
    this.stdout.write(JSON.stringify(value) + '\n');
  }
}
function fixture(
  t: TestContext,
  timeoutMs = 1000,
  route?: ConstructorParameters<typeof SealedSshBackend>[0]['route'],
  host?: ConstructorParameters<typeof SealedSshBackend>[0]['host'],
  fileEditing?: ConstructorParameters<typeof SealedSshBackend>[0]['fileEditing'],
  manual?: ConstructorParameters<typeof SealedSshBackend>[0]['manual'],
  manualMode = 'account',
) {
  let allowed = true,
    workspace: string | undefined = randomUUID();
  const children: Child[] = [],
    requests: VaultSshRequest[] = [],
    events: any[] = [];
  let onLine = (_event: any) => {};
  let failSpawn = false;
  let bundle = (q: VaultSshRequest) => Promise.resolve(sshBundle(q));
  const broker = new SealedSshBackend(
    {
      executable: () => '/native/backend',
      workspaceId: () => workspace,
      authorized: (epoch) => allowed && epoch === 1,
      bundle: (q) => {
        requests.push(q);
        return bundle(q);
      },
      parseEvent: (line) => {
        const e = JSON.parse(line);
        return e.type === 'invalid' ? undefined : { type: e.type, sessionId: e.session_id };
      },
      onLine: (line) => {
        const event = JSON.parse(line);
        events.push(event);
        onLine(event);
      },
      timeoutMs,
      route,
      host,
      fileEditing,
      manual,
    },
    (exe, args) => {
      if (failSpawn) throw Error('private spawn failure');
      assert.equal(exe, '/native/backend');
      assert.deepEqual(args, [
        '--operation',
        host && children.length === 0
          ? 'ssh-host-probe'
          : manual
            ? `ssh-manual-${manualMode}-sealed`
            : 'ssh-sealed',
        ...(fileEditing && !(host && children.length === 0)
          ? [
              '--database',
              fileEditing().databasePath,
              '--electron-user-data',
              fileEditing().userDataPath,
            ]
          : []),
      ]);
      const child = new Child();
      children.push(child);
      return child as unknown as ChildProcessWithoutNullStreams;
    },
  );
  t.after(async () => {
    for (const child of children) child.exit();
    await broker.closeAll();
  });
  const open = (
    id = randomUUID(),
    owner = () => true,
    intent: { manualCredentials?: true; manualKeyPassphrase?: true; mode?: 'sftp' } = {},
  ) => {
    const request = { sessionId: id, nodeId: randomUUID(), columns: 80, rows: 24, ...intent };
    const result = broker.open(request, 1, owner);
    void result.catch(() => {});
    return { request, result, child: children.at(-1)! };
  };
  const recipient = (child: Child) =>
    child.line({ type: 'recipient', publicKey: Buffer.alloc(32, 7).toString('base64') });
  const connect = async () => {
    const x = open();
    recipient(x.child);
    await tick();
    x.child.line({
      type: 'connected',
      session_id: x.request.sessionId,
      host: 'host.example',
      port: 22,
      username: 'alice',
      fingerprint: 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
    });
    await x.result;
    return x;
  };
  return {
    broker,
    children,
    requests,
    events,
    open,
    recipient,
    connect,
    failSpawn: (value: boolean) => {
      failSpawn = value;
    },
    setAllowed: (v: boolean) => {
      allowed = v;
    },
    setWorkspace: (v: string | undefined) => {
      workspace = v;
    },
    setOnLine: (v: typeof onLine) => {
      onLine = v;
    },
    setBundle: (v: typeof bundle) => {
      bundle = v;
    },
  };
}
test('main binds child recipient, request and opaque bundle; commands stay with their owning child', async (t) => {
  const f = fixture(t),
    x = await f.connect();
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0]!.publicKey, Buffer.alloc(32, 7).toString('base64'));
  assert.deepEqual(x.child.requests[0], { ...sshBundle(f.requests[0]!), columns: 80, rows: 24 });
  f.broker.send(x.request.sessionId, {
    type: 'input',
    session_id: x.request.sessionId,
    data: 'YQ==',
  });
  assert.deepEqual(x.child.requests[1], {
    type: 'input',
    sessionId: x.request.sessionId,
    data: 'YQ==',
  });
  x.child.line({ type: 'screen', session_id: x.request.sessionId, frame: { fixture: true } });
  assert.equal(f.events.at(-1).type, 'screen');
  assert.throws(
    () =>
      f.broker.send(x.request.sessionId, { type: 'sftp-edit', session_id: x.request.sessionId }),
    /Unsupported|unavailable/,
  );
  assert.throws(
    () =>
      f.broker.send(x.request.sessionId, {
        type: 'input',
        session_id: x.request.sessionId,
        password: 'private',
      }),
    /Unsupported|unavailable/,
  );
  assert.throws(() => f.broker.send(randomUUID(), { type: 'input' }), /unavailable/);
  await f.broker.close(x.request.sessionId);
  await tick();
  assert.equal(f.broker.has(x.request.sessionId), false);
  assert.equal(f.events.at(-1).type, 'closed');
  await f.broker.close(x.request.sessionId);
});
test('lock, workspace replacement, owner navigation and close discard late bundles', async (t) => {
  for (const mode of ['lock', 'workspace', 'owner', 'close', 'reject', 'wrong-binding']) {
    const f = fixture(t);
    let finish!: (v: VaultSshBundle) => void,
      reject!: (e: Error) => void,
      owner = true;
    f.setBundle(
      () =>
        new Promise((a, b) => {
          finish = a;
          reject = b;
        }),
    );
    const x = f.open(undefined, () => owner);
    f.recipient(x.child);
    await tick();
    if (mode === 'lock') f.setAllowed(false);
    if (mode === 'workspace') f.setWorkspace(randomUUID());
    if (mode === 'owner') owner = false;
    if (mode === 'close') await f.broker.close(x.request.sessionId);
    const bundle = sshBundle(f.requests[0]!);
    if (mode === 'wrong-binding') bundle.binding.nodeId = randomUUID();
    if (mode === 'reject') reject(Error('private diagnostic'));
    else finish(bundle);
    await assert.rejects(x.result, { message: 'Vault SSH connection stopped.' });
    await tick();
    assert.equal(x.child.requests.length, 0);
  }
});

test('sealed SFTP commands and events remain bound to the authenticated child', async (t) => {
  const f = fixture(t),
    x = await f.connect();
  const id = x.request.sessionId;
  for (const command of [
    { type: 'sftp-open', request_id: 'open' },
    { type: 'sftp-list', path: '/', request_id: 'list' },
    { type: 'sftp-local-list', path: '/tmp', request_id: 'local' },
    { type: 'sftp-tree-list', path: '/', pane: 'remote', request_id: 'tree' },
    {
      type: 'sftp-operation',
      pane: 'remote',
      operation: 'rename',
      path: '/a',
      destination_path: '/b',
      request_id: 'op',
    },
    {
      type: 'sftp-transfer',
      transfer_id: 't',
      direction: 'remote-to-local',
      destination_path: '/tmp',
      items: [],
    },
    {
      type: 'sftp-transfer-decision',
      transfer_id: 't',
      item_id: 'i',
      decision: 'skip',
      apply_to_all: false,
    },
    { type: 'sftp-transfer-cancel', transfer_id: 't', item_id: 'i' },
    { type: 'sftp-close' },
  ]) {
    f.broker.send(id, { ...command, session_id: id });
    assert.deepEqual(x.child.requests.at(-1), { ...command, sessionId: id });
    assert.throws(
      () => f.broker.send(id, { ...command, session_id: randomUUID() }),
      /Unsupported|unavailable/,
    );
    for (const field of ['password', 'host', 'source_session_id', 'editor_id', 'mode', 'publicKey'])
      assert.throws(
        () => f.broker.send(id, { ...command, session_id: id, [field]: 'injected' }),
        /Unsupported|unavailable/,
      );
  }
  for (const type of [
    'sftp.opening',
    'sftp.closed',
    'sftp.ready',
    'sftp.local.ready',
    'sftp.error',
    'sftp.local.error',
    'sftp.operation',
    'sftp.conflict',
    'sftp.transfer',
  ]) {
    x.child.line({ type, session_id: id });
    assert.equal(f.events.at(-1).type, type);
    assert.ok(f.broker.has(id));
  }
  for (const type of ['sftp-edit', 'open', '__proto__', 'constructor', undefined])
    assert.throws(() => f.broker.send(id, { type, session_id: id }), /Unsupported|unavailable/);
  x.child.line({ type: 'sftp.ready', session_id: randomUUID() });
  await tick();
  assert.equal(f.broker.has(id), false);
  assert.equal(f.events.at(-1).type, 'closed');
});

test('shared SFTP members reuse one child and survive their source closing', async (t) => {
  const f = fixture(t),
    x = await f.connect();
  const connectShared = async (source: string) => {
    const id = randomUUID(),
      result = f.broker.shareSftp(source, id, () => true);
    assert.deepEqual(x.child.requests.at(-1), {
      type: 'sftp-share',
      sessionId: source,
      newSessionId: id,
    });
    x.child.line({
      type: 'connected',
      session_id: id,
      host: 'host.example',
      port: 22,
      username: 'alice',
      fingerprint: 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
    });
    assert.equal((await result).sessionId, id);
    return id;
  };
  const first = await connectShared(x.request.sessionId);
  const closing = f.broker.close(x.request.sessionId);
  assert.deepEqual(x.child.requests.at(-1), { type: 'close', sessionId: x.request.sessionId });
  x.child.line({ type: 'closed', session_id: x.request.sessionId });
  await closing;
  assert.equal(f.broker.has(x.request.sessionId), false);
  assert.equal(f.broker.has(first), true);
  assert.equal(x.child.exitCode, null);
  const second = await connectShared(first);
  f.broker.send(second, { type: 'sftp-open', session_id: second });
  assert.equal(x.child.requests.at(-1).sessionId, second);
  assert.throws(
    () => f.broker.send(second, { type: 'input', session_id: second, data: 'YQ==' }),
    /Unsupported|unavailable/,
  );
  assert.equal(f.requests.length, 1);
  assert.equal(f.children.length, 1);
  const closeFirst = f.broker.close(first);
  x.child.line({ type: 'closed', session_id: first });
  await closeFirst;
  const before = f.events.length;
  x.child.line({ type: 'sftp.transfer', session_id: first });
  assert.equal(f.events.length, before);
  await f.broker.close(second);
  assert.equal(f.broker.has(second), false);
  assert.equal(x.child.exitCode, 0);
});

test('shared SFTP rejects foreign, reused, inactive and over-limit identities', async (t) => {
  const f = fixture(t),
    x = await f.connect();
  for (const [source, id, owner] of [
    [randomUUID(), randomUUID(), () => true],
    [x.request.sessionId, 'invalid', () => true],
    [x.request.sessionId, x.request.sessionId, () => true],
    [x.request.sessionId, randomUUID(), () => false],
  ] as const)
    await assert.rejects(f.broker.shareSftp(source, id, owner), /unavailable/);
  const pending = randomUUID(),
    result = f.broker.shareSftp(x.request.sessionId, pending, () => true);
  void result.catch(() => {});
  await assert.rejects(
    f.broker.shareSftp(pending, randomUUID(), () => true),
    /unavailable/,
  );
  await assert.rejects(
    f.broker.shareSftp(x.request.sessionId, pending, () => true),
    /unavailable/,
  );
  const closing = f.broker.close(pending);
  assert.equal(f.broker.close(pending), closing);
  x.child.line({ type: 'connected', session_id: pending }); // a cancelled opener cannot revive
  x.child.line({ type: 'closed', session_id: pending });
  await closing;
  await assert.rejects(result, /stopped/);
  await assert.rejects(
    f.broker.shareSftp(x.request.sessionId, pending, () => true),
    /unavailable/,
  );
  for (let index = 1; index < 32; index++) {
    const pendingResult = f.broker.shareSftp(x.request.sessionId, randomUUID(), () => true);
    void pendingResult.catch(() => {});
  }
  await assert.rejects(
    f.broker.shareSftp(x.request.sessionId, randomUUID(), () => true),
    /unavailable/,
  );
  assert.equal(f.children.length, 1);
  await f.broker.closeAll();
});

test('a failed shared subsystem does not close healthy members; identity substitution does', async (t) => {
  const f = fixture(t),
    x = await f.connect();
  const id = randomUUID(),
    result = f.broker.shareSftp(x.request.sessionId, id, () => true);
  x.child.line({ type: 'error', session_id: id, error: 'subsystem unavailable' });
  await assert.rejects(result, /stopped/);
  x.child.line({ type: 'closed', session_id: id });
  assert.ok(f.broker.has(x.request.sessionId));
  const changed = randomUUID(),
    changedResult = f.broker.shareSftp(x.request.sessionId, changed, () => true);
  x.child.line({
    type: 'connected',
    session_id: changed,
    host: 'host.example',
    port: 22,
    username: 'another-account',
    fingerprint: 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
  });
  await assert.rejects(changedResult);
  await tick();
  assert.equal(f.broker.has(x.request.sessionId), false);
  assert.equal(f.broker.has(changed), false);
});

test('shared opening cancellation, owner loss and close timeout retire their resources', async (t) => {
  for (const mode of ['opening-timeout', 'owner', 'closing-timeout', 'lock', 'terminal-event']) {
    const f = fixture(t, 25),
      x = await f.connect();
    let owned = true;
    const id = randomUUID(),
      result = f.broker.shareSftp(x.request.sessionId, id, () => owned);
    void result.catch(() => {});
    if (mode === 'opening-timeout') {
      await assert.rejects(result, /timed out/);
      assert.equal(x.child.requests.at(-1).type, 'close');
      x.child.line({ type: 'closed', session_id: id });
      assert.equal(f.broker.has(id), false);
      assert.ok(f.broker.has(x.request.sessionId));
    } else if (mode === 'closing-timeout') {
      await f.broker.close(id);
      assert.equal(f.broker.has(x.request.sessionId), false);
    } else {
      if (mode === 'owner') owned = false;
      if (mode === 'lock') f.setAllowed(false);
      x.child.line({ type: mode === 'terminal-event' ? 'screen' : 'connected', session_id: id });
      await assert.rejects(result);
      await tick();
      assert.equal(f.broker.has(id), false);
    }
  }
});
test('protocol rejects duplicate keys, unbounded/invalid bytes, unexpected frames and foreign sessions', async (t) => {
  for (const mode of [
    'duplicate',
    'large',
    'utf8',
    'wrong-key',
    'unknown',
    'early-event',
    'second-recipient',
    'foreign',
    'wrong-host',
    'duplicate-connected',
    'bad-event',
    'partial',
    'error',
    'closed',
  ]) {
    const f = fixture(t),
      x = f.open();
    if (mode === 'duplicate')
      x.child.stdout.write(
        '{"type":"recipient","type":"recipient","publicKey":"' +
          Buffer.alloc(32).toString('base64') +
          '"}\n',
      );
    else if (mode === 'large') x.child.stdout.write(Buffer.alloc(1025, 65));
    else if (mode === 'utf8') x.child.stdout.write(Buffer.from([255, 10]));
    else if (mode === 'wrong-key') x.child.line({ type: 'recipient', publicKey: 'invalid' });
    else if (mode === 'unknown')
      x.child.line({ type: 'recipient', publicKey: Buffer.alloc(32).toString('base64'), extra: 1 });
    else if (mode === 'partial') {
      x.child.stdout.write('{');
      x.child.stdout.end();
    } else {
      if (mode === 'early-event') f.setBundle(() => new Promise(() => {}));
      f.recipient(x.child);
      await tick();
      if (mode === 'second-recipient') f.recipient(x.child);
      else if (mode === 'bad-event')
        x.child.line({ type: 'mcp.access', session_id: x.request.sessionId });
      else if (mode === 'early-event')
        x.child.line({ type: 'screen', session_id: x.request.sessionId });
      else if (mode === 'error' || mode === 'closed')
        x.child.line({ type: mode, session_id: x.request.sessionId, error: 'private diagnostic' });
      else {
        const event = {
          type: 'connected',
          session_id: mode === 'foreign' ? randomUUID() : x.request.sessionId,
          host: mode === 'wrong-host' ? 'other' : 'host.example',
          port: 22,
          username: 'alice',
          fingerprint: 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
        };
        x.child.line(event);
        if (mode === 'duplicate-connected') {
          await x.result;
          x.child.line(event);
        }
      }
    }
    if (mode !== 'duplicate-connected') await assert.rejects(x.result);
    await tick();
    assert.equal(f.broker.has(x.request.sessionId), false, mode);
    assert.ok(!JSON.stringify(f.events).includes('private diagnostic'));
  }
});
test('pending IDs remain reserved until exit; deadlines retire silent children', async (t) => {
  const f = fixture(t, 10),
    x = f.open();
  x.child.exitOnEnd = false;
  await assert.rejects(x.result);
  assert.equal(f.broker.has(x.request.sessionId), true);
  await assert.rejects(f.broker.open(x.request, 1), /unavailable/);
  x.child.exit();
  await tick();
  assert.equal(f.broker.has(x.request.sessionId), false);
  const y = f.open(x.request.sessionId);
  assert.notEqual(y.child, x.child);
  await f.broker.close(y.request.sessionId);
  await assert.rejects(y.result);
});
test('stream failures and authority revocation retire active sessions without accepting commands', async (t) => {
  for (const mode of [
    'child',
    'stdin',
    'stdout',
    'stderr',
    'revoked',
    'output-after-lock',
    'write-throw',
    'oversized',
    'backpressure',
  ]) {
    const f = fixture(t),
      x = await f.connect();
    if (['child', 'stdin', 'stdout', 'stderr'].includes(mode)) {
      (mode === 'child' ? x.child : (x.child as any)[mode]).emit(
        'error',
        Error('private diagnostic'),
      );
    } else if (mode === 'output-after-lock') {
      f.setAllowed(false);
      x.child.line({ type: 'screen', session_id: x.request.sessionId });
    } else {
      if (mode === 'revoked') f.setAllowed(false);
      if (mode === 'backpressure')
        Object.defineProperty(x.child.stdin, 'writableLength', { value: 8 * 1024 * 1024 });
      if (mode === 'write-throw')
        x.child.stdin.write = () => {
          throw Error('private diagnostic');
        };
      assert.throws(
        () =>
          f.broker.send(x.request.sessionId, {
            type: 'input',
            session_id: x.request.sessionId,
            data: mode === 'oversized' ? 'x'.repeat(8 * 1024 * 1024) : 'YQ==',
          }),
        /unavailable/,
      );
    }
    await tick();
    assert.equal(f.broker.has(x.request.sessionId), false, mode);
  }
});
test('invalid starts and capacity limits never spawn additional children', async (t) => {
  const f = fixture(t);
  f.setWorkspace(undefined);
  await assert.rejects(f.open().result);
  assert.equal(f.children.length, 0);
  f.setWorkspace(randomUUID());
  f.setAllowed(false);
  await assert.rejects(f.open().result);
  assert.equal(f.children.length, 0);
  f.setAllowed(true);
  for (let i = 0; i < 32; i++) f.open();
  await assert.rejects(f.open().result, /unavailable/);
  assert.equal(f.children.length, 32);
  await f.broker.closeAll();
  await tick();
  for (const request of [
    { sessionId: 'bad', nodeId: randomUUID(), columns: 80, rows: 24 },
    { sessionId: randomUUID(), nodeId: randomUUID(), columns: 0, rows: 24 },
  ])
    await assert.rejects(f.broker.open(request, 1));
});

test('reentrant presentation failures cannot acknowledge a stale connection or escape child teardown', async (t) => {
  for (const mode of ['throw', 'lock']) {
    const f = fixture(t),
      x = f.open();
    f.setOnLine((event) => {
      if (event.type === 'closed') throw Error('destroyed view');
      if (mode === 'throw') throw Error('destroyed view');
      f.setAllowed(false);
    });
    f.recipient(x.child);
    await tick();
    x.child.line({
      type: 'connected',
      session_id: x.request.sessionId,
      host: 'host.example',
      port: 22,
      username: 'alice',
      fingerprint: 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
    });
    await assert.rejects(x.result);
    await tick();
    assert.equal(f.broker.has(x.request.sessionId), false);
  }
});

test('unconfirmed shutdown rejects cleanup and retains ownership until observed process close', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture(t),
    x = await f.connect();
  x.child.exitOnEnd = false;
  x.child.kill = () => false;
  const stopping = f.broker.closeAll();
  void stopping.catch(() => {});
  await tick();
  t.mock.timers.tick(1500);
  await tick();
  t.mock.timers.tick(1500);
  await tick();
  await assert.rejects(stopping, /could not be confirmed/);
  assert.equal(f.broker.has(x.request.sessionId), true);
  await assert.rejects(f.broker.open(x.request, 1), /unavailable/);
  x.child.exit();
  await f.broker.closeAll();
});

test('shared close rejects when forced process shutdown cannot be confirmed', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture(t),
    x = await f.connect();
  const id = randomUUID(),
    opened = f.broker.shareSftp(x.request.sessionId, id, () => true);
  x.child.line({
    type: 'connected',
    session_id: id,
    host: 'host.example',
    port: 22,
    username: 'alice',
    fingerprint: 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
  });
  await opened;
  x.child.exitOnEnd = false;
  x.child.kill = () => false;
  const closing = f.broker.close(id);
  void closing.catch(() => {});
  t.mock.timers.tick(1000);
  await tick();
  t.mock.timers.tick(1500);
  await tick();
  t.mock.timers.tick(1500);
  await tick();
  await assert.rejects(closing, /could not be confirmed/);
  assert.ok(f.broker.has(id));
  assert.ok(f.broker.has(x.request.sessionId));
  x.child.exit();
  await f.broker.closeAll();
});

test('spawn and timeout configuration failures are redacted and cannot reserve a session', async () => {
  const workspaceId = randomUUID();
  const options = {
    executable: () => '/private/path',
    workspaceId: () => workspaceId,
    authorized: () => true,
    bundle: async (q: VaultSshRequest) => sshBundle(q),
    parseEvent: () => undefined,
    onLine: () => {},
  };
  for (const timeoutMs of [0, -1, NaN, 120001])
    assert.throws(() => new SealedSshBackend({ ...options, timeoutMs }), /Invalid SSH timeout/);
  const broker = new SealedSshBackend(options, () => {
    throw Error('private spawn diagnostic');
  });
  const request = { sessionId: randomUUID(), nodeId: randomUUID(), columns: 80, rows: 24 };
  await assert.rejects(broker.open(request, 1), { message: 'SSH process could not start.' });
  assert.equal(broker.has(request.sessionId), false);
});

function routedFixture(t: TestContext, protocol: 'ssh' | 'sftp' = 'ssh') {
  let plan!: VaultRoutePlanRequest;
  let resolveMode: 'route' | 'direct' | 'error' | 'invalid' | 'other-protocol' = 'route';
  let waitPlan: Promise<void> | undefined, waitLease: Promise<void> | undefined;
  let leaseActive = true;
  let failRelease = false,
    failPendingClose = false,
    waitRelease: Promise<void> | undefined;
  let routeClosed!: () => void;
  const closed = new Promise<void>((resolve) => (routeClosed = resolve));
  const routedRequests: VaultRoutedSshRequest[] = [];
  let releases = 0,
    closes = 0,
    acquisitions = 0;
  let routeBinding: VaultRouteBinding | undefined;
  let bundle = async (q: VaultRoutedSshRequest) => ({
    ...sshBundle(q),
    binding: q.route,
    endpoint: q.endpoint,
  });
  const binding = (q: VaultRoutePlanRequest): VaultRouteBinding => ({
    ...sshBundle({ ...q, publicKey: '' }).binding,
    protocol,
    fileId: randomUUID(),
    tunnelConfigId: randomUUID(),
    kind: 6,
    rowVersion: '1',
    configurationVersion: '1',
  });
  const f = fixture(t, 1000, {
    resolve: async (q) => {
      plan = q;
      await waitPlan;
      if (resolveMode === 'error') throw Error('private native detail');
      if (resolveMode === 'invalid') return undefined as any;
      if (resolveMode === 'direct') return null;
      return {
        ...binding(q),
        protocol:
          resolveMode === 'other-protocol' ? (protocol === 'ssh' ? 'sftp' : 'ssh') : protocol,
      };
    },
    broker: {
      acquire: async (q, epoch, owner) => {
        acquisitions++;
        assert.equal(q.nodeId, plan.nodeId);
        assert.equal(q.credentialId ?? '', plan.credentialOverride);
        assert.equal(epoch, plan.epoch);
        assert.equal(owner!(), true);
        routeBinding = binding({ ...plan, requestId: randomUUID() });
        await waitLease;
        return {
          binding: routeBinding!,
          endpoint: '127.0.0.1:4567',
          closed,
          get active() {
            return leaseActive;
          },
          release: async () => {
            releases++;
            await waitRelease;
            if (failRelease) throw Error('private route release failure');
          },
        };
      },
      close: async () => {
        closes++;
        if (failPendingClose) throw Error('private pending route close failure');
      },
      closeAll: async () => {},
    },
    bundle: (q) => {
      routedRequests.push(q);
      return bundle(q);
    },
  });
  return {
    ...f,
    failRouteRelease: (value: boolean) => {
      failRelease = value;
    },
    failPendingClose: (value: boolean) => {
      failPendingClose = value;
    },
    setWaitRelease: (value: Promise<void> | undefined) => {
      waitRelease = value;
    },
    routedRequests,
    counts: () => ({ releases, closes, acquisitions }),
    loseRoute: () => {
      leaseActive = false;
      routeClosed();
    },
    setMode: (value: typeof resolveMode) => {
      resolveMode = value;
    },
    setWaitPlan: (value: Promise<void>) => {
      waitPlan = value;
    },
    setWaitLease: (value: Promise<void>) => {
      waitLease = value;
    },
    setBundle: (value: typeof bundle) => {
      bundle = value;
    },
    invalidateLease: () => {
      leaseActive = false;
    },
    corruptBinding: () => {
      routeBinding!.nodeId = randomUUID();
    },
  };
}

test('SSH native exit cannot free a cohort while route retirement is unconfirmed; explicit close can retry', async (t) => {
  const f = routedFixture(t),
    x = f.open();
  await tick();
  try {
    f.failRouteRelease(true);
    f.children[0]!.exit();
    await assert.rejects(x.result);
    await tick();
    assert.equal(f.broker.has(x.request.sessionId), true);
    await assert.rejects(f.broker.close(x.request.sessionId), /could not be confirmed/);
    const replacement = f.open(x.request.sessionId);
    await assert.rejects(replacement.result, /unavailable/);
    assert.equal(f.children.length, 1);
    f.failRouteRelease(false);
    await f.broker.close(x.request.sessionId);
    assert.equal(f.broker.has(x.request.sessionId), false);
    assert.ok(f.counts().releases >= 2);
    assert.equal(f.events.filter((e) => e.type === 'closed').length, 1);
  } finally {
    f.failRouteRelease(false);
    await f.broker.closeAll();
  }
});

test('SSH spawn failure does not free an already acquired route before confirmed retirement', async (t) => {
  const f = routedFixture(t);
  f.failSpawn(true);
  f.failRouteRelease(true);
  const x = f.open();
  try {
    await assert.rejects(x.result, /process could not start/);
    await tick();
    assert.equal(f.children.length, 0);
    assert.equal(f.broker.has(x.request.sessionId), true);
    await assert.rejects(f.broker.close(x.request.sessionId));
    f.failRouteRelease(false);
    await f.broker.close(x.request.sessionId);
    assert.equal(f.broker.has(x.request.sessionId), false);
  } finally {
    f.failRouteRelease(false);
    await f.broker.closeAll();
  }
});

test('SSH close joins route acknowledgement even after observing native process exit', async (t) => {
  const f = routedFixture(t),
    x = f.open();
  await tick();
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  f.setWaitRelease(gate);
  const closing = f.broker.close(x.request.sessionId);
  let stopped = false;
  void closing.then(() => {
    stopped = true;
  });
  try {
    await assert.rejects(x.result);
    await tick();
    assert.equal(f.children[0]!.exitCode, 0);
    assert.equal(stopped, false);
    assert.equal(f.broker.has(x.request.sessionId), true);
  } finally {
    release();
    await closing;
  }
  assert.equal(f.broker.has(x.request.sessionId), false);
});

test('an exited SSH process retains every live SFTP alias until its shared route is confirmed closed', async (t) => {
  const f = routedFixture(t),
    x = f.open();
  await tick();
  const child = f.children[0]!;
  f.recipient(child);
  await tick();
  const connected = {
    type: 'connected',
    host: 'host.example',
    port: 22,
    username: 'alice',
    fingerprint: 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
  };
  child.line({ ...connected, session_id: x.request.sessionId });
  await x.result;
  const alias = randomUUID(),
    sharing = f.broker.shareSftp(x.request.sessionId, alias, () => true);
  child.line({ ...connected, session_id: alias });
  await sharing;
  try {
    f.failRouteRelease(true);
    child.exit();
    await tick();
    assert.equal(f.broker.has(x.request.sessionId), true);
    assert.equal(f.broker.has(alias), true);
    assert.deepEqual(f.broker.connectedSessionIds(), []);
    await assert.rejects(f.broker.close(alias));
    f.failRouteRelease(false);
    await f.broker.close(alias);
    assert.equal(f.broker.has(x.request.sessionId), false);
    assert.equal(f.broker.has(alias), false);
  } finally {
    f.failRouteRelease(false);
    await f.broker.closeAll();
  }
});

test('native cohort retirement runs only after its last member and confirmed child/route cleanup', async (t) => {
  const f = routedFixture(t),
    sessionId = randomUUID();
  let retirements = 0,
    fail = true;
  const pending = f.broker.open(
    { sessionId, nodeId: randomUUID(), rows: 24, columns: 80 },
    1,
    () => true,
    async () => {
      assert.equal(f.children[0]!.exitCode, 0);
      assert.ok(f.counts().releases > 0);
      if (fail) throw Error('private target diagnostic');
      retirements++;
    },
  );
  await tick();
  const child = f.children[0]!;
  f.recipient(child);
  await tick();
  const event = {
    type: 'connected',
    host: 'host.example',
    port: 22,
    username: 'alice',
    fingerprint: 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
  };
  child.line({ ...event, session_id: sessionId });
  await pending;
  const alias = randomUUID(),
    sharing = f.broker.shareSftp(sessionId, alias, () => true);
  child.line({ ...event, session_id: alias });
  await sharing;
  const closingPrimary = f.broker.close(sessionId);
  child.line({ type: 'closed', session_id: sessionId });
  await closingPrimary;
  assert.equal(child.exitCode, null);
  assert.equal(retirements, 0);
  assert.equal(f.broker.has(alias), true);
  assert.equal(f.broker.has(sessionId), false);
  assert.equal(f.broker.hasReservation(sessionId), true);
  const duplicate = f.broker.admit({ sessionId, nodeId: randomUUID(), rows: 24, columns: 80 }, 1);
  assert.equal(duplicate.accepted, false);
  await assert.rejects(duplicate.result);
  await f.broker.close(sessionId);
  assert.equal(
    child.exitCode,
    null,
    'closing the retired primary member cannot close its live aliases',
  );
  try {
    await assert.rejects(f.broker.closeCohorts([sessionId, alias]), {
      message: 'SSH shutdown could not be confirmed.',
    });
    assert.equal(f.broker.has(alias), true);
    assert.equal(retirements, 0);
    fail = false;
    await f.broker.close(sessionId);
    assert.equal(retirements, 1);
    assert.equal(f.broker.has(alias), false);
    await f.broker.closeAll();
    assert.equal(retirements, 1);
  } finally {
    fail = false;
    await f.broker.closeAll();
  }
});

test('synchronous SSH admission receipt transfers retirement only after a cohort is reserved', async (t) => {
  const f = fixture(t),
    sessionId = randomUUID();
  let releases = 0;
  const retired = async () => {
    releases++;
  };
  const q = { sessionId, nodeId: randomUUID(), columns: 80, rows: 24 };
  for (const input of [{ ...q, nodeId: 'bad' }, q]) {
    const admission = f.broker.admit(input, 1, () => false, retired);
    assert.equal(admission.accepted, false);
    await assert.rejects(admission.result);
  }
  assert.equal(releases, 0, 'a rejected handoff leaves cleanup with the original caller');
  const admission = f.broker.admit(q, 1, () => true, retired);
  void admission.result.catch(() => {});
  assert.equal(admission.accepted, true);
  assert.equal(f.broker.hasReservation(sessionId), true);
  await f.broker.closeCohorts([sessionId, sessionId, randomUUID()]);
  await assert.rejects(admission.result);
  assert.equal(releases, 1);
  assert.equal(f.broker.hasReservation(sessionId), false);
  await f.broker.closeCohorts([sessionId]);
  assert.equal(releases, 1);
});

test('invalid or late SSH route receipts remain owned when their exact release fails', async (t) => {
  for (const late of [false, true]) {
    const f = routedFixture(t);
    let release!: () => void;
    f.setWaitLease(
      new Promise<void>((r) => {
        release = r;
      }),
    );
    const x = f.open();
    await tick();
    try {
      f.failRouteRelease(true);
      if (late) {
        f.failPendingClose(true);
        await assert.rejects(f.broker.close(x.request.sessionId));
      } else f.corruptBinding();
      release();
      await assert.rejects(x.result);
      await tick();
      assert.equal(f.broker.has(x.request.sessionId), true);
      assert.equal(f.children.length, 0);
      f.failRouteRelease(false);
      f.failPendingClose(false);
      await f.broker.close(x.request.sessionId);
      assert.equal(f.broker.has(x.request.sessionId), false);
      assert.ok(f.counts().releases >= 2, 'retry releases the captured receipt');
    } finally {
      release();
      f.failRouteRelease(false);
      f.failPendingClose(false);
      await f.broker.closeAll();
    }
  }
});

test('SSH waits for its route, binds credentials to the lease and fails closed on route loss', async (t) => {
  const f = routedFixture(t);
  let release!: () => void;
  f.setWaitLease(new Promise<void>((r) => (release = r)));
  const x = f.open();
  await tick();
  assert.equal(f.children.length, 0);
  assert.equal(f.broker.has(x.request.sessionId), true);
  release();
  await tick();
  const child = f.children[0]!;
  f.recipient(child);
  await tick();
  const q = f.routedRequests[0]!;
  assert.equal(f.requests.length, 0);
  assert.equal(q.requestId, q.route.requestId);
  assert.equal(q.endpoint, '127.0.0.1:4567');
  assert.deepEqual(child.requests[0], {
    binding: q.route,
    bundle: sshBundle(q).bundle,
    endpoint: q.endpoint,
    columns: 80,
    rows: 24,
  });
  child.line({
    type: 'connected',
    session_id: x.request.sessionId,
    host: 'host.example',
    port: 22,
    username: 'alice',
    fingerprint: 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
  });
  await x.result;
  f.loseRoute();
  await tick();
  assert.equal(child.exitCode, 0);
  assert.equal(f.broker.has(x.request.sessionId), false);
  assert.deepEqual(f.counts(), { releases: 1, closes: 0, acquisitions: 1 });
});

test('only an explicit direct plan bypasses the VPN, invalid plans never spawn SSH', async (t) => {
  for (const mode of ['direct', 'error', 'invalid', 'other-protocol'] as const) {
    const f = routedFixture(t);
    f.setMode(mode);
    const x = f.open();
    await tick();
    if (mode === 'direct') {
      f.recipient(f.children[0]!);
      await tick();
      assert.equal(f.requests.length, 1);
      assert.equal(f.routedRequests.length, 0);
      await f.broker.close(x.request.sessionId);
    } else {
      await assert.rejects(x.result, /stopped/);
      assert.equal(f.children.length, 0);
    }
    assert.equal(f.counts().acquisitions, 0);
  }
});

test('cancelled route planning and late leases never spawn or release a replacement by ID', async (t) => {
  for (const stage of ['plan', 'lease', 'invalid-lease', 'inactive-lease'] as const) {
    const f = routedFixture(t);
    let release!: () => void;
    const waiting = new Promise<void>((r) => (release = r));
    if (stage === 'plan') f.setWaitPlan(waiting);
    else f.setWaitLease(waiting);
    const x = f.open();
    await tick();
    if (stage === 'invalid-lease') f.corruptBinding();
    else if (stage === 'inactive-lease') f.invalidateLease();
    else await f.broker.close(x.request.sessionId);
    release();
    await assert.rejects(x.result);
    await tick();
    assert.equal(f.children.length, 0);
    assert.equal(f.counts().releases, stage === 'plan' ? 0 : 1);
  }
});

test('late SSH child close cleans up its exact lease even when presentation reopens the same ID', async (t) => {
  const f = routedFixture(t),
    x = f.open();
  await tick();
  let replacement: ReturnType<typeof f.open> | undefined;
  f.setOnLine((event) => {
    if (event.type === 'closed' && !replacement) replacement = f.open(x.request.sessionId);
  });
  f.children[0]!.exit();
  await assert.rejects(x.result);
  await tick();
  assert.ok(replacement);
  assert.equal(f.children.length, 2);
  assert.equal(f.children[1]!.exitCode, null);
  assert.equal(f.counts().closes, 0);
  assert.equal(f.counts().releases, 1);
  f.setOnLine(() => {});
});

test('routed credential response cannot change endpoint or revision, or publish after cancellation', async (t) => {
  for (const mode of ['endpoint', 'revision', 'cancel'] as const) {
    const f = routedFixture(t);
    let release!: () => void;
    f.setBundle(async (q) => {
      await new Promise<void>((r) => (release = r));
      return {
        ...sshBundle(q),
        binding: { ...q.route, rowVersion: mode === 'revision' ? '2' : '1' },
        endpoint: mode === 'endpoint' ? '127.0.0.1:9999' : q.endpoint,
      };
    });
    const x = f.open();
    await tick();
    const child = f.children[0]!;
    f.recipient(child);
    await tick();
    if (mode === 'cancel') await f.broker.close(x.request.sessionId);
    release();
    await assert.rejects(x.result);
    await tick();
    assert.equal(child.requests.length, 0);
    assert.equal(f.requests.length, 0);
  }
});

test('SSH probes identity before releasing credentials and awaits explicit trust only for new keys', async (t) => {
  const observed = 'SHA256:' + Buffer.alloc(32, 1).toString('base64').slice(0, -1);
  for (const known of [
    '',
    observed,
    'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
  ]) {
    let confirm!: () => void,
      confirmations = 0;
    const f = fixture(t, 1000, undefined, {
      plan: async (q) => ({
        binding: sshBundle({ ...q, publicKey: '' }).binding,
        fileId: randomUUID(),
        revision: 'a'.repeat(64),
        fingerprint: known,
      }),
      confirm: async (q, plan, received, accepted, signal) => {
        assert.equal(q.nodeId, plan.binding.nodeId);
        assert.equal(received, observed);
        assert.ok(accepted());
        assert.ok(!signal.aborted);
        confirmations++;
        await new Promise<void>((r) => {
          confirm = r;
        });
      },
    });
    const x = f.open();
    await tick();
    const probe = f.children[0]!,
      request = probe.requests[0];
    assert.deepEqual(Object.keys(request).sort(), ['endpoint', 'host', 'port', 'requestId']);
    assert.equal(request.endpoint, '');
    assert.equal(f.requests.length, 0);
    probe.exitOnEnd = false;
    probe.line({ requestId: request.requestId, fingerprint: observed });
    await tick();
    assert.equal(
      probe.stdin.writableEnded,
      true,
      'acknowledge the response before waiting for exit',
    );
    assert.equal(
      f.children.length,
      1,
      'response without confirmed probe exit cannot release credentials',
    );
    probe.exit();
    await tick();
    if (known !== observed) {
      assert.equal(confirmations, 1);
      assert.equal(f.children.length, 1);
      confirm();
      await tick();
    } else assert.equal(confirmations, 0);
    assert.equal(f.children.length, 2);
    f.recipient(f.children[1]!);
    await tick();
    assert.equal(f.requests.length, 1);
    await f.broker.close(x.request.sessionId);
    await assert.rejects(x.result);
  }
});

test('SSH host probe rejects malformed, late and failed observations without a credential release', async (t) => {
  const pin = 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1);
  for (const mode of [
    'invalid-plan',
    'bad-json',
    'extra',
    'wrong-id',
    'bad-pin',
    'oversize',
    'error',
    'exit',
    'late-plan',
    'cancel-dialog',
    'cancel-probe',
    'duplicate',
  ] as const) {
    let release!: () => void;
    let signal: AbortSignal | undefined;
    const f = fixture(t, 1000, undefined, {
      plan: async (q) => {
        if (mode === 'late-plan')
          await new Promise<void>((r) => {
            release = r;
          });
        return {
          binding: sshBundle({ ...q, publicKey: '' }).binding,
          fileId: randomUUID(),
          revision: mode === 'invalid-plan' ? 'bad' : 'a'.repeat(64),
          fingerprint: '',
        };
      },
      confirm: async (_q, _p, _v, _accepted, value) => {
        signal = value;
        throw Error('cancelled');
      },
    });
    const x = f.open();
    await tick();
    if (mode === 'late-plan') {
      await f.broker.close(x.request.sessionId);
      release();
    } else if (mode !== 'invalid-plan') {
      const child = f.children[0]!,
        request = child.requests[0];
      if (mode === 'bad-json') child.stdout.write('bad\n');
      else if (mode === 'oversize') child.stdout.write(Buffer.alloc(1025));
      else if (mode === 'error') child.emit('error', Error('private diagnostic'));
      else if (mode === 'cancel-probe') await f.broker.close(x.request.sessionId);
      else if (mode === 'exit') child.exit();
      else {
        child.line({
          requestId: mode === 'wrong-id' ? randomUUID() : request.requestId,
          fingerprint: mode === 'bad-pin' ? 'bad' : pin,
          ...(mode === 'extra' ? { password: 'forbidden' } : {}),
        });
        if (mode === 'duplicate') child.line({ requestId: request.requestId, fingerprint: pin });
        child.exit();
      }
    }
    await assert.rejects(x.result);
    await tick();
    assert.equal(f.requests.length, 0, mode);
    assert.ok(f.children.length <= 1, mode);
    if (signal) assert.ok(signal.aborted);
  }
});

test('credential handoff cannot switch the destination after host identity verification', async (t) => {
  const pin = 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1);
  const f = fixture(t, 1000, undefined, {
    plan: async (q) => ({
      binding: sshBundle({ ...q, publicKey: '' }).binding,
      fileId: randomUUID(),
      revision: 'a'.repeat(64),
      fingerprint: pin,
    }),
    confirm: async () => {
      assert.fail('already pinned');
    },
  });
  f.setBundle(async (q) => ({
    ...sshBundle(q),
    binding: { ...sshBundle(q).binding, host: 'replaced.example' },
  }));
  const x = f.open();
  await tick();
  const probe = f.children[0]!;
  probe.line({ requestId: probe.requests[0].requestId, fingerprint: pin });
  probe.exit();
  await tick();
  const child = f.children[1]!;
  f.recipient(child);
  await assert.rejects(x.result);
  await tick();
  assert.equal(child.requests.length, 0);
});
test('standalone SFTP sends only file commands and refuses terminal output', async (t) => {
  const f = fixture(t);
  f.setBundle(async (q) => {
    const b = sshBundle(q);
    b.binding.protocol = 'sftp';
    return b;
  });
  const q = {
    sessionId: randomUUID(),
    nodeId: randomUUID(),
    mode: 'sftp' as const,
    columns: 80,
    rows: 24,
  };
  const pending = f.broker.open(q, 1);
  const child = f.children[0]!;
  f.recipient(child);
  await tick();
  assert.equal(child.requests[0].binding.protocol, 'sftp');
  child.line({
    type: 'connected',
    session_id: q.sessionId,
    host: 'host.example',
    port: 22,
    username: 'alice',
    fingerprint: 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
  });
  await pending;
  for (const type of ['input', 'resize', 'snapshot', 'terminal-ack', 'auto-sudo-cancel'])
    assert.throws(
      () => f.broker.send(q.sessionId, { type, session_id: q.sessionId }),
      /Unsupported|unavailable/,
    );
  f.broker.send(q.sessionId, { type: 'sftp-open', session_id: q.sessionId, request_id: 'list' });
  assert.equal(child.requests.at(-1).type, 'sftp-open');
  child.line({ type: 'screen', session_id: q.sessionId });
  await tick();
  assert.equal(f.broker.has(q.sessionId), false);
  assert.ok(!f.events.some((e) => e.type === 'screen'));
});

test('terminal protocol and explicit file-only admission cannot be substituted', async (t) => {
  for (const mode of ['ssh', 'sftp'] as const) {
    const opposite = mode === 'ssh' ? 'sftp' : 'rdp';
    const f = fixture(t);
    f.setBundle(async (q) => {
      const b = sshBundle(q);
      b.binding.protocol = opposite as any;
      return b;
    });
    const pending = f.broker.open(
      {
        sessionId: randomUUID(),
        nodeId: randomUUID(),
        columns: 80,
        rows: 24,
        mode: mode === 'sftp' ? 'sftp' : 'terminal',
      },
      1,
    );
    const rejected = assert.rejects(pending);
    f.recipient(f.children[0]!);
    await rejected;
    assert.equal(f.children[0]!.requests.length, 0);
    const h = fixture(t, 1000, undefined, {
      plan: async (q) => ({
        binding: { ...sshBundle({ ...q, publicKey: '' }).binding, protocol: opposite as any },
        fileId: q.workspaceId,
        revision: 'a'.repeat(64),
        fingerprint: '',
      }),
      confirm: async () => {
        assert.fail('mismatched host reached trust');
      },
    });
    await assert.rejects(
      h.broker.open(
        {
          sessionId: randomUUID(),
          nodeId: randomUUID(),
          columns: 80,
          rows: 24,
          mode: mode === 'sftp' ? 'sftp' : 'terminal',
        },
        1,
      ),
    );
    assert.equal(h.children.length, 0);
    assert.equal(h.requests.length, 0);
  }
  const f = fixture(t);
  for (const mode of [null, 'rdp', '', 7])
    await assert.rejects(
      f.broker.open(
        { sessionId: randomUUID(), nodeId: randomUUID(), columns: 80, rows: 24, mode: mode as any },
        1,
      ),
    );
  assert.equal(f.children.length, 0);
});
test('standalone SFTP requires an exact VPN protocol and never falls back to direct', async (t) => {
  for (const stage of ['valid', 'plan', 'lease', 'bundle'] as const) {
    const f = routedFixture(t, 'sftp');
    if (stage === 'plan') f.setMode('other-protocol');
    let release!: () => void;
    if (stage === 'lease')
      f.setWaitLease(
        new Promise<void>((r) => {
          release = r;
        }),
      );
    if (stage === 'bundle')
      f.setBundle(async (q) => ({
        ...sshBundle(q),
        binding: { ...q.route, protocol: 'ssh' },
        endpoint: q.endpoint,
      }));
    const sessionId = randomUUID();
    const pending = f.broker.open(
      { sessionId, nodeId: randomUUID(), columns: 80, rows: 24, mode: 'sftp' },
      1,
    );
    void pending.catch(() => {});
    await tick();
    if (stage === 'lease') {
      f.corruptBinding();
      release();
      await tick();
    }
    if (stage === 'valid' || stage === 'bundle') {
      f.recipient(f.children[0]!);
      await tick();
    }
    if (stage === 'valid') {
      assert.equal(f.children[0]!.requests[0].binding.protocol, 'sftp');
      f.loseRoute();
    }
    await assert.rejects(pending);
    await tick();
    assert.equal(f.requests.length, 0, 'no direct credential request');
    if (stage === 'plan' || stage === 'lease') assert.equal(f.children.length, 0);
    if (stage === 'bundle') assert.equal(f.children[0]!.requests.length, 0);
  }
});
test('file mode on an SSH node preserves its protocol but cannot fall back to a terminal', async (t) => {
  for (const stripMode of [false, true]) {
    const f = fixture(t);
    f.setBundle(async (q) => {
      const result = sshBundle(q);
      if (stripMode) delete result.sftpOnly;
      return result;
    });
    const sessionId = randomUUID();
    const pending = f.broker.open(
      { sessionId, nodeId: randomUUID(), columns: 80, rows: 24, mode: 'sftp' },
      1,
    );
    void pending.catch(() => {});
    f.recipient(f.children[0]!);
    await tick();
    if (stripMode) {
      await assert.rejects(pending);
      assert.equal(f.children[0]!.requests.length, 0);
      continue;
    }
    assert.equal(f.children[0]!.requests[0].binding.protocol, 'ssh');
    assert.equal(f.children[0]!.requests[0].sftpOnly, true);
    f.children[0]!.line({
      type: 'connected',
      session_id: sessionId,
      host: 'host.example',
      port: 22,
      username: 'alice',
      fingerprint: 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
    });
    await pending;
    assert.throws(
      () => f.broker.send(sessionId, { type: 'input', session_id: sessionId, data: 'YQ==' }),
      /Unsupported|unavailable/,
    );
    await f.broker.close(sessionId);
  }
});

test('file editing uses trusted startup paths, exact commands and current connected members', async (t) => {
  const f = fixture(t, 1000, undefined, undefined, () => ({
    databasePath: '/owner/database',
    userDataPath: '/owner/files',
  }));
  assert.deepEqual(f.broker.connectedSessionIds(), []);
  const x = await f.connect(),
    id = x.request.sessionId;
  assert.deepEqual(f.broker.connectedSessionIds(), [id]);
  f.broker.send(id, {
    type: 'sftp-edit',
    session_id: id,
    request_id: 'list',
    operation: 'list',
    path: undefined,
  });
  assert.deepEqual(x.child.requests.at(-1), {
    type: 'sftp-edit',
    sessionId: id,
    request_id: 'list',
    operation: 'list',
  });
  x.child.line({ type: 'sftp.edit', session_id: id, request_id: 'list', edits: [] });
  assert.equal(f.events.at(-1).type, 'sftp.edit');
  assert.throws(
    () =>
      f.broker.send(id, {
        type: 'sftp-edit',
        session_id: id,
        request_id: 'list',
        operation: 'list',
        executable: '/injected',
      }),
    /Invalid/,
  );
  const alias = randomUUID();
  let live = true;
  const opening = f.broker.shareSftp(id, alias, () => live);
  x.child.line({
    ...x.child.requests[0].binding,
    type: 'connected',
    session_id: alias,
    username: 'alice',
    fingerprint: 'SHA256:' + Buffer.alloc(32).toString('base64').slice(0, -1),
  });
  await opening;
  assert.deepEqual(f.broker.connectedSessionIds(), [id, alias]);
  live = false;
  assert.deepEqual(f.broker.connectedSessionIds(), [id]);
  await f.broker.closeAll();
  assert.deepEqual(f.broker.connectedSessionIds(), []);
});
