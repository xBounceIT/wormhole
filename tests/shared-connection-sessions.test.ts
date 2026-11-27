import assert from 'node:assert/strict';
import test from 'node:test';
import {
  SharedConnectionSessions,
  type SharedSessionAPI,
  type SharedTerminal,
} from '../src/shared-connection-sessions.ts';
import { sharedConnectionMode } from '../src/shared-connection-mode.ts';
import type { SharedCatalogNode } from '../electron/vault-shared-catalog.ts';
import type { TerminalActions } from '../src/xterm-terminal.ts';

const node: SharedCatalogNode = {
  id: '11111111-1111-4111-8111-111111111111',
  parentId: null,
  name: 'Team SSH',
  kind: 1,
  protocol: 0,
  sortOrder: '0',
  host: 'public.invalid',
  port: 22,
  username: 'catalog-user',
  canUse: true,
};
const tick = async () => {
  for (let i = 0; i < 4; i++) await new Promise<void>((r) => setImmediate(r));
};
function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
function fixture(overrides: Record<string, unknown> = {}, terminalFails = false) {
  const calls: { name: string; args: any[] }[] = [];
  let rdpEvent!: (event: any) => void;
  let backendEvent!: (event: any) => void;
  let webEvent!: (event: any) => void;
  let serialEvent!: (event: WormholeSerialEvent) => void;
  let event!: (event: any) => void,
    unsubscribed = 0,
    notifications = 0;
  const terms = new Map<
    string,
    {
      actions: TerminalActions;
      disposed: number;
      output: any[];
      attached: number;
      detached: number;
      focus: number;
      fit: number;
    }
  >();
  const names = [
    'closeSshSession',
    'sendSshInput',
    'resizeSshSession',
    'closeSerialSession',
    'sendSerialInput',
    'resizeSerialSession',
    'openSftpBrowser',
    'listSftpDirectory',
    'listLocalSftpDirectory',
    'operateSftp',
    'startSftpTransfer',
    'decideSftpConflict',
    'cancelSftpTransfer',
  ];
  const api: any = Object.fromEntries(
    names.map((name) => [
      name,
      async (...args: any[]) => {
        calls.push({ name, args });
      },
    ]),
  );
  api.openSshSession = async (request: any) => {
    calls.push({ name: 'open', args: [request] });
    return {
      sessionId: request.sessionId,
      host: 'verified.invalid',
      port: 2222,
      username: 'native-user',
    };
  };
  api.onSshEvent = (callback: any) => {
    event = callback;
    return () => {
      unsubscribed++;
    };
  };
  api.onBackendEvent = (callback: any) => {
    backendEvent = callback;
    return () => {};
  };
  api.sendVncCommand = async (command: any) => {
    calls.push({ name: 'vnc', args: [command] });
    return { id: '', ok: true };
  };
  api.onRdpEvent = (callback: any) => {
    rdpEvent = callback;
    return () => {};
  };
  api.onWebEvent = (callback: any) => {
    webEvent = callback;
    return () => {};
  };
  api.onSerialEvent = (callback: typeof serialEvent) => {
    serialEvent = callback;
    return () => {};
  };
  api.openSerialSession = async (request: { sessionId: string }) => {
    calls.push({ name: 'serial-open', args: [request] });
    return { sessionId: request.sessionId, portName: 'COM23' };
  };
  api.openWebSession = async (request: any) => {
    calls.push({ name: 'web-open', args: [request] });
    return {
      protocol: 'https',
      host: 'verified.invalid',
      port: 443,
      url: 'https://verified.invalid/',
    };
  };
  api.closeWebSession = async (id: string) => {
    calls.push({ name: 'web-close', args: [id] });
  };
  api.openVaultRdpSession = async (q: any) => {
    calls.push({ name: 'rdp', args: [q] });
    return { type: 'ready', sessionId: q.sessionId };
  };
  api.commandRdpSession = async (q: any) => {
    calls.push({ name: 'rdp-control', args: [q] });
    return { type: 'ack', sessionId: q.sessionId };
  };
  api.prepareSftpEditClose = async () => true;
  api.pasteClipboardToSsh = async (id: string) => {
    calls.push({ name: 'paste', args: [id] });
    return { pasted: true };
  };
  Object.assign(api, overrides);
  const sessions = new SharedConnectionSessions(
    api as SharedSessionAPI,
    (id) => {
      if (terminalFails) throw Error('terminal failed');
      const state = {
        actions: {} as TerminalActions,
        disposed: 0,
        output: [] as any[],
        attached: 0,
        detached: 0,
        focus: 0,
        fit: 0,
      };
      terms.set(id, state);
      return {
        configure: (a: TerminalActions) => {
          state.actions = a;
        },
        dispose: () => {
          state.disposed++;
        },
        receive: (e: any) => {
          state.output.push(e);
        },
        attach: () => {
          state.attached++;
        },
        detach: () => {
          state.detached++;
        },
        focus: () => {
          state.focus++;
        },
        fit: () => {
          state.fit++;
        },
      } as SharedTerminal;
    },
    async (text) => {
      calls.push({ name: 'copy', args: [text] });
    },
  );
  const unsubscribe = sessions.subscribe(() => {
    notifications++;
  });
  const current = () => sessions.getSnapshot().sessions[0];
  return {
    rdpEvent: (e: any) => rdpEvent(e),
    webEvent: (e: any) => webEvent(e),
    serialEvent: (e: WormholeSerialEvent) => serialEvent(e),
    sessions,
    calls,
    terms,
    current,
    event: (e: any) => event(e),
    backendEvent: (e: any) => backendEvent(e),
    api,
    unsubscribe,
    get unsubscribed() {
      return unsubscribed;
    },
    get notifications() {
      return notifications;
    },
  };
}

test('shared session modes require Use and supported connection types', async () => {
  assert.equal(sharedConnectionMode(node), 'terminal');
  assert.equal(sharedConnectionMode({ ...node, protocol: 7 }), 'sftp');
  const f = fixture();
  try {
    for (const changed of [{ kind: 0 }, { canUse: false }, { protocol: 2 }]) {
      const value = { ...node, ...changed } as SharedCatalogNode;
      assert.equal(sharedConnectionMode(value), undefined);
      await f.sessions.open(value);
    }
    await f.sessions.open({ ...node, protocol: 7 }, 'terminal');
    assert.equal(f.calls.length, 0);
    assert.equal(f.sessions.getSnapshot().sessions.length, 0);
    assert.ok(f.sessions.getSnapshot().error);
  } finally {
    f.sessions.dispose();
  }
});

test('shared serial resolves inherited mode, routes frames and controls, and closes on revocation', async () => {
  const serial = { ...node, protocol: null, name: 'Serial console' };
  const f = fixture({
    readSharedConnectionContext: async () => ({ nodeId: node.id, protocol: 5 }),
  });
  try {
    assert.equal(sharedConnectionMode({ ...serial, protocol: 5 }), 'serial');
    await f.sessions.open(serial);
    const id = f.current().id;
    assert.equal(f.current().mode, 'serial');
    assert.equal(f.current().serialPort, 'COM23');
    assert.deepEqual(f.calls[0], {
      name: 'serial-open',
      args: [{ sessionId: id, nodeId: serial.id, columns: 80, rows: 24 }],
    });
    assert.equal(f.terms.size, 0);
    const cell = { character: 'Z', foreground: 2, background: 0 };
    const frame = {
      columns: 1,
      rows: 1,
      full: true,
      cells: [cell],
      changes: [],
      scrollbackReset: true,
      viewportReset: true,
      cursorX: 0,
      cursorY: 0,
      cursorVisible: false,
      applicationCursor: false,
      alternateScreen: false,
      sequence: 1,
    };
    f.serialEvent({ type: 'screen', sessionId: 'unused', frame });
    assert.equal(f.current().serialFrame, undefined);
    f.serialEvent({
      type: 'screen',
      sessionId: id,
      frame: { ...frame, full: false, cells: undefined },
    });
    assert.equal(f.current().serialFrame?.cells?.[0].character, ' ');
    f.serialEvent({ type: 'screen', sessionId: id, frame });
    assert.deepEqual(f.current().serialFrame?.cells, [cell]);
    f.serialEvent({
      type: 'screen',
      sessionId: id,
      frame: {
        ...frame,
        sequence: 2,
        full: false,
        cells: undefined,
        changes: [{ ...cell, index: 0, character: 'é' }],
      },
    });
    assert.equal(f.current().serialFrame?.cells?.[0].character, 'é');
    f.sessions.sendSerialInput(id, 'é');
    await f.sessions.resizeSerial(id, 100, 30);
    assert.deepEqual(f.calls.slice(-2), [
      { name: 'sendSerialInput', args: [id, 'w6k='] },
      { name: 'resizeSerialSession', args: [id, 100, 30] },
    ]);
    f.sessions.observeNodes([{ ...serial, canUse: false }]);
    f.sessions.sendSerialInput(id, 'blocked');
    await tick();
    assert.deepEqual(f.calls.at(-1), { name: 'closeSerialSession', args: [id] });
    assert.equal(f.sessions.getSnapshot().sessions.length, 0);
  } finally {
    f.sessions.dispose();
  }
});

test('shared serial releases pending opens on close and reconnects with fresh ownership after failure', async () => {
  const serial = { ...node, protocol: 5 };
  const pending = deferred<any>();
  const f = fixture({
    openSerialSession: () => pending.promise,
    closeSerialSession: async () => {
      pending.reject(Error('cancelled'));
    },
  });
  const opening = f.sessions.open(serial);
  await tick();
  assert.equal(await f.sessions.close(f.current().id), true);
  await opening;
  assert.equal(f.sessions.getSnapshot().sessions.length, 0);
  f.sessions.dispose();

  const retry = fixture();
  try {
    await retry.sessions.open(serial);
    const id = retry.current().id;
    retry.serialEvent({ type: 'error', sessionId: id, error: 'private diagnostic' });
    await tick();
    assert.equal(retry.current().status, 'failed');
    assert.doesNotMatch(retry.current().error ?? '', /private/);
    await retry.sessions.reconnect(id);
    assert.notEqual(retry.current().id, id);
    assert.equal(retry.current().status, 'connected');
    retry.serialEvent({ type: 'closed', sessionId: id });
    assert.equal(retry.current().status, 'connected');
  } finally {
    retry.sessions.dispose();
  }
});

test('shared web targets use the native browser and lose their session when Use is withdrawn', async () => {
  const f = fixture({
    readSharedConnectionContext: async () => ({ nodeId: node.id, protocol: 4 }),
  });
  assert.equal(sharedConnectionMode({ ...node, protocol: 3 }), 'web');
  assert.equal(sharedConnectionMode({ ...node, protocol: 4 }), 'web');
  try {
    await f.sessions.open({ ...node, protocol: null });
    const id = f.current().id;
    assert.deepEqual(f.calls, [
      { name: 'web-open', args: [{ sessionId: id, nodeId: node.id, attempt: 1 }] },
    ]);
    assert.equal(f.current().webTarget?.host, 'verified.invalid');
    f.webEvent({ sessionId: id, attempt: 2, type: 'navigation', url: 'https://stale.invalid/' });
    f.webEvent({ sessionId: id, attempt: 1, type: 'focus-address' });
    assert.equal(f.current().webEvent, undefined);
    f.webEvent({
      sessionId: id,
      attempt: 1,
      type: 'navigation',
      url: 'https://verified.invalid/active',
    });
    assert.equal(f.current().webEvent?.url, 'https://verified.invalid/active');
    f.event({ sessionId: id, type: 'closed' });
    assert.equal(f.current().status, 'connected');
    f.sessions.observeNodes([{ ...node, protocol: null, canUse: false }]);
    await tick();
    assert.equal(f.sessions.getSnapshot().sessions.length, 0);
    assert.deepEqual(f.calls.at(-1), { name: 'web-close', args: [id] });
  } finally {
    f.sessions.dispose();
  }
});

test('shared web closure joins a pending open and rejects stale navigation', async () => {
  const response = deferred<unknown>();
  const f = fixture({ openWebSession: () => response.promise });
  try {
    const opening = f.sessions.open({ ...node, protocol: 3 });
    await tick();
    const id = f.current().id;
    const closing = f.sessions.close(id);
    await tick();
    assert.equal(f.current().status, 'closing');
    f.webEvent({ sessionId: id, attempt: 1, type: 'navigation' });
    assert.equal(f.current().webEvent, undefined);
    response.resolve({ host: 'late.invalid' });
    await opening;
    assert.equal(await closing, true);
    assert.deepEqual(f.sessions.getSnapshot().sessions, []);
    assert.deepEqual(f.calls, [
      { name: 'web-close', args: [id] },
      { name: 'web-close', args: [id] },
    ]);
  } finally {
    f.sessions.dispose();
  }
});

test('native web failure retires the browser and reconnects only after cleanup', async () => {
  const response = deferred<unknown>();
  const close = deferred<void>();
  const f = fixture({
    openWebSession: () => response.promise,
    closeWebSession: () => close.promise,
  });
  try {
    const opening = f.sessions.open({ ...node, protocol: 3 });
    await tick();
    const id = f.current().id;
    f.webEvent({ sessionId: id, attempt: 1, type: 'failed', error: 'private native detail' });
    response.reject(Error('private native detail'));
    await tick();
    assert.equal(f.current().status, 'failed');
    assert.equal(f.current().closeConfirmed, false);
    await f.sessions.reconnect(id);
    assert.equal(f.current().id, id);
    close.resolve();
    await opening;
    assert.equal(f.current().closeConfirmed, true);
    assert.match(f.current().error ?? '', /Browser connection closed/);
    assert.doesNotMatch(JSON.stringify(f.sessions.getSnapshot()), /private native detail/);
  } finally {
    f.sessions.dispose();
  }
});

test('shared SSH opens by node ID only and binds terminal actions to the live active owner', async () => {
  const f = fixture();
  try {
    await f.sessions.open(node);
    const first = f.current();
    const term = f.terms.get(first.id)!;
    assert.deepEqual(f.calls[0].args, [
      { sessionId: first.id, nodeId: node.id, mode: 'terminal', columns: 80, rows: 24 },
    ]);
    assert.equal(first.connection?.host, 'verified.invalid');
    assert.equal(first.status, 'connected');
    const surface = {} as HTMLElement,
      detach = f.sessions.attach(first.id, surface);
    assert.equal(term.attached, 1);
    detach();
    assert.equal(term.detached, 1);
    f.sessions.fit(first.id);
    f.sessions.focus(first.id);
    assert.ok(term.focus >= 2 && term.fit >= 2);
    const actions = term.actions;
    actions.input('è🙂', false);
    actions.resize(100, 30);
    actions.copy('selected');
    assert.equal(await actions.paste(), true);
    actions.openLink('https://example.org');
    assert.equal(f.sessions.getSnapshot().link, 'https://example.org');
    f.sessions.closeLink();
    await tick();
    assert.equal(
      Buffer.from(f.calls.find((c) => c.name === 'sendSshInput')!.args[1], 'base64').toString(
        'utf8',
      ),
      'è🙂',
    );
    await f.sessions.open({ ...node, id: '22222222-2222-4222-8222-222222222222' });
    const before = f.calls.length;
    actions.resize(120, 40);
    actions.copy('stale');
    actions.openLink('https://stale.invalid');
    assert.equal(await actions.paste(), false);
    assert.equal(f.calls.length, before);
    assert.equal(f.sessions.getSnapshot().link, undefined);
    f.sessions.select(first.id);
    assert.equal(term.actions.active, true);
    f.sessions.select('missing');
    f.event({ type: 'terminal-output', sessionId: first.id, sequence: 1, data: 'eA==' });
    assert.equal(term.output.length, 1);
    f.event({ type: 'terminal-output', sessionId: 'unknown' });
    assert.equal(term.output.length, 1);
    assert.equal(await f.sessions.close(first.id), true);
    assert.equal(term.disposed, 1);
    actions.input('stale', true);
    await tick();
    assert.equal(f.calls.filter((c) => c.name === 'sendSshInput').length, 1);
    assert.equal(await f.sessions.close('missing'), true);
    f.sessions.fit('missing');
    f.sessions.focus('missing');
    f.sessions.attach('missing', surface)();
    f.unsubscribe();
  } finally {
    f.sessions.dispose();
  }
});

test('pending opens deduplicate and late admissions close only the original ID', async () => {
  const opened = deferred<any>();
  const f = fixture({ openSshSession: () => opened.promise });
  try {
    const opening = f.sessions.open(node);
    const id = f.current().id;
    assert.equal(f.sessions.open(node), opening);
    await tick();
    const closing = f.sessions.close(id);
    assert.equal(f.sessions.close(id), closing);
    await tick();
    assert.equal(f.current().status, 'closing');
    opened.resolve({ sessionId: id, host: 'native', port: 22, username: 'u' });
    await opening;
    assert.equal(await closing, true);
    assert.equal(f.sessions.getSnapshot().sessions.length, 0);
    assert.deepEqual(
      f.calls.filter((c) => c.name === 'closeSshSession').map((c) => c.args),
      [[id], [id]],
    );
  } finally {
    f.sessions.dispose();
  }
});

test('closing before dispatch avoids opening a native session', async () => {
  const f = fixture();
  const opening = f.sessions.open(node);
  const closing = f.sessions.close(f.current().id);
  await opening;
  await closing;
  assert.equal(f.calls.length, 0);
  f.sessions.dispose();
});

test('a late cleanup failure retains the tab until a confirmed retry', async () => {
  const opened = deferred<any>();
  let closes = 0;
  const f = fixture({
    openSshSession: () => opened.promise,
    closeSshSession: async () => {
      if (++closes === 2) throw Error('private');
    },
  });
  try {
    const opening = f.sessions.open(node);
    const id = f.current().id;
    await tick();
    const closing = f.sessions.close(id);
    await tick();
    opened.resolve({ sessionId: id });
    await opening;
    assert.equal(await closing, false);
    assert.equal(f.current().closeConfirmed, false);
    assert.equal(f.current().status, 'failed');
    await f.sessions.reconnect(id);
    assert.equal(f.current().id, id);
    assert.equal(await f.sessions.close(id), true);
    assert.equal(f.sessions.getSnapshot().sessions.length, 0);
  } finally {
    f.sessions.dispose();
  }
});

test('failed opens and mismatched receipts require cleanup before a new reconnect ID', async () => {
  for (const kind of ['reject', 'mismatch', 'sync']) {
    let fail = true;
    const f = fixture({
      openSshSession: (request: any) => {
        if (!fail) return Promise.resolve({ sessionId: request.sessionId });
        if (kind === 'sync') throw Error('private-password');
        return kind === 'reject'
          ? Promise.reject(Error('private-password'))
          : Promise.resolve({ sessionId: 'wrong' });
      },
    });
    try {
      await f.sessions.open(node);
      const id = f.current().id;
      assert.equal(f.current().status, 'failed');
      assert.equal(f.current().closeConfirmed, true);
      assert.doesNotMatch(JSON.stringify(f.sessions.getSnapshot()), /private-password/);
      fail = false;
      await f.sessions.reconnect(id);
      assert.notEqual(f.current().id, id);
      assert.equal(f.current().status, 'connected');
      assert.equal(f.terms.get(id)!.disposed, 1);
    } finally {
      f.sessions.dispose();
    }
  }
  const f = fixture({}, true);
  await f.sessions.open(node);
  assert.equal(f.current().closeConfirmed, true);
  assert.equal(f.calls.length, 0);
  f.sessions.dispose();
});

test('failed closure disables reconnect and remains retryable', async () => {
  let fail = true;
  const f = fixture({
    openSshSession: async () => {
      throw Error('private');
    },
    closeSshSession: async () => {
      if (fail) throw Error('private');
    },
  });
  try {
    await f.sessions.open(node);
    const id = f.current().id;
    assert.equal(f.current().closeConfirmed, false);
    await f.sessions.reconnect(id);
    assert.equal(f.current().id, id);
    assert.equal(await f.sessions.close(id), false);
    assert.equal(f.current().closeBusy, false);
    fail = false;
    assert.equal(await f.sessions.close(id), true);
    assert.equal(f.sessions.getSnapshot().sessions.length, 0);
  } finally {
    f.sessions.dispose();
  }
});

test('remote failures quarantine sessions, ignore late output, and reconnect only after admission settles', async () => {
  for (const type of ['closed', 'error', 'reconnect-failed']) {
    const opened = deferred<any>();
    const f = fixture({ openSshSession: () => opened.promise });
    try {
      const opening = f.sessions.open(node);
      const id = f.current().id;
      await tick();
      f.event({ sessionId: id, type, error: 'private' });
      f.event({ sessionId: id, type: 'terminal-output', sequence: 1, data: 'eA==' });
      f.event({ sessionId: id, type });
      await tick();
      assert.equal(f.current().closeConfirmed, false);
      await f.sessions.reconnect(id);
      assert.equal(f.current().id, id);
      opened.resolve({ sessionId: id });
      await opening;
      assert.equal(f.current().closeConfirmed, true);
      assert.equal(f.terms.get(id)!.output.length, 0);
      assert.doesNotMatch(JSON.stringify(f.sessions.getSnapshot()), /private/);
    } finally {
      f.sessions.dispose();
    }
  }
});

test('file close preserves pending edits on cancellation, but permission revocation bypasses the prompt', async () => {
  const prompt = deferred<boolean>();
  const f = fixture({ prepareSftpEditClose: () => prompt.promise });
  try {
    await f.sessions.open(node, 'sftp');
    await tick();
    const id = f.current().id;
    assert.ok(f.sessions.fileSession(id));
    assert.equal(f.terms.size, 0);
    const closing = f.sessions.close(id);
    await tick();
    assert.equal(f.current().closeBusy, true);
    f.sessions.observeNodes([{ ...node, canUse: false }]);
    assert.equal(await closing, true);
    assert.equal(f.sessions.getSnapshot().sessions.length, 0);
    assert.ok(f.calls.some((c) => c.name === 'closeSshSession'));
    prompt.resolve(false);
    await tick();
    await f.sessions.open({ ...node, protocol: 7 });
    const second = f.current().id;
    assert.equal(await f.sessions.close(second), false);
    assert.equal(f.current().status, 'connected');
    assert.equal(f.current().closeBusy, false);
    f.api.prepareSftpEditClose = async () => {
      throw Error('private');
    };
    assert.equal(await f.sessions.close(second), false);
    assert.equal(f.current().status, 'failed');
  } finally {
    f.sessions.dispose();
  }
});

test('catalog observations only revoke matching known nodes and preserve independent sessions', async () => {
  const f = fixture();
  try {
    await f.sessions.open(node);
    const id = f.current().id;
    f.sessions.observeNodes([]);
    f.sessions.observeNodes([{ ...node, id: 'missing', canUse: false }]);
    assert.equal(f.current().status, 'connected');
    f.sessions.observeNodes([{ ...node, protocol: 7 }]);
    await tick();
    assert.equal(f.sessions.getSnapshot().sessions.length, 0);
    assert.ok(f.calls.some((c) => c.name === 'closeSshSession' && c.args[0] === id));
  } finally {
    f.sessions.dispose();
  }
});

test('file events are correlated to the connection, and remote failure during a close prompt is retained', async () => {
  const prompt = deferred<boolean>(),
    f = fixture({ prepareSftpEditClose: () => prompt.promise });
  try {
    await f.sessions.open(node, 'sftp');
    await tick();
    const id = f.current().id;
    const request = f.calls.find((c) => c.name === 'openSftpBrowser')!.args[1];
    f.event({
      sessionId: id,
      type: 'sftp.ready',
      requestId: request,
      path: '/home',
      entries: [],
      truncated: false,
    });
    assert.equal(f.current().sftp?.path, '/home');
    const closing = f.sessions.close(id);
    await tick();
    f.event({ sessionId: id, type: 'error', error: 'private' });
    await tick();
    assert.equal(f.current().status, 'failed');
    prompt.resolve(false);
    assert.equal(await closing, false);
    assert.equal(f.current().status, 'failed');
    assert.equal(f.current().closeConfirmed, true);
  } finally {
    f.sessions.dispose();
  }
});

test('session bounds, disposal and stale callbacks cannot resurrect an owner', async () => {
  const f = fixture();
  for (let i = 0; i < 32; i++) await f.sessions.open(node);
  assert.equal(f.sessions.getSnapshot().sessions.length, 32);
  await f.sessions.open(node);
  assert.equal(f.sessions.getSnapshot().sessions.length, 32);
  assert.match(f.sessions.getSnapshot().error!, /Close a session/);
  f.sessions.dispose();
  f.sessions.dispose();
  await tick();
  assert.equal(f.unsubscribed, 1);
  assert.equal(f.calls.filter((c) => c.name === 'closeSshSession').length, 32);
  assert.equal(
    [...f.terms.values()].every((t) => t.disposed === 1),
    true,
  );
  await f.sessions.open(node);
  f.sessions.select('missing');
  f.sessions.observeNodes([node]);
  f.event({ type: 'closed', sessionId: 'missing' });
  assert.deepEqual(f.sessions.getSnapshot(), { sessions: [] });
  const opened = deferred<any>(),
    pending = fixture({ openSshSession: () => opened.promise });
  const opening = pending.sessions.open(node);
  const id = pending.current().id;
  await tick();
  pending.sessions.dispose();
  opened.resolve({ sessionId: id });
  await opening;
  await tick();
  assert.equal(pending.calls.filter((c) => c.name === 'closeSshSession').length, 2);
  assert.deepEqual(pending.sessions.getSnapshot(), { sessions: [] });
});

test('an earlier close receipt cannot erase a later failed late-admission cleanup', async () => {
  const opened = deferred<any>(),
    earlier = deferred<void>();
  let closes = 0;
  const f = fixture({
    openSshSession: () => opened.promise,
    closeSshSession: () =>
      ++closes === 1 ? earlier.promise : Promise.reject(Error('late cleanup failed')),
  });
  try {
    const opening = f.sessions.open(node),
      id = f.current().id;
    await tick();
    f.event({ type: 'error', sessionId: id });
    await tick();
    opened.resolve({ sessionId: id });
    await opening;
    assert.equal(f.current().closeConfirmed, false);
    earlier.resolve();
    await tick();
    assert.equal(f.current().closeConfirmed, false);
    await f.sessions.reconnect(id);
    assert.equal(f.current().id, id);
  } finally {
    f.sessions.dispose();
  }
});

test('a failed close retry remains quarantined after an older event-close receipt', async () => {
  const earlier = deferred<void>();
  let closes = 0;
  const f = fixture({
    closeSshSession: () =>
      ++closes === 1 ? earlier.promise : Promise.reject(Error('retry failed')),
  });
  try {
    await f.sessions.open(node);
    const id = f.current().id;
    f.event({ type: 'closed', sessionId: id });
    await tick();
    assert.equal(await f.sessions.close(id), false);
    earlier.resolve();
    await tick();
    assert.equal(f.current().closeConfirmed, false);
    await f.sessions.reconnect(id);
    assert.equal(f.current().id, id);
  } finally {
    f.sessions.dispose();
  }
});

test('inherited protocols are resolved only by native public context and retain explicit file intent', async () => {
  for (const protocol of [0, 7])
    for (const mode of [undefined, 'sftp'] as const) {
      let reads = 0;
      const f = fixture({
        readSharedConnectionContext: async (nodeId: string) => {
          reads++;
          return { nodeId, protocol };
        },
      });
      try {
        await f.sessions.open({ ...node, protocol: null }, mode);
        assert.equal(reads, 1);
        const chosen = mode ?? (protocol === 7 ? 'sftp' : 'terminal');
        assert.equal(f.current().mode, chosen);
        assert.equal(f.current().node.protocol, null);
        assert.equal(f.calls.find((c) => c.name === 'open')!.args[0].mode, chosen);
        assert.equal(f.terms.size, chosen === 'terminal' ? 1 : 0);
      } finally {
        f.sessions.dispose();
      }
    }
});

test('bad or unsupported inherited context never starts a protocol child', async () => {
  for (const value of [
    { nodeId: node.id, protocol: 2 },
    { nodeId: 'wrong', protocol: 0 },
    null,
    'throw',
  ]) {
    const f = fixture({
      readSharedConnectionContext: async () => {
        if (value === 'throw') throw Error('private');
        return value;
      },
    });
    try {
      await f.sessions.open({ ...node, protocol: null });
      assert.equal(f.current().status, 'failed');
      assert.equal(f.current().closeConfirmed, true);
      assert.equal(
        f.calls.some((c) => c.name === 'open' || c.name === 'closeSshSession'),
        false,
      );
      assert.doesNotMatch(JSON.stringify(f.sessions.getSnapshot()), /private/);
    } finally {
      f.sessions.dispose();
    }
  }
  const f = fixture({
    readSharedConnectionContext: async (nodeId: string) => ({ nodeId, protocol: 7 }),
  });
  await f.sessions.open({ ...node, protocol: null }, 'terminal');
  assert.equal(f.current().status, 'failed');
  assert.equal(f.calls.length, 0);
  f.sessions.dispose();
});

test('cancel/dispose before inherited context dispatch or receipt cannot admit a child', async () => {
  for (const kind of ['cancel-before', 'dispose-before', 'cancel-pending', 'dispose-pending']) {
    const context = deferred<any>();
    let reads = 0;
    const f = fixture({
      readSharedConnectionContext: () => {
        reads++;
        return context.promise;
      },
    });
    const pending = f.sessions.open({ ...node, protocol: null });
    const id = f.current().id;
    assert.equal(f.sessions.open({ ...node, protocol: null }), pending);
    if (kind.endsWith('pending')) await tick();
    const closing = kind.startsWith('cancel') ? f.sessions.close(id) : undefined;
    if (!closing) f.sessions.dispose();
    context.resolve({ nodeId: node.id, protocol: 0 });
    await pending;
    await closing;
    await tick();
    assert.equal(reads, kind.endsWith('pending') ? 1 : 0);
    assert.equal(f.calls.length, 0);
    assert.equal(f.sessions.getSnapshot().sessions.length, 0);
    f.sessions.dispose();
  }
});

test('inherited reconnect resolves a fresh protocol rather than reusing the old hint', async () => {
  let reads = 0;
  const f = fixture({
    readSharedConnectionContext: async (nodeId: string) => ({
      nodeId,
      protocol: ++reads === 1 ? 0 : 7,
    }),
  });
  try {
    await f.sessions.open({ ...node, protocol: null });
    const id = f.current().id;
    f.event({ type: 'closed', sessionId: id });
    await tick();
    await f.sessions.reconnect(id);
    assert.equal(reads, 2);
    assert.equal(f.current().mode, 'sftp');
    assert.notEqual(f.current().id, id);
  } finally {
    f.sessions.dispose();
  }
});

test('a subscriber retiring the terminal during publication prevents native dispatch', async () => {
  for (const mode of ['close', 'dispose']) {
    const f = fixture();
    f.sessions.subscribe(() => {
      const session = f.current();
      if (session?.status === 'opening' && f.terms.size) {
        if (mode === 'close') void f.sessions.close(session.id);
        else f.sessions.dispose();
      }
    });
    await f.sessions.open(node);
    await tick();
    assert.equal(
      f.calls.some((c) => c.name === 'open'),
      false,
    );
    assert.equal(f.sessions.getSnapshot().sessions.length, 0);
    f.sessions.dispose();
  }
});

test('VNC waits for its mounted subscriber and sends only native public identifiers', async () => {
  const f = fixture();
  try {
    assert.equal(sharedConnectionMode({ ...node, protocol: 6 }), 'vnc');
    const opening = f.sessions.open({ ...node, protocol: 6 });
    const id = f.current().id;
    await tick();
    assert.equal(f.current().vncMount, true);
    assert.equal(f.current().status, 'opening');
    assert.equal(f.calls.length, 0);
    f.sessions.readyVnc('foreign');
    f.sessions.readyVnc(id);
    await opening;
    assert.equal(f.current().status, 'connected');
    assert.equal(f.terms.size, 0);
    assert.deepEqual(f.calls, [
      { name: 'vnc', args: [{ action: 'vnc.connect', sessionId: id, nodeId: node.id }] },
    ]);
    const snapshot = f.sessions.getSnapshot();
    f.backendEvent({ type: 'vnc.frame', sessionId: id, image: 'private-frame' });
    assert.equal(f.sessions.getSnapshot(), snapshot);
    f.event({ type: 'error', sessionId: id });
    assert.equal(f.current().status, 'connected');
    await f.sessions.open({ ...node, id: '22222222-2222-4222-8222-222222222222' });
    f.sessions.select(id);
    assert.equal(
      f.calls.filter((c) => c.name === 'vnc' && c.args[0].action === 'vnc.connect').length,
      1,
    );
    f.sessions.readyVnc(id);
    assert.equal(await f.sessions.close(id), true);
    assert.ok(f.calls.some((c) => c.name === 'vnc' && c.args[0].action === 'vnc.disconnect'));
  } finally {
    f.sessions.dispose();
  }
});

test('inherited VNC resolves in Go and preserves the mounted session across selection', async () => {
  const f = fixture({
    readSharedConnectionContext: async (nodeId: string) => ({ nodeId, protocol: 6 }),
  });
  try {
    const opening = f.sessions.open({ ...node, protocol: null });
    await tick();
    const id = f.current().id;
    assert.equal(f.current().mode, 'vnc');
    f.sessions.readyVnc(id);
    await opening;
    assert.equal(f.current().status, 'connected');
    await f.sessions.open(node, 'sftp');
    f.sessions.select(id);
    assert.equal(f.calls.filter((c) => c.name === 'vnc').length, 1);
  } finally {
    f.sessions.dispose();
  }
});

test('VNC late admission cleanup is joined and unconfirmed cleanup remains retryable', async () => {
  for (const failLate of [false, true]) {
    const admitted = deferred<any>();
    let closes = 0;
    const f = fixture({
      sendVncCommand: async (command: any) => {
        if (command.action === 'vnc.connect') return admitted.promise;
        closes++;
        return { id: '', ok: !(failLate && closes === 2) };
      },
    });
    try {
      const opening = f.sessions.open({ ...node, protocol: 6 });
      await tick();
      const id = f.current().id;
      f.sessions.readyVnc(id);
      await tick();
      const closing = f.sessions.close(id);
      await tick();
      admitted.resolve({ id: '', ok: true });
      await opening;
      assert.equal(await closing, !failLate);
      assert.equal(closes, 2, 'both original and late admission must be closed');
      if (failLate) {
        assert.equal(f.current().closeConfirmed, false);
        await f.sessions.reconnect(id);
        assert.equal(f.current().id, id);
        assert.equal(await f.sessions.close(id), true);
        assert.equal(closes, 3, 'retry must recheck the quarantined native owner');
      }
      assert.equal(f.sessions.getSnapshot().sessions.length, 0);
    } finally {
      f.sessions.dispose();
    }
  }
});

test('cancelled or disposed VNC mount gates never start a native recipient', async () => {
  for (const kind of ['close', 'dispose']) {
    const f = fixture();
    const opening = f.sessions.open({ ...node, protocol: 6 });
    await tick();
    const id = f.current().id;
    const closing = kind === 'close' ? f.sessions.close(id) : undefined;
    if (kind === 'dispose') f.sessions.dispose();
    f.sessions.readyVnc(id);
    await opening;
    await closing;
    assert.equal(f.calls.length, 0);
    f.sessions.dispose();
  }
});

test('VNC failures quarantine, await receipts and reconnect with a fresh identity', async () => {
  for (const state of ['failed', 'disconnected']) {
    const f = fixture();
    try {
      const opening = f.sessions.open({ ...node, protocol: 6 });
      await tick();
      const id = f.current().id;
      f.sessions.readyVnc(id);
      await opening;
      f.backendEvent({ type: 'vnc.status', sessionId: 'foreign', status: state });
      assert.equal(f.current().status, 'connected');
      f.backendEvent({ type: 'vnc.status', sessionId: id, status: state, message: 'private' });
      await tick();
      assert.equal(f.current().status, 'failed');
      assert.equal(f.current().closeConfirmed, true);
      const reconnecting = f.sessions.reconnect(id);
      await tick();
      assert.notEqual(f.current().id, id);
      f.sessions.readyVnc(f.current().id);
      await reconnecting;
      assert.equal(f.current().status, 'connected');
      assert.doesNotMatch(JSON.stringify(f.sessions.getSnapshot()), /private/);
    } finally {
      f.sessions.dispose();
    }
  }
});

test('a negative VNC opening receipt after its failure event does not erase confirmed cleanup', async () => {
  const admitted = deferred<any>();
  const f = fixture({
    sendVncCommand: async (command: any) =>
      command.action === 'vnc.connect' ? admitted.promise : { id: '', ok: true },
  });
  try {
    const opening = f.sessions.open({ ...node, protocol: 6 });
    await tick();
    const id = f.current().id;
    f.sessions.readyVnc(id);
    await tick();
    f.backendEvent({ type: 'vnc.status', sessionId: id, status: 'failed' });
    await tick();
    assert.equal(f.current().closeConfirmed, false);
    admitted.resolve({ id: '', ok: false, error: 'private' });
    await opening;
    assert.equal(f.current().closeConfirmed, true);
    assert.equal(f.current().status, 'failed');
  } finally {
    f.sessions.dispose();
  }
});

test('VNC native response failures remain sanitized and a false close receipt blocks reconnect', async () => {
  let closed = false;
  const f = fixture({
    sendVncCommand: async (command: any) =>
      command.action === 'vnc.connect'
        ? { id: '', ok: false, error: 'private' }
        : { id: '', ok: closed },
  });
  try {
    const opening = f.sessions.open({ ...node, protocol: 6 });
    await tick();
    const id = f.current().id;
    f.sessions.readyVnc(id);
    await opening;
    await tick();
    assert.equal(f.current().status, 'failed');
    assert.equal(f.current().closeConfirmed, false);
    await f.sessions.reconnect(id);
    assert.equal(f.current().id, id);
    closed = true;
    assert.equal(await f.sessions.close(id), true);
  } finally {
    f.sessions.dispose();
  }
  const g = fixture();
  for (const [protocol, mode] of [
    [0, 'vnc'],
    [6, 'sftp'],
    [7, 'vnc'],
  ] as const)
    await g.sessions.open({ ...node, protocol }, mode);
  assert.equal(g.calls.length, 0);
  g.sessions.dispose();
});

test('a second subscription failure releases the first subscription', () => {
  let released = 0;
  assert.throws(
    () =>
      new SharedConnectionSessions(
        {
          onSshEvent: () => () => {
            released++;
          },
          onBackendEvent: () => {
            throw Error('bridge unavailable');
          },
        } as any,
        () => ({}) as SharedTerminal,
        async () => {},
      ),
  );
  assert.equal(released, 1);
});

test('shared manual VNC reconnect waits for confirmed cleanup and carries only an intent', async () => {
  const f = fixture();
  const desktop = { ...node, protocol: 6 };
  const opening = f.sessions.open(desktop);
  await tick();
  const first = f.sessions.getSnapshot().sessions[0];
  f.sessions.readyVnc(first.id);
  await opening;
  f.backendEvent({
    type: 'vnc.status',
    sessionId: first.id,
    status: 'failed',
    passwordRequired: true,
  });
  f.backendEvent({ type: 'vnc.status', sessionId: first.id, status: 'disconnected' });
  await tick();
  assert.equal(f.sessions.getSnapshot().sessions[0].passwordRequired, true);
  const retry = f.sessions.reconnect(first.id, true);
  await tick();
  const next = f.sessions.getSnapshot().sessions[0];
  assert.notEqual(next.id, first.id);
  f.sessions.readyVnc(next.id);
  await retry;
  const command = f.calls
    .filter((c) => c.name === 'vnc' && c.args[0].action === 'vnc.connect')
    .at(-1)!.args[0];
  assert.deepEqual(command, {
    action: 'vnc.connect',
    sessionId: next.id,
    nodeId: desktop.id,
    manualPassword: true,
  });
  f.backendEvent({ type: 'vnc.status', sessionId: next.id, status: 'disconnected' });
  await tick();
  await f.sessions.reconnect(next.id, true);
  assert.equal(
    f.sessions.getSnapshot().sessions[0].id,
    next.id,
    'non-auth failure offered manual password',
  );
  f.sessions.dispose();
});

test('RDP sessions wait for measured mounted surfaces and pass only node identity', async () => {
  const f = fixture(),
    desktop = { ...node, protocol: 1 };
  try {
    assert.equal(sharedConnectionMode(desktop), 'rdp');
    const opening = f.sessions.open(desktop);
    await tick();
    const id = f.current().id;
    assert.equal(f.current().rdpMount, true);
    assert.equal(f.current().rdpStatus, 'starting');
    assert.equal(
      f.calls.some((c) => c.name === 'rdp'),
      false,
    );
    f.sessions.readyRdp(id, { x: 0, y: 0, width: 0, height: 1 });
    await tick();
    assert.equal(
      f.calls.some((c) => c.name === 'rdp'),
      false,
    );
    const bounds = { x: -1.5, y: 2.25, width: 800, height: 600 };
    f.sessions.readyRdp(id, bounds);
    bounds.width = 1;
    await opening;
    assert.deepEqual(f.calls.find((c) => c.name === 'rdp')!.args[0], {
      sessionId: id,
      nodeId: node.id,
      bounds: { ...bounds, width: 800 },
    });
    assert.equal(f.current().status, 'opening');
    f.event({ type: 'error', sessionId: id });
    assert.equal(f.current().status, 'opening');
    f.rdpEvent({ type: 'frame', sessionId: id });
    assert.equal(f.current().status, 'opening');
    f.rdpEvent({ type: 'connected', sessionId: id });
    assert.equal(f.current().status, 'connected');
    f.rdpEvent({ type: 'autoReconnecting', sessionId: id });
    assert.equal(f.current().rdpStatus, 'starting');
    f.rdpEvent({ type: 'autoReconnected', sessionId: id });
    assert.equal(f.current().rdpStatus, 'connected');
    f.rdpEvent({ type: 'fatalError', sessionId: id, message: 'private' });
    await tick();
    assert.equal(f.current().status, 'failed');
    assert.equal(f.current().closeConfirmed, true);
    assert.doesNotMatch(JSON.stringify(f.sessions.getSnapshot()), /private/);
    assert.equal(f.calls.at(-1)!.name, 'rdp-control');
    const retry = f.sessions.reconnect(id);
    await tick();
    assert.notEqual(f.current().id, id);
    f.rdpEvent({ type: 'connected', sessionId: id });
    assert.equal(f.current().status, 'opening');
    f.sessions.readyRdp(f.current().id, { x: 0, y: 0, width: 800, height: 600 });
    await retry;
    assert.equal(await f.sessions.close(f.current().id), true);
    assert.equal(f.sessions.getSnapshot().sessions.length, 0);
  } finally {
    f.sessions.dispose();
  }
});

test('inherited RDP, cancelled mount gates, late receipts and failed cleanup retain correct ownership', async () => {
  for (const mode of ['inherited', 'cancel', 'dispose', 'late', 'wrong-receipt', 'close-failure']) {
    const admission = deferred<any>();
    const f = fixture({
      readSharedConnectionContext: async () => ({ nodeId: node.id, protocol: 1 }),
      ...(mode === 'late' ? { openVaultRdpSession: () => admission.promise } : {}),
      ...(mode === 'wrong-receipt'
        ? { openVaultRdpSession: async () => ({ sessionId: 'wrong', type: 'ready' }) }
        : {}),
      ...(mode === 'close-failure'
        ? { commandRdpSession: async () => ({ sessionId: 'wrong', type: 'ack' }) }
        : {}),
    });
    try {
      const opening = f.sessions.open({ ...node, protocol: mode === 'inherited' ? null : 1 });
      await tick();
      const id = f.current().id;
      if (mode === 'cancel') {
        assert.equal(await f.sessions.close(id), true);
        await opening;
        continue;
      }
      if (mode === 'dispose') {
        f.sessions.dispose();
        await opening;
        continue;
      }
      f.sessions.readyRdp(id, { x: 0, y: 0, width: 800, height: 600 });
      await tick();
      if (mode === 'late') {
        let finished = false;
        const close = f.sessions.close(id).then((v) => {
          finished = true;
          return v;
        });
        await tick();
        assert.equal(finished, false);
        admission.resolve({ sessionId: id, type: 'ready' });
        await opening;
        assert.equal(await close, true);
        continue;
      }
      await opening;
      if (mode === 'wrong-receipt') {
        assert.equal(f.current().status, 'failed');
        assert.equal(f.current().closeConfirmed, true);
      } else if (mode === 'close-failure') {
        assert.equal(await f.sessions.close(id), false);
        assert.equal(f.current().closeConfirmed, false);
        const count = f.calls.length;
        await f.sessions.reconnect(id);
        assert.equal(f.calls.length, count);
      } else {
        assert.equal(f.current().mode, 'rdp');
        await f.sessions.close(id);
      }
    } finally {
      f.sessions.dispose();
    }
  }
});

test('RDP subscriptions unwind on constructor failure and incompatible inherited modes never dispatch', async () => {
  let removed = 0;
  assert.throws(
    () =>
      fixture({
        onBackendEvent: () => () => {
          removed++;
        },
        onRdpEvent: () => {
          throw Error('subscription failed');
        },
      }),
    /subscription/,
  );
  assert.equal(removed, 1);
  for (const [protocol, mode] of [
    [0, 'rdp'],
    [1, 'vnc'],
    [6, 'rdp'],
    [7, 'rdp'],
  ]) {
    const f = fixture({ readSharedConnectionContext: async () => ({ nodeId: node.id, protocol }) });
    try {
      await f.sessions.open({ ...node, protocol: null }, mode as any);
      assert.equal(f.current().status, 'failed');
      assert.equal(
        f.calls.some((c) => c.name === 'rdp'),
        false,
      );
    } finally {
      f.sessions.dispose();
    }
  }
});

test('RDP early native failure joins its existing close receipt when initial admission rejects', async () => {
  const admission = deferred<any>(),
    stopped = deferred<any>();
  const f = fixture({
    openVaultRdpSession: () => admission.promise,
    commandRdpSession: () => stopped.promise,
  });
  try {
    const opening = f.sessions.open({ ...node, protocol: 1 });
    await tick();
    const id = f.current().id;
    f.sessions.readyRdp(id, { x: 0, y: 0, width: 800, height: 600 });
    await tick();
    f.rdpEvent({ type: 'exited', sessionId: id, code: 1 });
    await tick();
    admission.reject(Error('private initialization failure'));
    await tick();
    assert.equal(f.current().closeConfirmed, false);
    stopped.resolve({ type: 'ack', sessionId: id });
    await opening;
    await tick();
    assert.equal(f.current().status, 'failed');
    assert.equal(f.current().closeConfirmed, true);
    assert.equal(f.current().rdpStatus, 'failed');
    assert.doesNotMatch(JSON.stringify(f.sessions.getSnapshot()), /private/);
  } finally {
    f.sessions.dispose();
  }
});

test('shared RDP temporary reconnect waits for confirmed cleanup and sends only manual intent', async () => {
  const stopped = deferred<any>();
  let hold = true;
  const f = fixture({
    commandRdpSession: async (q: any) =>
      hold ? stopped.promise : { type: 'ack', sessionId: q.sessionId },
  });
  try {
    const opening = f.sessions.open({ ...node, protocol: 1 });
    await tick();
    const first = f.current().id;
    f.sessions.readyRdp(first, { x: 0, y: 0, width: 800, height: 600 });
    await opening;
    f.rdpEvent({ type: 'error', sessionId: first, message: 'failure' });
    await tick();
    await f.sessions.reconnect(first, true);
    assert.equal(f.calls.filter((c) => c.name === 'rdp').length, 1);
    hold = false;
    stopped.resolve({ type: 'ack', sessionId: first });
    await tick();
    const retry = f.sessions.reconnect(first, true);
    await tick();
    const second = f.current().id;
    assert.notEqual(second, first);
    f.sessions.readyRdp(second, { x: 0, y: 0, width: 800, height: 600 });
    await retry;
    const q = f.calls.filter((c) => c.name === 'rdp').at(-1)!.args[0];
    assert.deepEqual(Object.keys(q).sort(), ['bounds', 'manualCredentials', 'nodeId', 'sessionId']);
    assert.equal(q.manualCredentials, true);
  } finally {
    hold = false;
    f.sessions.dispose();
  }
});

test('shared pending saved and temporary RDP attempts never coalesce across credential modes', async () => {
  const f = fixture();
  try {
    const saved = f.sessions.open({ ...node, protocol: 1 });
    await tick();
    const first = f.current().id;
    const manual = f.sessions.open({ ...node, protocol: 1 }, undefined, true);
    await tick();
    const members = f.sessions.getSnapshot().sessions;
    assert.equal(members.length, 2);
    const second = members.find((s) => s.id !== first)!.id;
    for (const id of [first, second])
      f.sessions.readyRdp(id, { x: 0, y: 0, width: 800, height: 600 });
    await Promise.all([saved, manual]);
    const requests = f.calls.filter((c) => c.name === 'rdp').map((c) => c.args[0]);
    assert.equal(requests.length, 2);
    assert.equal(requests.find((q) => q.sessionId === first).manualCredentials, undefined);
    assert.equal(requests.find((q) => q.sessionId === second).manualCredentials, true);
    f.rdpEvent({ type: 'error', sessionId: second, message: 'failed' });
    await tick();
    const retry = f.sessions.reconnect(second);
    await tick();
    const third = f.sessions.getSnapshot().sessions.find((s) => s.id !== first)!.id;
    f.sessions.readyRdp(third, { x: 0, y: 0, width: 800, height: 600 });
    await retry;
    assert.equal(
      f.calls.filter((c) => c.name === 'rdp').at(-1)!.args[0].manualCredentials,
      true,
      'retry silently selected saved credentials',
    );
  } finally {
    f.sessions.dispose();
  }
});
