import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { RdpBackendClient } from '../electron/rdp.ts';

test('RDP cleanup is a no-op when the backend is not running', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  await client.hideAll('window');
  assert.equal((await client.command('hide', 'session', 'window')).type, 'ack');
  assert.equal((await client.command('disconnect', 'session', 'window')).type, 'ack');
  assert.equal((client as any).process, undefined);
});

test('RDP cannot spawn a replacement controller while disposal is in progress', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const internals = client as any;
  internals.disposing = new Promise<void>(() => undefined);

  await assert.rejects(internals.ensureProcess(), /backend is stopping/);
  assert.equal(internals.process, undefined);
});

test('concurrent RDP disconnect callers share one native cleanup command', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const internals = client as any;
  const commands: Array<Record<string, unknown>> = [];
  internals.sessionIds.add('session-1');
  internals.process = {
    killed: false,
    stdin: {
      writable: true,
      write(payload: string, callback: (error?: Error | null) => void) {
        commands.push(JSON.parse(payload) as Record<string, unknown>);
        callback();
        return true;
      },
    },
  };

  const first = client.command('disconnect', 'session-1', 'window');
  const second = client.command('disconnect', 'session-1', 'window');
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(commands.length, 1);
  internals.handleLine(
    JSON.stringify({
      type: 'ack',
      requestId: commands[0].requestId,
      sessionId: 'session-1',
    }),
  );

  assert.equal((await first).type, 'ack');
  assert.equal((await second).type, 'ack');
  assert.equal(internals.sessionIds.has('session-1'), false);
  assert.equal(internals.disconnects.size, 0);
});

test('RDP remembers pre-connect surface bounds without spawning the backend', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });

  const result = await client.resize(
    { sessionId: 'measured-session', bounds: { x: 12, y: 24, width: 900, height: 600 } },
    'window',
  );

  assert.equal(result.type, 'ack');
  assert.deepEqual((client as any).bounds.get('measured-session'), {
    x: 12,
    y: 24,
    width: 900,
    height: 600,
  });
  assert.equal((client as any).process, undefined);
});

test('RDP bounds are clamped before crossing the native controller boundary', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });

  await client.resize(
    {
      sessionId: 'bounded-session',
      bounds: { x: -9_000_000, y: 9_000_000, width: 99_999, height: -1 },
    },
    'window',
  );

  assert.deepEqual((client as any).bounds.get('bounded-session'), {
    x: -1_000_000,
    y: 1_000_000,
    width: 16_384,
    height: 1,
  });
});

test('RDP forwards newer bounds without waiting for an older native acknowledgement', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const commands: Array<Record<string, any>> = [];
  const internals = client as any;
  internals.sessionIds.add('live-session');
  internals.process = {
    killed: false,
    stdin: {
      writable: true,
      write(payload: string, callback: (error?: Error | null) => void) {
        commands.push(JSON.parse(payload) as Record<string, any>);
        callback();
        return true;
      },
    },
  };

  const first = client.resize(
    { sessionId: 'live-session', bounds: { x: 0, y: 0, width: 800, height: 600 } },
    'window',
  );
  const second = client.resize(
    { sessionId: 'live-session', bounds: { x: 0, y: 0, width: 900, height: 700 } },
    'window',
  );
  assert.equal(commands.length, 2);
  assert.deepEqual(commands[0].bounds, { x: 0, y: 0, width: 800, height: 600 });
  assert.deepEqual(commands[1].bounds, { x: 0, y: 0, width: 900, height: 700 });
  internals.handleLine(
    JSON.stringify({ type: 'ack', requestId: commands[0].requestId, sessionId: 'live-session' }),
  );
  internals.handleLine(
    JSON.stringify({ type: 'ack', requestId: commands[1].requestId, sessionId: 'live-session' }),
  );
  const responses = await Promise.all([first, second]);
  assert.deepEqual(
    responses.map((response) => response.type),
    ['ack', 'ack'],
  );
});

test('hideAll hides every started or measured RDP session', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const commands: Array<Record<string, unknown>> = [];
  const internals = client as any;
  internals.sessionIds.add('started-session');
  client.rememberBounds('measured-session', { x: 1, y: 2, width: 300, height: 200 });

  const fakeProcess = {
    killed: false,
    stdin: {
      writable: true,
      write(payload: string, callback: (error?: Error | null) => void) {
        const command = JSON.parse(payload) as Record<string, unknown>;
        commands.push(command);
        callback();
        queueMicrotask(() =>
          internals.handleLine(
            JSON.stringify({
              type: 'ack',
              requestId: command.requestId,
              sessionId: command.sessionId,
            }),
          ),
        );
        return true;
      },
    },
  };
  internals.process = fakeProcess;

  await client.hideAll('window-handle');

  assert.deepEqual(
    commands.map((command) => [command.op, command.sessionId, command.ownerWindow]),
    [
      ['hide', 'started-session', 'window-handle'],
      ['hide', 'measured-session', 'window-handle'],
    ],
  );
});

test('cancelPendingStarts disconnects only RDP handshakes still in progress', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const commands: Array<Record<string, unknown>> = [];
  const internals = client as any;
  const fakeProcess = {
    killed: false,
    stdin: {
      writable: true,
      write(payload: string, callback: (error?: Error | null) => void) {
        const command = JSON.parse(payload) as Record<string, unknown>;
        commands.push(command);
        callback();
        if (command.op === 'disconnect') {
          queueMicrotask(() =>
            internals.handleLine(
              JSON.stringify({
                type: 'ack',
                requestId: command.requestId,
                sessionId: command.sessionId,
              }),
            ),
          );
        }
        return true;
      },
    },
  };
  internals.process = fakeProcess;

  const pendingStart = (
    internals as { send(command: Record<string, unknown>): Promise<unknown> }
  ).send({ op: 'start', sessionId: 'pending-session' });
  internals.sessionIds.add('pending-session');
  internals.sessionIds.add('connected-session');

  client.cancelPendingStarts('window-handle');

  await assert.rejects(pendingStart, /cancelled while Wormhole locked/);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.deepEqual(
    commands.map((command) => [command.op, command.sessionId]),
    [
      ['start', 'pending-session'],
      ['disconnect', 'pending-session'],
    ],
  );
  assert.equal(internals.sessionIds.has('pending-session'), false);
  assert.equal(internals.sessionIds.has('connected-session'), true);
});

test('cancelling an older pending RDP start preserves its prepared replacement lifecycle', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const internals = client as any;
  const commands: Array<Record<string, unknown>> = [];
  const oldLifecycle = client.beginStart('shared-session');
  const fakeProcess = {
    killed: false,
    stdin: {
      writable: true,
      write(payload: string, callback: (error?: Error | null) => void) {
        const command = JSON.parse(payload) as Record<string, unknown>;
        commands.push(command);
        callback();
        if (command.op === 'disconnect') {
          queueMicrotask(() =>
            internals.handleLine(
              JSON.stringify({
                type: 'ack',
                requestId: command.requestId,
                sessionId: command.sessionId,
                lifecycleId: command.lifecycleId,
              }),
            ),
          );
        }
        return true;
      },
    },
  };
  internals.process = fakeProcess;
  const oldStart = internals.send({
    op: 'start',
    sessionId: 'shared-session',
    lifecycleId: oldLifecycle,
  });
  const replacementLifecycle = client.beginStart('shared-session');

  client.cancelPendingStarts('window-handle');

  await assert.rejects(oldStart, /cancelled while Wormhole locked/);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(client.currentLifecycleId('shared-session'), replacementLifecycle);
  assert.deepEqual(
    commands.map((command) => [command.op, command.lifecycleId]),
    [
      ['start', oldLifecycle],
      ['disconnect', oldLifecycle],
    ],
  );
});

test('targeted RDP disconnect cannot forget a newer lifecycle with the same session id', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const internals = client as any;
  const oldLifecycle = client.beginStart('retry-session');
  const replacementLifecycle = client.beginStart('retry-session');
  const commands: Array<Record<string, unknown>> = [];
  internals.process = { killed: false, stdin: { writable: true } };
  internals.send = async (command: Record<string, unknown>) => {
    commands.push(command);
    return { type: 'ack', sessionId: command.sessionId, lifecycleId: command.lifecycleId };
  };

  await client.command('disconnect', 'retry-session', 'window-handle', undefined, oldLifecycle);

  assert.equal(client.currentLifecycleId('retry-session'), replacementLifecycle);
  assert.deepEqual(
    commands.map((command) => command.lifecycleId),
    [oldLifecycle],
  );
});

test('RDP ignores events from a superseded backend process', () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const events: Array<Record<string, unknown>> = [];
  client.onEvent((event) => events.push(event as Record<string, unknown>));
  const internals = client as any;
  const staleProcess = {};
  const currentProcess = {};
  internals.process = currentProcess;

  internals.handleLineForProcess(
    staleProcess,
    JSON.stringify({ type: 'connected', sessionId: 'stale-session' }),
  );
  internals.handleLineForProcess(
    currentProcess,
    JSON.stringify({ type: 'connected', sessionId: 'current-session' }),
  );

  assert.deepEqual(events, [{ type: 'connected', sessionId: 'current-session' }]);
});

test('RDP ignores terminal events from a superseded lifecycle in the current controller', () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const events: Array<Record<string, unknown>> = [];
  client.onEvent((event) => events.push(event as Record<string, unknown>));
  const oldLifecycle = client.beginStart('retry-session');
  const newLifecycle = client.beginStart('retry-session');
  const internals = client as any;
  internals.sessionIds.add('retry-session');

  internals.handleLine(
    JSON.stringify({
      type: 'disconnected',
      sessionId: 'retry-session',
      lifecycleId: oldLifecycle,
    }),
  );
  assert.equal(internals.sessionIds.has('retry-session'), true);
  assert.equal(events.length, 0);

  internals.handleLine(
    JSON.stringify({
      type: 'connected',
      sessionId: 'retry-session',
      lifecycleId: newLifecycle,
    }),
  );
  assert.deepEqual(events, [
    { type: 'connected', sessionId: 'retry-session', lifecycleId: newLifecycle },
  ]);
});

test('terminal RDP lifecycle events make the tab immediately reconnectable', () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const internals = client as any;
  const lifecycleId = client.beginStart('session-1');
  internals.sessionIds.add('session-1');
  internals.lifecycleGenerations.set('session-1', 3);
  internals.bounds.set('session-1', { x: 1, y: 2, width: 800, height: 600 });

  internals.handleLine(
    JSON.stringify({
      type: 'disconnected',
      sessionId: 'session-1',
      lifecycleId,
      lifecycleGeneration: 3,
    }),
  );

  assert.equal(client.hasSession('session-1'), false);
  assert.equal(internals.lifecycleIds.has('session-1'), false);
  assert.equal(internals.lifecycleGenerations.has('session-1'), false);
  assert.equal(internals.bounds.has('session-1'), false);
});

test('RDP request responses retain their lifecycle generation', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const events: Array<Record<string, unknown>> = [];
  client.onEvent((event) => events.push(event as Record<string, unknown>));
  const internals = client as any;
  const lifecycleId = client.beginStart('session-1');
  let command: Record<string, unknown> | undefined;
  const fakeProcess = {
    stdin: {
      write(payload: string, callback: (error?: Error | null) => void) {
        command = JSON.parse(payload) as Record<string, unknown>;
        callback();
        return true;
      },
    },
  };

  const response = internals.sendToProcess(fakeProcess, {
    op: 'start',
    requestId: 'request-1',
    sessionId: 'session-1',
    lifecycleId,
    lifecycleGeneration: 7,
  });
  assert.ok(command);
  internals.handleLine(
    JSON.stringify({ type: 'started', requestId: 'request-1', sessionId: 'session-1' }),
  );

  assert.equal((await response).lifecycleId, lifecycleId);
  assert.equal((await response).lifecycleGeneration, 7);
  assert.equal(events[0].lifecycleId, lifecycleId);
  assert.equal(events[0].lifecycleGeneration, 7);
  assert.equal(client.hasSession('session-1'), true);
  assert.equal(internals.sessionIds.has('session-1'), true);
  assert.equal(internals.lifecycleGenerations.get('session-1'), 7);
});

test('a rejected duplicate start cannot replace the active lifecycle identity', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const internals = client as any;
  internals.sessionIds.add('session-1');
  internals.lifecycleGenerations.set('session-1', 4);
  const fakeProcess = {
    stdin: {
      write(_payload: string, callback: (error?: Error | null) => void) {
        callback();
        return true;
      },
    },
  };

  const response = internals.sendToProcess(fakeProcess, {
    op: 'start',
    requestId: 'duplicate',
    sessionId: 'session-1',
    lifecycleGeneration: 9,
  });
  internals.handleLine(
    JSON.stringify({
      type: 'error',
      requestId: 'duplicate',
      sessionId: 'session-1',
      message: 'already running',
    }),
  );

  await assert.rejects(response, /already running/);
  assert.equal(client.hasSession('session-1'), true);
  assert.equal(internals.sessionIds.has('session-1'), true);
  assert.equal(internals.lifecycleGenerations.get('session-1'), 4);
});

test('RDP controller failure terminates every tracked lifecycle exactly once', () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const internals = client as any;
  const process = {};
  internals.process = process;
  internals.sessionIds.add('first');
  // The second lifecycle is still connecting and has not received its native start ack.
  internals.bounds.set('first', { x: 0, y: 0, width: 800, height: 600 });
  internals.lifecycleIds.set('first', 'lifecycle-first');
  internals.lifecycleIds.set('second', 'lifecycle-second');
  internals.lifecycleGenerations.set('first', 4);
  internals.lifecycleGenerations.set('second', 9);
  const events: Array<Record<string, unknown>> = [];
  client.onEvent((event) => events.push(event as Record<string, unknown>));

  internals.handleProcessFailure(process, 'controller crashed');
  internals.handleProcessFailure(process, 'duplicate close event');

  assert.deepEqual(
    events.map((event) => [
      event.type,
      event.sessionId,
      event.lifecycleId,
      event.lifecycleGeneration,
      event.code,
    ]),
    [
      ['exited', 'first', 'lifecycle-first', 4, -1],
      ['exited', 'second', 'lifecycle-second', 9, -1],
    ],
  );
  assert.equal(internals.sessionIds.size, 0);
  assert.equal(internals.bounds.size, 0);
  assert.equal(internals.lifecycleIds.size, 0);
  assert.equal(internals.lifecycleGenerations.size, 0);
});

test('failed RDP start disconnects the native attempt before forgetting the session', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const internals = client as any;
  const commands: Array<Record<string, unknown>> = [];
  const fakeProcess = { killed: false, stdin: { writable: true } };
  internals.process = fakeProcess;
  internals.send = async () => Promise.reject(new Error('start timed out'));
  internals.sendToProcess = async (_child: unknown, command: Record<string, unknown>) => {
    commands.push(command);
    return { type: 'ack', sessionId: command.sessionId };
  };

  await assert.rejects(
    client.start({ sessionId: 'late-session', profile: { host: 'server.test' } }, 'window'),
    /start timed out/,
  );

  assert.deepEqual(
    commands.map((command) => [command.op, command.sessionId]),
    [['disconnect', 'late-session']],
  );
  assert.equal(internals.sessionIds.has('late-session'), false);
});

test('RDP tracks a connecting lifecycle generation before controller startup', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const internals = client as any;
  const lifecycleId = client.beginStart('connecting-session');
  const events: Array<Record<string, unknown>> = [];
  client.onEvent((event) => events.push(event as Record<string, unknown>));
  internals.ensureProcess = async () => {
    const process = { killed: false, kill() {} };
    internals.process = process;
    internals.handleProcessFailure(process, 'controller crashed');
    throw new Error('controller crashed');
  };

  await assert.rejects(
    client.start(
      { sessionId: 'connecting-session', profile: { host: 'server.test' } },
      'window',
      undefined,
      lifecycleId,
      12,
    ),
    /controller crashed/,
  );

  assert.deepEqual(events, [
    {
      type: 'exited',
      sessionId: 'connecting-session',
      lifecycleId,
      lifecycleGeneration: 12,
      code: -1,
      message: 'The RDP controller exited unexpectedly.',
    },
  ]);
  assert.equal(internals.lifecycleGenerations.has('connecting-session'), false);
});

test('RDP disposal emits terminal events and waits for graceful process exit', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const internals = client as any;
  const processEvents = new EventEmitter();
  const events: Array<Record<string, unknown>> = [];
  client.onEvent((event) => events.push(event as Record<string, unknown>));
  internals.sessionIds.add('vpn-session');
  let fakeProcess: any;
  fakeProcess = {
    killed: false,
    exitCode: null,
    signalCode: null,
    once: processEvents.once.bind(processEvents),
    removeListener: processEvents.removeListener.bind(processEvents),
    stdin: {
      writable: true,
      write(payload: string, callback: (error?: Error | null) => void) {
        const command = JSON.parse(payload) as Record<string, unknown>;
        callback();
        queueMicrotask(() =>
          internals.handleLineForProcess(
            fakeProcess,
            JSON.stringify({ type: 'ack', requestId: command.requestId }),
          ),
        );
        return true;
      },
      end() {
        fakeProcess.exitCode = 0;
        queueMicrotask(() => processEvents.emit('close'));
      },
    },
    kill() {
      fakeProcess.killed = true;
    },
  };
  internals.process = fakeProcess;

  let timeout: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      client.dispose(),
      new Promise<never>((_, reject) => {
        timeout = setTimeout(() => reject(new Error('RDP disposal timed out.')), 500);
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }

  assert.equal(fakeProcess.killed, false);
  assert.equal(internals.process, undefined);
  assert.deepEqual(
    events.filter((event) => event.type === 'exited'),
    [{ type: 'exited', sessionId: 'vpn-session' }],
  );
});

test('oversized RDP commands are rejected before touching the controller pipe', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const internals = client as any;
  let writes = 0;
  const process = {
    killed: false,
    stdin: {
      writable: true,
      write() {
        writes++;
        return true;
      },
    },
  };
  internals.process = process;

  await assert.rejects(
    internals.send({
      op: 'start',
      sessionId: 'oversized',
      profile: { host: 'server', password: 'x'.repeat(256 * 1024) },
    }),
    /too large/,
  );
  assert.equal(writes, 0);
  assert.equal(internals.pending.size, 0);
});

test('oversized RDP controller events fail closed before JSON parsing', () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const internals = client as any;
  let killed = false;
  const process = {
    killed: false,
    kill() {
      killed = true;
      process.killed = true;
    },
  };
  internals.process = process;
  internals.sessionIds.add('session-1');
  internals.lifecycleGenerations.set('session-1', 3);
  const events: Array<Record<string, unknown>> = [];
  client.onEvent((event) => events.push(event as Record<string, unknown>));

  internals.readOutputForProcess(process, 'x'.repeat(256 * 1024 + 1));

  assert.equal(killed, true);
  assert.equal(internals.process, undefined);
  assert.equal(internals.outputBuffer, '');
  assert.deepEqual(events, [
    {
      type: 'exited',
      sessionId: 'session-1',
      lifecycleGeneration: 3,
      code: -1,
      message: 'The RDP controller exited unexpectedly.',
    },
  ]);
});
