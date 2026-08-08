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
