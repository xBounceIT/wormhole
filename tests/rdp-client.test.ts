import assert from 'node:assert/strict';
import test from 'node:test';
import { RdpBackendClient } from '../electron/rdp.ts';

test('RDP cleanup is a no-op when the backend is not running', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  await client.hideAll('window');
  assert.equal((await client.command('hide', 'session', 'window')).type, 'ack');
  assert.equal((await client.command('disconnect', 'session', 'window')).type, 'ack');
  assert.equal((client as any).process, undefined);
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

test('RDP disposal accepts the shutdown acknowledgement before releasing the process', async () => {
  const client = new RdpBackendClient({ executable: 'unused', args: [] });
  const internals = client as any;
  let fakeProcess: any;
  fakeProcess = {
    killed: false,
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

  assert.equal(fakeProcess.killed, true);
  assert.equal(internals.process, undefined);
});
