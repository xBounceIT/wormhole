import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { parseSshTerminalOutput, SshTerminalDelivery } from '../electron/ssh-terminal-stream.ts';

const wire = { session_id: 'session-1', data: 'eA==', sequence: 1 };

test('fatal input cleanup releases terminal ownership before forwarding the final error', () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const methodStart = source.indexOf('  private handleLine(line: string): void {');
  const bodyStart = source.indexOf('    const event = parseSshBackendEvent(line);', methodStart);
  const bodyEnd = source.indexOf('  private broadcast(event: SshBackendEvent): void {', bodyStart);
  assert.ok(methodStart > 0 && bodyStart > methodStart && bodyEnd > bodyStart);
  const Harness = new Function(
    'SshTerminalDelivery',
    'parseSshBackendEvent',
    stripTypeScriptTypes(`class Harness {
      terminalDelivery = new SshTerminalDelivery();
      terminalOwners = new Map([['session-1', {}]]);
      activeSessions = new Set(['session-1']);
      retainedMismatchSessions = new Set();
      openWaiters = new Map();
      events = []; releases = [];
      releaseTunnel(id) { this.releases.push(id); return Promise.resolve(); }
      broadcast(event) { this.events.push(event); }
      handleLine(line) { ${source.slice(bodyStart, bodyEnd)}
    }`) + '; return Harness;',
  )(SshTerminalDelivery, JSON.parse);
  const backend = new Harness();
  backend.terminalDelivery.receive(parseSshTerminalOutput(wire)!);
  backend.handleLine(JSON.stringify({ type: 'closed', sessionId: 'session-1' }));
  backend.handleLine(
    JSON.stringify({ type: 'error', sessionId: 'session-1', error: 'SSH input queue is full' }),
  );
  assert.equal(backend.activeSessions.has('session-1'), false);
  assert.equal(backend.terminalOwners.has('session-1'), false);
  assert.deepEqual(backend.terminalDelivery.pending(), []);
  assert.deepEqual(backend.releases, ['session-1', 'session-1']);
  assert.deepEqual(backend.events, [
    { type: 'closed', sessionId: 'session-1' },
    { type: 'error', sessionId: 'session-1', error: 'SSH input queue is full' },
  ]);
});

test('terminal stream validates bounded bytes, sequence, reset geometry and optional fields', () => {
  const output = parseSshTerminalOutput(wire)!;
  assert.equal(output.reset, false);
  assert.equal(output.columns, 0);
  assert.equal(parseSshTerminalOutput({ ...wire, reset: true, columns: 80, rows: 24 })?.rows, 24);
  assert.ok(parseSshTerminalOutput({ ...wire, data: '', reset: true, columns: 1, rows: 500 }));
  // Go's json omitempty omits data on an empty reset packet.
  assert.deepEqual(
    parseSshTerminalOutput({
      session_id: 'session-1',
      sequence: 2,
      reset: true,
      columns: 80,
      rows: 24,
    }),
    {
      type: 'terminal-output',
      sessionId: 'session-1',
      sequence: 2,
      data: '',
      reset: true,
      columns: 80,
      rows: 24,
    },
  );
  assert.ok(parseSshTerminalOutput({ ...wire, data: Buffer.alloc(16384).toString('base64') }));
  for (const invalid of [
    { session_id: '' },
    { session_id: 'x'.repeat(129) },
    { session_id: 1 },
    { data: 5 },
    { data: undefined },
    { data: null },
    { reset: true, columns: 80, rows: 24, data: null },
    { data: '***=' },
    { data: 'eA=' },
    { data: '====' },
    { data: Buffer.alloc(16385).toString('base64') },
    { sequence: 0 },
    { sequence: -1 },
    { sequence: 1.5 },
    { sequence: '1' },
    { sequence: Infinity },
    { reset: 1 },
    { columns: 1 },
    { rows: 1 },
    { reset: true },
    { reset: true, columns: 501, rows: 24 },
    { reset: true, columns: 80, rows: 0 },
    { reset: true, columns: 80, rows: 501 },
    { columns: '0' },
    { rows: '0' },
    { columns: 0.5 },
    { rows: 0.5 },
  ])
    assert.equal(
      parseSshTerminalOutput({ ...wire, ...invalid }),
      undefined,
      JSON.stringify(invalid),
    );
});

test('native delivery gates output and acknowledgments by authentication and window ownership', () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = source.indexOf('  private terminalDelivery = new SshTerminalDelivery();');
  const end = source.indexOf('  private ', source.indexOf('  private deliverTerminal', start) + 10);
  assert.ok(start > 0 && end > start);
  const auth = { isAccessAllowed: true };
  const sent: unknown[] = [],
    written: unknown[] = [];
  let destroyed = false,
    stopped = false;
  const owner = { isDestroyed: () => destroyed, send: (...args: unknown[]) => sent.push(args) };
  const Harness = new Function(
    'SshTerminalDelivery',
    'authSession',
    'write',
    stripTypeScriptTypes(
      `class Harness { ${source.slice(start, end)} write(command) { write(command); } }`,
    ) + '; return Harness;',
  )(SshTerminalDelivery, auth, (command: unknown) => {
    if (stopped) throw new Error('stopped');
    written.push(command);
  });
  const harness = new Harness();
  const packet = parseSshTerminalOutput(wire)!;
  harness.terminalDelivery.receive(packet);
  harness.deliverTerminal(packet);
  assert.deepEqual(sent, []);
  harness.terminalOwners.set('session-1', owner);
  auth.isAccessAllowed = false;
  harness.deliverTerminal(packet);
  harness.acknowledgeTerminal(owner, 'session-1', 1);
  assert.deepEqual(written, []);
  auth.isAccessAllowed = true;
  destroyed = true;
  harness.deliverTerminal(packet);
  assert.deepEqual(sent, []);
  destroyed = false;
  harness.deliverTerminal(packet);
  assert.equal(sent.length, 1);
  harness.acknowledgeTerminal({}, 'session-1', 1);
  assert.deepEqual(written, []);
  harness.acknowledgeTerminal(owner, 'session-1', 999);
  assert.deepEqual(written, []);
  harness.acknowledgeTerminal(owner, 'session-1', 1);
  harness.acknowledgeTerminal(owner, 'session-1', 1);
  assert.deepEqual(written, [{ type: 'terminal-ack', session_id: 'session-1', sequence: 1 }]);
  harness.terminalDelivery.receive({ ...packet, sequence: 2 });
  stopped = true;
  assert.doesNotThrow(() => harness.acknowledgeTerminal(owner, 'session-1', 2));
});

test('locked delivery retains exact packets, bounds queues, rejects duplicate acknowledgments and resets generations', () => {
  const delivery = new SshTerminalDelivery();
  for (let sequence = 1; sequence <= 16; sequence++) {
    assert.equal(delivery.receive(parseSshTerminalOutput({ ...wire, sequence })!), true);
  }
  assert.equal(delivery.pending().length, 16);
  assert.equal(delivery.receive(parseSshTerminalOutput({ ...wire, sequence: 17 })!), false);
  assert.equal(delivery.acknowledge('missing', 1), false);
  assert.equal(delivery.acknowledge('session-1', 999), false);
  assert.equal(delivery.acknowledge('session-1', 1), true);
  assert.equal(delivery.acknowledge('session-1', 1), false);
  assert.equal(delivery.receive(parseSshTerminalOutput({ ...wire, sequence: 2 })!), false);
  assert.equal(delivery.receive(parseSshTerminalOutput({ ...wire, sequence: 17 })!), true);
  assert.equal(
    delivery.receive(
      parseSshTerminalOutput({ ...wire, sequence: 18, reset: true, columns: 80, rows: 24 })!,
    ),
    true,
  );
  assert.deepEqual(
    delivery.pending().map((packet) => packet.sequence),
    [18],
  );
  assert.equal(delivery.acknowledge('session-1', 18), true);
  assert.deepEqual(delivery.pending(), []);
  delivery.receive(parseSshTerminalOutput(wire)!);
  delivery.remove('session-1');
  delivery.clear();
  assert.deepEqual(delivery.pending(), []);
});

test('a rejected duplicate SSH open cannot replace the terminal owner', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const methodsStart = source.indexOf('  private terminalDelivery = new SshTerminalDelivery();');
  const methodsEnd = source.indexOf('  private child:', methodsStart);
  const openStart = source.indexOf('  async open(', methodsStart);
  const openEnd = source.indexOf('  private async openCurrent(', openStart);
  assert.ok(methodsStart > 0 && methodsEnd > methodsStart && openStart > 0 && openEnd > openStart);
  const Harness = new Function(
    'SshTerminalDelivery',
    stripTypeScriptTypes(`class Harness {
      ${source.slice(methodsStart, methodsEnd)}
      pendingConnections = new Map(); openWaiters = new Map(); activeSessions = new Set();
      connectionAttempts = { begin: () => 1 };
      async openCurrent() { return {}; }
      ${source.slice(openStart, openEnd)}
    }`) + '; return Harness;',
  )(SshTerminalDelivery);
  const backend = new Harness();
  const handlers = new Map<string, (...args: unknown[]) => Promise<unknown>>();
  const ipcStart = source.indexOf("  ipcMain.handle('ssh:open',");
  const ipcEnd = source.indexOf("  ipcMain.handle('ssh:trust-host-key',", ipcStart);
  new Function(
    'ipcMain',
    'sshBackend',
    'requireNativeResourcesRunning',
    'isSshOpenRequest',
    'runAuthorizedOperation',
    stripTypeScriptTypes(source.slice(ipcStart, ipcEnd)),
  )(
    {
      handle: (name: string, handler: (...args: unknown[]) => Promise<unknown>) =>
        handlers.set(name, handler),
    },
    backend,
    () => {},
    () => true,
    (operation: (epoch: number) => unknown) => operation(1),
  );
  const open = handlers.get('ssh:open')!;
  const owner = {},
    otherWindow = {};
  await open({ sender: owner }, { sessionId: 'session-1' });
  assert.equal(backend.terminalOwners.get('session-1'), owner);
  for (const busy of [backend.pendingConnections, backend.openWaiters, backend.activeSessions]) {
    if (busy instanceof Map) busy.set('session-1', 1);
    else busy.add('session-1');
    await assert.rejects(
      open({ sender: otherWindow }, { sessionId: 'session-1' }),
      /already in use/,
    );
    assert.equal(backend.terminalOwners.get('session-1'), owner);
    busy.delete('session-1');
  }
});
