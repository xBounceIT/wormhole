import assert from 'node:assert/strict';
import test from 'node:test';
import {
  SerialBackendClient,
  isSerialInput,
  isSerialOpenRequest,
  isSerialSessionId,
} from '../electron/serial.ts';

test('serial open requests require one bounded local target', () => {
  assert.equal(
    isSerialOpenRequest({
      sessionId: 'serial-1',
      portName: 'COM10',
      settings: { baudRate: 115200, dataBits: 8, stopBits: 1, parity: 0, flowControl: 0 },
      columns: 80,
      rows: 24,
    }),
    true,
  );
  assert.equal(isSerialOpenRequest({ sessionId: 'serial-1', columns: 80, rows: 24 }), false);
  assert.equal(
    isSerialOpenRequest({
      sessionId: 'serial-1',
      portName: 'COM10',
      settings: { baudRate: 115200, dataBits: 9, stopBits: 1, parity: 0, flowControl: 0 },
      columns: 80,
      rows: 24,
    }),
    false,
  );
  assert.equal(
    isSerialOpenRequest({
      sessionId: ' serial-1 ',
      nodeId: 'node-1',
      columns: 80,
      rows: 24,
    }),
    false,
  );
});

test('serial session and input validators bound untrusted renderer data', () => {
  assert.equal(isSerialSessionId('serial-1'), true);
  assert.equal(isSerialSessionId(' serial-1'), false);
  assert.equal(isSerialSessionId('x'.repeat(129)), false);
  assert.equal(isSerialInput('A'.repeat(1_500_000)), true);
  assert.equal(isSerialInput('A'.repeat(1_500_001)), false);
});

test('serial backend client only broadcasts validated terminal events', () => {
  const client = new SerialBackendClient({ executable: 'unused', args: [] });
  const events: Array<Record<string, unknown>> = [];
  client.onEvent((event) => events.push(event as Record<string, unknown>));
  const internals = client as any;

  internals.handleLine(
    JSON.stringify({
      type: 'screen',
      session_id: 'serial-1',
      frame: {
        columns: 2,
        rows: 1,
        full: true,
        cells: [{ character: 'A', foreground: 7, background: 0 }],
        cursor_x: 0,
        cursor_y: 0,
        cursor_visible: true,
        application_cursor: false,
        sequence: 1,
      },
    }),
  );
  assert.equal(events.length, 0);

  internals.handleLine(
    JSON.stringify({
      type: 'screen',
      session_id: 'serial-1',
      frame: {
        columns: 2,
        rows: 1,
        full: true,
        cells: [
          { character: 'A', foreground: 7, background: 0 },
          { character: ' ', foreground: 7, background: 0 },
        ],
        cursor_x: 1,
        cursor_y: 0,
        cursor_visible: true,
        application_cursor: false,
        sequence: 1,
      },
    }),
  );

  assert.equal(events.length, 1);
  assert.deepEqual(events[0], {
    type: 'screen',
    sessionId: 'serial-1',
    frame: {
      columns: 2,
      rows: 1,
      full: true,
      cells: [
        { character: 'A', foreground: 7, background: 0 },
        { character: ' ', foreground: 7, background: 0 },
      ],
      changes: [],
      scrollbackReset: false,
      viewportReset: false,
      scrollback: undefined,
      cursorX: 1,
      cursorY: 0,
      cursorVisible: true,
      applicationCursor: false,
      title: undefined,
      sequence: 1,
    },
  });
});

test('serial backend lifecycle events maintain active session state', () => {
  const client = new SerialBackendClient({ executable: 'unused', args: [] });
  const internals = client as any;

  internals.handleLine(
    JSON.stringify({
      type: 'connected',
      session_id: 'serial-1',
      port_name: 'COM10',
      baud_rate: 9600,
      data_bits: 8,
      stop_bits: 1,
      parity: 0,
      flow_control: 0,
    }),
  );
  assert.equal(internals.activeSessions.has('serial-1'), true);

  internals.handleLine(JSON.stringify({ type: 'closed', session_id: 'serial-1' }));
  assert.equal(internals.activeSessions.has('serial-1'), false);
});
