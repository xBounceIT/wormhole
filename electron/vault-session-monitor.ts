import { spawn, type ChildProcessByStdio } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';

type SessionMonitor = ChildProcessByStdio<Writable, Readable, null>;
type SleepHold = { retired: Promise<void>; release: () => void };
type SessionSource = { child: SessionMonitor; sleep?: SleepHold & { ticket: number } };

export function bindNativeVaultSession(
  platform: 'linux' | 'win32',
  executable: () => string,
  lock: () => void,
  options: { start?: (path: string) => SessionMonitor; beginSleep?: () => SleepHold } = {},
): () => void {
  const start =
    options.start ??
    ((path) =>
      spawn(path, ['--operation', 'vault-session-monitor'], {
        stdio: ['pipe', 'pipe', 'ignore'],
        windowsHide: true,
      }));
  let stopped = false;
  let subscribed = false;
  let current: SessionSource | undefined;
  let retry: ReturnType<typeof setTimeout> | undefined;

  function reconnect(delay: number): void {
    if (!stopped && (subscribed || platform === 'win32')) retry = setTimeout(connect, delay);
  }

  function connect(): void {
    if (stopped) return;
    let child: SessionMonitor;
    try {
      child = start(executable());
    } catch {
      reconnect(10000);
      return;
    }
    const source: SessionSource = { child };
    current = source;
    let ready = false;
    let lastTicket = 0;
    let frame = '';
    const ended = () => {
      if (current !== source) return;
      current = undefined;
      if (ready && !stopped) {
        // A previously active source can have missed a session transition.
        lock();
      }
      source.sleep?.release();
      reconnect(ready ? 2000 : 10000);
    };
    const handleFrame = () => {
      if (!ready) {
        if (frame !== 'ready') return false;
        ready = true;
        subscribed = true;
        return true;
      }
      if (frame === 'lock') {
        lock();
        return true;
      }
      if (platform !== 'linux' || !options.beginSleep) return false;
      const message = /^(sleep|resume) ([1-9][0-9]{0,9})$/.exec(frame);
      if (!message) return false;
      const [, action, value] = message;
      const ticket = Number(value);
      if (ticket > 0xffffffff) return false;
      if (action === 'resume') {
        if (source.sleep?.ticket !== ticket) return false;
        source.sleep.release();
        source.sleep = undefined;
        return true;
      }
      if (source.sleep || ticket <= lastTicket) return false;
      lastTicket = ticket;
      const hold = { ...options.beginSleep(), ticket };
      source.sleep = hold;
      void hold.retired
        .then(() => {
          if (
            !stopped &&
            current === source &&
            source.sleep === hold &&
            !child.stdin.destroyed &&
            !child.stdin.writableEnded
          ) {
            child.stdin.write(`ack ${ticket}\n`);
          }
        })
        .catch(() => {
          // Cleanup could not be confirmed. Let logind enforce its own deadline.
        });
      return true;
    };
    child.once('error', ended);
    child.once('close', ended);
    child.stdin.on('error', () => {});
    child.stdout.on('data', (chunk: Buffer) => {
      if (current !== source || stopped) return;
      for (const byte of chunk) {
        if (byte !== 10 && frame.length < (platform === 'linux' ? 17 : 5)) {
          frame += String.fromCharCode(byte);
          continue;
        }
        if (byte !== 10 || !handleFrame()) {
          child.kill();
          ended();
          return;
        }
        frame = '';
      }
    });
  }

  connect();
  return () => {
    stopped = true;
    if (retry !== undefined) clearTimeout(retry);
    // EOF retires the native subscriptions and ends the helper process.
    current?.child.stdin.end();
    current?.sleep?.release();
    current = undefined;
  };
}
