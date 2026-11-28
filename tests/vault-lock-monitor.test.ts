import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import type { ChildProcessByStdio } from 'node:child_process';
import { PassThrough, type Readable, type Writable } from 'node:stream';
import test, { type TestContext } from 'node:test';
import { bindNativeVaultSession } from '../electron/vault-session-monitor.ts';
import { VaultLockMonitor, bindVaultPowerEvents } from '../electron/vault-lock-monitor.ts';
import type { VaultSecurity, VaultProfile } from '../electron/vault-security.ts';

class SessionMonitorFixture extends EventEmitter {
  readonly stdin = new PassThrough();
  readonly stdout = new PassThrough();
  killed = false;

  kill() {
    this.killed = true;
  }
}

test('Linux native lock notifications authenticate monitor readiness and survive a restart', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const children: SessionMonitorFixture[] = [];
  let locks = 0;
  const dispose = bindNativeVaultSession(
    'linux',
    () => 'native-backend',
    () => locks++,
    {
      start: (path) => {
        assert.equal(path, 'native-backend');
        const child = new SessionMonitorFixture();
        children.push(child);
        return child as unknown as ChildProcessByStdio<Writable, Readable, null>;
      },
    },
  );
  t.after(dispose);
  const first = children[0];
  first.stdout.write('rea');
  first.stdout.write('dy\nlo');
  assert.equal(locks, 0);
  first.stdout.write('ck\nlock\n');
  assert.equal(locks, 2);
  first.emit('error', new Error('monitor lost'));
  first.emit('close');
  assert.equal(locks, 3);
  t.mock.timers.tick(1999);
  assert.equal(children.length, 1);
  t.mock.timers.tick(1);
  assert.equal(children.length, 2);
  first.stdout.write('lock\n');
  assert.equal(locks, 3);
  const second = children[1];
  second.emit('close');
  t.mock.timers.tick(9999);
  assert.equal(children.length, 2);
  t.mock.timers.tick(1);
  assert.equal(children.length, 3);
  assert.equal(locks, 3);
  const recovered = children[2];
  recovered.stdout.write('ready\nlock\n');
  assert.equal(locks, 4);
  dispose();
  assert.equal(recovered.stdin.writableEnded, true);
  recovered.emit('close');
  t.mock.timers.tick(2000);
  assert.equal(children.length, 3);
  assert.equal(locks, 4);
});

test('Linux session monitor caps frames and retires a malformed active source', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  for (const ready of [false, true]) {
    const child = new SessionMonitorFixture();
    let locks = 0;
    const dispose = bindNativeVaultSession(
      'linux',
      () => 'native-backend',
      () => locks++,
      { start: () => child as unknown as ChildProcessByStdio<Writable, Readable, null> },
    );
    try {
      if (ready) child.stdout.write('ready\n');
      child.stdout.write(Buffer.alloc(4096, 'x'));
      child.emit('close');
      assert.equal(child.killed, true);
      assert.equal(locks, ready ? 1 : 0);
    } finally {
      dispose();
    }
  }
});

test('Linux session monitor can coexist with missing native services at startup', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let locks = 0;
  let starts = 0;
  const monitor = new SessionMonitorFixture();
  const dispose = bindNativeVaultSession(
    'linux',
    () => 'native-backend',
    () => locks++,
    {
      start: () => {
        starts++;
        return monitor as unknown as ChildProcessByStdio<Writable, Readable, null>;
      },
    },
  );
  t.after(dispose);
  monitor.emit('close');
  t.mock.timers.tick(2000);
  assert.equal(starts, 1);
  assert.equal(locks, 0);
  assert.doesNotThrow(() =>
    bindNativeVaultSession(
      'linux',
      () => {
        throw Error('missing native component');
      },
      () => locks++,
    )(),
  );
});

test('Windows retries session registration when WTS is temporarily unavailable at startup', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const children: SessionMonitorFixture[] = [];
  let locks = 0;
  const dispose = bindNativeVaultSession(
    'win32',
    () => 'native-backend',
    () => locks++,
    {
      start: () => {
        const child = new SessionMonitorFixture();
        children.push(child);
        return child as unknown as ChildProcessByStdio<Writable, Readable, null>;
      },
    },
  );
  t.after(dispose);
  children[0].emit('close');
  assert.equal(locks, 0);
  t.mock.timers.tick(10000);
  assert.equal(children.length, 2);
  children[1].stdout.write('ready\nlock\n');
  assert.equal(locks, 1);
});

test('Linux suspend waits for confirmed retirement and keeps admission held until resume', async (t) => {
  const monitor = new SessionMonitorFixture();
  const acknowledgements: string[] = [];
  monitor.stdin.on('data', (data: Buffer) => acknowledgements.push(data.toString()));
  const retirements: Array<{ confirm: () => void; fail: (reason: Error) => void }> = [];
  let holds = 0;
  let locks = 0;
  const dispose = bindNativeVaultSession(
    'linux',
    () => 'native-backend',
    () => locks++,
    {
      start: () => monitor as unknown as ChildProcessByStdio<Writable, Readable, null>,
      beginSleep: () => {
        holds++;
        return {
          retired: new Promise<void>((confirm, fail) => retirements.push({ confirm, fail })),
          release: () => holds--,
        };
      },
    },
  );
  t.after(dispose);
  monitor.stdout.write('ready\nsle');
  monitor.stdout.write('ep 1\n');
  assert.equal(holds, 1);
  assert.deepEqual(acknowledgements, []);
  retirements[0].confirm();
  await flush();
  assert.deepEqual(acknowledgements, ['ack 1\n']);
  assert.equal(holds, 1);
  monitor.stdout.write('resume 1\nsleep 2\n');
  retirements[1].fail(new Error('vault shutdown unconfirmed'));
  await flush();
  assert.deepEqual(acknowledgements, ['ack 1\n']);
  assert.equal(holds, 1);
  monitor.stdout.write('resume 2\nsleep 3\nresume 3\nsleep 4\n');
  retirements[2].confirm();
  await flush();
  assert.deepEqual(acknowledgements, ['ack 1\n']);
  assert.equal(holds, 1);
  retirements[3].confirm();
  await flush();
  assert.deepEqual(acknowledgements, ['ack 1\n', 'ack 4\n']);
  assert.equal(locks, 0);
  dispose();
  assert.equal(holds, 0);
});

test('lost or out-of-order native sleep messages fail closed and cannot acknowledge a replacement', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const first = new SessionMonitorFixture();
  const second = new SessionMonitorFixture();
  const children = [first, second];
  let release = 0;
  let locks = 0;
  const acknowledgements: string[] = [];
  const confirm: Array<() => void> = [];
  for (const child of children) {
    child.stdin.on('data', (data: Buffer) => acknowledgements.push(data.toString()));
  }
  const dispose = bindNativeVaultSession(
    'linux',
    () => 'native-backend',
    () => locks++,
    {
      start: () => children.shift()! as unknown as ChildProcessByStdio<Writable, Readable, null>,
      beginSleep: () => ({
        retired: new Promise<void>((resolve) => confirm.push(resolve)),
        release: () => release++,
      }),
    },
  );
  t.after(dispose);
  first.stdout.write('ready\nsleep 1\nresume 2\n');
  assert.equal(first.killed, true);
  assert.equal(release, 1);
  assert.equal(locks, 1);
  t.mock.timers.tick(2000);
  second.stdout.write('ready\nsleep 4294967295\n');
  confirm[0]();
  await flush();
  assert.deepEqual(acknowledgements, []);
  confirm[1]();
  await flush();
  assert.deepEqual(acknowledgements, ['ack 4294967295\n']);
  second.emit('close');
  assert.equal(release, 2);
  assert.equal(locks, 2);
});

function profile(effective: VaultProfile = 'default', sequence = '1'): VaultSecurity {
  return {
    sequence,
    workspace: effective,
    user: 'default',
    os: 'default',
    effective,
    source: 'workspace',
  };
}
const flush = async () => {
  for (let i = 0; i < 6; i++) await Promise.resolve();
};
function fixture(
  t: TestContext,
  applyProfile?: (profile: VaultProfile) => void,
  profileChanged?: () => void,
) {
  t.mock.timers.enable({ apis: ['setInterval'] });
  let now = 0,
    idle = 0,
    state = 'active',
    locks = 0,
    reads = 0;
  let read = () => Promise.resolve(profile());
  let lock = () => Promise.resolve();
  const monitor = new VaultLockMonitor({
    applyProfile,
    profileChanged,
    now: () => now,
    idleSeconds: () => idle,
    idleState: () => state,
    security: () => {
      reads++;
      return read();
    },
    lock: () => {
      locks++;
      return lock();
    },
  });
  t.after(() => monitor.deactivate());
  return {
    monitor,
    get locks() {
      return locks;
    },
    get reads() {
      return reads;
    },
    idle: (v: number) => {
      idle = v;
    },
    state: (v: string) => {
      state = v;
    },
    read: (v: typeof read) => {
      read = v;
    },
    lock: (v: typeof lock) => {
      lock = v;
    },
    tick: async (milliseconds: number) => {
      now = milliseconds;
      t.mock.timers.tick(1000);
      await flush();
    },
  };
}

test('slot eligibility changes refresh settings without changing the signed policy sequence', async (t) => {
  let notices = 0;
  const f = fixture(t, undefined, () => notices++);
  f.monitor.activate(profile());
  await flush();
  f.read(async () => ({ ...profile(), canTightenToStandard: true }));
  await f.tick(1000);
  assert.equal(f.monitor.profileStatus?.canTightenToStandard, true);
  assert.equal(notices, 2);
  f.read(async () => profile());
  await f.tick(2000);
  assert.equal(f.monitor.profileStatus?.canTightenToStandard, undefined);
  assert.equal(notices, 3);
});

test('profile status reports the applied authority across refresh, relaxation and unlock', async (t) => {
  let notices = 0;
  const f = fixture(t, undefined, () => notices++);
  const read = (p: VaultSecurity) => f.read(async () => p);
  const base = profile();
  assert.equal(f.monitor.profileStatus, undefined);
  f.monitor.activate(base);
  await flush();
  assert.equal(notices, 1);
  assert.deepEqual(f.monitor.profileStatus, {
    effective: 'default',
    source: 'workspace',
    retainedUntilLock: false,
  });
  const user: VaultSecurity = {
    ...base,
    sequence: '2',
    effective: 'standard',
    user: 'standard',
    source: 'user',
  };
  read(user);
  await f.tick(1000);
  assert.deepEqual(f.monitor.profileStatus, {
    effective: 'standard',
    source: 'user',
    retainedUntilLock: false,
  });
  read({ ...user, os: 'standard', source: 'os' });
  await f.tick(2000);
  assert.deepEqual(f.monitor.profileStatus, {
    effective: 'standard',
    source: 'os',
    retainedUntilLock: false,
  });
  read({ ...profile('default', '3'), canTightenToStandard: true });
  await f.tick(3000);
  assert.deepEqual(f.monitor.profileStatus, {
    effective: 'standard',
    source: 'os',
    retainedUntilLock: true,
  });
  await f.tick(4000);
  assert.equal(notices, 4);
  read({
    ...user,
    sequence: '4',
    user: 'default',
    os: 'default',
    source: 'os',
    retainedUntilLock: true,
  });
  await f.tick(5000);
  assert.deepEqual(f.monitor.profileStatus, {
    effective: 'standard',
    source: 'os',
    retainedUntilLock: true,
  });
  read({ ...user, sequence: '4', user: 'default', os: 'standard', source: 'os' });
  await f.tick(6000);
  assert.deepEqual(f.monitor.profileStatus, {
    effective: 'standard',
    source: 'os',
    retainedUntilLock: false,
  });
  assert.equal(notices, 6);
  f.monitor.deactivate();
  assert.equal(f.monitor.profileStatus, undefined);
  assert.equal(notices, 7);
  f.monitor.activate(profile('default', '3'));
  assert.deepEqual(f.monitor.profileStatus, {
    effective: 'default',
    source: 'workspace',
    retainedUntilLock: false,
  });
});

test('window policy must activate synchronously and a failed tightening locks the vault', async (t) => {
  const applied: VaultProfile[] = [];
  const f = fixture(t, (effective) => {
    applied.push(effective);
    if (effective === 'paranoid') throw Error('Content protection unavailable.');
  });
  assert.throws(() => f.monitor.activate(profile('paranoid')), /Content protection unavailable/);
  assert.equal(f.monitor.active, false);
  assert.equal(f.reads, 0);
  f.read(async () => profile('hardened', '2'));
  f.monitor.activate(profile());
  await flush();
  assert.deepEqual(applied, ['paranoid', 'default', 'hardened']);
  assert.equal(f.monitor.effectiveProfile, 'hardened');
  f.read(async () => profile('standard', '3'));
  await f.tick(1000);
  assert.deepEqual(applied, ['paranoid', 'default', 'hardened']);
  f.read(async () => profile('paranoid', '4'));
  await f.tick(2000);
  assert.deepEqual(applied, ['paranoid', 'default', 'hardened', 'paranoid']);
  assert.equal(f.monitor.active, false);
  assert.equal(f.locks, 1);
});

test('an unavailable settings listener cannot interrupt a vault lock', async (t) => {
  const f = fixture(t, undefined, () => {
    throw Error('window closed');
  });
  f.monitor.activate(profile());
  f.state('locked');
  await f.tick(1000);
  assert.equal(f.locks, 1);
  assert.equal(f.monitor.profileStatus, undefined);
});

test('vault idle limits use system-wide activity and a fresh unlock grace period', async (t) => {
  const f = fixture(t);
  for (const [name, limit] of [
    ['default', 900],
    ['standard', 900],
    ['hardened', 300],
    ['paranoid', 120],
  ] as const) {
    f.read(() => Promise.resolve(profile(name)));
    f.monitor.activate(profile(name));
    await flush();
    f.idle(0);
    const origin = 2_000_000 * (['default', 'standard', 'hardened', 'paranoid'].indexOf(name) + 1);
    await f.tick(origin);
    assert.equal(f.monitor.active, true, 'activity in another app keeps vault alive');
    f.idle(limit - 1);
    await f.tick(origin + 1000);
    assert.equal(f.monitor.active, true);
    f.idle(limit);
    await f.tick(origin + 2000);
    assert.equal(f.monitor.active, false);
  }
  assert.equal(f.locks, 4);
  f.idle(5000);
  f.read(() => Promise.resolve(profile()));
  f.monitor.activate(profile());
  await f.tick(8_002_001);
  assert.equal(
    f.monitor.active,
    true,
    'biometric unlock resets idle age without keyboard activity',
  );
  await f.tick(8_902_000);
  assert.equal(f.locks, 5);
});

test('pending policy requests never suspend idle enforcement or overlap reads', async (t) => {
  const f = fixture(t);
  f.read(() => new Promise(() => {}));
  f.monitor.activate(profile());
  await f.tick(1000);
  assert.equal(f.reads, 1);
  f.idle(900);
  await f.tick(900_000);
  assert.equal(f.locks, 1);
  assert.equal(f.monitor.active, false);
  await f.tick(901_000);
  assert.equal(f.locks, 1);
});

test('invalid OS samples fail closed and immediate failures cannot acknowledge activation', async (t) => {
  const f = fixture(t);
  for (const value of [-1, 0.5, NaN, Infinity]) {
    f.idle(value);
    assert.throws(() => f.monitor.activate(profile()), /unavailable/);
    await flush();
  }
  f.idle(0);
  for (const state of ['unknown', '', 'locked']) {
    f.state(state);
    assert.throws(() => f.monitor.activate(profile()), /unavailable/);
    await flush();
  }
  f.state('active');
  f.monitor.activate(profile());
  await f.tick(-1);
  assert.equal(f.locks, 8);
  assert.throws(() => f.monitor.activate(null as never));
  for (const intervalMs of [0, -1, NaN, 1001, 0.5])
    assert.throws(
      () =>
        new VaultLockMonitor({
          idleSeconds: () => 0,
          idleState: () => 'active',
          security: async () => profile(),
          lock: async () => {},
          intervalMs,
        }),
    );
});

test('policy authentication failures and sequence regressions retire the owner', async (t) => {
  const f = fixture(t);
  for (const read of [
    () => Promise.reject(Error('unavailable')),
    () => {
      throw Error('unavailable');
    },
    () => Promise.resolve(null as never),
    () => Promise.resolve(profile('default', '1')),
    () => Promise.resolve(profile('standard', '2')),
  ]) {
    f.read(read);
    try {
      f.monitor.activate(profile('default', '2'));
    } catch {
      /* synchronous read fails closed */
    }
    await flush();
    assert.equal(f.monitor.active, false);
  }
  assert.equal(f.locks, 5);
});

test('late policy completions cannot affect a replacement generation', async (t) => {
  const f = fixture(t);
  for (const reject of [false, true]) {
    let finish!: () => void;
    f.read(
      () =>
        new Promise((resolve, fail) => {
          finish = () => (reject ? fail(Error('old')) : resolve(profile('paranoid')));
        }),
    );
    f.monitor.activate(profile());
    f.monitor.deactivate();
    f.read(() => Promise.resolve(profile()));
    f.monitor.activate(profile());
    await flush();
    finish();
    await flush();
    f.monitor.minimized();
    assert.equal(f.monitor.active, true);
    f.monitor.deactivate();
  }
  assert.equal(f.locks, 0);
});

test('stronger policy is enforced and lowering it cannot extend an unlocked session', async (t) => {
  const f = fixture(t);
  f.read(() => Promise.resolve(profile('paranoid', '2')));
  f.monitor.activate(profile());
  await flush();
  f.read(() => Promise.resolve(profile('default', '3')));
  await f.tick(1000);
  f.idle(120);
  await f.tick(120_000);
  assert.equal(f.locks, 1);
  f.monitor.activate(profile());
  await flush();
  f.monitor.minimized();
  assert.equal(f.monitor.active, true, 'new unlock may apply a relaxed policy');
  f.monitor.deactivate();
  f.monitor.activate(profile('hardened'));
  f.monitor.minimized();
  assert.equal(f.locks, 2);
});

test('retirement rejects synchronous reentry and keeps activation barred until lock settles', async (t) => {
  const f = fixture(t);
  let finish!: () => void;
  f.lock(() => {
    assert.throws(() => f.monitor.activate(profile()), /unavailable/);
    return new Promise<void>((resolve) => {
      finish = resolve;
    });
  });
  f.read(() => Promise.resolve(profile('hardened')));
  f.monitor.activate(profile('hardened'));
  f.monitor.minimized();
  assert.throws(() => f.monitor.activate(profile()), /unavailable/);
  f.monitor.minimized();
  assert.equal(f.locks, 1);
  finish();
  await flush();
  for (const lock of [
    () => Promise.reject(Error('exit unconfirmed')),
    () => {
      throw Error('exit unconfirmed');
    },
  ]) {
    f.lock(lock);
    f.monitor.activate(profile('hardened'));
    f.monitor.minimized();
    await flush();
    assert.equal(f.monitor.active, false);
  }
});

test('clock and native sampling exceptions fail closed', async () => {
  for (const failing of ['clock', 'idle', 'state', 'nan-clock'] as const) {
    let locks = 0;
    const monitor = new VaultLockMonitor({
      now: () => {
        if (failing === 'clock') throw Error('clock');
        return failing === 'nan-clock' ? NaN : 0;
      },
      idleSeconds: () => {
        if (failing === 'idle') throw Error('idle');
        return 0;
      },
      idleState: () => {
        if (failing === 'state') throw Error('state');
        return 'active';
      },
      security: async () => profile(),
      lock: async () => {
        locks++;
      },
      intervalMs: 1,
    });
    assert.throws(() => monitor.activate(profile()));
    assert.equal(monitor.active, false);
    assert.equal(locks, failing === 'idle' || failing === 'state' ? 1 : 0);
    monitor.deactivate();
  }
});

test('power event bindings lock on session transitions and dispose every listener', () => {
  const power = new EventEmitter();
  let locks = 0;
  const dispose = bindVaultPowerEvents(power, () => {
    locks++;
  });
  for (const event of ['lock-screen', 'suspend', 'resume', 'user-did-resign-active', 'shutdown'])
    power.emit(event);
  assert.equal(locks, 5);
  dispose();
  dispose();
  assert.deepEqual(power.eventNames(), []);
});
