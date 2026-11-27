import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { readFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { Session } from 'node:inspector';
import { parseSync } from 'vite';
import { stripTypeScriptTypes } from 'node:module';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { RdpBackendClient } from '../electron/rdp.ts';
const sourceText = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
const source = parseSync('main.ts', sourceText).program;
const builtinCoverage =
  !!process.env.NODE_V8_COVERAGE && process.env.WORMHOLE_PROCESS_OWNER_PROFILE_CHILD !== '1';
const session = new Session(),
  spans = new Map<string, { start: number; end: number }[]>();
const post = (method: string, params: Record<string, unknown> = {}) =>
  new Promise<any>((yes, no) =>
    session.post(method as any, params, (e, r) => (e ? no(e) : yes(r))),
  );
before(async () => {
  if (builtinCoverage) return;
  session.connect();
  await post('Profiler.enable');
  await post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
});
after(async () => {
  if (builtinCoverage) return;
  const data = await post('Profiler.takePreciseCoverage');
  for (const [url, ranges] of spans) {
    const scripts = data.result.filter((x: any) => x.url === url);
    assert.ok(scripts.length, 'missing native ownership profile');
    const merged = new Map<string, { count: number }>();
    for (const r of scripts.flatMap((s: any) => s.functions.flatMap((f: any) => f.ranges))) {
      if (!ranges.some((s) => r.startOffset >= s.start && r.endOffset <= s.end)) continue;
      const key = `${r.startOffset}:${r.endOffset}`;
      merged.set(key, { count: (merged.get(key)?.count ?? 0) + r.count });
    }
    const blocks = [...merged.values()];
    assert.ok(blocks.length > 0);
    const percentage = (100 * blocks.filter((b: any) => b.count > 0).length) / blocks.length;
    console.log(url + ' ' + percentage.toFixed(2) + '% V8 blocks');
    assert.ok(percentage >= 80, 'native owner shutdown coverage below80%');
  }
  await post('Profiler.stopPreciseCoverage');
  session.disconnect();
});
const tick = () => new Promise<void>((r) => setImmediate(r));
function loadOwner(
  name: string,
  methods: string[],
  measured: string[],
  globals: Record<string, unknown>,
) {
  const declaration = source.body.find(
    (n: any) => n.type === 'ClassDeclaration' && n.id?.name === name,
  ) as any;
  assert.ok(declaration);
  const selected = methods.map((name) => {
    const member = declaration.body.body.find(
      (m: any) => m.type === 'MethodDefinition' && m.key.name === name,
    );
    assert.ok(member);
    return sourceText.slice(member.start, member.end);
  });
  const js = stripTypeScriptTypes(
    'class Subject{' + selected.join('\n') + '}\nglobalThis.Subject=Subject;',
  );
  const parsed = parseSync('owner.js', js).program,
    klass = parsed.body.find((n: any) => n.type === 'ClassDeclaration') as any;
  const url = 'native-owner-' + name + '.js';
  spans.set(
    url,
    klass.body.body
      .filter((m: any) => m.type === 'MethodDefinition' && measured.includes(m.key.name))
      .map((m: any) => ({ start: m.start, end: m.end })),
  );
  const context = vm.createContext({ console, setTimeout, clearTimeout, ...globals });
  new vm.Script(js, { filename: url }).runInContext(context);
  return new context.Subject();
}
test('app service retains an unconfirmed process, blocks restart, coalesces stop and permits verified retry', async () => {
  let release!: (value: boolean) => void,
    calls = 0,
    mode = 'pending';
  const child = {};
  const owner = loadOwner('NativeBackendProcess', ['stop', 'start'], ['stop', 'start'], {
    stopChildProcess: async (c: unknown, options: any) => {
      assert.equal(c, child);
      assert.equal(options.nativeExecutable, '/native/backend');
      calls++;
      return mode === 'pending' ? new Promise<boolean>((r) => (release = r)) : true;
    },
    backendPath: () => '/native/backend',
    nativeBackendShutdownTimeoutMs: 1,
  });
  Object.assign(owner, { child, stopping: false, permanentlyStopped: false, rejectAll: () => {} });
  const first = owner.stop(),
    second = owner.stop();
  await tick();
  assert.equal(calls, 1);
  const rejections = [
    assert.rejects(first, /termination could not be confirmed/),
    assert.rejects(second, /termination could not be confirmed/),
  ];
  release(false);
  await Promise.all(rejections);
  assert.equal(owner.child, child);
  assert.equal(owner.stopping, true);
  await assert.rejects(owner.start(), /stopping/);
  mode = 'confirmed';
  await owner.stop();
  assert.equal(owner.child, undefined);
  assert.equal(owner.stopping, false);
  await owner.stop(true);
  await assert.rejects(owner.start(), /has stopped/);
});
test('SSH retains killed-but-unconfirmed ownership, drains output, awaits every cleanup and retries safely', async () => {
  let confirmed = false,
    stopCalls = 0,
    readerClosed = 0,
    released = 0,
    sealedClosed = 0;
  const child = { killed: true };
  const owner = loadOwner(
    'NativeSshBackend',
    ['dispose', 'disposeOwnedProcess', 'ensureStarted'],
    ['dispose', 'disposeOwnedProcess'],
    {
      stopChildProcess: async (c: unknown) => {
        assert.equal(c, child);
        stopCalls++;
        return confirmed;
      },
      backendPath: () => '/native/backend',
      mcpApprovalWindowCoordinator: { reset: () => {} },
      releaseNativeTunnelLease: () => {},
    },
  );
  Object.assign(owner, {
    child,
    sealed: {
      closeAll: async () => {
        sealedClosed++;
      },
    },
    terminalDelivery: new Map(),
    terminalOwners: new Map(),
    terminalAdmissions: new Map([['queued-session', {}]]),
    pendingConnections: new Map(),
    openWaiters: new Map(),
    failControlWaiters: () => {},
    activeSessions: new Set(),
    retainedMismatchSessions: new Set(),
    tunnelLeases: {
      releaseAll: async () => {
        released++;
      },
    },
    sharedRoutes: new Map(),
    lineReader: {
      close: () => {
        readerClosed++;
      },
    },
    shutdownUnconfirmed: false,
  });
  const first = owner.dispose(),
    second = owner.dispose();
  await Promise.all([
    assert.rejects(first, /termination could not be confirmed/),
    assert.rejects(second, /termination could not be confirmed/),
  ]);
  assert.equal(stopCalls, 1);
  assert.equal(owner.terminalAdmissions.size, 0, 'shutdown invalidates queued terminal admissions');
  assert.equal(readerClosed, 0);
  assert.equal(released, 1);
  assert.equal(sealedClosed, 1);
  assert.equal(owner.child, child);
  assert.equal(owner.shutdownUnconfirmed, true);
  assert.throws(() => owner.ensureStarted(), /unconfirmed/);
  confirmed = true;
  await owner.dispose();
  assert.equal(owner.child, undefined);
  assert.equal(readerClosed, 1);
  assert.equal(owner.shutdownUnconfirmed, false);
  await owner.dispose();
  assert.equal(stopCalls, 2);
});

test('post-spawn app service errors cannot forget a live process before confirmed cleanup', async () => {
  let confirmed = false;
  const child = Object.assign(new EventEmitter(), {
    pid: 123,
    stdin: new PassThrough(),
    stdout: new PassThrough(),
  });
  const owner = loadOwner('NativeBackendProcess', ['stop', 'start'], ['stop', 'start'], {
    spawn: () => child,
    backendPath: () => '/native/backend',
    wormholeDatabasePath: () => '/native/database',
    electronUserDataPath: () => '/native/data',
    nativeBackendShutdownTimeoutMs: 1,
    stopChildProcess: async () => confirmed,
  });
  Object.assign(owner, {
    rejectAll: () => {},
    stopping: false,
    permanentlyStopped: false,
    readOutput: () => {},
  });
  const starting = owner.start();
  child.emit('spawn');
  await starting;
  child.emit('error', Error('native error'));
  await tick();
  assert.equal(owner.child, child);
  assert.equal(owner.stopping, true);
  await assert.rejects(owner.start(), /stopping/);
  confirmed = true;
  await owner.stop();
  assert.equal(owner.child, undefined);
});
test('RDP keeps its process quarantined after failed disposal and allows a confirmed retry', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const owner = new RdpBackendClient({ executable: '/native/absent-backend', args: [] }) as any;
  const child = Object.assign(new EventEmitter(), {
    exitCode: null as number | null,
    signalCode: null,
    stdin: { end: () => {} },
    kill: () => false,
  });
  owner.process = child;
  owner.sendToProcess = async () => {};
  owner.handleProcessFailure(child, 'protocol failure');
  assert.equal(owner.process, child);
  assert.equal(owner.shutdownUnconfirmed, true);
  const failed = assert.rejects(owner.dispose(), /termination could not be confirmed/);
  await tick();
  t.mock.timers.tick(10001);
  await tick();
  t.mock.timers.tick(3001);
  await failed;
  assert.equal(owner.process, child);
  assert.equal(owner.shutdownUnconfirmed, true);
  await assert.rejects(owner.ensureProcess(), /unconfirmed/);
  child.exitCode = 0;
  await owner.dispose();
  assert.equal(owner.process, undefined);
  assert.equal(owner.shutdownUnconfirmed, false);
  await owner.dispose();
  assert.equal(owner.shutdownUnconfirmed, false);
  const killed = Object.assign(new EventEmitter(), {
    killed: true,
    exitCode: null,
    signalCode: null,
  });
  owner.process = killed;
  await assert.rejects(owner.ensureProcess(), /unconfirmed/);
  assert.equal(owner.process, killed);
  owner.handleProcessFailure(killed, 'not started', true);
  assert.equal(owner.process, undefined);
});

// Starting a second inspector profiler in Node's coverage worker resets its
// coverage collection. Measure the extracted main-process methods separately.
if (builtinCoverage) {
  test('native owner source coverage in an independent worker', async () => {
    const env = { ...process.env };
    delete env.NODE_V8_COVERAGE;
    delete env.NODE_TEST_CONTEXT;
    env.WORMHOLE_PROCESS_OWNER_PROFILE_CHILD = '1';
    const result = await promisify(execFile)(
      process.execPath,
      ['--experimental-strip-types', '--test', fileURLToPath(import.meta.url)],
      { env, timeout: 30_000, maxBuffer: 1024 * 1024, windowsHide: true },
    );
    assert.match(result.stdout, /native-owner-NativeBackendProcess.js [0-9.]+% V8 blocks/);
    assert.match(result.stdout, /native-owner-NativeSshBackend.js [0-9.]+% V8 blocks/);
  });
}

test('late native notifications and pipe errors cannot stop or corrupt a replacement app service', async () => {
  const makeChild = (pid: number) =>
    Object.assign(new EventEmitter(), {
      pid,
      stdin: new PassThrough(),
      stdout: new PassThrough(),
    });
  const old = makeChild(100),
    replacement = makeChild(101);
  let child = old,
    rejected = 0,
    reads = 0,
    stops = 0;
  const owner = loadOwner('NativeBackendProcess', ['stop', 'start'], ['stop', 'start'], {
    spawn: () => child,
    backendPath: () => '/native/backend',
    wormholeDatabasePath: () => '/native/database',
    electronUserDataPath: () => '/native/data',
    nativeBackendShutdownTimeoutMs: 1,
    stopChildProcess: async () => {
      stops++;
      return true;
    },
  });
  Object.assign(owner, {
    rejectAll: () => {
      rejected++;
    },
    readOutput: () => {
      reads++;
    },
  });
  const starting = owner.start();
  old.emit('spawn');
  await starting;
  await owner.stop();
  child = replacement;
  const restarting = owner.start();
  replacement.emit('spawn');
  await restarting;
  owner.outputBuffer = 'replacement response';
  const before = rejected;
  old.stdout.emit('data', 'old data');
  old.stdout.emit('error', Error('old output error'));
  old.stdin.emit('error', Error('old input error'));
  old.emit('error', Error('old process error'));
  old.emit('close', 0);
  await tick();
  assert.equal(owner.child, replacement);
  assert.equal(owner.outputBuffer, 'replacement response');
  assert.equal(rejected, before);
  assert.equal(reads, 0);
  assert.equal(stops, 1);
  replacement.stdout.emit('data', 'current data');
  assert.equal(reads, 1);
  await owner.stop();
});

test('app startup failures, current pipe errors and close events retain accurate ownership', async () => {
  for (const event of [
    'spawn-error',
    'early-close',
    'stdin-error',
    'stdout-error',
    'close-code',
    'close-null',
  ]) {
    const child = Object.assign(new EventEmitter(), {
      pid: event === 'spawn-error' ? undefined : 200,
      stdin: new PassThrough(),
      stdout: new PassThrough(),
    });
    let rejected = 0;
    const owner = loadOwner('NativeBackendProcess', ['stop', 'start'], ['stop', 'start'], {
      spawn: () => child,
      backendPath: () => '/native/backend',
      wormholeDatabasePath: () => '/native/database',
      electronUserDataPath: () => '/native/data',
      nativeBackendShutdownTimeoutMs: 1,
      stopChildProcess: async () => true,
    });
    Object.assign(owner, {
      rejectAll: () => {
        rejected++;
      },
      readOutput: () => {},
    });
    const starting = owner.start();
    if (event === 'spawn-error' || event === 'early-close') {
      const failure = assert.rejects(starting);
      if (event === 'spawn-error') child.emit('error', Error('spawn failed'));
      else child.emit('close', -1);
      await failure;
      assert.equal(owner.child, undefined);
    } else {
      child.emit('spawn');
      await starting;
      if (event === 'stdin-error') child.stdin.emit('error', Error('input failed'));
      else if (event === 'stdout-error') child.stdout.emit('error', Error('output failed'));
      else child.emit('close', event === 'close-null' ? null : 0);
      await tick();
      assert.equal(owner.child, event === 'stdin-error' ? child : undefined);
    }
    assert.ok(rejected > 0);
    await owner.stop();
  }
});
