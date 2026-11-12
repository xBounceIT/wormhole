import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { Session } from 'node:inspector/promises';
import vm from 'node:vm';
import test, { before, after } from 'node:test';
import { TunnelLeaseRegistry, settleTunnelCleanup } from '../electron/tunnel-lease-registry.ts';
import { WebSessionAttemptTracker } from '../electron/web-session-attempt.ts';
import { KeyedSingleFlight } from '../electron/keyed-single-flight.ts';
import { sshOpenCredentialFields } from '../electron/ssh-open-credentials.ts';
import {
  canProceedWithRdpTunnelRoute,
  rdpTunnelEnabledForNative,
  rdpGatewayCredentialIdForResolution,
  rdpGatewayUsername,
} from '../electron/rdp-contract.ts';
import { coverageThreshold } from '../scripts/test-coverage.ts';

const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
const sshStart = source.indexOf('  private async openCurrent(');
const sshOpenStart = source.indexOf('  async open(', source.indexOf('class NativeSshBackend'));
const sshCloseStart = source.indexOf('  async close(sessionId: string): Promise<void> {', sshStart);
const sshCloseSource = source.slice(
  sshCloseStart,
  source.indexOf('  cancelPendingConnections()', sshCloseStart),
);
const sshSource = `class Backend { ${source.slice(sshOpenStart, source.indexOf('  async trustHostKey(', sshStart))} ${sshCloseSource} }; globalThis.Backend = Backend;`;
const rdpStart = source.indexOf("  ipcMain.handle('rdp:start'");
const rdpSource = source.slice(
  rdpStart,
  source.indexOf("  ipcMain.handle('rdp:system-client-capability'", rdpStart),
);
let profiler: Session | undefined;
before(async () => {
  if (process.execArgv.includes('--experimental-test-coverage') || process.env.NODE_V8_COVERAGE)
    return;
  profiler = new Session();
  profiler.connect();
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { detailed: true, callCount: true });
});
after(async () => {
  if (!profiler) return;
  try {
    const coverage = await profiler.post('Profiler.takePreciseCoverage');
    for (const name of ['ssh', 'rdp']) {
      const scripts = coverage.result.filter(
        (script) => script.url === `wormhole-route-${name}.js`,
      );
      const blocks = new Map<string, number>();
      for (const script of scripts) {
        for (const fn of script.functions) {
          for (const range of fn.ranges) {
            const key = `${range.startOffset}:${range.endOffset}`;
            blocks.set(key, (blocks.get(key) ?? 0) + range.count);
          }
        }
      }
      assert.ok(blocks.size > 0);
      const percent =
        (100 * [...blocks.values()].filter((count) => count > 0).length) / blocks.size;
      console.log(`${name.toUpperCase()} route handlers: V8 block coverage ${percent.toFixed(2)}%`);
      assert.ok(percent >= coverageThreshold);
    }
  } finally {
    await profiler.post('Profiler.stopPreciseCoverage');
    profiler.disconnect();
  }
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
const tick = () => new Promise<void>((resolve) => setImmediate(resolve));

function harness(protocol: 'ssh' | 'rdp', extra: Record<string, any> = {}) {
  const trace: string[] = [];
  const attempts = new WebSessionAttemptTracker();
  attempts.begin('session');
  const leases = new TunnelLeaseRegistry();
  let sequence = 0;
  let authorized = true;
  let onExit = () => {};
  const client = {
    hasSession: () => false,
    currentLifecycleId: () => undefined,
    beginStart: () => 'lifecycle',
    command: async () => {
      trace.push('disconnect');
    },
    cancelStart: () => {
      trace.push('cancel');
    },
    start: async (request: any) => {
      trace.push('connect');
      return request;
    },
  };
  const backend = {
    acquireTunnel: async (request: any) => {
      trace.push('route');
      onExit = request.onExit;
      return '127.0.0.1:1080';
    },
    acquireTunnelRoute: async (request: any) => {
      trace.push('route');
      onExit = request.onExit;
      return { active: true, socksEndpoint: '127.0.0.1:1080' };
    },
  };
  const release = async (ownerId: string) =>
    leases.release(ownerId, async () => {
      trace.push('release');
    });
  let handler!: (event: any, request: any) => Promise<any>;
  const owner = { isDestroyed: () => false, webContents: { send: () => {} } };
  const sandbox: Record<string, any> = {
    ipcMain: {
      handle: (_name: string, fn: typeof handler) => {
        handler = fn;
      },
    },
    BrowserWindow: { fromWebContents: () => owner },
    parseRdpStartRequest: (request: any) => request,
    requireNativeResourcesRunning: () => {},
    assertRdpSurfaceOwner: () => {},
    rdpSurfacePlacements: new Map(),
    rdpStartOperations: { runExclusive: (_key: string, fn: () => unknown) => fn() },
    rdpStartAttempts: attempts,
    rdpSessionAttempts: new WebSessionAttemptTracker(),
    rdpConnectingLifecycles: new Map(),
    rdpTunnelLeaseSessions: new Map(),
    rdpTunnelLeases: leases,
    getRdpClient: () => client,
    runAuthorizedOperation: async (fn: (epoch: number) => unknown, lost: () => Promise<void>) => {
      try {
        return await fn(1);
      } finally {
        if (!authorized) await lost();
      }
    },
    assertRdpStartCurrent: (_id: string, attempt: number) => {
      if (!attempts.isCurrent('session', attempt)) throw new Error('cancelled');
    },
    requireAuthorizationEpoch: () => {
      if (!authorized) throw new Error('locked');
    },
    isAuthorizationEpochCurrent: () => authorized,
    nativeWindowHandle: () => 'window',
    currentRdpSurfaceScreenBounds: () => ({}),
    rememberRdpSurfacePlacement: () => {},
    toScreenBounds: () => ({}),
    releaseRdpTunnelsForSession: async () => {},
    releaseRdpTunnel: release,
    settleTunnelCleanup,
    canProceedWithRdpTunnelRoute,
    rdpTunnelEnabledForNative,
    rdpGatewayCredentialIdForResolution,
    rdpGatewayUsername,
    getNativeBackend: () => backend,
    randomUUID: () => `lease-${++sequence}`,
    tunnelClosedMessage: 'VPN closed',
    sshOpenCredentialFields,
    Error,
    console,
    clearTimeout,
    runBitwardenBackend: async () => {
      trace.push('credentials');
      return { bitwarden: false };
    },
    resolveNativeRdpProfile: async () => {
      trace.push('credentials');
      return { nodeId: 'node', host: 'host' };
    },
    resolveRdpExternalClientRequirement: async () => false,
    resolveNativeRdpCredential: async () => {
      trace.push('credentials');
      return { username: 'user', password: 'secret', domain: 'domain' };
    },
    ...extra,
  };
  const context = vm.createContext(sandbox);
  vm.runInContext(
    stripTypeScriptTypes(protocol === 'ssh' ? sshSource : rdpSource, { mode: 'transform' }),
    context,
    { filename: `wormhole-route-${protocol}.js` },
  );
  const ssh =
    protocol === 'ssh'
      ? Object.assign(new context.Backend(), {
          connectionAttempts: attempts,
          tunnelLeases: leases,
          releaseTunnel: release,
          broadcast: () => {},
          finishEditClose: async () => {},
          terminalDelivery: { remove: () => {} },
          terminalOwners: new Map(),
          pendingConnections: new Map(),
          activeSessions: new Set(),
          closingConnections: new KeyedSingleFlight<string, void>(),
          openWaiters: new Map(),
          ensureStarted: () => {},
          waitForConnection: async (_id: string, start: () => void) => {
            start();
            return {};
          },
          write: (request: any) => {
            trace.push(request.type === 'open' ? 'connect' : request.type);
            return request;
          },
        })
      : undefined;
  const open = (profile: Record<string, any> = { nodeId: 'node' }, options = {}) =>
    protocol === 'ssh'
      ? ssh.open({ sessionId: 'session', ...profile, ...options }, 1, owner.webContents)
      : handler({ sender: {} }, { sessionId: 'session', profile, ...options });
  return {
    open,
    trace,
    backend,
    sandbox,
    client,
    ssh,
    leases,
    attempts,
    exit: () => onExit(),
    lock: () => {
      authorized = false;
    },
  };
}

for (const protocol of ['ssh', 'rdp'] as const) {
  test(`${protocol}: route selection precedes a slow credential lookup and cancellation skips it`, async () => {
    const h = harness(protocol);
    const route = deferred<any>();
    const credentials = deferred<any>();
    const acquire = protocol === 'ssh' ? 'acquireTunnel' : 'acquireTunnelRoute';
    h.backend[acquire] = async () => {
      h.trace.push('route');
      return route.promise;
    };
    h.sandbox[protocol === 'ssh' ? 'runBitwardenBackend' : 'resolveNativeRdpProfile'] =
      async () => {
        h.trace.push('credentials');
        return credentials.promise;
      };
    const pending = h.open();
    await tick();
    assert.ok(h.trace.includes('route'));
    assert.ok(!h.trace.includes('credentials'));
    route.resolve(
      protocol === 'ssh' ? '127.0.0.1:1080' : { active: true, socksEndpoint: '127.0.0.1:1080' },
    );
    await tick();
    assert.ok(h.trace.includes('credentials'));
    assert.ok(!h.trace.includes('connect'));
    credentials.resolve(protocol === 'ssh' ? { bitwarden: false } : { nodeId: 'node' });
    await pending;
    assert.ok(h.trace.includes('connect'));

    const cancelled = harness(protocol);
    cancelled.backend[acquire] = async () => {
      throw new Error('Connection cancelled');
    };
    await assert.rejects(cancelled.open(), /cancelled/);
    assert.ok(!cancelled.trace.includes('credentials'));
    assert.ok(cancelled.trace.includes('release'));

    const locked = harness(protocol);
    locked.backend[acquire] = async () => {
      locked.lock();
      return protocol === 'ssh'
        ? '127.0.0.1:1080'
        : { active: true, socksEndpoint: '127.0.0.1:1080' };
    };
    await assert.rejects(locked.open(), /locked/);
    assert.ok(!locked.trace.includes('credentials'));
    assert.ok(locked.trace.includes('release'));
  });

  test(`${protocol}: credential failures, lock and tunnel loss release the lease before connecting`, async () => {
    for (const failure of ['credentials', 'non-error', 'lock', 'close', 'tunnel']) {
      const h = harness(protocol);
      h.sandbox[protocol === 'ssh' ? 'runBitwardenBackend' : 'resolveNativeRdpProfile'] =
        async () => {
          if (failure === 'credentials') throw new Error('vault unavailable');
          if (failure === 'non-error') throw 'unavailable';
          if (failure === 'lock') h.lock();
          if (failure === 'close') h.attempts.cancel('session');
          if (failure === 'tunnel') h.exit();
          return protocol === 'ssh' ? { bitwarden: false } : { nodeId: 'node' };
        };
      await assert.rejects(h.open());
      assert.ok(h.trace.includes('release'), failure);
      assert.ok(!h.trace.includes('connect'), failure);
    }
  });
}

test('SSH keeps direct/manual connections and fails closed on missing or cancelled routes', async () => {
  await harness('ssh').open({}, { manualCredentials: true, username: 'user' });
  await harness('ssh').open({ credentialId: 'selected', mode: 'smb' });
  for (const saved of [true, false]) {
    const h = harness('ssh');
    h.backend.acquireTunnel = async () => '';
    if (saved) await h.open();
    else await assert.rejects(h.open({ tunnelConfigId: 'vpn' }), /no SOCKS endpoint/);
  }
  const stale = harness('ssh');
  await assert.rejects(stale.ssh.openCurrent({ sessionId: 'session' }, 1, -1), /closed before/);
  const lost = harness('ssh');
  lost.backend.acquireTunnel = async () => {
    lost.attempts.cancel('session');
    return 'endpoint';
  };
  await assert.rejects(lost.open(), /closed while/);
  const failed = harness('ssh');
  failed.ssh.ensureStarted = () => {
    throw new Error('service unavailable');
  };
  await assert.rejects(failed.open(), /service unavailable/);
  assert.ok(failed.trace.includes('release'));
});

test('SSH close and VPN failure invalidate pending credentials before slow journal cleanup', async () => {
  for (const failure of ['close', 'tunnel']) {
    const h = harness('ssh');
    const credentials = deferred<any>();
    const journal = deferred<void>();
    h.ssh.finishEditClose = () => journal.promise;
    h.sandbox.runBitwardenBackend = () => credentials.promise;
    const pending = h.open();
    await tick();
    const closing = failure === 'close' ? h.ssh.close('session') : (h.exit(), undefined);
    credentials.resolve({ bitwarden: false });
    try {
      await assert.rejects(pending, /closed/);
      assert.ok(!h.trace.includes('connect'));
    } finally {
      journal.resolve();
      await closing;
      await tick();
    }
    assert.ok(h.trace.includes('release'));
  }
});

test('SSH close cancels native work and releases its route even when journal or pipe cleanup fails', async () => {
  for (const failure of ['none', 'journal', 'pipe']) {
    const h = harness('ssh');
    await h.open();
    h.ssh.child = { killed: false };
    if (failure === 'journal')
      h.ssh.finishEditClose = async () => {
        throw new Error('journal unavailable');
      };
    if (failure === 'pipe')
      h.ssh.write = () => {
        throw new Error('pipe closed');
      };
    let rejected = false;
    h.ssh.openWaiters.set('session', {
      timeout: setTimeout(() => {}, 1000),
      reject: () => {
        rejected = true;
      },
    });
    await h.ssh.close('session');
    assert.equal(rejected, true);
    assert.equal(h.ssh.openWaiters.size, 0);
    assert.ok(h.trace.includes('release'));
  }
});

test('SSH retries wait for old cleanup and duplicate closes cannot tear down a replacement', async () => {
  const h = harness('ssh');
  const journal = deferred<void>();
  const credentials = deferred<any>();
  let journalCalls = 0;
  h.ssh.finishEditClose = () => {
    journalCalls++;
    return journal.promise;
  };
  h.sandbox.runBitwardenBackend = () => credentials.promise;
  const first = h.open();
  await tick();
  const closing = h.ssh.close('session');
  const duplicateClose = h.ssh.close('session');
  credentials.resolve({ bitwarden: false });
  await assert.rejects(first, /closed/);
  const retry = h.open();
  try {
    await tick();
    assert.ok(!h.trace.includes('connect'));
    assert.equal(journalCalls, 1);
  } finally {
    journal.resolve();
    await closing;
    await duplicateClose;
    await retry;
  }
  assert.ok(h.trace.includes('connect'));
  assert.equal(h.leases.has('session'), true);
  assert.equal(h.ssh.terminalOwners.size, 1);
});

test('SSH queued retries remain cancellable while the previous close is pending', async () => {
  const h = harness('ssh');
  const journal = deferred<void>();
  h.ssh.finishEditClose = () => journal.promise;
  const closing = h.ssh.close('session');
  const retry = h.open();
  const cancelled = assert.rejects(retry, /closed/);
  await tick();
  const secondClose = h.ssh.close('session');
  journal.resolve();
  await Promise.all([closing, secondClose, cancelled]);
  assert.ok(!h.trace.includes('route'));
  assert.ok(!h.trace.includes('connect'));
  assert.equal(h.ssh.terminalOwners.size, 0);
});

test('RDP preserves direct, manual, external-client and gateway credential flows after route selection', async () => {
  const direct = harness('rdp');
  direct.backend.acquireTunnelRoute = async () => ({ active: false, socksEndpoint: '' });
  const result = await direct.open();
  assert.equal(result.profile.tunnelEnabled, false);
  for (const profile of [
    {},
    { credentialId: 'selected' },
    { useExternalClient: true },
    { gatewayUsageMethod: 1, gatewayUseSameCreds: true, credentialId: 'selected' },
    { gatewayUsageMethod: 1, gatewayCredentialId: 'gateway' },
  ]) {
    const h = harness('rdp');
    await h.open(profile);
    assert.ok(h.trace.includes('connect'));
  }
  const manual = harness('rdp');
  await manual.open({ credentialId: 'ignored' }, { manualCredentials: true });
  assert.ok(!manual.trace.includes('credentials'));
  const gateway = harness('rdp');
  gateway.sandbox.resolveNativeRdpCredential = async () => {
    throw new Error('gateway locked');
  };
  await assert.rejects(
    gateway.open({ gatewayUsageMethod: 1, gatewayCredentialId: 'gateway' }),
    /Gateway credential/,
  );
  const invalid = harness('rdp');
  invalid.backend.acquireTunnelRoute = async () => ({ active: false, socksEndpoint: '' });
  await assert.rejects(invalid.open({ tunnelConfigId: 'vpn' }), /invalid route/);
  assert.ok(!invalid.trace.includes('credentials'));
  const active = harness('rdp');
  active.client.hasSession = () => true;
  await assert.rejects(active.open(), /already running/);
});

test('RDP tears down failed or superseded native starts and ignores retired tunnel callbacks', async () => {
  const unavailable = harness('rdp', { BrowserWindow: { fromWebContents: () => undefined } });
  await assert.rejects(unavailable.open(), /owner window/);
  const failed = harness('rdp');
  failed.client.start = async () => {
    throw new Error('native start failed');
  };
  await assert.rejects(failed.open({}, { bounds: {} }), /native start failed/);
  const superseded = harness('rdp');
  superseded.client.start = async (request: any) => {
    superseded.attempts.cancel('session');
    return request;
  };
  await assert.rejects(superseded.open(), /closed while/);
  assert.ok(superseded.trace.includes('release'));
  const retired = harness('rdp');
  await retired.open();
  retired.exit();
  await tick();
  assert.ok(retired.trace.includes('release'));
  const callbacks = retired.trace.length;
  retired.exit();
  assert.equal(retired.trace.length, callbacks);
  for (const error of [new Error('credential failed'), 'credential failed']) {
    const h = harness('rdp');
    h.sandbox.resolveNativeRdpCredential = async () => {
      throw error;
    };
    await assert.rejects(h.open({ credentialId: 'primary', tunnelConfigId: 'vpn' }));
    assert.ok(h.trace.includes('release'));
    assert.ok(!h.trace.includes('connect'));
    await assert.rejects(
      h.open({ gatewayUsageMethod: 1, gatewayCredentialId: 'gateway' }),
      /Gateway credential/,
    );
  }
});
