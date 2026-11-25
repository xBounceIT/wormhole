import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { Session } from 'node:inspector/promises';
import vm from 'node:vm';
import test, { before, after } from 'node:test';
import { TunnelLeaseRegistry, settleTunnelCleanup } from '../electron/tunnel-lease-registry.ts';
import { WebSessionAttemptTracker } from '../electron/web-session-attempt.ts';
import { KeyedSingleFlight } from '../electron/keyed-single-flight.ts';
import { assertTunnelRouteUnchanged } from '../electron/tunnel-route-snapshot.ts';
import { sshOpenCredentialFields } from '../electron/ssh-open-credentials.ts';
import {
  canProceedWithRdpTunnelRoute,
  rdpTunnelEnabledForNative,
  rdpGatewayCredentialIdForResolution,
  rdpGatewayUsername,
} from '../electron/rdp-contract.ts';

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
const authorizationSource = stripTypeScriptTypes(
  source.slice(
    source.indexOf('async function runAuthorizedOperation'),
    source.indexOf('function isAuthorizationEpochCurrent'),
  ),
);
const rdpLifecycleSource = stripTypeScriptTypes(
  source.slice(
    source.indexOf('async function releaseRdpTunnel('),
    source.indexOf('async function releaseAllRdpTunnels'),
  ),
);
const rdpSupport = new vm.Script(authorizationSource + '\n' + rdpLifecycleSource);
const routeHandlers = {
  ssh: new vm.Script(stripTypeScriptTypes(sshSource, { mode: 'transform' }), {
    filename: 'wormhole-route-ssh.js',
  }),
  rdp: new vm.Script(stripTypeScriptTypes(rdpSource, { mode: 'transform' }), {
    filename: 'wormhole-route-rdp.js',
  }),
};
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
      if (blocks.size === 0) continue;
      const percent =
        (100 * [...blocks.values()].filter((count) => count > 0).length) / blocks.size;
      console.log(`${name.toUpperCase()} route handlers: V8 block coverage ${percent.toFixed(2)}%`);
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

test('route snapshots preserve unchanged VPN/direct choices and reject missing or changed metadata', () => {
  for (const id of ['', 'vpn-a']) assert.doesNotThrow(() => assertTunnelRouteUnchanged(id, id));
  for (const [acquired, resolved] of [
    ['', 'vpn-a'],
    ['vpn-a', 'vpn-b'],
    ['vpn-a', ''],
    [undefined, ''],
    ['', undefined],
    [null, ''],
    [42, ''],
    ['', {}],
  ])
    assert.throws(() => assertTunnelRouteUnchanged(acquired, resolved), /VPN route.*matches/);
});

function harness(protocol: 'ssh' | 'rdp', extra: Record<string, any> = {}) {
  const trace: string[] = [];
  const attempts = new WebSessionAttemptTracker();
  attempts.begin('session');
  const leases = new TunnelLeaseRegistry();
  let sequence = 0;
  let lifecycleSequence = 0;
  const lifecycles = new Map<string, string>();
  const releasedLeases: string[] = [];
  let authorized = true;
  let onExit = () => {};
  const client = {
    hasSession: () => false,
    currentLifecycleId: (sessionId: string) => lifecycles.get(sessionId),
    beginStart: (sessionId: string) => {
      const lifecycleId = `lifecycle-${++lifecycleSequence}`;
      lifecycles.set(sessionId, lifecycleId);
      return lifecycleId;
    },
    command: async (
      _operation: string,
      _sessionId: string,
      _owner: string,
      _bounds: unknown,
      _lifecycleId?: string,
    ) => {
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
    acquireTunnelRoute: async (request: any) => {
      trace.push('route');
      onExit = request.onExit;
      return { active: true, socksEndpoint: '127.0.0.1:1080', configuredTunnelId: 'vpn-1' };
    },
  };
  const release = async (ownerId: string) =>
    leases.release(ownerId, async () => {
      trace.push('release');
    });
  let handler!: (event: any, request: any) => Promise<any>;
  const owner = { isDestroyed: () => false, webContents: { send: () => {} } };
  const sandbox: Record<string, any> = {
    reportWarning: () => {},
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
    rdpStartOperations: new KeyedSingleFlight<string>(),
    rdpStartAttempts: attempts,
    rdpSessionAttempts: new WebSessionAttemptTracker(),
    rdpConnectingLifecycles: new Map(),
    rdpTunnelLeaseSessions: new Map(),
    rdpTunnelLeases: leases,
    getRdpClient: () => client,
    rdpClient: client,
    authSession: {
      get isAccessAllowed() {
        return authorized;
      },
      authorizationEpoch: 1,
    },
    serializeAuthOperation: async (operation: () => Promise<unknown>) => operation(),
    requireWorkspaceAuth: async () => {
      if (!authorized) throw new Error('Authentication is required.');
    },
    requireAuthorizationEpoch: () => {
      if (!authorized) throw new Error('locked');
    },
    isAuthorizationEpochCurrent: () => authorized,
    nativeWindowHandle: () => 'window',
    currentRdpSurfaceScreenBounds: () => ({}),
    rememberRdpSurfacePlacement: () => {},
    toScreenBounds: () => ({}),
    releaseNativeTunnelLease: async (leaseId: string) => {
      trace.push('release');
      releasedLeases.push(leaseId);
    },
    settleTunnelCleanup,
    canProceedWithRdpTunnelRoute,
    rdpTunnelEnabledForNative,
    rdpGatewayCredentialIdForResolution,
    rdpGatewayUsername,
    getNativeBackend: () => backend,
    randomUUID: () => `lease-${++sequence}`,
    tunnelClosedMessage: 'VPN closed',
    sshOpenCredentialFields,
    assertTunnelRouteUnchanged,
    Error,
    console,
    clearTimeout,
    runBitwardenBackend: async () => {
      trace.push('credentials');
      return { bitwarden: false };
    },
    resolveNativeRdpProfile: async () => {
      trace.push('credentials');
      return { nodeId: 'node', host: 'host', tunnelEnabled: true, tunnelConfigId: 'vpn-1' };
    },
    resolveRdpExternalClientRequirement: async () => false,
    resolveNativeRdpCredential: async () => {
      trace.push('credentials');
      return { username: 'user', password: 'secret', domain: 'domain' };
    },
    ...extra,
  };
  const context = vm.createContext(sandbox);
  if (protocol === 'rdp') rdpSupport.runInContext(context);
  routeHandlers[protocol].runInContext(context);
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
    releasedLeases,
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
    h.backend.acquireTunnelRoute = async () => {
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
    route.resolve({ active: true, socksEndpoint: '127.0.0.1:1080', configuredTunnelId: 'vpn-1' });
    await tick();
    assert.ok(h.trace.includes('credentials'));
    assert.ok(!h.trace.includes('connect'));
    credentials.resolve(
      protocol === 'ssh'
        ? { bitwarden: false }
        : { nodeId: 'node', tunnelEnabled: true, tunnelConfigId: 'vpn-1' },
    );
    await pending;
    assert.ok(h.trace.includes('connect'));

    const cancelled = harness(protocol);
    cancelled.backend.acquireTunnelRoute = async () => {
      throw new Error('Connection cancelled');
    };
    await assert.rejects(cancelled.open(), /cancelled/);
    assert.ok(!cancelled.trace.includes('credentials'));
    assert.ok(cancelled.trace.includes('release'));

    const locked = harness(protocol);
    locked.backend.acquireTunnelRoute = async () => {
      locked.lock();
      return { active: true, socksEndpoint: '127.0.0.1:1080', configuredTunnelId: 'vpn-1' };
    };
    await assert.rejects(locked.open(), /locked|Authentication is required/);
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
    h.backend.acquireTunnelRoute = async () => ({
      active: false,
      socksEndpoint: '',
      configuredTunnelId: '',
    });
    if (saved) await h.open();
    else await assert.rejects(h.open({ tunnelConfigId: 'vpn' }), /no SOCKS endpoint/);
  }
  const stale = harness('ssh');
  await assert.rejects(stale.ssh.openCurrent({ sessionId: 'session' }, 1, -1), /closed before/);
  const lost = harness('ssh');
  lost.backend.acquireTunnelRoute = async () => {
    lost.attempts.cancel('session');
    return { active: true, socksEndpoint: 'endpoint', configuredTunnelId: 'vpn-1' };
  };
  await assert.rejects(lost.open(), /closed while/);
  const failed = harness('ssh');
  failed.ssh.ensureStarted = () => {
    throw new Error('service unavailable');
  };
  await assert.rejects(failed.open(), /service unavailable/);
  assert.ok(failed.trace.includes('release'));
});

test('SSH forwards the acquired saved-route snapshot after a pending vault lookup', async () => {
  for (const mode of ['terminal', 'sftp', 'smb']) {
    for (const route of [
      { active: false, socksEndpoint: '', configuredTunnelId: '' },
      { active: false, socksEndpoint: '', configuredTunnelId: 'vpn-old' },
      { active: true, socksEndpoint: '127.0.0.1:1080', configuredTunnelId: 'vpn-old' },
    ]) {
      const h = harness('ssh');
      const credentials = deferred<any>();
      h.backend.acquireTunnelRoute = async () => route;
      h.sandbox.runBitwardenBackend = () => credentials.promise;
      let command: any;
      h.ssh.write = (request: any) => {
        command = request;
      };
      const pending = h.open({ nodeId: 'node', mode });
      await tick();
      assert.equal(command, undefined);
      credentials.resolve({ bitwarden: false });
      await pending;
      assert.equal(command.configured_tunnel_id, route.configuredTunnelId);
      assert.equal(command.socks_endpoint, route.socksEndpoint);
      assert.equal(command.tunnel_enabled, route.socksEndpoint ? undefined : false);
    }
  }
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
    const stoppedTerminalStreams: string[] = [];
    h.ssh.terminalDelivery.remove = (sessionId: string) => stoppedTerminalStreams.push(sessionId);
    await h.ssh.close('session');
    assert.equal(rejected, true);
    assert.deepEqual(stoppedTerminalStreams, ['session']);
    if (failure !== 'pipe') assert.ok(h.trace.includes('close'));
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
  direct.backend.acquireTunnelRoute = async () => ({
    active: false,
    socksEndpoint: '',
    configuredTunnelId: 'vpn-1',
  });
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
  const finishStart = deferred<void>();
  active.client.start = async (request: any) => {
    assert.ok(!active.trace.includes('connect'), 'only one native start may proceed');
    active.trace.push('connect');
    await finishStart.promise;
    return request;
  };
  const starting = active.open();
  await tick();
  const pendingStart = [...active.trace];
  try {
    await assert.rejects(active.open(), /already starting/);
    assert.deepEqual(
      active.trace,
      pendingStart,
      'overlapping starts must leave the pending VPN alone',
    );
  } finally {
    finishStart.resolve(undefined);
    await starting;
  }
  active.client.hasSession = () => true;
  const acceptedStart = [...active.trace];
  await assert.rejects(active.open(), /already running/);
  assert.deepEqual(
    active.trace,
    acceptedStart,
    'duplicate opens must leave the active route alone',
  );
});

test('RDP tears down failed or superseded native starts and ignores retired tunnel callbacks', async () => {
  const unavailable = harness('rdp', { BrowserWindow: { fromWebContents: () => undefined } });
  await assert.rejects(unavailable.open(), /owner window/);
  const failed = harness('rdp');
  failed.client.start = async () => {
    throw new Error('native start failed');
  };
  await assert.rejects(failed.open({}, { bounds: {} }), /native start failed/);
  for (const tracker of ['rdpStartAttempts', 'rdpSessionAttempts']) {
    const superseded = harness('rdp');
    let acknowledgedAt = 0;
    superseded.client.start = async (request: any) => {
      acknowledgedAt = superseded.trace.length;
      superseded.sandbox[tracker].cancel('session');
      return request;
    };
    await assert.rejects(superseded.open(), /closed while/);
    const cleanup = superseded.trace.slice(acknowledgedAt);
    assert.equal(cleanup.filter((event) => event === 'disconnect').length, 1);
    assert.equal(cleanup.filter((event) => event === 'release').length, 1);
  }
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

test('retrying RDP retires the old native lifecycle and lease before acquiring the new route', async () => {
  const h = harness('rdp');
  const callbacks: Array<() => void> = [];
  const acquireRoute = h.backend.acquireTunnelRoute;
  h.backend.acquireTunnelRoute = (request) => {
    callbacks.push(request.onExit);
    return acquireRoute(request);
  };
  await h.open();
  const previousLifecycle = h.client.currentLifecycleId('session');
  await h.open(undefined, { sessionId: 'other-session' });
  assert.ok(previousLifecycle);

  const previousDisconnect = deferred<void>();
  const previousRelease = deferred<void>();
  const releaseNativeLease = h.sandbox.releaseNativeTunnelLease;
  h.sandbox.releaseNativeTunnelLease = async (leaseId: string) => {
    if (leaseId === 'lease-1') await previousRelease.promise;
    await releaseNativeLease(leaseId);
  };
  const nativeDisconnect = h.client.command;
  const disconnectedLifecycles: Array<string | undefined> = [];
  h.client.command = async (...args) => {
    disconnectedLifecycles.push(args[4]);
    await previousDisconnect.promise;
    await nativeDisconnect(...args);
  };
  const retry = h.open();
  try {
    await tick();
    assert.deepEqual(disconnectedLifecycles, [previousLifecycle]);
    assert.deepEqual(h.releasedLeases, []);
    assert.equal(callbacks.length, 2, 'a new route must wait for the old native disconnect');
    previousDisconnect.resolve(undefined);
    await tick();
    assert.equal(callbacks.length, 2, 'a new route must wait for the broker release');
  } finally {
    previousDisconnect.resolve(undefined);
    previousRelease.resolve(undefined);
    await retry;
  }

  assert.deepEqual(h.releasedLeases, ['lease-1']);
  assert.equal(callbacks.length, 3);
  assert.ok(h.trace.lastIndexOf('release') < h.trace.lastIndexOf('route'));
  const replacement = [...h.trace];
  callbacks[0]();
  await tick();
  assert.deepEqual(h.trace, replacement, 'the old VPN callback must leave the replacement alone');
  callbacks[2]();
  await tick();
  assert.deepEqual(h.releasedLeases, ['lease-1', 'lease-3']);
  assert.deepEqual(disconnectedLifecycles, [
    previousLifecycle,
    h.client.currentLifecycleId('session'),
  ]);
});

test('cancelling a pending RDP start releases its VPN before the profile resolves', async () => {
  const h = harness('rdp');
  const profile = deferred<{ nodeId: string; tunnelEnabled: true; tunnelConfigId: string }>();
  h.sandbox.resolveNativeRdpProfile = () => profile.promise;
  const rejected = assert.rejects(h.open(), /closed or superseded/);
  await tick();
  assert.ok(h.trace.includes('route'));
  try {
    h.sandbox.cancelPreparingRdpStarts();
    await tick();
    assert.equal(h.trace.filter((event) => event === 'release').length, 1);
  } finally {
    profile.resolve({ nodeId: 'node', tunnelEnabled: true, tunnelConfigId: 'vpn-1' });
  }
  await rejected;
  assert.ok(!h.trace.includes('connect'));
  assert.equal(h.trace.filter((event) => event === 'release').length, 1);
});

test('locking RDP during native startup retires the connection even after its window closes', async () => {
  let destroyed = false;
  const h = harness('rdp', {
    BrowserWindow: { fromWebContents: () => ({ isDestroyed: () => destroyed }) },
    nativeWindowHandle: () => {
      assert.equal(destroyed, false, 'cleanup must work without consulting a destroyed window');
      return 'window';
    },
  });
  let acknowledgedAt = 0;
  h.client.start = async (request: any) => {
    acknowledgedAt = h.trace.length;
    destroyed = true;
    h.lock();
    return request;
  };

  await assert.rejects(h.open(), /Authentication is required/);
  const cleanup = h.trace.slice(acknowledgedAt);
  assert.equal(cleanup.filter((event) => event === 'disconnect').length, 1);
  assert.equal(cleanup.filter((event) => event === 'release').length, 1);
});

test('Azure AD Quick Connect starts the system client without reading or forwarding passwords', async () => {
  const h = harness('rdp');
  const credentialId = 'azure-credential';
  h.sandbox.resolveRdpExternalClientRequirement = async (request: { credentialId: string }) =>
    request.credentialId === credentialId;

  const response = await h.open({
    credentialId,
    gatewayUsageMethod: 1,
    gatewayCredentialId: 'gateway-credential',
    password: 'inline-password',
    gatewayPassword: 'gateway-password',
  });

  assert.equal(response.profile.useExternalClient, true);
  assert.equal(response.profile.password, undefined);
  assert.equal(response.profile.gatewayPassword, undefined);
  assert.ok(!h.trace.includes('credentials'));
});

test('saved RDP profiles cannot change their required VPN while the route prompt is pending', async () => {
  for (const prior of [
    { configuredTunnelId: '', active: false, socksEndpoint: '' },
    { configuredTunnelId: 'vpn-old', active: false, socksEndpoint: '' },
    { configuredTunnelId: 'vpn-old', active: true, socksEndpoint: '127.0.0.1:1080' },
  ]) {
    const h = harness('rdp');
    const route = deferred<typeof prior>();
    h.backend.acquireTunnelRoute = async () => route.promise;
    const pending = h.open();
    const rejected = assert.rejects(pending, /VPN route.*(changed|matches)/);
    await tick();
    h.sandbox.resolveNativeRdpProfile = async () => ({
      nodeId: 'node',
      host: 'changed.internal',
      tunnelEnabled: true,
      tunnelConfigId: 'vpn-new',
    });
    route.resolve(prior);
    await rejected;
    assert.ok(!h.trace.includes('connect'));
    assert.ok(h.trace.includes('release'));
  }
});

test('disabled saved RDP routes stay direct and missing required configurations fail closed', async () => {
  const h = harness('rdp');
  h.backend.acquireTunnelRoute = async () => ({
    active: false,
    socksEndpoint: '',
    configuredTunnelId: '',
  });
  h.sandbox.resolveNativeRdpProfile = async () => ({
    nodeId: 'node',
    tunnelEnabled: false,
    tunnelConfigId: 'unused-vpn',
  });
  const target = await h.open();
  assert.equal(target.profile.tunnelEnabled, false);
  h.sandbox.resolveNativeRdpProfile = async () => ({ nodeId: 'node', tunnelEnabled: true });
  await assert.rejects(h.open(), /VPN route.*matches/);
});
