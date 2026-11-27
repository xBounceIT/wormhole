import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext, createContext } from 'node:vm';
import { SshTerminalDelivery } from '../../electron/ssh-terminal-stream.ts';
import { SharedSshRoutes } from '../../electron/ssh-shared-route.ts';
import { TunnelLeaseRegistry } from '../../electron/tunnel-lease-registry.ts';
import { WebSessionAttemptTracker } from '../../electron/web-session-attempt.ts';
import { KeyedSingleFlight } from '../../electron/keyed-single-flight.ts';
import { resolveVaultSSHBitwarden } from '../../electron/vault-ssh-bitwarden.ts';
import { ipcRegistration } from './main-source.ts';

export const mainSshSource = readFileSync(
  new URL('../../electron/main.ts', import.meta.url),
  'utf8',
);
export function mainSshHarness(Sealed: any, backend: any, extra: Record<string, any> = {}) {
  let allowed = true,
    destroyed = false,
    url = 'file:///vault-main';
  const events: any[] = [],
    dialogs: any[] = [];
  const owner = Object.assign(new EventEmitter(), {
    isDestroyed: () => destroyed,
    getURL: () => url,
    send: (...event: any[]) => events.push(event),
  });
  const parent = { isDestroyed: () => destroyed, webContents: owner };
  const context: any = {
    Buffer,
    URL,
    Set,
    Map,
    AbortController,
    TextDecoder,
    TextEncoder,
    setTimeout,
    clearTimeout,
    console,
    SealedSshBackend: Sealed,
    resolveVaultSSHBitwarden,
    SealedRouteBroker: class {
      options: any;
      constructor(q: any) {
        this.options = q;
      }
    },
    vaultBackend: backend,
    vaultSshIpc: { isQuickTarget: () => false },
    vaultSshCredentialsDialog: { cancel: async () => {}, cancelSession: async () => {} },
    backendPath: () => '/backend',
    wormholeDatabasePath: () => '/database',
    electronUserDataPath: () => '/user-data',
    SshTerminalDelivery,
    SharedSshRoutes,
    TunnelLeaseRegistry,
    WebSessionAttemptTracker,
    KeyedSingleFlight,
    authSession: {
      authorizationEpoch: 4,
      get isAccessAllowed() {
        return allowed;
      },
      requireVerificationEpoch(epoch: number) {
        if (!allowed || epoch !== 4) throw Error('locked');
      },
    },
    isAuthorizationEpochCurrent: (epoch: number) => allowed && epoch === 4,
    requireAuthorizationEpoch: (epoch: number) => {
      if (!allowed || epoch !== 4) throw Error('locked');
    },
    isTrustedVaultSender: (event: any) => event.sender === owner && event.trusted !== false,
    BrowserWindow: {
      fromWebContents: (contents: any) => (contents === owner ? parent : undefined),
      getAllWindows: () => [parent],
    },
    windowCloseCoordinators: new WeakMap([[parent, true]]),
    parseMcpBackendMessage: () => undefined,
    parseSshBackendEvent: (line: string) => {
      const e = JSON.parse(line);
      return { ...e, sessionId: e.session_id ?? e.sessionId };
    },
    showCoordinatedMessageBox: async (_parent: any, q: any) => {
      dialogs.push(q);
      return { response: 1 };
    },
    vaultReauthenticationDialog: {
      open: async (_p: any, _accepted: any, _operation: any, _descriptor: any, submit: any) =>
        submit(),
    },
    mcpApprovalWindowCoordinator: { reset: () => [] },
    releaseNativeTunnelLease: async () => {},
    ...extra,
  };
  createContext(context);
  const code = mainSshSource.slice(
    mainSshSource.indexOf('class NativeSshBackend {'),
    mainSshSource.indexOf('function serializeAuthOperation'),
  );
  const Native = runInNewContext(stripTypeScriptTypes(code + '\nNativeSshBackend;'), context, {
    filename: 'wormhole-vault-ssh-main.js',
  });
  const native = new Native();
  context.sshBackend = native;
  return {
    native,
    context,
    owner,
    parent,
    events,
    dialogs,
    event: { sender: owner },
    setAllowed: (value: boolean) => {
      allowed = value;
    },
    setDestroyed: (value: boolean) => {
      destroyed = value;
    },
    setURL: (value: string) => {
      url = value;
    },
    register: (channels: string[]) => {
      const handlers = new Map<string, any>();
      context.ipcMain = { handle: (name: string, fn: any) => handlers.set(name, fn) };
      runInNewContext(
        stripTypeScriptTypes(
          channels.map((name) => ipcRegistration(mainSshSource, name)).join('\n'),
        ),
        context,
        { filename: 'wormhole-vault-ssh-handlers.js' },
      );
      return handlers;
    },
  };
}
