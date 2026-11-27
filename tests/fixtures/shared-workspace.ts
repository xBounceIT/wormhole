import { copyTextToClipboard } from '../../src/clipboard';
import { mountSharedWorkspace } from '../../src/vault-shared-workspace';
import { mountSharedStartup } from '../../src/vault-shared-startup';
import { mountSharedCatalogScreen } from '../../src/vault-shared-catalog-screen';
import type { SharedCatalogNode } from '../../electron/vault-shared-catalog';
import type { VaultProfileStatus } from '../../electron/vault-security';
import '../../src/startup.css';

const check = (ok: unknown, message: string) => {
  if (!ok) throw Error(message);
};
const tick = () => new Promise<void>((r) => setTimeout(r, 25));
async function until(run: () => boolean, label: string) {
  for (let i = 0; i < 100; i++) {
    if (run()) return;
    await tick();
  }
  throw Error(label);
}
const node: SharedCatalogNode = {
  id: '11111111-1111-4111-8111-111111111111',
  parentId: null,
  name: 'Development server',
  kind: 1,
  protocol: null,
  host: 'catalog.example',
  port: 22,
  username: 'operator',
  sortOrder: '0',
  canUse: true,
};
let dispose: () => void;
function quietUpdateAPI() {
  return {
    updateStatus: async () => ({ currentVersion: '2.4.3', result: null }),
    onUpdateResult: () => () => {},
    onUpdateProgress: () => () => {},
  };
}
async function checkSharedClipboard() {
  const previous = Object.getOwnPropertyDescriptor(navigator, 'clipboard'),
    command = document.execCommand,
    selection = document.getSelection;
  const input = document.createElement('input'),
    label = document.createElement('p');
  label.textContent = 'Selection to preserve';
  document.body.append(input, label);
  input.focus();
  const range = document.createRange();
  range.selectNodeContents(label);
  document.getSelection()!.removeAllRanges();
  document.getSelection()!.addRange(range);
  try {
    let copied = '';
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (text: string) => {
          copied = text;
        },
      },
    });
    await copyTextToClipboard('async text');
    check(copied === 'async text', 'async clipboard write');
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async () => {
          throw Error('denied');
        },
      },
    });
    document.execCommand = () => {
      check(
        (document.activeElement as HTMLTextAreaElement).value === 'fallback text',
        'fallback copy payload',
      );
      return true;
    };
    await copyTextToClipboard('fallback text');
    check(
      document.activeElement === input &&
        document.getSelection()!.toString() === 'Selection to preserve',
      'clipboard changed focus/selection',
    );
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined });
    document.getSelection = () => null;
    document.execCommand = () => false;
    let failed = false;
    try {
      await copyTextToClipboard('unavailable');
    } catch {
      failed = true;
    }
    check(failed, 'clipboard error swallowed');
  } finally {
    if (previous) Object.defineProperty(navigator, 'clipboard', previous);
    else delete (navigator as any).clipboard;
    document.execCommand = command;
    document.getSelection = selection;
    input.remove();
    label.remove();
  }
}
export async function runSharedWorkspaceTests() {
  await checkSharedClipboard();
  const listeners = new Set<(event: any) => void>(),
    calls: { name: string; args: any[] }[] = [],
    ack: number[] = [];
  const emit = (event: any) => {
    for (const listener of listeners) listener(event);
  };
  let failOpen = false,
    denyUse = false,
    resolveOpen: ((value: any) => void) | undefined;
  const record = (name: string, ...args: any[]) => {
    calls.push({ name, args });
  };
  const entry = (path: string, name: string, isDirectory = false) => ({
    name,
    fullPath: path + '/' + name,
    isDirectory,
    isSymbolicLink: false,
    size: 12,
  });
  const ready = (sessionId: string, pane: 'local' | 'remote', path: string, requestId: string) =>
    queueMicrotask(() =>
      emit({
        sessionId,
        type: pane === 'remote' ? 'sftp.ready' : 'sftp.local.ready',
        requestId,
        path: path || (pane === 'remote' ? '/home/operator' : 'C:/Documents'),
        entries: [
          entry(path || '/home/operator', 'notes.txt'),
          entry(path || '/home/operator', 'project', true),
        ],
        truncated: false,
      }),
    );
  const backendListeners = new Set<(event: any) => void>();
  const emitBackend = (event: any) => {
    for (const listener of backendListeners) listener(event);
  };
  let holdRdpClose = false,
    resumeRdpClose: (() => void) | undefined;
  const rdpListeners = new Set<(event: any) => void>();
  const emitRdp = (event: any) => {
    for (const listener of rdpListeners) listener(event);
  };
  const updateResult = {
    currentVersion: '2.4.3',
    latestVersion: '2.4.4',
    isNewerRelease: true,
    isUpdateAvailable: true,
    checkFailed: false,
    releaseUrl: 'https://github.com/xBounceIT/wormhole/releases/tag/v2.4.4',
    installerUrl:
      'https://github.com/xBounceIT/wormhole/releases/download/v2.4.4/Wormhole.AppImage',
    installerFileName: 'Wormhole.AppImage',
    installerSize: 100,
    installerSha256: 'e'.repeat(64),
  };
  let updateListener: ((result: WormholeUpdateCheckResult) => void) | undefined;
  let progressListener: ((progress: { downloaded: number; total: number }) => void) | undefined;
  let updateError = false;
  const workspaceProfile: VaultProfileStatus = {
    effective: 'standard',
    source: 'workspace',
    retainedUntilLock: false,
  };
  let readProfile = async (): Promise<VaultProfileStatus> => workspaceProfile;
  let profileChoices = 0;
  let profileChanged: (() => void) | undefined;
  const api: any = {
    ...quietUpdateAPI(),
    getVaultSecurityProfile: () => readProfile(),
    tightenSharedVaultProfile: async () => {
      profileChoices++;
    },
    onVaultSecurityProfileChanged: (callback: () => void) => {
      profileChanged = callback;
      return () => {
        profileChanged = undefined;
      };
    },
    onUpdateResult: (listen: typeof updateListener) => {
      updateListener = listen;
      return () => {
        updateListener = undefined;
      };
    },
    onUpdateProgress: (listen: typeof progressListener) => {
      progressListener = listen;
      return () => {
        progressListener = undefined;
      };
    },
    checkForUpdates: async () => {
      record('check-update');
      return updateResult;
    },
    downloadUpdate: async (request: { installerFileName: string }) => {
      record('download-update', request);
      progressListener?.({ downloaded: 20, total: 100 });
      if (updateError) throw Error('Download refused');
      return 'cache/' + request.installerFileName;
    },
    installUpdate: async (file: string) => {
      record('install-update', file);
      return { appWillQuit: false };
    },
    openExternal: async (link: string) => {
      record('update-link', link);
    },
    onWebEvent: () => () => {},
    onSerialEvent: () => () => {},
    onRdpEvent: (listener: any) => {
      rdpListeners.add(listener);
      return () => rdpListeners.delete(listener);
    },
    openVaultRdpSession: async (request: any) => {
      record('rdp-open', request);
      const event = {
        sessionId: request.sessionId,
        lifecycleId: request.sessionId,
        backend: 'freerdp',
        external: false,
      };
      queueMicrotask(() => {
        emitRdp({ ...event, type: 'ready' });
        emitRdp({ ...event, type: 'connected' });
      });
      return { ...event, type: 'ready' };
    },
    resizeRdpSession: async (request: any) => {
      record('rdp-resize', request);
      return { type: 'ack', sessionId: request.sessionId };
    },
    commandRdpSession: async (request: any) => {
      record('rdp-command', request);
      if (request.operation === 'disconnect' && holdRdpClose)
        await new Promise<void>((resolve) => {
          resumeRdpClose = resolve;
        });
      return { type: 'ack', sessionId: request.sessionId };
    },
    sendRdpInput: async (request: any) => {
      record('rdp-input', request);
    },
    onBackendEvent: (listener: any) => {
      backendListeners.add(listener);
      return () => backendListeners.delete(listener);
    },
    sendVncCommand: async (command: any) => {
      record('vnc', command);
      if (command.action === 'vnc.connect')
        queueMicrotask(() => {
          emitBackend({ type: 'vnc.status', sessionId: command.sessionId, status: 'connected' });
          emitBackend({
            type: 'vnc.frame',
            sessionId: command.sessionId,
            width: 1,
            height: 1,
            image:
              'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII=',
          });
        });
      if (command.action === 'vnc.disconnect')
        queueMicrotask(() =>
          emitBackend({ type: 'vnc.status', sessionId: command.sessionId, status: 'disconnected' }),
        );
      return { id: '', ok: true };
    },
    readSharedConnectionContext: async (nodeId: string) => ({ nodeId, protocol: 0 }),
    onSshEvent: (listener: any) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    onSharedCatalogChanged: () => () => {},
    loadSharedChanges: async () => ({ epoch: '1', changeSeq: '1', reset: true, nodes: [] }),
    loadSharedCatalogPage: async () => ({
      epoch: '1',
      changeSeq: '1',
      nodes: [
        {
          ...node,
          id: '33333333-3333-4333-8333-333333333333',
          name: 'Design desktop',
          protocol: 6,
          host: 'vnc.team.internal',
          port: 5900,
        },
        {
          ...node,
          id: '44444444-4444-4444-8444-444444444444',
          name: 'Windows desktop',
          protocol: 1,
          port: 3389,
        },
        { ...node, canUse: !denyUse },
        {
          ...node,
          id: '22222222-2222-4222-8222-222222222222',
          name: 'Read only server',
          canUse: false,
        },
      ],
      next: null,
    }),
    authenticateSharedVault: async () => ({
      admitted: true,
      lockedMemory: true,
      orgEscrow: true,
      tls: 'off',
    }),
    lockAuthentication: async () => {
      record('lock');
    },
    openSshSession: (request: any) => {
      record('open', request);
      if (failOpen) return Promise.reject(Error('private backend details'));
      return new Promise((resolve) => {
        resolveOpen = () =>
          resolve({
            sessionId: request.sessionId,
            host: 'ssh.team.internal',
            port: 22,
            username: 'operator',
          });
      });
    },
    closeSshSession: async (id: string) => {
      record('close', id);
    },
    prepareSftpEditClose: async () => true,
    sendSshInput: async (...args: any[]) => {
      record('input', ...args);
    },
    resizeSshSession: async (...args: any[]) => {
      record('resize', ...args);
    },
    acknowledgeSshTerminal: (_id: string, sequence: number) => {
      ack.push(sequence);
    },
    pasteClipboardToSsh: async () => ({ pasted: false }),
    openSftpBrowser: async (id: string, request: string) => {
      ready(id, 'remote', '', request);
    },
    listSftpDirectory: async (id: string, path: string, request: string) => {
      record('remote', path);
      ready(id, 'remote', path, request);
    },
    listLocalSftpDirectory: async (id: string, path: string, request: string) => {
      record('local', path);
      ready(id, 'local', path, request);
    },
    listSftpTree: async (id: string, pane: string, path: string, requestId: string) =>
      queueMicrotask(() =>
        emit({
          type: 'sftp.tree',
          sessionId: id,
          pane,
          path,
          requestId,
          entries: [],
          truncated: false,
        }),
      ),
    readSftpEditorSettings: async () => ({
      editors: [],
      defaultEditor: 'auto',
      maxFileSize: 1048576,
      swapPanels: false,
    }),
    sftpEdit: async () => ({ type: 'sftp.edit', edits: [] }),
    setNativeSurfaceOverlay: async () => {},
    setNativeSurfaceVisible: async () => {},
    operateSftp: async (sessionId: string, request: any) => {
      record('operation', request);
      queueMicrotask(() => emit({ type: 'sftp.operation', sessionId, ...request }));
    },
    startSftpTransfer: async (sessionId: string, request: any) => {
      record('transfer', request);
      queueMicrotask(() =>
        emit({
          type: 'sftp.transfer',
          sessionId,
          transferId: request.transferId,
          itemId: 'one',
          transferState: 'running',
          displayName: 'notes.txt',
          expectedBytes: 12,
          bytesTransferred: 0,
        }),
      );
    },
    decideSftpConflict: async (...args: any[]) => {
      record('conflict', ...args);
    },
    cancelSftpTransfer: async (sessionId: string, transferId: string) => {
      record('cancel', transferId);
      queueMicrotask(() =>
        emit({
          type: 'sftp.transfer',
          sessionId,
          transferId,
          transferState: 'batch-failed',
          error: 'private transfer failure',
        }),
      );
    },
  };
  window.wormhole = api;
  document.documentElement.classList.add('dark');
  const shell = document.createElement('main');
  shell.className = 'startup-shell';
  const card = document.createElement('section');
  card.className = 'startup-card';
  shell.append(card);
  document.body.append(shell);
  dispose = mountSharedStartup(
    card,
    {
      shared: { lastLoginName: 'operator', serverDisplayName: 'Engineering' },
      slots: { formatVersion: 1, vaultId: node.id, encrypted: true, slots: [] },
      newWorkspace: false,
      cosmetics: { theme: 'dark' },
    },
    api,
    async (container, failed) => mountSharedWorkspace(container, api, failed),
  );
  (card.querySelector('button') as HTMLButtonElement).click();
  await until(
    () => !!card.querySelector('[aria-label="Connect · Development server"]'),
    'catalog not mounted',
  );
  const updateButton = (label: string) =>
    [...card.querySelectorAll('button')].find(
      (button) => (button.getAttribute('aria-label') ?? button.textContent?.trim()) === label,
    );
  await until(() => !!updateButton('Check for updates'), 'shared updater not mounted');
  const settings = [...card.querySelectorAll('summary')].find(
    (s) => s.textContent === 'Security settings',
  )!;
  const profile = () => card.querySelector('[aria-label="Effective security profile"]');
  check(!profile() && !profileChanged, 'closed security settings subscribed');
  settings.click();
  await until(
    () => profile()?.textContent?.includes('Set by your organization') === true,
    'missing organization label',
  );
  check(
    profile()?.querySelector('svg') &&
      profile()?.textContent?.includes('Standard') &&
      profile()?.textContent?.includes('Workspace policy'),
    'missing managed profile',
  );
  let finish!: (value: VaultProfileStatus) => void;
  readProfile = async () => ({
    effective: 'default',
    source: 'workspace',
    retainedUntilLock: false,
    canTightenToStandard: true,
  });
  profileChanged!();
  const chooseStandard = () => updateButton('Use Standard on this device and lock workspace…');
  await until(() => !!chooseStandard(), 'eligible shared device cannot choose Standard');
  chooseStandard()!.click();
  await until(() => profileChoices === 1, 'shared profile action was not dispatched');
  readProfile = () =>
    new Promise((resolve) => {
      finish = resolve;
    });
  profileChanged!();
  readProfile = async () => ({ effective: 'standard', source: 'user', retainedUntilLock: false });
  profileChanged!();
  await until(
    () => profile()?.textContent?.includes('Your preference') === true,
    'missing personal preference',
  );
  finish(workspaceProfile);
  await tick();
  check(
    !profile()?.querySelector('svg') && !profile()?.textContent?.includes('Workspace policy'),
    'late profile changed current authority',
  );
  readProfile = async () => ({ effective: 'standard', source: 'os', retainedUntilLock: true });
  profileChanged!();
  await until(
    () => profile()?.textContent?.includes('until you lock the vault') === true,
    'missing retained profile',
  );
  check(
    profile()?.textContent?.includes('Device policy') &&
      !profile()?.textContent?.includes('Set by your organization'),
    'obsolete device floor labelled current',
  );
  readProfile = async () => {
    throw Error('private detail');
  };
  profileChanged!();
  await until(
    () => profile()?.textContent?.includes('Unavailable') === true,
    'withdrawn status still shown',
  );
  check(
    !profile()?.textContent?.includes('private detail') &&
      !profile()?.textContent?.includes('Standard'),
    'failed profile read retained details',
  );
  settings.click();
  await until(() => !profile() && !profileChanged, 'closed security settings still subscribed');
  updateButton('Check for updates')!.click();
  await until(() => !!updateButton('Update now'), 'shared release not offered');
  updateButton('View changes')!.click();
  check(
    calls.find((c) => c.name === 'update-link')?.args[0] === updateResult.releaseUrl,
    'shared changelog',
  );
  updateError = true;
  updateButton('Update now')!.click();
  await until(
    () => card.textContent?.includes('Download refused') === true,
    'shared installer failure hidden',
  );
  updateError = false;
  updateButton('Update now')!.click();
  await until(
    () => card.textContent?.includes('AppImage downloaded') === true,
    'shared installer handoff',
  );
  check(
    calls.find((c) => c.name === 'download-update')?.args[0].installerSha256 ===
      updateResult.installerSha256,
    'shared installer digest',
  );
  check(
    calls.find((c) => c.name === 'install-update')?.args[0] === 'cache/Wormhole.AppImage',
    'shared cached installer',
  );
  updateButton('Close update notification')!.click();
  await until(() => !updateButton('Update now'), 'shared dismissal');
  updateListener?.({
    ...updateResult,
    updatePolicy: 'notify',
    isUpdateAvailable: false,
    latestVersion: '2.4.5',
  });
  await until(() => !!updateButton('View changes'), 'shared notification-only update not visible');
  check(!updateButton('Update now'), 'notification-only shared install button');
  updateListener?.({
    ...updateResult,
    latestVersion: '2.4.6',
    updatePolicy: 'managed',
    installerFileName: 'Wormhole.rpm',
    installerUrl: 'managed-update:Wormhole.rpm',
  });
  await until(() => !!updateButton('Update now'), 'approved RPM missing');
  updateButton('Update now')!.click();
  await until(
    () => card.textContent?.includes('Ask your administrator to install') === true,
    'managed RPM instructions missing',
  );
  check(
    !card.textContent?.includes('AppImage downloaded'),
    'public instructions shown for a managed package',
  );
  updateListener?.({
    ...updateResult,
    updatePolicy: 'managed',
    isUpdateAvailable: false,
    isNewerRelease: false,
  });
  await until(
    () =>
      card.textContent?.includes('managed by your administrator') === true &&
      !card.textContent?.includes('Ask your administrator to install'),
    'shared managed policy',
  );
  check(!card.querySelector('input[type=password]'), 'password entered shared workspace');
  check(card.textContent?.includes('View only'), 'missing View-only hint');
  const transportNotice = card.querySelector('.shared-transport-notice') as HTMLElement;
  check(
    transportNotice && !transportNotice.hidden && transportNotice.textContent?.includes('TLS Off'),
    'missing admitted transport warning',
  );
  check(
    transportNotice.getBoundingClientRect().height > 0 &&
      transportNotice.getBoundingClientRect().width > 0,
    'transport warning hidden by workspace layout',
  );
  const connect = () =>
    (
      card.querySelector('[aria-label="Connect · Development server"]') as HTMLButtonElement
    ).click();
  connect();
  await until(() => !!resolveOpen, 'open not dispatched');
  check(card.textContent?.includes('Connecting'), 'missing pending state');
  resolveOpen!({});
  await until(() => !!card.querySelector('.xterm-screen'), 'real terminal not mounted');
  const first = calls.find((c) => c.name === 'open')!.args[0];
  check(
    Object.keys(first).sort().join(',') === 'columns,mode,nodeId,rows,sessionId',
    'renderer sent a connection plan',
  );
  emit({
    type: 'terminal-output',
    sessionId: first.sessionId,
    sequence: 1,
    data: btoa('Connected to Engineering\r\noperator@dev:~$ '),
    reset: false,
    columns: 80,
    rows: 24,
  });
  await until(() => ack.includes(1), 'terminal did not acknowledge output');
  check(card.textContent?.includes('operator@ssh.team.internal:22'), 'verified endpoint missing');
  (card.querySelector('[aria-label="Files · Development server"]') as HTMLButtonElement).click();
  await until(() => calls.filter((c) => c.name === 'open').length === 2, 'files not dispatched');
  resolveOpen!({});
  await until(
    () => !!card.querySelector('[aria-label="SFTP browser"]'),
    'file browser not mounted',
  );
  check(card.querySelectorAll('[role=tab]').length === 2, 'file session replaced terminal');
  check(
    (card.querySelector('[aria-label="Remote path"]') as HTMLInputElement)?.value ===
      '/home/operator',
    'remote folder missing',
  );
  const refresh = card.querySelector(
    '[aria-label="Remote files"] [aria-label="Refresh"]',
  ) as HTMLButtonElement;
  refresh?.click();
  await tick();
  for (const pane of ['Remote', 'Local']) {
    const section = card.querySelector(`[aria-label="${pane} files"]`)!;
    (
      section.querySelector(
        '[aria-label="Go up in ' + pane.toLowerCase() + ' files"]',
      ) as HTMLButtonElement
    ).click();
    await tick();
    (section.querySelector('[aria-label="Refresh"]') as HTMLButtonElement).click();
    await tick();
  }
  const remote = card.querySelector('[aria-label="Remote files"]')!;
  (remote.querySelector('[aria-label="New folder"]') as HTMLButtonElement).click();
  await tick();
  const nameInput = remote.querySelector('input[placeholder="Name"]') as HTMLInputElement;
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(
    nameInput,
    'new-folder',
  );
  nameInput.dispatchEvent(new Event('input', { bubbles: true }));
  await tick();
  remote
    .querySelector('form')!
    .dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  await tick();
  check(
    calls.some((c) => c.name === 'operation'),
    'file mutation not wired',
  );
  const local = card.querySelector('[aria-label="Local files"]') as HTMLElement;
  (local.querySelector('[aria-label="Select notes.txt"]') as HTMLButtonElement).click();
  await tick();
  local.dispatchEvent(new KeyboardEvent('keydown', { key: 'F5', bubbles: true, cancelable: true }));
  await until(() => calls.some((c) => c.name === 'transfer'), 'copy shortcut not wired');
  const transfer = calls.find((c) => c.name === 'transfer')!.args[0],
    fileId = calls.filter((c) => c.name === 'open')[1].args[0].sessionId;
  emit({
    type: 'sftp.conflict',
    sessionId: fileId,
    transferId: transfer.transferId,
    itemId: 'one',
    displayName: 'notes.txt',
    path: '/home/notes.txt',
    direction: 'local-to-remote',
    incomingSize: 12,
    existingSize: 3,
    existingIsDirectory: false,
  });
  await tick();
  (
    Array.from(card.querySelectorAll('button')).find(
      (b) => b.textContent === 'Skip',
    ) as HTMLButtonElement
  ).click();
  await until(() => calls.some((c) => c.name === 'conflict'), 'conflict choice not wired');
  (card.querySelector('[aria-label="Cancel notes.txt"]') as HTMLButtonElement).click();
  await until(
    () => !!card.querySelector('[aria-label="Dismiss transfer error"]'),
    'transfer failure missing',
  );
  (card.querySelector('[aria-label="Dismiss transfer error"]') as HTMLButtonElement).click();
  (card.querySelector('[aria-label="Remove notes.txt"]') as HTMLButtonElement).click();
  await tick();
  check(!card.textContent?.includes('private transfer failure'), 'raw transfer error leaked');
  let tabs = Array.from(card.querySelectorAll('[role=tab]')) as HTMLButtonElement[];
  check(tabs[0].tabIndex === -1 && tabs[1].tabIndex === 0, 'roving tab focus missing');
  for (const key of ['ArrowRight', 'ArrowLeft', 'Home', 'End', 'Home', 'x']) {
    const selected = card.querySelector('[role=tab][aria-selected=true]') as HTMLButtonElement;
    selected.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true }));
    await tick();
  }
  check(
    card.querySelectorAll('[role=tab][tabindex="0"]').length === 1,
    'multiple keyboard tab stops',
  );
  const terminalTab = card.querySelector('[role=tab]') as HTMLButtonElement;
  terminalTab.click();
  await until(() => !!card.querySelector('.xterm-screen'), 'terminal did not reattach');
  emit({ type: 'error', sessionId: first.sessionId, error: 'private backend details' });
  await until(
    () =>
      !!card.querySelector('button') &&
      !!Array.from(card.querySelectorAll('button')).find((b) => b.textContent === 'Reconnect'),
    'failed session missing reconnect',
  );
  check(!card.textContent?.includes('private backend details'), 'private failure rendered');
  failOpen = true;
  (
    Array.from(card.querySelectorAll('button')).find(
      (b) => b.textContent === 'Reconnect',
    ) as HTMLButtonElement
  ).click();
  await until(
    () => calls.filter((c) => c.name === 'open').length === 3,
    'reconnect not dispatched',
  );
  await until(
    () => !!Array.from(card.querySelectorAll('button')).find((b) => b.textContent === 'Reconnect'),
    'failed open not retryable',
  );
  failOpen = false;
  (
    Array.from(card.querySelectorAll('button')).find(
      (b) => b.textContent === 'Reconnect',
    ) as HTMLButtonElement
  ).click();
  await until(
    () => calls.filter((c) => c.name === 'open').length === 4,
    'second reconnect not dispatched',
  );
  resolveOpen!({});
  await until(() => !!card.querySelector('.xterm-screen'), 'reconnected terminal missing');
  const last = calls.filter((c) => c.name === 'open').at(-1)!.args[0];
  emit({
    type: 'terminal-output',
    sessionId: last.sessionId,
    sequence: 1,
    data: btoa('Welcome back, operator.\r\noperator@dev:~$ '),
    reset: false,
    columns: 80,
    rows: 24,
  });
  await tick();
  (card.querySelector('[aria-label="Connect · Design desktop"]') as HTMLButtonElement).click();
  await until(() => !!card.querySelector('.shared-vnc-surface img'), 'VNC frame not mounted');
  const vncSurface = card.querySelector('.shared-vnc-surface [role=application]') as HTMLElement;
  const firstVnc = calls.find((c) => c.name === 'vnc' && c.args[0].action === 'vnc.connect')!
    .args[0];
  check(
    Object.keys(firstVnc).sort().join(',') === 'action,nodeId,sessionId',
    'VNC exposed endpoint or credentials',
  );
  const image = card.querySelector('.shared-vnc-surface img');
  vncSurface.focus();
  vncSurface.dispatchEvent(
    new KeyboardEvent('keydown', { key: 'a', code: 'KeyA', bubbles: true, cancelable: true }),
  );
  await tick();
  (
    Array.from(card.querySelectorAll('[role=tab]')).find((tab) =>
      tab.textContent?.includes('SSH'),
    ) as HTMLButtonElement
  ).click();
  await tick();
  check(
    card.querySelector('.shared-vnc-surface img') === image &&
      getComputedStyle(card.querySelector('.shared-vnc-surface')!).display === 'none',
    'tab switch disposed or displayed inactive VNC',
  );
  check(
    calls.some(
      (c) => c.name === 'vnc' && c.args[0].action === 'vnc.key' && c.args[0].down === false,
    ),
    'hidden VNC retained a pressed key',
  );
  const controls = calls.filter((c) => c.name === 'vnc').length;
  vncSurface.dispatchEvent(
    new KeyboardEvent('keydown', { key: 'b', code: 'KeyB', bubbles: true, cancelable: true }),
  );
  await tick();
  check(calls.filter((c) => c.name === 'vnc').length === controls, 'hidden VNC accepted input');
  (
    Array.from(card.querySelectorAll('[role=tab]')).find((tab) =>
      tab.textContent?.includes('VNC'),
    ) as HTMLButtonElement
  ).click();
  await tick();
  check(
    card.querySelector('.shared-vnc-surface img') === image &&
      calls.filter((c) => c.name === 'vnc' && c.args[0].action === 'vnc.connect').length === 1,
    'select reconnected VNC',
  );
  emitBackend({
    type: 'vnc.status',
    sessionId: firstVnc.sessionId,
    status: 'failed',
    passwordRequired: true,
    message: 'VNC connection failed',
  });
  await until(
    () => !!card.querySelector('.shared-vnc-surface button:not(:disabled)'),
    'VNC cleanup did not permit reconnect',
  );
  check(
    card.textContent?.includes('Enter password securely'),
    'shared VNC omitted protected manual release',
  );
  (
    Array.from(card.querySelectorAll('.shared-vnc-surface button')).find((button) =>
      button.textContent?.includes('Enter password securely'),
    ) as HTMLButtonElement
  ).click();
  await until(
    () => calls.filter((c) => c.name === 'vnc' && c.args[0].action === 'vnc.connect').length === 2,
    'VNC reconnect missing',
  );
  const secondVnc = calls
    .filter((c) => c.name === 'vnc' && c.args[0].action === 'vnc.connect')
    .at(-1)!.args[0];
  check(secondVnc.sessionId !== firstVnc.sessionId, 'VNC reused closed identity');
  check(
    secondVnc.manualPassword === true && Object.keys(secondVnc).length === 4,
    'manual VNC intent leaked extra fields',
  );
  emitBackend({ type: 'vnc.status', sessionId: secondVnc.sessionId, status: 'disconnected' });
  await until(
    () =>
      !!Array.from(card.querySelectorAll('.shared-vnc-surface button')).find(
        (button) =>
          button.textContent?.trim() === 'Reconnect' && !(button as HTMLButtonElement).disabled,
      ),
    'VNC reconnect remained disabled',
  );
  (
    Array.from(card.querySelectorAll('.shared-vnc-surface button')).find(
      (button) => button.textContent?.trim() === 'Reconnect',
    ) as HTMLButtonElement
  ).click();
  await until(
    () => calls.filter((c) => c.name === 'vnc' && c.args[0].action === 'vnc.connect').length === 3,
    'saved VNC reconnect missing',
  );
  const thirdVnc = calls
    .filter((c) => c.name === 'vnc' && c.args[0].action === 'vnc.connect')
    .at(-1)!.args[0];
  check(!('manualPassword' in thirdVnc), 'manual intent persisted into ordinary reconnect');
  (card.querySelector('[aria-label="Close Design desktop"]') as HTMLButtonElement).click();
  await until(
    () => !card.querySelector('.shared-vnc-surface'),
    'VNC tab close retained the surface',
  );
  check(
    calls.filter((c) => c.name === 'vnc' && c.args[0].action === 'vnc.disconnect').length >= 2,
    'VNC native cleanup missing',
  );
  (card.querySelector('[aria-label="Connect · Windows desktop"]') as HTMLButtonElement).click();
  await until(
    () =>
      calls.some((c) => c.name === 'rdp-open') &&
      calls.some((c) => c.name === 'rdp-command' && c.args[0].operation === 'show'),
    'RDP not connected',
  );
  const firstRdp = calls.find((c) => c.name === 'rdp-open')!.args[0];
  check(
    Object.keys(firstRdp).sort().join(',') === 'bounds,nodeId,sessionId',
    'RDP renderer sent target or credentials',
  );
  const rdp = card.querySelector('.shared-rdp-surface')!;
  const rdpBounds = rdp.querySelector('[data-rdp-native-surface-region]')!.getBoundingClientRect();
  check(rdpBounds.width > 500 && rdpBounds.height > 250, 'RDP surface geometry collapsed');
  (
    Array.from(card.querySelectorAll('[role=tab]')).find((tab) =>
      tab.textContent?.includes('SSH'),
    ) as HTMLButtonElement
  ).click();
  await until(
    () =>
      getComputedStyle(rdp).display === 'none' &&
      calls.some((c) => c.name === 'rdp-command' && c.args[0].operation === 'hide'),
    'inactive RDP did not hide',
  );
  (
    Array.from(card.querySelectorAll('[role=tab]')).find((tab) =>
      tab.textContent?.includes('RDP'),
    ) as HTMLButtonElement
  ).click();
  await until(() => getComputedStyle(rdp).display !== 'none', 'RDP did not reappear');
  check(calls.filter((c) => c.name === 'rdp-open').length === 1, 'tab selection restarted RDP');
  holdRdpClose = true;
  emitRdp({
    type: 'fatalError',
    sessionId: firstRdp.sessionId,
    message: 'private backend diagnostic',
  });
  await until(
    () =>
      Array.from(rdp.querySelectorAll('button')).some(
        (b) => b.textContent?.trim() === 'Retry connection',
      ),
    'RDP failure missing retry',
  );
  check(!rdp.textContent?.includes('private backend diagnostic'), 'raw RDP error rendered');
  await tick();
  await until(() => !!resumeRdpClose, 'RDP close was not requested');
  (
    Array.from(rdp.querySelectorAll('button')).find(
      (b) => b.textContent?.trim() === 'Enter credentials securely',
    ) as HTMLButtonElement
  ).click();
  await tick();
  check(
    calls.filter((c) => c.name === 'rdp-open').length === 1,
    'RDP reopened before closure confirmation',
  );
  holdRdpClose = false;
  resumeRdpClose!();
  await tick();
  (
    Array.from(rdp.querySelectorAll('button')).find(
      (b) => b.textContent?.trim() === 'Enter credentials securely',
    ) as HTMLButtonElement
  ).click();
  await until(() => calls.filter((c) => c.name === 'rdp-open').length === 2, 'RDP retry missing');
  const secondRdp = calls.filter((c) => c.name === 'rdp-open').at(-1)!.args[0];
  check(secondRdp.sessionId !== firstRdp.sessionId, 'RDP reused retired identity');
  check(
    secondRdp.manualCredentials === true &&
      !('username' in secondRdp) &&
      !('password' in secondRdp),
    'manual RDP leaked credentials or lost intent',
  );
  emitRdp({ type: 'disconnected', sessionId: secondRdp.sessionId, code: 0 });
  await tick();
  const secondSurface = card.querySelector('.shared-rdp-surface')!;
  await until(
    () =>
      Array.from(secondSurface.querySelectorAll('button')).some(
        (b) => b.textContent?.trim() === 'Connect',
      ),
    'RDP closed state missing connect',
  );
  (
    Array.from(secondSurface.querySelectorAll('button')).find(
      (b) => b.textContent?.trim() === 'Connect',
    ) as HTMLButtonElement
  ).click();
  await until(
    () => calls.filter((c) => c.name === 'rdp-open').length === 3,
    'RDP reconnect missing',
  );
  (card.querySelector('[aria-label="Close Windows desktop"]') as HTMLButtonElement).click();
  await until(() => !card.querySelector('.shared-rdp-surface'), 'RDP close retained surface');
  check(
    calls.filter((c) => c.name === 'rdp-command' && c.args[0].operation === 'disconnect').length >=
      3,
    'RDP close receipts missing',
  );
  const bounds = card.getBoundingClientRect(),
    panel = card.querySelector('.shared-session-panel')!.getBoundingClientRect();
  check(bounds.width > 900 && panel.width > 500 && panel.height > 250, 'workspace collapsed');
  (globalThis as any).sharedUI = {
    calls,
    card,
    deny: () => {
      denyUse = true;
    },
    dispose,
    check,
    until,
  };
  return {
    sessions: card.querySelectorAll('[role=tab]').length,
    opens: calls.filter((c) => c.name === 'open').length,
  };
}
export async function finishSharedWorkspaceTests() {
  const { calls, card, deny, dispose, check, until } = (globalThis as any).sharedUI;
  deny();
  (Array.from(card.querySelectorAll('button')) as HTMLButtonElement[])
    .find((b) => b.textContent === 'Refresh catalog')!
    .click();
  await until(
    () => card.querySelectorAll('[role=tab]').length === 0,
    'revoked sessions survived catalog refresh',
  );
  check(
    calls.filter((c: any) => c.name === 'close').length >= 4,
    'session close ownership missing',
  );
  dispose();
  check(card.querySelectorAll('[role=tab]').length === 0, 'disposed DOM retained');
}

export async function checkSharedRenderFailure() {
  const card = document.createElement('div');
  document.body.append(card);
  const original = window.ResizeObserver;
  let callback = 0,
    closed = 0,
    port: ReturnType<typeof mountSharedWorkspace>;
  const api: any = {
    ...quietUpdateAPI(),
    ...window.wormhole,
    onSshEvent: () => () => {},
    onWebEvent: () => () => {},
    onSerialEvent: () => () => {},
    openSshSession: async (request: any) => ({
      sessionId: request.sessionId,
      host: 'host',
      port: 22,
      username: 'u',
    }),
    closeSshSession: async () => {
      closed++;
    },
  };
  try {
    window.ResizeObserver = class {
      constructor() {
        throw Error('simulated resize observer failure');
      }
    } as any;
    port = mountSharedWorkspace(card, api, () => {
      callback++;
      port.dispose();
    });
    port.connect(node);
    await until(() => callback === 1 && closed >= 1, 'React error did not close sessions');
    check(!card.hasChildNodes(), 'failed React root retained DOM');
  } finally {
    window.ResizeObserver = original;
    card.remove();
  }
}

export async function checkSharedWebSurface() {
  const card = document.createElement('div');
  document.body.append(card);
  const previous = window.wormhole;
  const web = { ...node, protocol: 4, name: 'Shared console' };
  const url = 'https://verified.example/console';
  const browser = {
    activeTabId: '1',
    route: 'direct',
    tabs: [
      { id: '1', title: 'Console', url, isLoading: false, canGoBack: false, canGoForward: false },
    ],
  };
  let opened: { nodeId: string; sessionId: string; attempt: number } | undefined;
  let closed: string | undefined;
  const api = {
    ...previous,
    ...quietUpdateAPI(),
    onSshEvent: () => () => {},
    onBackendEvent: () => () => {},
    onRdpEvent: () => () => {},
    onWebEvent: () => () => {},
    onSerialEvent: () => () => {},
    setWebSessionBounds: async () => undefined,
    closeBitwardenPopup: async () => {},
    openWebSession: async (request: NonNullable<typeof opened>) => {
      opened = request;
      return { url, host: 'verified.example', port: 443, protocol: 'https', browser };
    },
    closeWebSession: async (id: string) => {
      closed = id;
    },
  } as any;
  window.wormhole = api;
  const workspace = mountSharedWorkspace(card, api, () => {
    throw Error('Web surface did not render');
  });
  try {
    workspace.connect(web, 'web');
    await until(
      () => !!card.querySelector('[aria-label="Website address"]'),
      'shared native browser did not mount',
    );
    const address = card.querySelector<HTMLInputElement>('[aria-label="Website address"]');
    check(address?.value === url, 'browser used catalog address instead of verified target');
    check(
      opened?.nodeId === web.id && opened?.attempt === 1,
      'browser became disconnected from the catalog node',
    );
    check(Object.keys(opened!).length === 3, 'renderer supplied connection details');
    workspace.observeNodes([{ ...web, canUse: false }]);
    await until(
      () => !!closed && !card.querySelector('[aria-label="Website address"]'),
      'revoked browser remained mounted',
    );
    check(closed === opened?.sessionId, 'revocation closed an unrelated browser');
  } finally {
    workspace.dispose();
    window.wormhole = previous;
    card.remove();
  }
}

export async function checkSharedSerialSurface() {
  const catalog = document.createElement('section');
  const panel = document.createElement('div');
  panel.style.height = '420px';
  panel.style.display = 'flex';
  document.body.append(catalog, panel);
  const serial = {
    ...node,
    protocol: 5,
    name: 'Rack console',
    host: 'old-port',
    port: null,
    username: null,
  };
  let allowed = true;
  let requested: { sessionId: string; nodeId: string; columns: number; rows: number } | undefined;
  let listener: ((event: WormholeSerialEvent) => void) | undefined;
  const sent: string[] = [];
  const resized: string[] = [];
  const closed: string[] = [];
  const api: any = {
    ...quietUpdateAPI(),
    onSshEvent: () => () => {},
    onBackendEvent: () => () => {},
    onRdpEvent: () => () => {},
    onWebEvent: () => () => {},
    onSerialEvent: (callback: typeof listener) => {
      listener = callback;
      return () => {
        listener = undefined;
      };
    },
    onSharedCatalogChanged: () => () => {},
    loadSharedChanges: async () => ({ ...{ epoch: '1', changeSeq: '0' }, reset: true, nodes: [] }),
    loadSharedCatalogPage: async () => ({
      epoch: '1',
      changeSeq: '0',
      nodes: [{ ...serial, canUse: allowed }],
      next: null,
    }),
    openSerialSession: async (request: NonNullable<typeof requested>) => {
      requested = request;
      const connection = {
        sessionId: request.sessionId,
        portName: 'COM42',
        baudRate: 9600,
        dataBits: 8,
        stopBits: 1,
        parity: 0,
        flowControl: 0,
      };
      listener?.({ type: 'connected', ...connection });
      listener?.({
        type: 'screen',
        sessionId: request.sessionId,
        frame: {
          columns: 2,
          rows: 1,
          full: true,
          cells: [
            { character: 'O', foreground: 2, background: 0 },
            { character: 'K', foreground: 2, background: 0 },
          ],
          changes: [],
          scrollbackReset: true,
          viewportReset: true,
          cursorX: 0,
          cursorY: 0,
          cursorVisible: false,
          applicationCursor: false,
          alternateScreen: false,
          sequence: 1,
        },
      });
      return connection;
    },
    sendSerialInput: async (id: string, data: string) => {
      if (id === requested?.sessionId) sent.push(atob(data));
    },
    resizeSerialSession: async (id: string, columns: number, rows: number) => {
      if (columns > 0 && rows > 0) resized.push(id);
    },
    closeSerialSession: async (id: string) => {
      closed.push(id);
    },
  };
  const fail = () => {
    throw Error('Serial surface did not render');
  };
  const workspace = mountSharedWorkspace(panel, api, fail);
  const unmountCatalog = mountSharedCatalogScreen(catalog, api, fail, workspace);
  try {
    await until(
      () => !!catalog.querySelector('[aria-label="Connect · Rack console"]'),
      'serial was not connectable',
    );
    (catalog.querySelector('[aria-label="Connect · Rack console"]') as HTMLButtonElement).click();
    const surface = () => panel.querySelector<HTMLElement>('[aria-label="Live serial terminal"]');
    await until(() => surface()?.textContent === 'OK', 'serial event grid did not render');
    check(
      panel.querySelector('.shared-session-route code')?.textContent === 'COM42',
      'catalog label replaced the native serial line',
    );
    check(
      Object.keys(requested!).sort().join(',') === 'columns,nodeId,rows,sessionId',
      'serial opening accepted a renderer port',
    );
    check(requested?.nodeId === serial.id, 'serial lost its canonical catalog node');
    surface()?.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'a', bubbles: true, cancelable: true }),
    );
    const data = new DataTransfer();
    data.setData('text/plain', 'first\nsecond');
    surface()?.dispatchEvent(
      new ClipboardEvent('paste', { clipboardData: data, bubbles: true, cancelable: true }),
    );
    await until(
      () => sent.length >= 2 && resized.includes(requested!.sessionId),
      'serial input or resize did not reach IPC',
    );
    check(sent.join('|') === 'a|first\rsecond', 'serial input encoding or paste newlines changed');
    allowed = false;
    Array.from(catalog.querySelectorAll('button'))
      .find((button) => button.textContent === 'Refresh catalog')
      ?.click();
    await until(
      () => closed.includes(requested!.sessionId) && !surface(),
      'revoked serial remained open',
    );
    check(
      !catalog.querySelector('[aria-label="Connect · Rack console"]'),
      'revoked serial is still connectable',
    );
  } finally {
    unmountCatalog();
    workspace.dispose();
    panel.remove();
    catalog.remove();
  }
}
