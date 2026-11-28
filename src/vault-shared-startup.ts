import type { VaultStartupMetadata } from '../electron/vault-contract.ts';
import type { SharedVaultSessionAdmission } from '../electron/vault-shared-unlock.ts';
import { parseSharedVaultTransport } from '../electron/vault-shared-transport.ts';
import { mountSharedCertificateRenewal } from './vault-shared-certificate.ts';
import {
  mountSharedCatalogScreen,
  type SharedWorkspacePort,
} from './vault-shared-catalog-screen.ts';

export function mountSharedStartup(
  card: HTMLElement,
  startup: VaultStartupMetadata,
  api: Pick<
    NonNullable<Window['wormhole']>,
    | 'authenticateSharedVault'
    | 'lockAuthentication'
    | 'loadSharedCatalogPage'
    | 'loadSharedChanges'
    | 'onSharedCatalogChanged'
  > &
    Partial<
      Pick<
        NonNullable<Window['wormhole']>,
        | 'renewSharedServerCertificate'
        | 'sharedWorkspaceCA'
        | 'exportSharedTLSBundle'
        | 'refreshSharedRecoveryKit'
        | 'recoverSharedWorkspace'
        | 'openSharedRecoveryBackup'
        | 'openSharedAccountReset'
        | 'openSharedAdministration'
        | 'showVaultNotes'
        | 'editSharedNode'
      >
    >,
  mountSessions?: (container: HTMLElement, failed: () => void) => Promise<SharedWorkspacePort>,
  initialAdmission?: SharedVaultSessionAdmission,
) {
  let initial = startup.shared ? initialAdmission : undefined;
  let joining = !!startup.sharedJoin;
  const title = document.createElement('h1');
  title.textContent = startup.sharedJoin?.accountReset
    ? 'Continue resetting your account'
    : joining
      ? 'Continue joining your workspace'
      : 'Shared workspace';
  const detail = document.createElement('p');
  const hint = startup.sharedJoin ?? startup.shared!;
  detail.textContent = `${hint.lastLoginName} · ${hint.serverDisplayName}`;
  const transport = document.createElement('p');
  transport.className = 'shared-transport-notice';
  transport.setAttribute('role', 'status');
  transport.hidden = true;
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.className = 'startup-status';
  const signIn = document.createElement('button');
  signIn.type = 'button';
  signIn.className = 'startup-button';
  signIn.textContent = joining ? 'Continue' : 'Sign in';
  const recover = document.createElement('button');
  recover.type = 'button';
  recover.className = 'startup-button startup-button-secondary';
  recover.textContent = 'Finish an interrupted password change';
  recover.hidden = joining;
  const resumeAdmin = document.createElement('button');
  resumeAdmin.type = 'button';
  resumeAdmin.className = recover.className;
  resumeAdmin.textContent = 'Resume emergency recovery';
  resumeAdmin.hidden = !startup.sharedJoin?.adminRecovery || !api.recoverSharedWorkspace;
  const signOut = document.createElement('button');
  signOut.type = 'button';
  signOut.className = 'startup-button startup-button-secondary';
  signOut.textContent = 'Sign out';
  signOut.hidden = true;
  const backup = document.createElement('button');
  backup.type = 'button';
  backup.className = recover.className;
  backup.textContent = 'Export workspace recovery backup…';
  backup.hidden = true;
  const reset = document.createElement('button');
  reset.type = 'button';
  reset.className = recover.className;
  reset.textContent = 'Issue account reset…';
  reset.hidden = true;
  const administration = document.createElement('button');
  administration.type = 'button';
  administration.className = recover.className;
  administration.textContent = 'Workspace administration…';
  administration.hidden = true;
  const catalog = document.createElement('section');
  catalog.className = 'shared-workspace-catalog';
  const sessionContainer = document.createElement('div');
  sessionContainer.className = 'shared-workspace-sessions';
  const layout = document.createElement('div');
  layout.className = 'shared-workspace-layout';
  layout.append(catalog, sessionContainer);
  let sessions: SharedWorkspacePort | undefined;
  let disposeRenewal: (() => void) | undefined;
  let workspaceFailed = false;
  let generation = 0;
  const clearWorkspace = () => {
    generation++;
    disposeCatalog?.();
    disposeCatalog = undefined;
    disposeRenewal?.();
    disposeRenewal = undefined;
    sessions?.dispose();
    sessions = undefined;
    backup.hidden = reset.hidden = administration.hidden = true;
    sessionContainer.replaceChildren();
    card.classList.remove('shared-workspace');
  };
  const lockAfterFailure = () => {
    if (disposed || !admitted || workspaceFailed) return;
    workspaceFailed = true;
    clearWorkspace();
    const version = generation;
    busy = true;
    signOut.disabled = true;
    signIn.disabled = recover.disabled = true;
    status.textContent = 'Could not open the workspace. Signing out…';
    void Promise.resolve()
      .then(() => api.lockAuthentication())
      .then(() => {
        if (disposed || version !== generation) return;
        admitted = false;
        transport.hidden = true;
        signOut.hidden = true;
        signIn.hidden = recover.hidden = false;
        signIn.disabled = recover.disabled = busy;
        status.textContent = 'Could not open the workspace. Sign in again.';
      })
      .catch(() => {
        if (!disposed && version === generation)
          status.textContent = 'Could not confirm sign out. Try again.';
      })
      .finally(() => {
        if (disposed || version !== generation) return;
        busy = false;
        signOut.disabled = false;
        signIn.disabled = recover.disabled = admitted;
      });
  };
  let disposeCatalog: (() => void) | undefined;
  let disposed = false,
    busy = false,
    admitted = false;
  const run = async (mode: 'admit' | 'recover-password' | 'recover-enrollment', resume = false) => {
    if (
      disposed ||
      busy ||
      admitted ||
      (joining ? mode !== 'recover-enrollment' : mode === 'recover-enrollment')
    )
      return;
    busy = true;
    const version = ++generation;
    const failed = () => {
      if (version === generation) lockAfterFailure();
    };
    signIn.disabled = recover.disabled = resumeAdmin.disabled = true;
    status.textContent = '';
    try {
      const initialResult = initial;
      initial = undefined;
      const result =
        initialResult ??
        (resume && api.recoverSharedWorkspace
          ? await api.recoverSharedWorkspace()
          : await api.authenticateSharedVault(mode));
      if (disposed || version !== generation || result === null) return;
      if (
        (mode === 'admit' || mode === 'recover-enrollment') &&
        'admitted' in result &&
        result.admitted === true
      ) {
        joining = false;
        signIn.textContent = 'Sign in';
        title.textContent = 'Shared workspace';
        admitted = true;
        workspaceFailed = false;
        if (typeof result.orgEscrow !== 'boolean') throw Error('Invalid admission notice');
        const tls = parseSharedVaultTransport(result.tls);
        if (!tls) throw Error('Invalid transport notice');
        transport.hidden = tls === 'verified';
        transport.textContent =
          tls === 'off'
            ? 'TLS Off: the workspace connection is not encrypted. Metadata is exposed and sessions can be hijacked.'
            : tls === 'encrypted'
              ? 'TLS Encrypted: the workspace connection is encrypted, but the server certificate is not verified.'
              : '';
        signOut.hidden = false;
        status.textContent = 'Signed in.';
        if (!result.lockedMemory)
          status.textContent += ' Protected memory is unavailable on this computer.';
        status.textContent += result.orgEscrow
          ? ' Your admin can see your personal items.'
          : ' Your admin cannot see your personal items.';
        signIn.hidden = recover.hidden = resumeAdmin.hidden = true;
        if (mountSessions) {
          const mounted = await mountSessions(sessionContainer, failed);
          if (disposed || version !== generation || !admitted || workspaceFailed) {
            mounted.dispose();
            return;
          }
          sessions = mounted;
          card.classList.add('shared-workspace');
        }
        disposeCatalog = mountSharedCatalogScreen(catalog, api, failed, sessions);
        backup.hidden =
          tls !== 'verified' ||
          !result.orgEscrow ||
          result.recoveryBackup !== true ||
          !api.openSharedRecoveryBackup;
        reset.hidden =
          tls !== 'verified' ||
          !result.orgEscrow ||
          result.recoveryBackup !== true ||
          !api.openSharedAccountReset;
        administration.hidden = tls !== 'verified' || !api.openSharedAdministration;
        administration.textContent =
          result.administrator === true ? 'Workspace administration…' : 'My workspace…';
        if (tls === 'verified' && api.renewSharedServerCertificate) {
          disposeRenewal = mountSharedCertificateRenewal(
            card,
            api.renewSharedServerCertificate,
            failed,
            api.sharedWorkspaceCA
              ? {
                  request: api.sharedWorkspaceCA,
                  exportBundle: api.exportSharedTLSBundle,
                  refreshKit: api.refreshSharedRecoveryKit,
                  reconnect: () =>
                    void runSignOut('Sign in again to use the updated workspace CA.'),
                }
              : undefined,
          );
        }
      } else if (
        mode === 'recover-password' &&
        'recovered' in result &&
        result.recovered === true
      ) {
        status.textContent = 'Password change completed. You can now sign in.';
      } else throw Error('Invalid response');
    } catch {
      if (!disposed && version === generation) {
        if (admitted) lockAfterFailure();
        else status.textContent = 'Could not sign in. Try again.';
      }
    } finally {
      if (!disposed && version === generation) {
        busy = false;
        signIn.disabled = recover.disabled = resumeAdmin.disabled = admitted;
      }
    }
  };
  signIn.onclick = () => {
    void run(joining ? 'recover-enrollment' : 'admit');
  };
  recover.onclick = () => {
    void run('recover-password');
  };
  resumeAdmin.onclick = () => {
    if (!resumeAdmin.hidden) void run('recover-enrollment', true);
  };
  const runSignOut = async (confirmation = 'Signed out.') => {
    if (disposed || busy || !admitted) return;
    busy = true;
    signOut.disabled = true;
    clearWorkspace();
    const version = generation;
    try {
      await api.lockAuthentication();
      if (!disposed && version === generation) {
        admitted = false;
        transport.hidden = true;
        signOut.hidden = true;
        signIn.hidden = recover.hidden = false;
        status.textContent = confirmation;
      }
    } catch {
      if (!disposed && version === generation)
        status.textContent = 'Could not confirm sign out. Try again.';
    } finally {
      if (!disposed && version === generation) {
        busy = false;
        signOut.disabled = false;
        signIn.disabled = recover.disabled = admitted;
      }
    }
  };
  signOut.onclick = () => void runSignOut();
  backup.onclick = async () => {
    if (disposed || backup.hidden || backup.disabled || !api.openSharedRecoveryBackup) return;
    const version = generation;
    backup.disabled = true;
    try {
      await api.openSharedRecoveryBackup();
    } catch {
      if (!disposed && version === generation)
        status.textContent = 'Could not open workspace backup.';
    } finally {
      backup.disabled = false;
    }
  };
  reset.onclick = async () => {
    if (disposed || reset.hidden || reset.disabled || !api.openSharedAccountReset) return;
    const version = generation;
    reset.disabled = true;
    try {
      await api.openSharedAccountReset();
    } catch {
      if (!disposed && version === generation) status.textContent = 'Could not open account reset.';
    } finally {
      reset.disabled = false;
    }
  };
  administration.onclick = async () => {
    if (
      disposed ||
      administration.hidden ||
      administration.disabled ||
      !api.openSharedAdministration
    )
      return;
    const version = generation;
    administration.disabled = true;
    try {
      await api.openSharedAdministration();
    } catch {
      if (!disposed && version === generation)
        status.textContent = 'Could not open workspace administration.';
    } finally {
      administration.disabled = false;
    }
  };
  card.replaceChildren(
    title,
    detail,
    transport,
    status,
    signIn,
    recover,
    signOut,
    resumeAdmin,
    backup,
    reset,
    administration,
    layout,
  );
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    clearWorkspace();
    signIn.disabled = recover.disabled = resumeAdmin.disabled = signOut.disabled = true;
    window.removeEventListener('pagehide', dispose);
  };
  window.addEventListener('pagehide', dispose);
  if (initial) void run('admit');
  return dispose;
}
