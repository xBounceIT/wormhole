import type {
  AdminInventoryKind,
  AdminInventoryReply,
  AdminInventoryRequest,
  CreateSlotPort,
} from '../electron/vault-shared-admin-inventory.ts';
import { mountCreateSlot } from './vault-shared-create-slot.ts';
import {
  mountSharedGroupAdministration,
  type GroupAdminPort,
} from './vault-shared-group-administration.ts';
import type { NodeGrantAdministration } from '../electron/vault-shared-node-grants.ts';
import { mountSharedGrantAdministration } from './vault-shared-grant-administration.ts';
import type { GroupKeyPort } from '../electron/vault-shared-group-key.ts';
import type { MemberRotationPort } from '../electron/vault-shared-group-member-rotation.ts';
import { mountAccountSuspension } from './vault-account-suspension.ts';
import {
  mountSharedAccountResetIssue,
  type SharedAccountResetIssueApi,
} from './vault-shared-account-reset-screen.ts';
import type {
  AccountBoundaryRotationPort,
  AccountSuspensionPort,
  PersonalRootRecoveryPort,
} from '../electron/vault-account-suspension.ts';
import type {
  WorkspaceAccessPort,
  WorkspaceAccessRequest,
} from '../electron/vault-shared-access.ts';

export type SharedAdministrationApi = {
  adminInventory(request: AdminInventoryRequest): Promise<AdminInventoryReply>;
  createSlot?: CreateSlotPort;
  adminGroups?: GroupAdminPort;
  grantTargets?: NodeGrantAdministration['catalog'];
  nodeGrant?: NodeGrantAdministration['grant'];
  groupBoundaryGrant?: NodeGrantAdministration['boundary'];
  groupBoundaryRotation?: NodeGrantAdministration['rotation'];
  groupKey?: GroupKeyPort;
  memberRotation?: MemberRotationPort;
  workspaceAccess?: WorkspaceAccessPort;
  accountSuspension?: AccountSuspensionPort;
  accountBoundaryRotation?: AccountBoundaryRotationPort;
  personalRootRecovery?: PersonalRootRecoveryPort;
  resetContext?: SharedAccountResetIssueApi['resetContext'];
  issueReset?: SharedAccountResetIssueApi['issueReset'];
  contentProtectionAvailable?: boolean;
  close(): void;
};

const sections: Record<AdminInventoryKind, string> = {
  accounts: 'Accounts',
  slots: 'Credential slots',
  devices: 'Devices',
  'my-devices': 'My devices',
  sessions: 'Recorded sessions',
  'unencrypted-clients': 'Unencrypted clients',
  audit: 'Audit',
};

const accessLabels: Record<WorkspaceAccessRequest['action'], string> = {
  'disable-account': 'Disable account',
  'enable-account': 'Enable account',
  'revoke-device': 'Revoke device',
};

export function mountSharedAdministration(
  card: HTMLElement,
  api: SharedAdministrationApi,
  ownDevicesOnly = false,
) {
  const heading = document.createElement('h1');
  heading.textContent = ownDevicesOnly ? 'My devices' : 'Workspace administration';
  const sectionLabel = document.createElement('label');
  sectionLabel.textContent = 'Section';
  const section = document.createElement('select');
  for (const [value, label] of Object.entries(sections))
    if (!ownDevicesOnly || value === 'my-devices') section.add(new Option(label, value));
  sectionLabel.hidden = ownDevicesOnly;
  if (!ownDevicesOnly && api.adminGroups) section.add(new Option('Groups', 'groups'));
  const grantPort =
    !ownDevicesOnly && api.grantTargets && api.nodeGrant
      ? {
          catalog: api.grantTargets,
          grant: api.nodeGrant,
          boundary: api.groupBoundaryGrant,
          rotation: api.groupBoundaryRotation,
        }
      : undefined;
  if (grantPort && api.adminGroups) section.add(new Option('Grants', 'grants'));
  sectionLabel.append(section);
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  const accessNotice = document.createElement('p');
  accessNotice.setAttribute('role', 'status');
  const list = document.createElement('ul');
  list.className = 'shared-administration-list';
  const adminPanel = document.createElement('div');
  const actions = document.createElement('div');
  actions.className = 'shared-setup-actions';
  const button = (label: string) => {
    const element = document.createElement('button');
    element.type = 'button';
    element.className = 'startup-button startup-button-secondary';
    element.textContent = label;
    actions.append(element);
    return element;
  };
  const previous = button('Previous page');
  const next = button('Next page');
  const refresh = button('Refresh');
  const close = button('Close');
  card.replaceChildren(heading, sectionLabel, status, accessNotice, list, adminPanel, actions);

  let requests: AdminInventoryRequest[] = [];
  let nextRequest: AdminInventoryRequest | undefined;
  let disposed = false;
  let disposePanel: (() => void) | undefined;
  let reviewingAccess = false;
  const reviewAccess = async (
    change: WorkspaceAccessRequest,
    request: AdminInventoryRequest,
    trigger: HTMLButtonElement,
  ) => {
    const access = api.workspaceAccess;
    if (!access || disposed || reviewingAccess) return;
    reviewingAccess = true;
    accessNotice.textContent = '';
    previous.disabled = next.disabled = refresh.disabled = section.disabled = true;
    list.hidden = true;
    const finish = (notice: string) => {
      if (disposed) return;
      reviewingAccess = false;
      accessNotice.textContent = notice;
      adminPanel.replaceChildren();
      adminPanel.hidden = true;
      list.hidden = false;
      previous.disabled = requests.length < 2;
      next.disabled = !nextRequest;
      refresh.disabled = section.disabled = false;
      trigger.focus();
    };
    const outcome = (status: string) => {
      switch (status) {
        case 'busy':
          return 'The workspace is busy. Review the change again.';
        case 'stale':
        case 'unchanged':
          return 'Access has already changed. Refresh the list before trying again.';
        case 'unsupported':
          return 'Update the workspace schema to change access.';
        case 'personal-recovery-required':
          return 'Restore personal access before re-enabling this account.';
        default:
          return 'This access change is unavailable.';
      }
    };
    try {
      const result = await access(change);
      if (disposed) return;
      if (result.status !== 'review') {
        finish(outcome(result.status));
        return;
      }
      const { action, targetId, revision, name, login, currentDevice } = result.review;
      const summary = document.createElement('p');
      summary.textContent = [accessLabels[action], name, login, targetId]
        .filter(Boolean)
        .join(' · ');
      const detail = document.createElement('p');
      detail.textContent = currentDevice
        ? 'This device will be signed out and will require a new enrollment.'
        : action === 'disable-account'
          ? 'This account will lose access to the workspace. On supported workspaces, this device will rotate the keys it can administer while you are signed in. Restoring personal access can require re-enrollment.'
          : action === 'enable-account'
            ? 'This account can sign in again using an active device.'
            : 'This device will require a new enrollment.';
      const cancel = document.createElement('button');
      cancel.type = 'button';
      cancel.textContent = 'Cancel';
      cancel.className = 'startup-button startup-button-secondary';
      const confirm = document.createElement('button');
      confirm.type = 'button';
      confirm.textContent = accessLabels[action];
      confirm.className = 'startup-button';
      cancel.onclick = () => finish('');
      confirm.onclick = async () => {
        if (confirm.disabled || disposed) return;
        cancel.disabled = confirm.disabled = true;
        try {
          const result = await access({ action, targetId, revision });
          if (disposed) return;
          if (result.status !== 'changed') {
            finish(outcome(result.status));
            return;
          }
          finish(
            action === 'revoke-device'
              ? 'Device revoked.'
              : action === 'enable-account'
                ? 'Account enabled.'
                : 'Account disabled.',
          );
          if (!currentDevice) await load(request, requests.slice(0, -1));
        } catch {
          finish('Could not confirm the access change. Refresh the list to check its state.');
        }
      };
      adminPanel.replaceChildren(summary, detail, cancel, confirm);
      adminPanel.hidden = false;
      cancel.focus();
    } catch {
      finish('Could not review the access change.');
    }
  };
  const load = async (request: AdminInventoryRequest, history: AdminInventoryRequest[]) => {
    disposePanel?.();
    disposePanel = undefined;
    adminPanel.replaceChildren();
    adminPanel.hidden = true;
    nextRequest = undefined;
    previous.disabled = next.disabled = refresh.disabled = section.disabled = true;
    status.textContent = 'Loading…';
    list.replaceChildren();
    try {
      const result = await api.adminInventory(request);
      if (disposed) return;
      if (result.status !== 'ready') {
        requests = [];
        status.textContent =
          result.status === 'unsupported'
            ? 'Update the workspace schema to use administration.'
            : 'Workspace administration is unavailable for this account.';
        return;
      }
      requests = [...history, request];
      const { entries, next: cursor } = result.page;
      nextRequest = cursor ? { kind: request.kind, next: cursor } : undefined;
      status.textContent = entries.length ? `Page ${requests.length}` : 'No records on this page.';
      if (request.kind === 'slots' && !ownDevicesOnly && api.createSlot) {
        adminPanel.hidden = false;
        disposePanel = mountCreateSlot(
          adminPanel,
          api.createSlot,
          (busy) => {
            section.disabled = refresh.disabled = busy;
            previous.disabled = busy || requests.length < 2;
            next.disabled = busy || !nextRequest;
          },
          (name) => {
            accessNotice.textContent = `Created credential slot “${name}”.`;
            void load({ kind: 'slots' }, []);
          },
        );
      }
      if (!entries.length && !request.next && request.kind === 'unencrypted-clients')
        status.textContent = 'No unencrypted clients connected.';
      for (const record of entries) {
        const row = document.createElement('li');
        const label = document.createElement('strong');
        const detail = document.createElement('p');
        const localTime = record.at ? new Date(record.at).toLocaleString() : '';
        if (request.kind === 'slots') {
          label.textContent = record.name ?? record.id;
          detail.textContent = [
            record.protocol?.toUpperCase(),
            record.allowSelfService
              ? 'Users can choose a credential'
              : 'Assigned by an administrator',
          ].join(' · ');
        } else if (request.kind === 'accounts') {
          label.textContent = record.name || record.login || record.id;
          detail.textContent = [record.name ? record.login : '', record.role, record.status]
            .filter(Boolean)
            .join(' · ');
        } else if (
          request.kind === 'devices' ||
          request.kind === 'my-devices' ||
          request.kind === 'unencrypted-clients'
        ) {
          label.textContent = record.name || record.id;
          detail.textContent = [
            record.login,
            record.status,
            request.kind === 'unencrypted-clients' ? `Connected since ${localTime}` : localTime,
            record.name ? record.id : '',
          ]
            .filter(Boolean)
            .join(' · ');
        } else if (request.kind === 'sessions') {
          label.textContent = record.login ?? record.id;
          detail.textContent = [
            localTime,
            record.appVersion,
            record.transport,
            record.deviceId,
            record.id,
          ].join(' · ');
        } else {
          label.textContent = `${record.action} · ${record.status}`;
          detail.textContent = [
            localTime,
            record.login || record.actorId,
            record.source,
            record.sessionId,
          ].join(' · ');
        }
        row.append(label, detail);
        const accessAction =
          request.kind === 'accounts'
            ? record.status === 'enabled'
              ? 'disable-account'
              : 'enable-account'
            : (request.kind === 'devices' || request.kind === 'my-devices') &&
                record.status !== 'revoked'
              ? 'revoke-device'
              : undefined;
        if (api.workspaceAccess && accessAction) {
          const change = document.createElement('button');
          change.type = 'button';
          change.className = 'startup-button startup-button-secondary';
          change.textContent = accessLabels[accessAction];
          change.setAttribute('aria-label', accessLabels[accessAction] + ' · ' + label.textContent);
          change.onclick = () =>
            void reviewAccess({ action: accessAction, targetId: record.id }, request, change);
          row.append(change);
        }
        const suspension = api.accountSuspension;
        if (suspension && request.kind === 'accounts' && record.status === 'disabled') {
          const review = document.createElement('button');
          review.type = 'button';
          review.className = 'startup-button startup-button-secondary';
          review.textContent = 'Review access at suspension';
          review.setAttribute('aria-label', review.textContent + ' · ' + label.textContent);
          review.onclick = () => {
            previous.hidden = next.hidden = refresh.hidden = list.hidden = status.hidden = true;
            section.disabled = true;
            accessNotice.textContent = '';
            adminPanel.hidden = false;
            const closeReview = () => {
              disposePanel?.();
              disposePanel = undefined;
              adminPanel.hidden = true;
              previous.hidden = next.hidden = refresh.hidden = list.hidden = status.hidden = false;
              section.disabled = false;
              review.focus();
            };
            const groups = api.adminGroups;
            const { resetContext, issueReset } = api;
            const openSuspension = (selected?: true) => {
              disposePanel?.();
              disposePanel = mountAccountSuspension(
                adminPanel,
                suspension,
                record.id,
                label.textContent ?? record.login ?? record.id,
                closeReview,
                api.accountBoundaryRotation,
                {
                  selected,
                  open: groups
                    ? (entry, suspensionRevision) => {
                        disposePanel?.();
                        disposePanel = mountSharedGroupAdministration(
                          adminPanel,
                          groups,
                          () => {},
                          api.groupKey,
                          api.memberRotation,
                          {
                            group: { id: entry.id, name: entry.name, revision: entry.revision },
                            accountId: record.id,
                            suspension: suspensionRevision,
                            jobId: entry.jobId,
                            back: () => openSuspension(true),
                          },
                        );
                      }
                    : undefined,
                },
                api.personalRootRecovery,
                resetContext && issueReset
                  ? (suspensionRevision) => {
                      disposePanel?.();
                      const lifetime = new AbortController();
                      disposePanel = () => lifetime.abort();
                      adminPanel.textContent = 'Opening re-enrollment…';
                      void mountSharedAccountResetIssue(
                        adminPanel,
                        {
                          resetContext,
                          issueReset,
                          contentProtectionAvailable: api.contentProtectionAvailable,
                          close: async () => {
                            openSuspension();
                            return true;
                          },
                        },
                        {
                          targetLogin: record.login ?? '',
                          targetUserId: record.id,
                          suspension: suspensionRevision,
                          signal: lifetime.signal,
                        },
                      ).catch(() => {
                        if (lifetime.signal.aborted) return;
                        openSuspension();
                        accessNotice.textContent = 'Could not open account re-enrollment.';
                      });
                    }
                  : undefined,
              );
            };
            openSuspension();
          };
          row.append(review);
        }
        list.append(row);
      }
    } catch {
      requests = [];
      if (!disposed) status.textContent = 'Could not load workspace administration.';
    } finally {
      if (!disposed) {
        previous.disabled = requests.length < 2;
        next.disabled = !nextRequest;
        refresh.disabled = section.disabled = false;
      }
    }
  };
  const start = () => {
    accessNotice.textContent = '';
    disposePanel?.();
    disposePanel = undefined;
    const groups = section.value === 'groups' ? api.adminGroups : undefined;
    const grants = section.value === 'grants' ? grantPort : undefined;
    const customPanel = !!(groups || grants);
    previous.hidden = next.hidden = refresh.hidden = list.hidden = status.hidden = customPanel;
    adminPanel.hidden = !customPanel;
    if (customPanel) {
      list.replaceChildren();
      const setBusy = (busy: boolean) => {
        section.disabled = busy;
      };
      if (groups)
        disposePanel = mountSharedGroupAdministration(
          adminPanel,
          groups,
          setBusy,
          api.groupKey,
          api.memberRotation,
        );
      else if (grants && api.adminGroups)
        disposePanel = mountSharedGrantAdministration(adminPanel, grants, api.adminGroups, setBusy);
      return;
    }
    void load({ kind: section.value as AdminInventoryKind }, []);
  };
  section.onchange = refresh.onclick = start;
  next.onclick = () => {
    if (nextRequest) void load(nextRequest, requests);
  };
  previous.onclick = () => {
    if (requests.length > 1) void load(requests[requests.length - 2]!, requests.slice(0, -2));
  };
  close.onclick = () => api.close();
  window.addEventListener(
    'pagehide',
    () => {
      disposed = true;
      disposePanel?.();
      list.replaceChildren();
    },
    { once: true },
  );
  start();
}
