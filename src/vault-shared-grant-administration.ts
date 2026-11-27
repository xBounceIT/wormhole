import type { SharedCatalogCursor, SharedCatalogNode } from '../electron/vault-shared-catalog.ts';
import type { GroupEntry } from '../electron/vault-shared-admin-groups.ts';
import type {
  GroupBoundaryGrantRequest,
  GroupBoundaryGrantStatus,
  GroupBoundaryMask,
} from '../electron/vault-shared-group-boundary-grant.ts';
import {
  parseNodeGrantRequest,
  workspacePermissionLabels,
  type DirectNodeGrant,
  type GrantKind,
  type NodeGrantAdministration,
  type NodeGrantRequest,
  type NodeGrantStatus,
} from '../electron/vault-shared-node-grants.ts';
import type { GroupAdminPort } from './vault-shared-group-administration.ts';

const grantMessages: Record<NodeGrantStatus, string> = {
  unavailable: 'You need Manage on a shared item to administer its grants.',
  unsupported: 'Update the workspace schema to manage grants.',
  busy: 'The workspace is busy. Try again.',
  stale: 'Permissions or the selected item changed. Reopen the item and review its grants.',
  changed: 'Grant saved.',
  unchanged: 'This grant is already current.',
  'subject-unavailable': 'The selected group or enabled account is unavailable.',
  'signed-grant': 'Changes to this signed grant require its signing workflow.',
  'cannot-delegate': 'You can only add permissions you currently have on this item.',
};

const boundaryMessages: Record<GroupBoundaryGrantStatus, string> = {
  unavailable:
    'Sharing boundary keys requires workspace custody and Manage on the shared boundary.',
  unsupported: 'Update the workspace schema to share boundary keys.',
  busy: 'The workspace is busy. Try again.',
  stale: 'The group or boundary changed. Reopen the shared item and review the grant again.',
  'key-required': 'Issue a key to this group in Groups before sharing a boundary.',
  'rotation-required': 'This change requires rotating the group or boundary keys.',
  unchanged: 'This boundary grant is already current.',
  changed: 'Boundary grant saved and keys issued.',
};

const boundaryPermissions = { 0: 'None', 1: 'View', 2: 'Use', 3: 'View and Use' } as const;

type GrantTarget = SharedCatalogNode & { grantRevision: string };

export function mountSharedGrantAdministration(
  root: HTMLElement,
  port: NodeGrantAdministration,
  groups: GroupAdminPort,
  setBusy: (busy: boolean) => void,
) {
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  const controls = document.createElement('fieldset');
  controls.setAttribute('aria-label', 'Direct grants');
  root.replaceChildren(status, controls);
  let disposed = false;

  const button = (label: string, click: () => void) => {
    const element = document.createElement('button');
    element.type = 'button';
    element.className = 'startup-button startup-button-secondary';
    element.textContent = label;
    element.onclick = click;
    return element;
  };
  const run = async (load: () => Promise<void>) => {
    if (disposed || controls.disabled) return;
    controls.disabled = true;
    setBusy(true);
    status.textContent = 'Working…';
    try {
      await load();
    } catch {
      if (!disposed) status.textContent = 'Could not load or save grants.';
    } finally {
      controls.disabled = false;
      if (!disposed) setBusy(false);
    }
  };

  const catalog = (cursor?: SharedCatalogCursor) =>
    void run(async () => {
      controls.replaceChildren(button('Reload shared items', () => catalog()));
      const page = await port.catalog({
        limit: 32,
        ...(cursor ?? { after: '', epoch: '0', changeSeq: '0' }),
      });
      if (disposed) return;
      const picks = page.nodes.filter((node): node is GrantTarget => !!node.grantRevision);
      for (const node of picks) {
        const item = button(node.name, () => open(node, 'account'));
        item.title = `${node.kind === 0 ? 'Folder' : 'Connection'} · ${node.id}`;
        controls.append(item);
      }
      status.textContent = picks.length
        ? 'Choose a shared item.'
        : 'No manageable items on this page.';
      if (page.next) controls.append(button('More shared items', () => catalog(page.next!)));
    });

  const open = (
    node: GrantTarget,
    kind: GrantKind,
    cursor?: { after: string; epoch: string; changeSeq: string },
  ) => void run(() => renderGrants(node, kind, cursor));

  const loadGroupPicker = async (form: HTMLElement, select: HTMLSelectElement) => {
    const available = new Map<string, GroupEntry>();
    let next: string | undefined;
    const more = button('More groups', () => void run(() => load(next, true)));
    const load = async (after?: string, announce = false) => {
      const reply = await groups({ action: 'list', ...(after ? { after } : {}) });
      if (disposed) return;
      available.clear();
      select.replaceChildren(new Option('Choose a group', ''));
      if (reply.status === 'ready') {
        for (const item of reply.page.entries as GroupEntry[]) {
          available.set(item.id, item);
          select.add(new Option(item.name, item.id));
        }
        next = reply.page.after;
        if (announce)
          status.textContent = available.size ? 'Choose a group.' : 'No groups on this page.';
      } else {
        next = undefined;
        status.textContent = 'Could not load groups. Try again.';
      }
      select.disabled = !available.size;
      more.hidden = !next;
    };
    form.append(
      more,
      button('First groups page', () => void run(() => load(undefined, true))),
    );
    await load();
    return available;
  };

  const renderBoundary = async (node: GrantTarget, rotation = false) => {
    const change = rotation ? port.rotation : port.boundary;
    const boundaryId = node.grantBoundary;
    if (!change || !boundaryId) return;
    const back = button('Back to item grants', () => open(node, 'group'));
    const title = document.createElement('h2');
    title.textContent = `${node.name} · ${rotation ? 'Rotate boundary keys' : 'Boundary keys'}`;
    const scope = document.createElement('p');
    scope.textContent = rotation
      ? 'This replaces the keys for the permissions you remove across the entire shared boundary. Access already used to copy a secret cannot be recalled.'
      : 'Sharing keys applies to the entire boundary. Access to each shared item also requires its item permissions.';
    const select = document.createElement('select');
    select.setAttribute(
      'aria-label',
      rotation ? 'Group losing boundary permissions' : 'Group receiving boundary keys',
    );
    const mask = document.createElement('select');
    mask.setAttribute('aria-label', 'Boundary permissions');
    if (rotation) mask.add(new Option('Choose retained permissions', ''));
    for (const value of rotation ? ([0, 1, 2] as const) : ([1, 2, 3] as const)) {
      mask.add(new Option(boundaryPermissions[value], String(value)));
    }
    const form = document.createElement('div');
    form.append(select, mask);
    controls.replaceChildren(back, title, scope, form);
    status.textContent = rotation
      ? 'Choose a group and the boundary permissions it should keep.'
      : 'Choose a group and the boundary permissions to grant.';
    const groups = await loadGroupPicker(form, select);
    if (disposed) return;
    form.append(
      button(rotation ? 'Review boundary rotation' : 'Review boundary grant', () => {
        const group = groups.get(select.value);
        if (!group) {
          status.textContent = 'Choose a group.';
          return;
        }
        if (mask.value === '') {
          status.textContent = 'Choose the permissions the group should keep.';
          return;
        }
        const request: GroupBoundaryGrantRequest = {
          nodeId: node.id,
          nodeRevision: node.grantRevision,
          boundaryId,
          groupId: group.id,
          groupRevision: group.revision,
          mask: Number(mask.value) as 0 | GroupBoundaryMask,
        };
        void run(async () => {
          const result = await change(request);
          if (disposed) return;
          if (result.status !== 'review') {
            status.textContent = boundaryMessages[result.status];
            return;
          }
          const { review, previousMask, members } = result.preview;
          const changes = document.createElement('p');
          changes.textContent = `${group.name} · ${boundaryPermissions[previousMask]} → ${boundaryPermissions[request.mask]}`;
          const list = document.createElement('ul');
          list.setAttribute('aria-label', 'Certified group members receiving access');
          for (const member of members) {
            const row = document.createElement('li');
            row.textContent = member.login;
            list.append(row);
          }
          controls.replaceChildren(
            back,
            title,
            scope,
            changes,
            ...(members.length ? [list] : []),
            button(
              rotation ? 'Confirm and rotate boundary keys' : 'Confirm and issue boundary keys',
              () =>
                void run(async () => {
                  const saved = await change({ ...request, review });
                  if (disposed) return;
                  controls.replaceChildren(back, title, scope);
                  status.textContent =
                    saved.status === 'review'
                      ? 'The grant changed. Review it again.'
                      : rotation && saved.status === 'changed'
                        ? 'Boundary grant reduced and keys rotated.'
                        : boundaryMessages[saved.status];
                }),
            ),
          );
          status.textContent = rotation
            ? 'Review the permission change before replacing the boundary keys.'
            : 'Review the boundary permissions and certified recipients.';
        });
      }),
    );
  };

  const renderGrants = async (
    node: GrantTarget,
    kind: GrantKind,
    cursor?: { after: string; epoch: string; changeSeq: string },
  ) => {
    const back = button('Back to shared items', () => catalog());
    controls.replaceChildren(back);
    const target = { nodeId: node.id, nodeRevision: node.grantRevision, kind };
    const result = await port.grant(cursor ? { ...target, ...cursor } : target);
    if (disposed) return;
    if (result.status !== 'ready') {
      status.textContent = grantMessages[result.status];
      return;
    }
    const { epoch, changeSeq, after, grants } = result.page;
    const title = document.createElement('h2');
    title.textContent = node.name;
    const explanation = document.createElement('p');
    explanation.textContent =
      'Direct grants are listed here. Folder grants apply to descendants. Write implies Reveal.';
    const tabs = document.createElement('div');
    tabs.className = 'shared-setup-actions';
    const accounts = button('Account grants', () => open(node, 'account'));
    const team = button('Group grants', () => open(node, 'group'));
    accounts.setAttribute('aria-pressed', String(kind === 'account'));
    team.setAttribute('aria-pressed', String(kind === 'group'));
    tabs.append(accounts, team);
    controls.append(title, explanation, tabs);
    if (kind === 'group' && port.boundary && node.grantBoundary)
      tabs.append(button('Boundary keys', () => void run(() => renderBoundary(node))));
    if (kind === 'group' && port.rotation && node.grantBoundary)
      tabs.append(button('Rotate boundary keys', () => void run(() => renderBoundary(node, true))));

    const save = (
      change: { subjectId: string } | { login: string },
      grantRevision: string,
      mask: number,
    ) => {
      const request: NodeGrantRequest = {
        ...target,
        epoch,
        changeSeq,
        ...change,
        grantRevision,
        mask,
      };
      if (!parseNodeGrantRequest(request)) {
        status.textContent = 'Choose an account or group and at least one permission.';
        return;
      }
      void run(async () => {
        const reply = await port.grant(request);
        if (disposed) return;
        if (reply.status === 'changed' || reply.status === 'unchanged') {
          await renderGrants(node, kind);
        } else if (reply.status !== 'ready') {
          status.textContent = grantMessages[reply.status];
          if (reply.status === 'stale' || reply.status === 'unavailable')
            controls.replaceChildren(back);
        }
      });
    };

    const editor = (grant?: DirectNodeGrant) => {
      const editor = document.createElement('fieldset');
      const caption = document.createElement('legend');
      caption.textContent =
        grant?.label ?? (kind === 'account' ? 'New account grant' : 'New group grant');
      editor.append(caption);
      const subject = document.createElement(kind === 'account' ? 'input' : 'select');
      if (!grant) {
        subject.setAttribute(
          'aria-label',
          kind === 'account' ? 'Account sign-in name' : 'Choose group',
        );
        editor.append(subject);
      }
      const options = workspacePermissionLabels.map((name, bit) => {
        const label = document.createElement('label');
        const input = document.createElement('input');
        input.type = 'checkbox';
        input.checked = !!((grant?.mask ?? 0) & (1 << bit));
        label.append(input, name);
        editor.append(label);
        return input;
      });
      editor.append(
        button(grant ? 'Save permissions' : 'Add grant', () => {
          const mask = options.reduce(
            (mask, input, bit) => mask | (input.checked ? 1 << bit : 0),
            0,
          );
          if (!mask) {
            status.textContent = 'Choose at least one permission or revoke the grant.';
            return;
          }
          const ref = grant
            ? { subjectId: grant.subjectId }
            : kind === 'group'
              ? { subjectId: subject.value }
              : { login: subject.value };
          save(ref, grant?.revision ?? '0', mask);
        }),
      );
      if (grant)
        editor.append(
          button('Revoke grant', () => save({ subjectId: grant.subjectId }, grant.revision, 0)),
        );
      controls.append(editor);
      return { editor, subject };
    };

    for (const grant of grants) editor(grant);
    if (after)
      controls.append(
        button('More direct grants', () => open(node, kind, { after, epoch, changeSeq })),
      );
    const form = editor();
    status.textContent = grants.length ? '' : 'No direct grants on this page.';
    if (form.subject instanceof HTMLSelectElement) await loadGroupPicker(form.editor, form.subject);
  };

  catalog();
  return () => {
    disposed = true;
    root.replaceChildren();
  };
}
