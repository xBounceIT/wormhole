import type {
  GroupEntry,
  GroupMember,
  GroupReply,
  GroupRequest,
} from '../electron/vault-shared-admin-groups.ts';
import type {
  GroupKeyPort,
  GroupKeyRequest,
  GroupKeyStatus,
} from '../electron/vault-shared-group-key.ts';
import type {
  MemberRotationPort,
  MemberRotationReply,
  MemberRotationRequest,
  MemberRotationStatus,
} from '../electron/vault-shared-group-member-rotation.ts';

export type GroupAdminPort = (request: GroupRequest) => Promise<GroupReply>;

type GroupReviewSelection = {
  group: GroupEntry;
  accountId: string;
  suspension: string;
  jobId?: string;
  back: () => void;
};

const messages = {
  stale: 'The group changed. Refresh the list and try again.',
  busy: 'The workspace is busy. Try again.',
  unsupported: 'Update the workspace schema to manage groups.',
  unavailable: 'Group administration is unavailable for this account.',
  'group-in-use': 'Remove the group members and grants before deleting it.',
  'key-change-required': 'Membership changes for this group require updating its keys.',
  'account-unavailable': 'No enabled account has that sign-in name.',
} as const;

const groupKeyMessages: Record<GroupKeyStatus, string> = {
  busy: 'The workspace is busy. Try again.',
  stale:
    'The group or its certified recipients changed. Reopen the group and review the recipients.',
  unavailable: 'Group key issuance requires organisation custody over verified TLS.',
  unsupported: 'Update the workspace schema to issue group keys.',
  'no-members': 'Add an enabled member before issuing a group key.',
  'too-large': 'This group exceeds the size supported for key issuance.',
  incomplete: 'All enabled members need certified accounts and a compatible key configuration.',
  provisioned: 'This group already has a certified encryption key.',
  issued: 'Group encryption key issued.',
};

const memberRotationMessages: Record<MemberRotationStatus, string> = {
  unsupported: 'Update the workspace schema to remove a member from a keyed group.',
  unavailable:
    'A custodian with access to the affected shared boundaries must continue the rotation.',
  incomplete: 'The remaining members need current certified accounts before the key can rotate.',
  'rotation-pending': 'Finish the pending key rotation before removing another member.',
  busy: 'The workspace is busy. Try the rotation again.',
  stale: 'The group or its boundary grants changed. Review the removal again.',
  'account-unavailable': messages['account-unavailable'],
  unchanged: 'This account already belongs to the group.',
};

const rotationMessage = (reply: MemberRotationReply, fallback: string) =>
  Object.hasOwn(memberRotationMessages, reply.status)
    ? memberRotationMessages[reply.status as MemberRotationStatus]
    : fallback;

export function mountSharedGroupAdministration(
  root: HTMLElement,
  admin: GroupAdminPort,
  setBusy: (busy: boolean) => void,
  groupKey?: GroupKeyPort,
  memberRotation?: MemberRotationPort,
  selection?: GroupReviewSelection,
) {
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  const controls = document.createElement('fieldset');
  controls.setAttribute('aria-label', 'Groups');
  root.replaceChildren(status, controls);
  let disposed = false;
  let pending = false;
  const button = (label: string, run: () => void) => {
    const element = document.createElement('button');
    element.type = 'button';
    element.className = 'startup-button startup-button-secondary';
    element.textContent = label;
    element.onclick = run;
    return element;
  };
  const input = (label: string, submit: string, run: (value: string) => void, initial = '') => {
    const form = document.createElement('form');
    const field = document.createElement('input');
    field.setAttribute('aria-label', label);
    field.value = initial;
    field.required = true;
    field.maxLength = Math.max(initial.length, 256);
    const save = button(submit, () => {});
    save.type = 'submit';
    save.onclick = null;
    form.append(field, save);
    form.onsubmit = (event) => {
      event.preventDefault();
      const value = label === 'Account sign-in name' ? field.value : field.value.trim();
      if (!value || /\p{Cc}/u.test(value) || new TextEncoder().encode(value).length > 256) {
        status.textContent = `Enter a valid ${label.toLowerCase()}.`;
        return;
      }
      run(value);
    };
    return form;
  };

  const run = async <T>(operation: () => Promise<T>): Promise<T | undefined> => {
    if (pending || disposed) return;
    pending = controls.disabled = true;
    setBusy(true);
    status.textContent = 'Working…';
    try {
      const result = await operation();
      if (disposed) return;
      return result;
    } catch {
      if (!disposed) status.textContent = 'Could not complete the group request.';
    } finally {
      pending = controls.disabled = false;
      if (!disposed) setBusy(false);
    }
  };
  const call = async (request: GroupRequest) => {
    const result = await run(() => admin(request));
    if (result)
      status.textContent =
        result.status === 'ready'
          ? ''
          : result.status === 'changed' || result.status === 'unchanged'
            ? 'Group saved.'
            : messages[result.status];
    return result;
  };

  const openGroups = async (after?: string) => {
    controls.replaceChildren();
    const result = await call({ action: 'list', ...(after ? { after } : {}) });
    if (disposed) return;
    if (result?.status !== 'ready') {
      controls.replaceChildren(button('Refresh groups', () => void openGroups()));
      return;
    }
    const create = input('Group name', 'Create group', (name) => void createGroup(name));
    const list = document.createElement('ul');
    list.className = 'shared-administration-list';
    for (const group of result.page.entries as GroupEntry[]) {
      const row = document.createElement('li');
      const open = button(group.name, () => void openMembers(group));
      open.title = group.id;
      row.append(open);
      list.append(row);
    }
    controls.replaceChildren(create, list);
    if (!result.page.entries.length) status.textContent = 'No groups on this page.';
    if (after) controls.append(button('First groups page', () => void openGroups()));
    if (result.page.after)
      controls.append(button('More groups', () => void openGroups(result.page.after)));
  };

  // Retain a create ID while the same form and name are in use, including retries.
  let creation: { name: string; id: string } | undefined;
  const createGroup = async (name: string) => {
    if (creation?.name !== name) creation = { name, id: crypto.randomUUID() };
    const result = await call({ action: 'create', groupId: creation.id, name });
    if (result?.status === 'changed' || result?.status === 'unchanged') {
      creation = undefined;
      await openGroups();
    }
  };

  const openMembers = async (group: GroupEntry, after?: string) => {
    controls.replaceChildren();
    const ref = { groupId: group.id, revision: group.revision };
    const result = await call({ action: 'members', ...ref, ...(after ? { after } : {}) });
    if (disposed) return;
    const back = selection
      ? button('Back to groups at suspension', selection.back)
      : button('Back to groups', () => void openGroups());
    if (result?.status !== 'ready') {
      controls.replaceChildren(back);
      return;
    }
    const title = document.createElement('h2');
    title.textContent = group.name;
    const memberReview = document.createElement('div');
    const resumeRotation = async (jobId?: string, expected = Number.POSITIVE_INFINITY) => {
      if (!memberRotation) return;
      memberReview.replaceChildren();
      while (!disposed) {
        const request: MemberRotationRequest = {
          action: 'resume',
          groupId: group.id,
          ...(jobId ? { jobId } : {}),
        };
        const progress = await run(() => memberRotation(request));
        if (!progress || disposed) return;
        if (progress.status === 'complete') {
          if (selection) {
            selection.back();
            return;
          }
          await openGroups();
          if (!disposed) status.textContent = 'Group key rotation complete.';
          return;
        }
        if (progress.status === 'roster-changed') {
          status.textContent =
            'Certified group recipients changed. Review them before resuming the rotation.';
          memberReview.append(
            button(
              'Review changed recipients',
              () =>
                void reviewReconciliation({
                  action: 'reconcile',
                  groupId: group.id,
                  jobId: progress.receipt.jobId,
                }),
            ),
          );
          return;
        }
        if (progress.status !== 'pending') {
          status.textContent = rotationMessage(progress, 'Could not resume the key rotation.');
          return;
        }
        if (progress.receipt.pending >= expected) {
          status.textContent =
            'Some boundaries are still pending. Choose Resume key rotation to continue.';
          return;
        }
        jobId = progress.receipt.jobId;
        expected = progress.receipt.pending;
      }
    };
    const reviewReconciliation = async (
      request: Extract<MemberRotationRequest, { action: 'reconcile' }>,
    ) => {
      if (!memberRotation) return;
      memberReview.replaceChildren();
      const result = await run(() => memberRotation(request));
      if (!result || disposed) return;
      if (result.status === 'reconciled' || result.status === 'unchanged') {
        await resumeRotation(request.jobId);
        return;
      }
      if (result.status !== 'reconcile-review') {
        status.textContent =
          result.status === 'stale'
            ? 'The recipients or boundary scope changed. Resume rotation to review again.'
            : rotationMessage(result, 'Could not review the changed recipients.');
        return;
      }
      const { groupName, members, boundaries, review } = result.reconciliation;
      const scope = document.createElement('p');
      scope.textContent = `${groupName} needs a new group key. ${boundaries} shared ${boundaries === 1 ? 'boundary is' : 'boundaries are'} queued for rotation.`;
      const recipients = document.createElement('ul');
      recipients.setAttribute('aria-label', 'Certified group recipients');
      for (const member of members) {
        const item = document.createElement('li');
        item.textContent = member.login;
        recipients.append(item);
      }
      status.textContent = members.length
        ? 'Confirm the certified recipients for the replacement group key.'
        : 'Confirm the replacement group key for organisation recovery.';
      memberReview.append(scope);
      if (members.length) memberReview.append(recipients);
      memberReview.append(
        button(
          'Confirm recipients and resume',
          () => void reviewReconciliation({ ...request, review }),
        ),
      );
    };
    const reviewRemoval = async (
      request: Extract<MemberRotationRequest, { action: 'remove' }>,
      login: string,
      suspended: boolean,
    ) => {
      if (!memberRotation) return;
      memberReview.replaceChildren();
      const result = await run(() => memberRotation(request));
      if (!result || disposed) return;
      if (result.status === 'rotated') {
        controls.replaceChildren(
          title,
          back,
          button('Resume key rotation', () => void resumeRotation(result.receipt.jobId)),
          memberReview,
        );
        if (suspended && result.receipt.pending > 0)
          status.textContent =
            'Key rotation queued. Queue any other groups for this account, then resume.';
        else await resumeRotation(result.receipt.jobId, result.receipt.pending);
        return;
      }
      if (result.status !== 'review') {
        status.textContent =
          request.suspension && result.status === 'stale'
            ? 'The suspension or group changed. Return to the suspension inventory and review again.'
            : rotationMessage(result, 'Could not review the member removal.');
        return;
      }
      const { remaining, boundaries, review } = result.preview;
      const scope = document.createElement('p');
      scope.textContent = `Remove ${login}. ${boundaries} shared ${boundaries === 1 ? 'boundary needs' : 'boundaries need'} new keys.`;
      const recipients = document.createElement('ul');
      recipients.setAttribute('aria-label', 'Remaining certified group members');
      for (const member of remaining) {
        const item = document.createElement('li');
        item.textContent = member.login;
        recipients.append(item);
      }
      status.textContent = suspended
        ? 'Confirm the member removal and queue the boundary keys.'
        : 'Confirm the member removal and key rotation.';
      memberReview.append(scope);
      if (remaining.length) memberReview.append(recipients);
      memberReview.append(
        button(
          suspended
            ? 'Confirm member removal and queue keys'
            : 'Confirm member removal and rotate keys',
          () => void reviewRemoval({ ...request, review }, login, suspended),
        ),
      );
    };
    const reviewAddition = async (request: Extract<MemberRotationRequest, { action: 'add' }>) => {
      if (!memberRotation) return;
      memberReview.replaceChildren();
      const result = await run(() => memberRotation(request));
      if (!result || disposed) return;
      switch (result.status) {
        case 'review-add': {
          const { member, boundaries, review } = result.addition;
          const scope = document.createElement('p');
          scope.textContent = `Add ${member.login}. This grants access to group keys for ${boundaries} shared ${boundaries === 1 ? 'boundary' : 'boundaries'}.`;
          status.textContent = 'Confirm the member addition.';
          memberReview.append(
            scope,
            button('Confirm member addition', () => void reviewAddition({ ...request, review })),
          );
          break;
        }
        case 'added':
          await openMembers({ ...group, revision: (BigInt(group.revision) + 1n).toString() });
          if (!disposed) status.textContent = 'Member added and group keys updated.';
          break;
        case 'unsupported':
          status.textContent = 'Update the workspace schema to add a member to a keyed group.';
          break;
        case 'unavailable':
          status.textContent =
            'Adding a member requires organisation custody and access to the affected boundaries.';
          break;
        case 'stale':
          status.textContent =
            'The group or its boundary grants changed. Review the addition again.';
          break;
        case 'rotation-pending':
          status.textContent = 'Finish the pending key rotation before adding a member.';
          break;
        default:
          status.textContent = rotationMessage(result, 'Could not review the member addition.');
      }
    };
    const change = async (request: GroupRequest) => {
      memberReview.replaceChildren();
      const result = await call(request);
      if (
        result?.status === 'key-change-required' &&
        request.action === 'add-member' &&
        memberRotation
      ) {
        await reviewAddition({
          action: 'add',
          ...ref,
          jobId: crypto.randomUUID(),
          login: request.login,
        });
        return;
      }
      if (result?.status === 'stale' || result?.status === 'unavailable') {
        controls.replaceChildren(back);
        return;
      }
      if (result?.status !== 'changed' && result?.status !== 'unchanged') return;
      if (request.action === 'delete') {
        await openGroups();
        return;
      }
      const revision = (
        BigInt(group.revision) + (result.status === 'changed' ? 1n : 0n)
      ).toString();
      await openMembers({
        id: group.id,
        revision,
        name: request.action === 'rename' ? request.name : group.name,
      });
    };
    const list = document.createElement('ul');
    list.className = 'shared-administration-list';
    for (const member of result.page.entries as GroupMember[]) {
      if (selection && (selection.jobId || member.id !== selection.accountId)) continue;
      const row = document.createElement('li');
      const label = document.createElement('span');
      label.textContent =
        member.status === 'disabled' ? `${member.login} (disabled)` : member.login;
      row.append(label);
      list.append(row);
      if (selection && member.status !== 'disabled') {
        status.textContent = 'This account is enabled. Return to the suspension inventory.';
        continue;
      }
      if (selection) {
        if (memberRotation)
          row.append(
            button(
              'Review member removal',
              () =>
                void reviewRemoval(
                  {
                    action: 'remove',
                    ...ref,
                    jobId: crypto.randomUUID(),
                    memberId: member.id,
                    suspension: selection.suspension,
                  },
                  member.login,
                  true,
                ),
            ),
          );
        continue;
      }
      const remove = button('Remove', () => {
        const request = { action: 'remove-member', ...ref, memberId: member.id } as const;
        if (!memberRotation) {
          void change(request);
          return;
        }
        void (async () => {
          memberReview.replaceChildren();
          const result = await call(request);
          if (disposed) return;
          if (result?.status === 'key-change-required') {
            const selection = {
              action: 'remove',
              ...ref,
              jobId: crypto.randomUUID(),
              memberId: member.id,
            } as const;
            memberReview.append(
              button(
                'Review member removal',
                () => void reviewRemoval(selection, member.login, member.status === 'disabled'),
              ),
            );
          } else if (result?.status === 'changed' || result?.status === 'unchanged') {
            const revision = (
              BigInt(group.revision) + (result.status === 'changed' ? 1n : 0n)
            ).toString();
            await openMembers({ ...group, revision });
          } else if (result?.status === 'stale' || result?.status === 'unavailable') {
            controls.replaceChildren(back);
          }
        })();
      });
      remove.setAttribute('aria-label', `Remove ${member.login}`);
      row.append(remove);
    }
    controls.replaceChildren(title, back);
    if (selection) {
      if (!selection.jobId) controls.append(list);
    } else {
      const rename = input(
        'Group name',
        'Rename group',
        (name) => void change({ action: 'rename', ...ref, name }),
        group.name,
      );
      const add = input(
        'Account sign-in name',
        'Add member',
        (login) => void change({ action: 'add-member', ...ref, login }),
      );
      controls.append(
        rename,
        add,
        list,
        button('Delete group', () => void change({ action: 'delete', ...ref })),
      );
    }
    if (memberRotation && (!selection || selection.jobId))
      controls.append(button('Resume key rotation', () => void resumeRotation(selection?.jobId)));
    if (memberRotation) controls.append(memberReview);
    if (groupKey && !selection) {
      const keyReview = document.createElement('div');
      const review = async (request: GroupKeyRequest) => {
        keyReview.replaceChildren();
        const result = await run(() => groupKey(request));
        if (!result || disposed) return;
        if (result.status !== 'review') {
          status.textContent = groupKeyMessages[result.status];
          if (result.status === 'issued' || result.status === 'stale')
            controls.replaceChildren(title, back);
          return;
        }
        const recipients = document.createElement('ul');
        recipients.className = 'shared-administration-list';
        for (const member of result.preview.members) {
          const item = document.createElement('li');
          item.textContent = member.login;
          recipients.append(item);
        }
        status.textContent =
          'Confirm the certified recipients. The organisation also receives a recovery copy.';
        keyReview.append(
          recipients,
          button('Issue group key', () => void review({ ...ref, review: result.preview.review })),
        );
      };
      controls.append(
        button('Review group key recipients', () => void review(ref)),
        keyReview,
      );
    }
    if (!selection?.jobId) {
      if (after) controls.append(button('First members page', () => void openMembers(group)));
      if (result.page.after)
        controls.append(button('More members', () => void openMembers(group, result.page.after)));
      if (selection && list.childElementCount === 0)
        status.textContent = 'The account is absent from this member page.';
      else if (!result.page.entries.length) status.textContent = 'No members on this page.';
    }
  };
  if (selection) void openMembers(selection.group);
  else void openGroups();
  return () => {
    disposed = true;
    root.replaceChildren();
  };
}
