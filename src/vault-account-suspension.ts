import type {
  AccountBoundaryRotationPort,
  AccountBoundaryRotationReply,
  AccountBoundaryRotationRequest,
  AccountSuspensionPort,
  AccountSuspensionRequest,
  PersonalRootRecoveryPort,
  PersonalRootRecoveryReply,
  PersonalRootRecoveryRequest,
  SuspensionGroupEntry,
} from '../electron/vault-account-suspension.ts';

export function mountAccountSuspension(
  panel: HTMLElement,
  read: AccountSuspensionPort,
  accountId: string,
  name: string,
  close: () => void,
  rotate?: AccountBoundaryRotationPort,
  groupReview?: {
    open?: (group: SuspensionGroupEntry, suspension: string) => void;
    selected?: true;
  },
  recover?: PersonalRootRecoveryPort,
  openReenrollment?: (suspension: string) => void,
) {
  const heading = document.createElement('h2');
  heading.textContent = 'Access at suspension · ' + name;
  const label = document.createElement('label');
  label.textContent = 'Inventory';
  const type = document.createElement('select');
  type.add(new Option('Boundary keys', 'roots'));
  type.add(new Option('Password references', 'passwords'));
  type.add(new Option('Persistent web sessions', 'web-sessions'));
  type.add(new Option('Groups at suspension', 'groups'));
  if (groupReview?.selected) type.value = 'groups';
  label.append(type);
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  const list = document.createElement('ul');
  const confirmation = document.createElement('div');
  const actions = document.createElement('div');
  actions.className = 'shared-setup-actions';
  const button = (text: string) => {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'startup-button startup-button-secondary';
    item.textContent = text;
    actions.append(item);
    return item;
  };
  const back = button('Back to accounts');
  const previous = button('Previous page');
  const next = button('Next page');
  const refresh = button('Refresh inventory');
  const recoverKeys = button('Restore personal keys…');
  recoverKeys.hidden = true;
  const issueReenrollment = button('Issue re-enrollment offer…');
  issueReenrollment.hidden = true;
  panel.replaceChildren(heading, label, status, list, confirmation, actions);
  let active = true;
  let busy = false;
  let history: AccountSuspensionRequest[] = [];
  let more: AccountSuspensionRequest | undefined;
  let recoveryScope: PersonalRootRecoveryRequest | undefined;
  let clearRecoveryFactors: (() => void) | undefined;
  const updateControls = (locked: boolean) => {
    busy = locked;
    back.disabled = type.disabled = refresh.disabled = locked;
    previous.disabled = locked || history.length < 2;
    next.disabled = locked || !more;
    recoverKeys.disabled = locked || !recoveryScope;
    issueReenrollment.disabled = locked || !recoveryScope;
  };
  const recoveryMessage = (reply: Exclude<PersonalRootRecoveryReply, { status: 'review' }>) => {
    switch (reply.status) {
      case 'changed':
      case 'unchanged':
        return 'Personal keys restored. You can review re-enabling the account.';
      case 'rotation-required':
        return 'Rotate both personal keys before restoring access.';
      case 'enrollment-required':
        return 'The account needs a certified replacement enrollment before its keys can be restored.';
      case 'invalid-authentication':
        return 'Check your password and Account Secret Key, then reopen the review.';
      case 'busy':
        return 'The workspace is busy. Review recovery again.';
      case 'stale':
        return 'The enrollment or suspension changed. Refresh the inventory.';
      case 'unsupported':
        return 'Update the workspace schema to restore personal keys.';
      case 'unavailable':
        return 'Personal key recovery is unavailable for this account.';
    }
  };
  recoverKeys.onclick = async () => {
    if (!recover || !recoveryScope || busy || !active) return;
    const scope = recoveryScope;
    issueReenrollment.hidden = true;
    updateControls(true);
    list.hidden = true;
    status.textContent = 'Reviewing personal key recovery…';
    const finish = (message: string) => {
      if (!active) return;
      clearRecoveryFactors?.();
      clearRecoveryFactors = undefined;
      confirmation.replaceChildren();
      list.hidden = false;
      status.textContent = message;
      updateControls(false);
      recoverKeys.focus();
    };
    try {
      const review = await recover(scope);
      if (!active) return;
      if (review.status !== 'review') {
        finish(recoveryMessage(review));
        if (review.status === 'enrollment-required' && review.canReenroll && openReenrollment) {
          issueReenrollment.hidden = false;
          issueReenrollment.focus();
        }
        return;
      }
      status.textContent = 'Confirm recovery of the View and Secret keys.';
      const detail = document.createElement('p');
      detail.textContent = 'Replacement enrollment · ' + review.enrollment;
      const form = document.createElement('form');
      form.className = 'startup-form';
      const field = (text: string, name: string, maxLength: number, required: boolean) => {
        const label = document.createElement('label');
        label.textContent = text;
        const input = document.createElement('input');
        input.type = 'password';
        input.name = name;
        input.autocomplete = 'off';
        input.spellcheck = false;
        input.maxLength = maxLength;
        input.required = required;
        label.append(input);
        form.append(label);
        return input;
      };
      const password = field('Your Wormhole password', 'password', 1024, true);
      const ask = field(
        'Your Account Secret Key, if required (64 hexadecimal characters)',
        'ask',
        64,
        false,
      );
      const clear = () => {
        password.value = '';
        ask.value = '';
      };
      clearRecoveryFactors = clear;
      const cancel = document.createElement('button');
      cancel.type = 'button';
      cancel.className = 'startup-button startup-button-secondary';
      cancel.textContent = 'Cancel';
      cancel.onclick = () => finish('Recovery cancelled.');
      const confirm = document.createElement('button');
      confirm.type = 'submit';
      confirm.className = 'startup-button';
      confirm.textContent = 'Restore both keys';
      form.onsubmit = async (event) => {
        event.preventDefault();
        if (!active || confirm.disabled) return;
        const passwordBytes = new TextEncoder().encode(password.value);
        const pairs = /^[0-9a-f]{64}$/i.test(ask.value) ? ask.value.match(/../g) : null;
        const valid =
          passwordBytes.length >= 1 &&
          passwordBytes.length <= 1024 &&
          (ask.value.length === 0 || pairs !== null);
        const askBytes = pairs ? Uint8Array.from(pairs, (pair) => parseInt(pair, 16)) : undefined;
        clear();
        try {
          let pending: ReturnType<PersonalRootRecoveryPort>;
          try {
            if (!valid) {
              status.textContent = 'Enter your password and check the Account Secret Key format.';
              password.focus();
              return;
            }
            cancel.disabled = confirm.disabled = password.disabled = ask.disabled = true;
            status.textContent = 'Restoring personal keys…';
            pending = recover(
              { ...scope, review: review.review },
              { password: passwordBytes, ...(askBytes ? { ask: askBytes } : {}) },
            );
          } finally {
            passwordBytes.fill(0);
            askBytes?.fill(0);
          }
          const reply = await pending;
          finish(reply.status === 'review' ? 'Review the recovery again.' : recoveryMessage(reply));
        } catch {
          finish(
            'Could not confirm recovery. Open another review to check whether the keys were restored.',
          );
        }
      };
      const controls = document.createElement('div');
      controls.className = 'shared-setup-actions';
      controls.append(cancel, confirm);
      form.append(controls);
      confirmation.replaceChildren(detail, form);
      password.focus();
    } catch {
      finish('Could not review personal key recovery.');
    }
  };
  issueReenrollment.onclick = () => {
    if (active && !busy && !issueReenrollment.hidden && recoveryScope)
      openReenrollment?.(recoveryScope.suspension);
  };
  const rotationMessage = (reply: AccountBoundaryRotationReply) => {
    switch (reply.status) {
      case 'group-rotation-required':
        return 'Open Groups at suspension to review the related group rotations.';
      case 'unchanged':
        return 'This key has already been retired. Refresh the inventory.';
      case 'busy':
        return 'The workspace is busy. Review the key again.';
      case 'stale':
        return 'The key or suspension changed. Refresh the inventory.';
      case 'unsupported':
        return 'Update the workspace schema to rotate this key.';
      default:
        return 'This key is unavailable for rotation.';
    }
  };
  const reviewRotation = async (
    input: AccountBoundaryRotationRequest,
    inventory: AccountSuspensionRequest,
    trigger: HTMLButtonElement,
    boundaryLabel: string,
    personal?: true,
  ) => {
    if (!rotate || busy || !active) return;
    updateControls(true);
    list.hidden = true;
    status.textContent = 'Reviewing boundary key…';
    const finish = (message: string) => {
      if (!active) return;
      confirmation.replaceChildren();
      list.hidden = false;
      status.textContent = message;
      updateControls(false);
      trigger.focus();
    };
    try {
      const reply = await rotate(input);
      if (!active) return;
      if (reply.status !== 'review') {
        finish(rotationMessage(reply));
        return;
      }
      status.textContent = 'Confirm the replacement key.';
      const detail = document.createElement('p');
      detail.textContent = [
        input.purpose === 'view' ? 'View key' : 'Secret key',
        boundaryLabel,
        'Version ' + input.rootVersion,
      ].join(' · ');
      const cancel = document.createElement('button');
      cancel.type = 'button';
      cancel.className = 'startup-button startup-button-secondary';
      cancel.textContent = 'Cancel';
      cancel.onclick = () => finish('Rotation cancelled.');
      const confirm = document.createElement('button');
      confirm.type = 'button';
      confirm.className = 'startup-button';
      confirm.textContent = 'Confirm key rotation';
      confirm.onclick = async () => {
        if (confirm.disabled || !active) return;
        cancel.disabled = confirm.disabled = true;
        try {
          const result = await rotate({ ...input, review: reply.review });
          if (!active) return;
          if (result.status !== 'changed') {
            finish(rotationMessage(result));
            return;
          }
          const prior = history.slice(0, -1);
          finish('Boundary key rotated.');
          await load(inventory, prior, 'Boundary key rotated.');
        } catch {
          finish('Could not confirm the rotation. Refresh the inventory to check the key.');
        }
      };
      confirmation.replaceChildren(detail);
      if (personal) {
        const custody = document.createElement('p');
        custody.textContent =
          'The organisation will hold the replacement key. Restore personal access before re-enabling this account.';
        confirmation.append(custody);
      }
      confirmation.append(cancel, confirm);
      cancel.focus();
    } catch {
      finish('Could not review the boundary key.');
    }
  };
  const load = async (
    request: AccountSuspensionRequest,
    prior: AccountSuspensionRequest[],
    notice?: string,
  ) => {
    if (busy || !active) return;
    updateControls(true);
    more = undefined;
    recoveryScope = undefined;
    recoverKeys.hidden = true;
    issueReenrollment.hidden = true;
    history = [];
    list.replaceChildren();
    status.textContent = 'Loading access inventory…';
    try {
      const reply = await read(request);
      if (!active) return;
      if (reply.status !== 'ready') {
        switch (reply.status) {
          case 'not-recorded':
            status.textContent = 'This suspension has no recorded access inventory.';
            break;
          case 'unsupported':
            status.textContent = 'Update the workspace schema to review this inventory.';
            break;
          case 'stale':
            status.textContent = 'The suspension record changed. Refresh the inventory.';
            break;
          case 'busy':
            status.textContent = 'The workspace is busy. Refresh the inventory.';
            break;
          default:
            status.textContent = 'The access inventory is unavailable.';
        }
        return;
      }
      const { page } = reply;
      history = [...prior, request];
      if (page.after)
        more = { accountId, kind: request.kind, revision: page.revision, after: page.after };
      let restricted = 0;
      for (const entry of page.entries) {
        if (entry.kind === 'group') {
          const row = document.createElement('li');
          const groupStatus = {
            'needs-removal': 'Member removal needed',
            queued: 'Key rotation queued',
            waiting: 'Another rotation is in progress',
            resolved: 'Member removed',
          }[entry.status];
          row.textContent = [entry.name, groupStatus].join(' · ');
          const open = groupReview?.open;
          if (open && (entry.status === 'needs-removal' || entry.status === 'queued')) {
            const action = document.createElement('button');
            action.type = 'button';
            action.className = 'startup-button startup-button-secondary';
            action.textContent =
              entry.status === 'queued' ? 'Open queued rotation' : 'Open group review';
            action.setAttribute('aria-label', action.textContent + ' · ' + entry.name);
            action.onclick = () => open(entry, page.revision);
            row.append(action);
          }
          list.append(row);
          continue;
        }
        if (!entry.boundaryId) {
          restricted++;
          continue;
        }
        const row = document.createElement('li');
        if ('status' in entry) {
          if (recover && entry.personal && entry.status === 'retired') {
            recoveryScope = { accountId, suspension: page.revision };
            recoverKeys.hidden = false;
          }
          const groups = Number(entry.groupCount);
          const boundaryLabel =
            (entry.personal ? 'Personal boundary ' : 'Boundary ') + entry.boundaryId;
          const origin = [
            entry.direct ? 'Direct copy' : '',
            groups ? 'Group copies (' + groups + ')' : '',
          ].filter(Boolean);
          row.textContent = [
            entry.kind === 'view' ? 'View key' : 'Secret key',
            boundaryLabel,
            'Version ' + entry.revision,
            entry.status,
            ...origin,
          ].join(' · ');
          if (rotate && entry.status === 'active' && entry.revision !== '2147483647') {
            const action = document.createElement('button');
            action.type = 'button';
            action.className = 'startup-button startup-button-secondary';
            action.textContent = 'Rotate key…';
            action.setAttribute('aria-label', action.textContent + ' · ' + row.textContent);
            action.onclick = () =>
              void reviewRotation(
                {
                  accountId,
                  suspension: page.revision,
                  boundaryId: entry.boundaryId,
                  purpose: entry.kind,
                  rootId: entry.id,
                  rootVersion: entry.revision,
                },
                request,
                action,
                boundaryLabel,
                entry.personal,
              );
            row.append(action);
          }
        } else if (entry.kind === 'web-target') {
          row.textContent = [entry.name, entry.id].join(' · ');
        } else {
          const owner =
            entry.kind === 'credential'
              ? 'Credential'
              : entry.kind === 'node'
                ? 'Connection'
                : entry.kind === 'tunnel'
                  ? 'Tunnel'
                  : 'Credential slot';
          row.textContent = [entry.name || owner, entry.id].join(' · ');
        }
        list.append(row);
      }
      if (restricted) {
        const row = document.createElement('li');
        row.textContent =
          restricted === 1 ? '1 restricted entry' : restricted + ' restricted entries';
        list.append(row);
      }
      status.textContent =
        notice ?? (page.entries.length ? 'Page ' + history.length : 'No entries were recorded.');
    } catch {
      if (active) status.textContent = 'Could not load the access inventory.';
    } finally {
      if (active) updateControls(false);
    }
  };
  const start = () => {
    const selected = type.value;
    const kind =
      selected === 'groups' || selected === 'passwords' || selected === 'web-sessions'
        ? selected
        : 'roots';
    void load({ accountId, kind }, []);
  };
  type.onchange = refresh.onclick = start;
  previous.onclick = () => {
    if (history.length > 1) void load(history[history.length - 2]!, history.slice(0, -2));
  };
  next.onclick = () => {
    if (more) void load(more, history);
  };
  back.onclick = close;
  start();
  return () => {
    active = false;
    clearRecoveryFactors?.();
    panel.replaceChildren();
  };
}
