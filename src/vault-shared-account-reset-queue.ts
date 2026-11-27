import {
  parseAccountResetMarkResult,
  parseAccountResetTargetPage,
  type AccountResetMark,
  type AccountResetTarget,
  type AccountResetTargetStatus,
} from '../electron/vault-shared-account-reset-queue.ts';

export type AccountResetQueueApi = {
  resetTargets(after: string | null): Promise<unknown>;
  markResetHandover(mark: AccountResetMark): Promise<unknown>;
  leaveResetPending(offerId: string): Promise<unknown>;
};

const statusLabels: Record<AccountResetTargetStatus, string> = {
  'not-issued': 'No offer issued',
  'awaiting-handover': 'Awaiting handover',
  'handed-over': 'Handed over',
  redeemed: 'Redeemed',
  expired: 'Expired',
  inactive: 'Inactive',
};

export function createAccountResetQueue(
  section: HTMLElement,
  status: HTMLElement,
  api: AccountResetQueueApi,
  start: (targets: AccountResetTarget[]) => void,
) {
  const list = document.createElement('ul');
  list.className = 'shared-reset-targets';
  const controls = document.createElement('div');
  controls.className = 'shared-reset-actions';
  const button = (label: string, primary = false) => {
    const value = document.createElement('button');
    value.type = 'button';
    value.textContent = label;
    value.className = primary ? 'startup-button' : 'startup-button startup-button-secondary';
    controls.append(value);
    return value;
  };
  const startSelected = button('Issue resets for selected accounts', true);
  const selectOutstanding = button('Select accounts that need an offer');
  const refresh = button('Refresh account list');
  const more = button('Load more accounts');
  section.append(list, controls);

  let targets: AccountResetTarget[] = [];
  const selected = new Set<string>();
  let next: string | undefined;
  let busy = false;
  let disposed = false;
  const setControls = () => {
    startSelected.disabled = busy || !selected.size;
    selectOutstanding.disabled = busy || !targets.some(needsOffer);
    refresh.disabled = more.disabled = busy;
    more.hidden = !next;
    for (const input of list.querySelectorAll<HTMLInputElement>('input'))
      input.disabled = busy || input.dataset.eligible !== 'true';
    for (const mark of list.querySelectorAll<HTMLButtonElement>('button')) mark.disabled = busy;
  };
  const needsOffer = (target: AccountResetTarget) =>
    target.eligible &&
    (target.status === 'not-issued' || target.status === 'expired' || target.status === 'inactive');
  const markHandover = async (target: Extract<AccountResetTarget, { offerId: string }>) => {
    if (busy || disposed) return;
    busy = true;
    setControls();
    try {
      const result = parseAccountResetMarkResult(
        await api.markResetHandover({ userId: target.userId, offerId: target.offerId }),
      );
      if (disposed) return;
      if (result?.status === 'handed-over' || result?.status === 'redeemed') {
        target.status = result.status;
        status.textContent =
          result.status === 'redeemed' ? 'The offer was already redeemed.' : 'Handover recorded.';
        render();
      } else {
        status.textContent = 'Could not confirm handover. Refresh to check the current offer.';
      }
    } catch {
      if (!disposed) status.textContent = 'Could not confirm handover.';
    } finally {
      busy = false;
      if (!disposed) setControls();
    }
  };
  const render = () => {
    list.replaceChildren();
    for (const target of targets) {
      const item = document.createElement('li');
      const label = document.createElement('label');
      const include = document.createElement('input');
      include.type = 'checkbox';
      include.dataset.eligible = String(target.eligible);
      include.checked = selected.has(target.userId);
      include.onchange = () => {
        if (include.checked) selected.add(target.userId);
        else selected.delete(target.userId);
        setControls();
      };
      label.append(include, document.createTextNode(target.loginName));
      const state = document.createElement('span');
      state.textContent = target.eligible
        ? statusLabels[target.status]
        : `${statusLabels[target.status]} · Recovery keys unavailable`;
      item.append(label, state);
      if (target.status === 'awaiting-handover') {
        const mark = document.createElement('button');
        mark.type = 'button';
        mark.className = 'startup-button startup-button-secondary';
        mark.textContent = 'Mark handed over';
        mark.setAttribute('aria-label', `Mark handover for ${target.loginName}`);
        mark.onclick = () => void markHandover(target);
        item.append(mark);
      }
      list.append(item);
    }
    setControls();
  };
  const load = async (after: string | null) => {
    if (busy || disposed) return false;
    busy = true;
    setControls();
    try {
      const result = parseAccountResetTargetPage(await api.resetTargets(after), after);
      if (disposed) return false;
      if (result?.status === 'unavailable' || result?.status === 'unsupported') {
        targets = [];
        selected.clear();
        next = undefined;
        render();
      }
      if (result?.status === 'unsupported') return false;
      if (result?.status !== 'ready') {
        status.textContent = 'Could not load account reset targets.';
        return true;
      }
      if (after === null) {
        targets = [];
        selected.clear();
      }
      targets.push(...result.page.targets);
      next = result.page.next;
      render();
      status.textContent = targets.length
        ? 'Select accounts to issue resets one at a time.'
        : 'No accounts available for reset.';
    } catch {
      if (!disposed) status.textContent = 'Could not load account reset targets.';
    } finally {
      busy = false;
      if (!disposed) setControls();
    }
    return true;
  };
  startSelected.onclick = () => {
    if (!busy && !disposed) {
      const choices = targets.filter(({ userId }) => selected.has(userId));
      if (choices.length) start(choices);
    }
  };
  selectOutstanding.onclick = () => {
    if (busy || disposed) return;
    for (const target of targets.filter(needsOffer)) selected.add(target.userId);
    render();
  };
  refresh.onclick = () => void load(null);
  more.onclick = () => {
    if (next) void load(next);
  };
  setControls();
  return {
    load: () => load(null),
    dispose: () => {
      disposed = true;
      selected.clear();
      targets = [];
      list.replaceChildren();
      busy = true;
      setControls();
    },
  };
}
