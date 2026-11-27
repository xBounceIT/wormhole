import type { SharedCatalogCursor, SharedCatalogNode } from '../electron/vault-shared-catalog.ts';
import {
  sharedEditFields,
  parseSharedNodeEditRequest,
  type SharedEditKey,
  type SharedEditValue,
  type SharedEditValues,
  type SharedMoveParent,
  type SharedNodeChanges,
} from '../electron/vault-shared-node-edit.ts';

type EditPort = NonNullable<Window['wormhole']>['editSharedNode'];
type FolderPagePort = NonNullable<Window['wormhole']>['loadSharedCatalogPage'];

function mountSlotPicker(
  row: HTMLElement,
  page: (after: string) => ReturnType<EditPort>,
  choose: (id: string) => void,
  current: () => boolean,
) {
  const browse = document.createElement('button');
  browse.type = 'button';
  browse.textContent = 'Choose slot by name…';
  const list = document.createElement('select');
  list.setAttribute('aria-label', 'Available credential slots');
  const previous = document.createElement('button'),
    next = document.createElement('button');
  previous.type = next.type = 'button';
  previous.textContent = 'Previous slots';
  next.textContent = 'Next slots';
  const notice = document.createElement('span');
  notice.setAttribute('role', 'status');
  list.hidden = previous.hidden = next.hidden = true;
  row.append(browse, list, previous, next, notice);
  let cursors = [''],
    following: string | undefined;
  async function load(history: string[]) {
    if (!current() || browse.disabled) return;
    browse.disabled = list.disabled = previous.disabled = next.disabled = true;
    list.replaceChildren();
    notice.textContent = 'Loading credential slots…';
    try {
      const result = await page(history.at(-1)!);
      if (!current()) return;
      if (result.status !== 'slot-choices') throw Error('unavailable');
      const { entries, next: cursor } = result.slotPage;
      cursors = history;
      following = cursor?.id;
      list.replaceChildren(new Option('Select a credential slot', ''));
      for (const entry of entries) {
        const option = new Option(entry.name + ' · ' + entry.protocol.toUpperCase(), entry.id);
        option.title = entry.id;
        list.add(option);
      }
      browse.hidden = true;
      list.hidden = !entries.length;
      previous.hidden = history.length === 1;
      next.hidden = !following;
      notice.textContent = entries.length ? '' : 'No visible credential slots on this page.';
    } catch {
      if (!current()) return;
      list.hidden = previous.hidden = next.hidden = true;
      browse.hidden = false;
      notice.textContent =
        'Could not load slots for this revision. Refresh the catalog or enter the slot ID.';
    } finally {
      if (current()) {
        browse.disabled = list.disabled = previous.disabled = next.disabled = false;
        if (!list.hidden) list.focus();
      }
    }
  }
  browse.onclick = () => void load(['']);
  previous.onclick = () => {
    if (cursors.length > 1) void load(cursors.slice(0, -1));
  };
  next.onclick = () => {
    if (following) void load([...cursors, following]);
  };
  list.onchange = () => {
    if (current() && !list.disabled && list.value) choose(list.value);
  };
}

function mountMovePicker(
  fields: HTMLFieldSetElement,
  node: SharedCatalogNode,
  snapshot: { epoch: string; changeSeq: string },
  loadPage: FolderPagePort,
  current: () => boolean,
  select: (value: SharedMoveParent | undefined) => void,
  status: HTMLElement,
) {
  const label = document.createElement('label'),
    folders = document.createElement('select');
  label.textContent = 'Destination folder';
  label.append(folders);
  const next = document.createElement('button');
  next.type = 'button';
  next.textContent = 'Next page';
  next.hidden = true;
  fields.replaceChildren(label, next);
  let cursor: SharedCatalogCursor | null = null;
  let choices = new Map<string, SharedMoveParent>();
  folders.onchange = () => select(choices.get(folders.value));
  async function load() {
    select(undefined);
    folders.disabled = next.disabled = true;
    status.textContent = 'Loading destination folders…';
    try {
      const page = await loadPage({
        ...(cursor ?? { after: '', epoch: '0', changeSeq: '0' }),
        limit: 32,
      });
      if (!current()) return;
      if (page.epoch !== snapshot.epoch || page.changeSeq !== snapshot.changeSeq)
        throw Error('stale');
      choices = new Map();
      folders.replaceChildren(new Option('Choose a destination', ''));
      if (node.parentId !== null) {
        folders.add(new Option('Workspace root', 'root'));
        choices.set('root', null);
      }
      for (const item of page.nodes) {
        if (
          item.kind !== 0 ||
          !item.editRevision ||
          item.id === node.id ||
          item.parentId === node.id ||
          item.id === node.parentId
        )
          continue;
        const option = new Option(item.name, item.id);
        option.title = item.id;
        folders.add(option);
        choices.set(item.id, { id: item.id, revision: item.editRevision });
      }
      cursor = page.next;
      next.hidden = !cursor;
      next.disabled = false;
      folders.disabled = false;
      status.textContent = choices.size ? '' : 'No writable destinations on this page.';
      folders.focus();
    } catch {
      if (current()) {
        next.hidden = true;
        status.textContent =
          'Could not load this catalog revision. Close the editor and refresh the catalog.';
      }
    }
  }
  next.onclick = () => {
    if (current() && cursor && !next.disabled) void load();
  };
  void load();
}

function editControl(key: SharedEditKey, initial: SharedEditValue) {
  const field = sharedEditFields[key];
  const row = document.createElement('div');
  const label = document.createElement('label');
  label.textContent = field.label;
  row.append(label);
  if (field.type === 'choice' || field.type === 'boolean') {
    const select = document.createElement('select');
    select.add(new Option('Inherit', ''));
    const options = field.type === 'choice' ? field.options : { true: 'Yes', false: 'No' };
    for (const [value, text] of Object.entries(options)) select.add(new Option(text, value));
    select.value = initial === null ? '' : String(initial);
    label.append(select);
    return {
      row,
      set: (value: string | null) => {
        select.value = value ?? '';
      },
      read: () =>
        select.value === ''
          ? null
          : field.type === 'boolean'
            ? select.value === 'true'
            : Number(select.value),
    };
  }
  const input = document.createElement('input');
  input.type = field.type === 'port' ? 'number' : 'text';
  if (field.type === 'port') {
    input.min = '0';
    input.max = '65535';
    input.required = true;
  }
  if ('max' in field) input.maxLength = field.max;
  if (field.type === 'id') {
    input.maxLength = 36;
    input.required = true;
  }
  input.value = initial === null ? '' : String(initial);
  label.append(input);
  if (field.type === 'name') {
    input.required = true;
    return { row, read: () => input.value };
  }
  const inherit = document.createElement('input');
  inherit.type = 'checkbox';
  inherit.checked = initial === null;
  input.disabled = inherit.checked;
  inherit.onchange = () => {
    input.disabled = inherit.checked;
    if (!inherit.checked) input.focus();
  };
  const inheritLabel = document.createElement('label');
  inheritLabel.append(inherit, 'Inherit');
  inherit.setAttribute('aria-label', 'Inherit ' + field.label);
  row.append(inheritLabel);
  return {
    row,
    set: (value: string | null) => {
      inherit.checked = input.disabled = value === null;
      input.value = value ?? '';
    },
    read: () =>
      inherit.checked ? null : field.type === 'port' ? input.valueAsNumber : input.value,
  };
}

export function openSharedNodeEditor(
  container: HTMLElement,
  node: SharedCatalogNode,
  edit: EditPort,
  closed: (saved: boolean) => void,
  loadPage?: FolderPagePort,
) {
  const dialog = document.createElement('dialog');
  dialog.className = 'shared-node-editor';
  const form = document.createElement('form');
  const title = document.createElement('h2');
  title.textContent = 'Edit ' + node.name;
  dialog.setAttribute('aria-label', title.textContent);
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.textContent = 'Loading settings…';
  const fields = document.createElement('fieldset');
  const save = document.createElement('button');
  save.className = 'startup-button';
  save.type = 'submit';
  save.textContent = 'Save changes';
  save.disabled = true;
  const cancel = document.createElement('button');
  cancel.className = 'startup-button startup-button-secondary';
  cancel.type = 'button';
  cancel.textContent = 'Cancel';
  const actions = document.createElement('div');
  actions.className = 'shared-catalog-actions';
  actions.append(cancel, save);
  form.append(title, status, fields, actions);
  dialog.append(form);
  container.append(dialog);
  dialog.showModal();
  let active = true,
    writing = false;
  function close(saved = false) {
    if (!active) return;
    active = false;
    dialog.close();
    dialog.remove();
    closed(saved);
  }
  cancel.onclick = () => close();
  dialog.oncancel = (event) => {
    event.preventDefault();
    if (!writing) close();
  };
  async function load() {
    const request = { nodeId: node.id, revision: node.editRevision! };
    const ready = await edit(request);
    if (!active) return;
    if (ready.status !== 'ready') throw Error('unavailable');
    let keys = Object.keys(sharedEditFields) as SharedEditKey[];
    if (ready.usesInlinePassword) {
      const explanation = document.createElement('p');
      explanation.textContent = 'This connection uses its own stored password.';
      fields.append(explanation);
      keys = keys.filter(
        (key) => !['credentialMode', 'credentialId', 'credentialSlotId'].includes(key),
      );
    }
    const controls = keys.map((key) => {
      const { row, read, set } = editControl(key, ready.fields[key]);
      fields.append(row);
      // HTML controls normalize some stored strings when displaying them.
      // Compare with the initial control value to preserve untouched metadata.
      return { key, row, read, set, initial: read() };
    });
    let moving = false,
      destination: SharedMoveParent | undefined;
    const changes = (): SharedNodeChanges => {
      if (moving) return destination === undefined ? {} : { parent: destination };
      const result: Partial<SharedEditValues> = {};
      for (const { key, read, initial } of controls) {
        const value = read();
        if (value !== initial) result[key] = value;
      }
      return result;
    };
    const snapshot = {
      ...request,
      workspaceId: ready.workspaceId,
      epoch: ready.epoch,
      changeSeq: ready.changeSeq,
    };
    const move = document.createElement('button');
    if (ready.canMove && loadPage) {
      move.type = 'button';
      move.textContent = 'Move to folder…';
      move.className = 'startup-button startup-button-secondary';
      actions.prepend(move);
      move.onclick = () => {
        if (!active || writing || moving || Object.keys(changes()).length) return;
        moving = true;
        move.hidden = true;
        title.textContent = 'Move ' + node.name;
        dialog.setAttribute('aria-label', title.textContent);
        save.textContent = 'Move';
        mountMovePicker(
          fields,
          node,
          snapshot,
          loadPage,
          () => active && !writing,
          (value) => {
            destination = value;
            validate();
          },
          status,
        );
      };
    }
    const validate = () => {
      save.disabled = writing || !parseSharedNodeEditRequest({ ...snapshot, changes: changes() });
      move.disabled = writing || (!moving && Object.keys(changes()).length > 0);
    };
    const slot = controls.find((c) => c.key === 'credentialSlotId');
    if (slot) {
      mountSlotPicker(
        slot.row,
        (slotAfter) => edit({ ...snapshot, slotAfter }),
        (id) => {
          controls.find((c) => c.key === 'credentialMode')?.set?.('3');
          controls.find((c) => c.key === 'credentialId')?.set?.(null);
          slot.set?.(id);
          validate();
        },
        () => active && !moving && !writing && !fields.disabled,
      );
    }
    form.oninput = validate;
    form.onchange = validate;
    status.textContent = '';
    fields.querySelector('input')?.focus();
    form.onsubmit = async (event) => {
      event.preventDefault();
      const update = parseSharedNodeEditRequest({ ...snapshot, changes: changes() });
      if (!active || writing || !update || !form.reportValidity()) return;
      writing = true;
      fields.disabled = save.disabled = cancel.disabled = true;
      status.textContent = 'Saving changes…';
      try {
        const reply = await edit(update);
        if (!active) return;
        if (reply.status === 'saved') {
          close(true);
          return;
        }
      } catch {
        /* A changed workspace or denied update requires a fresh snapshot. */
      }
      if (active) {
        status.textContent =
          'Changes could not be saved. Close the editor and refresh the catalog to try again.';
        writing = false;
        cancel.disabled = false;
        cancel.textContent = 'Close';
      }
    };
  }
  void load().catch(() => {
    if (active) {
      status.textContent = 'Settings are unavailable. Refresh the catalog to try again.';
      cancel.textContent = 'Close';
    }
  });
  return () => close();
}
