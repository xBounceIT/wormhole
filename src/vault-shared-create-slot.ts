import { parseCreateSlot, type CreateSlotPort } from '../electron/vault-shared-admin-inventory.ts';

export function mountCreateSlot(
  panel: HTMLElement,
  create: CreateSlotPort,
  setBusy: (busy: boolean) => void,
  saved: (name: string) => void,
): () => void {
  const details = document.createElement('details');
  const summary = document.createElement('summary');
  summary.textContent = 'Create credential slot';
  const form = document.createElement('form');
  const fieldset = document.createElement('fieldset');
  const field = (caption: string, control: HTMLElement) => {
    const label = document.createElement('label');
    label.append(caption, control);
    fieldset.append(label);
  };
  const name = document.createElement('input');
  name.required = true;
  name.maxLength = 1024;
  field('Slot name', name);
  const protocol = document.createElement('select');
  for (const option of ['ssh', 'rdp', 'vnc'])
    protocol.add(new Option(option.toUpperCase(), option));
  field('Protocol', protocol);
  const selfService = document.createElement('input');
  selfService.type = 'checkbox';
  field('Allow users to choose a credential', selfService);
  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.className = 'startup-button startup-button-primary';
  submit.textContent = 'Create slot';
  const notice = document.createElement('p');
  notice.setAttribute('role', 'status');
  fieldset.append(submit);
  form.append(fieldset, notice);
  details.append(summary, form);
  panel.replaceChildren(details);
  let active = true;
  // Reuse the same identity if a commit acknowledgement is lost.
  let id = crypto.randomUUID();
  form.onsubmit = async (event) => {
    event.preventDefault();
    if (!active || fieldset.disabled) return;
    const request = parseCreateSlot({
      id,
      name: name.value,
      protocol: protocol.value,
      allowSelfService: selfService.checked,
    });
    if (!request) {
      notice.textContent =
        'Enter a slot name of up to 1,024 UTF-8 bytes without control characters.';
      name.focus();
      return;
    }
    fieldset.disabled = true;
    setBusy(true);
    notice.textContent = 'Creating slot…';
    try {
      const result = await create(request);
      if (!active) return;
      if (result.status === 'saved') {
        setBusy(false);
        saved(request.name);
        return;
      }
      if (result.status === 'stale') id = crypto.randomUUID();
      notice.textContent = {
        busy: 'The workspace is busy. Try again.',
        stale: 'The workspace changed. Check the list before creating another slot.',
        unavailable: 'You need permission to manage slots in this workspace.',
        unsupported: 'Update the workspace schema to create credential slots.',
      }[result.status];
    } catch {
      if (active) notice.textContent = 'Could not confirm creation. Retry to check this slot.';
    } finally {
      if (active) {
        fieldset.disabled = false;
        setBusy(false);
      }
    }
  };
  return () => {
    active = false;
  };
}
