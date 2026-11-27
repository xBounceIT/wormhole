import { fortinetIPsecEditorSettings, fortinetIPsecFieldVisible } from './fortinet-ipsec-state.ts';
import { watchguardAuthModeForEditor } from './tunnel-state.ts';
import {
  vaultTunnelFields,
  type VaultTunnelProjection,
  type VaultTunnelField,
} from './vault-tunnel-form.ts';

export type VaultTunnelReferences = {
  connections: { id: string; name: string }[];
  credentials: { id: string; name: string }[];
  tunnels: { id: string; name: string }[];
};
type Control = {
  field: VaultTunnelField;
  row: HTMLElement;
  input: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;
  mode?: HTMLSelectElement;
};

// Owned by the isolated editor document. Saved factors are represented by field
// presence only; replacement values live solely in their temporary DOM inputs.
export function mountVaultTunnelFields(
  container: HTMLElement,
  projection: VaultTunnelProjection,
  references: VaultTunnelReferences,
  newConfiguration: boolean,
  changed: () => void = () => {},
) {
  const { kind } = projection;
  const settings =
    kind === 9 ? fortinetIPsecEditorSettings(projection.settings) : projection.settings;
  const present = new Set(projection.present);
  const controls = new Map<string, Control>(),
    dirty = new Set<string>();
  const sections = new Map<string, HTMLElement>();
  let disposed = false;
  const document = container.ownerDocument;
  const forget = document.createElement('input');
  forget.type = 'checkbox';
  const pin = document.createElement('label');
  pin.className = 'vault-tunnel-pin';
  const pinText = document.createElement('span');
  pinText.textContent =
    typeof settings.HostKeySha256 === 'string'
      ? `Forget saved host key (${settings.HostKeySha256})`
      : '';
  pin.append(forget, pinText);
  container.replaceChildren();
  container.classList.add('vault-tunnel-fields');
  const text = (value: unknown) =>
    Array.isArray(value)
      ? value.join(', ')
      : typeof value === 'string' || typeof value === 'number'
        ? String(value)
        : '';
  const selectOption = (select: HTMLSelectElement, value: string, label: string) => {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = label;
    select.append(option);
  };
  function value(key: string): string | boolean {
    const control = controls.get(key);
    return control?.input instanceof HTMLInputElement && control.input.type === 'checkbox'
      ? control.input.checked
      : (control?.input.value ?? '');
  }
  function visibility() {
    const ipsec =
      kind === 9
        ? Object.fromEntries(
            [...controls]
              .filter(([, c]) => !c.field.secret)
              .map(([key, c]) => [
                key,
                c.input instanceof HTMLInputElement && c.input.type === 'checkbox'
                  ? c.input.checked
                  : c.field.type === 'number' ||
                      c.field.options?.some((o) => typeof o.value === 'number')
                    ? Number(c.input.value)
                    : c.input.value,
              ]),
          )
        : {};
    const sso =
      kind === 2 ? value('UseSingleSignOn') === true : kind === 3 && value('AuthMode') === '2';
    for (const control of controls.values()) {
      const key = control.field.key;
      const hidden =
        (sso && ['Username', 'Password', 'TotpSecret'].includes(key)) ||
        (kind === 9 &&
          (!fortinetIPsecFieldVisible(key, ipsec) ||
            (key === 'PreSharedKey' && ipsec.AuthMethod === 1) ||
            (['ClientCert', 'ClientKey', 'CaCert'].includes(key) && ipsec.AuthMethod !== 1) ||
            (key === 'Password' && ipsec.UserAuth !== 2))) ||
        (kind === 4 && key === 'ProfileOvpn' && value('Mode') !== '1') ||
        (kind === 8 &&
          (value('Mode') === 'connection'
            ? ['Host', 'Port', 'Username', 'CredentialId'].includes(key)
            : key === 'JumpConnectionId'));
      control.row.hidden = hidden;
      control.input.hidden = control.mode !== undefined && control.mode.value !== 'replace';
      if (hidden && control.field.secret) control.input.value = '';
      control.input.disabled =
        hidden || (control.mode !== undefined && control.mode.value !== 'replace');
    }
    pin.hidden = kind !== 8 || value('Mode') !== 'manual' || !pinText.textContent;
    if (pin.hidden) forget.checked = false;
  }
  for (const field of vaultTunnelFields(kind)) {
    const section = field.section ?? 'Settings';
    let group = sections.get(section);
    if (!group) {
      const fieldset = document.createElement('fieldset'),
        legend = document.createElement('legend');
      legend.textContent = section;
      fieldset.append(legend);
      group = document.createElement('div');
      group.className = 'vault-tunnel-grid';
      fieldset.append(group);
      container.append(fieldset);
      sections.set(section, group);
    }
    const row = document.createElement('div');
    row.className = 'vault-tunnel-field';
    row.dataset.field = field.key;
    if (field.fullWidth || field.type === 'textarea') row.classList.add('vault-tunnel-wide');
    const label = document.createElement('label');
    label.textContent = field.label;
    label.htmlFor = `vault-tunnel-${field.key}`;
    let input: Control['input'];
    if (field.options || field.reference) {
      const select = document.createElement('select');
      input = select;
      if (field.reference) {
        selectOption(
          select,
          '',
          field.reference === 'tunnel'
            ? 'No fallback'
            : `Select ${field.reference === 'connection' ? 'an SSH connection' : 'an SSH credential'}`,
        );
        const options =
          field.reference === 'connection'
            ? references.connections
            : field.reference === 'tunnel'
              ? references.tunnels
              : references.credentials;
        for (const option of options) selectOption(select, option.id, option.name);
        if (settings[field.key] && !options.some((o) => o.id === settings[field.key]))
          selectOption(select, String(settings[field.key]), 'Unavailable saved selection');
      } else
        for (const option of field.options!)
          selectOption(select, String(option.value), option.label);
    } else if (field.type === 'textarea') {
      input = document.createElement('textarea');
      input.rows = 5;
      input.maxLength = 4 * 1024 * 1024;
    } else {
      input = document.createElement('input');
      input.type =
        field.type === 'switch' || field.type === 'checkbox'
          ? 'checkbox'
          : field.type === 'number'
            ? 'number'
            : field.secret
              ? 'password'
              : 'text';
      if (input.type === 'number') input.step = '1';
      if (field.type === 'switch') input.setAttribute('role', 'switch');
      input.maxLength = 4 * 1024 * 1024;
    }
    input.id = label.htmlFor;
    input.name = field.key;
    input.autocomplete = 'off';
    if (input instanceof HTMLInputElement || input instanceof HTMLTextAreaElement) {
      input.spellcheck = false;
      input.placeholder = field.placeholder ?? '';
    }
    if (input instanceof HTMLInputElement && input.type === 'checkbox')
      input.checked = settings[field.key] === true;
    else if (!field.secret) {
      input.value = text(settings[field.key]);
      if (kind === 3 && field.key === 'AuthMode') {
        const presence = Object.fromEntries(projection.present.map((key) => [key, 'stored']));
        input.value = String(watchguardAuthModeForEditor({ ...settings, ...presence }));
      }
      if (kind === 4 && field.key === 'Mode' && settings.Mode == null)
        input.value = present.has('ProfileOvpn') ? '1' : '0';
      if (kind === 8 && field.key === 'Port' && settings.Port == null) input.value = '22';
    }
    const control: Control = { field, row, input };
    row.append(label);
    if (field.secret) {
      const mode = document.createElement('select');
      mode.setAttribute('aria-label', `${field.label}: stored value`);
      selectOption(mode, 'keep', present.has(field.key) ? 'Keep stored value' : 'Leave unset');
      selectOption(mode, 'replace', present.has(field.key) ? 'Replace stored value' : 'Set value');
      selectOption(mode, 'remove', 'Remove stored value');
      mode.onchange = () => {
        if (disposed) return;
        input.value = '';
        visibility();
        changed();
      };
      control.mode = mode;
      row.append(mode);
    }
    row.append(input);
    if (field.hint) {
      const hint = document.createElement('p');
      hint.textContent = field.hint;
      hint.className = 'startup-subtitle';
      row.append(hint);
    }
    input.oninput = () => {
      if (disposed) return;
      dirty.add(field.key);
      if (kind === 8 && field.key === 'Mode')
        for (const key of ['Host', 'Port', 'Username', 'CredentialId', 'JumpConnectionId'])
          dirty.add(key);
      visibility();
      changed();
    };
    controls.set(field.key, control);
    group.append(row);
  }
  forget.onchange = () => {
    if (!disposed) changed();
  };
  container.append(pin);
  visibility();
  function clearSubmitted() {
    for (const c of controls.values()) if (c.field.secret) c.input.value = '';
  }
  function dispose() {
    if (disposed) return;
    disposed = true;
    clearSubmitted();
    for (const c of controls.values()) {
      c.input.value = '';
      c.input.oninput = null;
      if (c.mode) c.mode.onchange = null;
    }
    forget.onchange = null;
    forget.checked = false;
    container.replaceChildren();
    controls.clear();
  }
  function serialize(): { patch: Uint8Array; forgetHostKey: boolean } {
    if (disposed) throw Error('Tunnel editor is closed.');
    const patch: Record<string, unknown> = {};
    for (const c of controls.values()) {
      const key = c.field.key;
      // Explicit removal survives a later mode switch that hides the field.
      if (c.mode?.value === 'remove') {
        patch[key] = null;
        continue;
      }
      if (c.row.hidden) continue;
      if (c.mode) {
        if (c.mode.value === 'replace') {
          if (!c.input.value)
            throw Error(
              `Enter ${c.field.label.toLowerCase()} again, or choose to keep the stored value.`,
            );
          patch[key] = c.input.value;
        }
      } else if (newConfiguration || dirty.has(key)) {
        if (c.input instanceof HTMLInputElement && c.input.type === 'checkbox')
          patch[key] = c.input.checked;
        else if (!c.input.value) patch[key] = null;
        else if (
          c.field.type === 'number' ||
          c.field.options?.some((o) => typeof o.value === 'number')
        ) {
          const number = Number(c.input.value);
          if (!Number.isSafeInteger(number))
            throw Error(`Enter a whole number for ${c.field.label.toLowerCase()}.`);
          patch[key] = number;
        } else patch[key] = c.input.value;
      }
    }
    const bytes = new TextEncoder().encode(JSON.stringify(patch));
    if (bytes.length > 4 * 1024 * 1024) {
      bytes.fill(0);
      throw Error('Tunnel settings are too large.');
    }
    return { patch: bytes, forgetHostKey: !pin.hidden && forget.checked };
  }
  return { serialize, clearSubmitted, dispose };
}
