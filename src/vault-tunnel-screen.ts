import {
  tunnelImportFormats,
  type VaultTunnelImportChoice,
  type VaultTunnelImportFormat,
} from '../electron/vault-tunnel-import.ts';
import { createTunnelImportRecipient } from './vault-tunnel-import-recipient.ts';
import {
  vaultFields,
  vaultID,
  vaultMetadataText,
  vaultRecord,
} from '../electron/vault-contract.ts';
import { parseVaultTunnelSelection, type VaultTunnelInput } from '../electron/vault-tunnel.ts';
import { tunnelKindAvailable } from './tunnel-state.ts';
import { tunnelDefaultSettings, tunnelKinds } from './tunnel-editor-schema.ts';
import { mountVaultTunnelFields, type VaultTunnelReferences } from './vault-tunnel-fields.ts';
import { consumeVaultTunnelProjection, type VaultTunnelProjection } from './vault-tunnel-form.ts';
import { createTunnelEditorRecipient } from './vault-tunnel-recipient.ts';

export type VaultTunnelApi = {
  contentProtectionAvailable: boolean;
  context(): Promise<unknown>;
  references(): Promise<unknown>;
  capabilities(): Promise<unknown>;
  read(publicKey: string): Promise<unknown>;
  importProfile(choice: VaultTunnelImportChoice): Promise<unknown>;
  discardImport(): Promise<void>;
  save(input: VaultTunnelInput): Promise<boolean>;
  close(): Promise<void>;
};

function parseReferences(value: unknown): VaultTunnelReferences {
  if (!vaultRecord(value) || !vaultFields(value, ['connections', 'credentials', 'tunnels']))
    throw Error('Invalid tunnel references.');
  const result: VaultTunnelReferences = { connections: [], credentials: [], tunnels: [] };
  for (const key of ['connections', 'credentials', 'tunnels'] as const) {
    const items = value[key];
    if (!Array.isArray(items) || items.length > 50_000) throw Error('Invalid tunnel references.');
    const seen = new Set<string>();
    for (const item of items) {
      if (
        !vaultRecord(item) ||
        !vaultFields(item, ['id', 'name']) ||
        !vaultID(item.id) ||
        seen.has(item.id) ||
        !vaultMetadataText(item.name, 1024, true)
      )
        throw Error('Invalid tunnel references.');
      seen.add(item.id);
      result[key].push({ id: item.id, name: item.name });
    }
  }
  return result;
}

// The document owns replacement factors only until submission or disposal.
// The app receives a saved identity/revision; no settings are returned to React.
export function mountVaultTunnelScreen(card: HTMLElement, api: VaultTunnelApi) {
  const document = card.ownerDocument;
  const heading = document.createElement('h1');
  heading.textContent = 'VPN tunnel';
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.textContent = 'Opening protected tunnel editor…';
  const form = document.createElement('form');
  const controls = document.createElement('fieldset');
  controls.className = 'vault-tunnel-controls';
  controls.disabled = true;
  const nameLabel = document.createElement('label');
  nameLabel.textContent = 'Name';
  const name = document.createElement('input');
  name.name = 'name';
  name.required = true;
  name.maxLength = 256;
  name.autocomplete = 'off';
  nameLabel.append(name);
  const kindLabel = document.createElement('label');
  kindLabel.textContent = 'Provider';
  const kind = document.createElement('select');
  kind.name = 'kind';
  for (const provider of tunnelKinds) {
    const option = document.createElement('option');
    option.value = String(provider.value);
    option.textContent = provider.label;
    kind.append(option);
  }
  kindLabel.append(kind);
  const imports = document.createElement('div');
  imports.className = 'vault-tunnel-imports';
  const fieldsContainer = document.createElement('div');
  const save = document.createElement('button');
  save.type = 'submit';
  save.disabled = true;
  save.className = 'startup-button';
  save.textContent = 'Save tunnel';
  const close = document.createElement('button');
  close.type = 'button';
  close.name = 'cancel';
  close.className = 'startup-button startup-button-secondary';
  close.textContent = 'Cancel';
  const notice = document.createElement('p');
  notice.className = 'startup-subtitle';
  notice.textContent = api.contentProtectionAvailable
    ? 'Stored secrets stay hidden. This editor closes when Wormhole locks or after five minutes.'
    : 'Screen capture protection is unavailable on Linux. Stored secrets stay hidden. This editor closes when Wormhole locks or after five minutes.';
  controls.append(nameLabel, kindLabel, imports, fieldsContainer);
  const scroll = document.createElement('div');
  scroll.className = 'vault-tunnel-scroll';
  scroll.append(controls, notice);
  const actions = document.createElement('footer');
  actions.className = 'vault-dialog-actions';
  actions.append(close, save);
  form.append(scroll, actions);
  card.replaceChildren(heading, status, form);
  let disposed = false,
    pending = false;
  let selection: ReturnType<typeof parseVaultTunnelSelection>;
  let fields: ReturnType<typeof mountVaultTunnelFields> | undefined;
  let recipient: Awaited<ReturnType<typeof createTunnelEditorRecipient>> | undefined;
  let references: VaultTunnelReferences = { connections: [], credentials: [], tunnels: [] };
  let currentKind = 0;
  let capabilities: { openVpn: boolean } | null = null;
  let original: VaultTunnelProjection | undefined;
  let identity: { workspaceId: string; editorId: string } | undefined;
  let imported = false;
  function setControlsDisabled(disabled: boolean) {
    controls.disabled = disabled;
    save.disabled = disabled || !tunnelKindAvailable(currentKind, capabilities);
  }
  function dispose() {
    if (disposed) return;
    disposed = true;
    recipient?.dispose();
    recipient = undefined;
    fields?.dispose();
    fields = undefined;
    references = { connections: [], credentials: [], tunnels: [] };
    original = undefined;
    identity = undefined;
    imports.replaceChildren();
    name.value = '';
    setControlsDisabled(true);
    close.disabled = true;
    form.onsubmit = null;
    kind.onchange = null;
    close.onclick = null;
    card.removeEventListener('copy', preventCopy);
    card.removeEventListener('cut', preventCopy);
    window.removeEventListener('pagehide', dispose);
  }
  function preventCopy(event: Event) {
    event.preventDefault();
  }
  card.addEventListener('copy', preventCopy);
  card.addEventListener('cut', preventCopy);
  window.addEventListener('pagehide', dispose);
  close.onclick = () => {
    dispose();
    void api.close().catch(() => undefined);
  };
  function mount(projection: VaultTunnelProjection, fresh: boolean) {
    fields?.dispose();
    currentKind = projection.kind;
    kind.value = String(currentKind);
    for (const option of kind.options) {
      const available = tunnelKindAvailable(Number(option.value), capabilities);
      option.hidden = !available && option.value !== kind.value;
      option.disabled = !available;
    }
    save.disabled = !tunnelKindAvailable(currentKind, capabilities);
    fields = mountVaultTunnelFields(fieldsContainer, projection, references, fresh);
    imports.replaceChildren();
    for (const format of tunnelImportFormats(currentKind)) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'startup-button startup-button-secondary';
      button.dataset.import = format;
      button.disabled = save.disabled;
      button.textContent = {
        openvpn: 'Import OpenVPN profile',
        watchguard: 'Import WatchGuard bundle',
        azure: 'Import Azure profile',
        cisco: 'Import Cisco profile',
        'ipsec-cert': 'Import client certificate',
        'ipsec-key': 'Import private key',
        'ipsec-ca': 'Import CA certificates',
      }[format];
      button.onclick = () => {
        void importProfile(format);
      };
      imports.append(button);
    }
  }
  async function importProfile(format: VaultTunnelImportFormat) {
    if (
      disposed ||
      pending ||
      controls.disabled ||
      !identity ||
      !tunnelKindAvailable(currentKind, capabilities)
    )
      return;
    if (!window.confirm('Importing replaces unsaved settings in this form. Continue?')) return;
    pending = true;
    setControlsDisabled(true);
    status.textContent = 'Importing profile…';
    let published = false;
    let bytes: Uint8Array | undefined;
    try {
      const context = { ...identity, importId: crypto.randomUUID(), kind: currentKind };
      const generated = await createTunnelImportRecipient(context);
      if (disposed) {
        generated.dispose();
        return;
      }
      recipient = generated;
      const response = await api.importProfile({
        importId: context.importId,
        kind: currentKind,
        format,
        publicKey: generated.publicKey,
      });
      if (disposed) return;
      if (response === null) {
        status.textContent = 'Import canceled.';
        return;
      }
      published = true;
      bytes = await generated.open(response);
      if (disposed) return;
      const projection = consumeVaultTunnelProjection(bytes);
      if (projection.kind !== currentKind) throw Error('Invalid import provider.');
      const base =
        original?.kind === currentKind
          ? original
          : {
              name: '',
              kind: currentKind,
              settings: tunnelDefaultSettings(currentKind),
              present: [],
            };
      const settings = { ...base.settings, ...projection.settings };
      // The imported explicit mode supersedes the legacy display alias, just
      // as the native merge does when committing the staged configuration.
      if (currentKind === 3 && projection.settings.AuthMode !== undefined)
        delete settings.UseSingleSignOn;
      mount(
        {
          ...projection,
          settings,
          present: [...new Set([...base.present, ...projection.present])],
        },
        !original || original.kind !== currentKind,
      );
      imported = true;
      if (!name.value.trim()) name.value = projection.name;
      status.textContent =
        'Profile imported. Review the settings and save the tunnel. Imported secrets stay hidden.';
    } catch {
      if (!disposed) {
        if (published) {
          // Native staging succeeded. Never save the old form against a new,
          // unverified preview; retire the document and its staged snapshot.
          dispose();
          void api.close().catch(() => undefined);
          status.textContent = 'The import preview could not be verified. Reopen the editor.';
        } else
          status.textContent = 'The profile could not be imported. Check the file and try again.';
      }
    } finally {
      bytes?.fill(0);
      recipient?.dispose();
      recipient = undefined;
      if (!disposed) {
        pending = false;
        setControlsDisabled(false);
      }
    }
  }
  kind.onchange = () => {
    if (disposed || pending || !fields) return;
    const next = Number(kind.value);
    if (next === currentKind) return;
    if (!tunnelKindAvailable(next, capabilities)) {
      kind.value = String(currentKind);
      return;
    }
    if (
      !window.confirm(
        'Changing provider discards this form and replaces the stored configuration when saved. Continue?',
      )
    ) {
      kind.value = String(currentKind);
      return;
    }
    const change = () => {
      const restored = original?.kind === next ? original : undefined;
      mount(
        restored ?? {
          name: name.value,
          kind: next,
          settings: tunnelDefaultSettings(next),
          present: [],
        },
        !restored,
      );
      status.textContent = restored
        ? 'Stored configuration restored. Unsaved changes were discarded.'
        : 'Provider changed. Enter the settings for the new configuration.';
    };
    if (!imported) {
      change();
      return;
    }
    pending = true;
    setControlsDisabled(true);
    void api
      .discardImport()
      .then(() => {
        if (disposed) return;
        imported = false;
        pending = false;
        setControlsDisabled(false);
        change();
      })
      .catch(() => {
        if (disposed) return;
        dispose();
        status.textContent = 'The import could not be discarded. Reopen the editor.';
        void api.close().catch(() => undefined);
      });
  };
  form.onsubmit = (event) => {
    event.preventDefault();
    if (
      disposed ||
      pending ||
      !fields ||
      controls.disabled ||
      !tunnelKindAvailable(currentKind, capabilities)
    )
      return;
    const title = name.value.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, '');
    if (!vaultMetadataText(title, 512, true) || [...title].length > 128) {
      status.textContent = 'Enter a name of at most 128 characters.';
      return;
    }
    let input: ReturnType<typeof fields.serialize>;
    try {
      input = fields.serialize();
    } catch (error) {
      status.textContent = error instanceof Error ? error.message : 'Check the tunnel settings.';
      return;
    }
    pending = true;
    setControlsDisabled(true);
    status.textContent = 'Saving tunnel…';
    let operation: Promise<boolean>;
    try {
      operation = api.save({
        metadata: { id: selection?.id ?? '', name: title, kind: currentKind },
        rowVersion: selection?.rowVersion ?? '0',
        ...input,
      });
    } catch {
      operation = Promise.resolve(false);
    } finally {
      input.patch.fill(0);
      fields.clearSubmitted();
    }
    void operation
      .catch(() => false)
      .then((saved) => {
        if (disposed) return;
        if (saved === true) {
          dispose();
          status.textContent = 'Tunnel saved.';
          void api.close().catch(() => undefined);
        } else {
          pending = false;
          setControlsDisabled(false);
          status.textContent =
            'The tunnel was not saved. Check the settings and re-enter replacement secrets. If it changed elsewhere, close this editor and refresh the workspace.';
        }
      });
  };
  void (async () => {
    let bytes: Uint8Array | undefined;
    try {
      const context = await api.context();
      if (disposed) return;
      if (
        !vaultRecord(context) ||
        !vaultFields(context, ['workspaceId', 'requestId', 'selection']) ||
        !vaultID(context.workspaceId) ||
        !vaultID(context.requestId)
      )
        throw Error('Invalid tunnel context.');
      identity = { workspaceId: context.workspaceId, editorId: context.requestId };
      selection =
        context.selection === null ? undefined : parseVaultTunnelSelection(context.selection);
      if (context.selection !== null && !selection) throw Error('Invalid tunnel selection.');
      const options = await api.references();
      if (disposed) return;
      references = parseReferences(options);
      const supported = await api.capabilities();
      if (disposed) return;
      if (
        !vaultRecord(supported) ||
        !vaultFields(supported, ['openVpn']) ||
        typeof supported.openVpn !== 'boolean'
      )
        throw Error('Invalid tunnel capabilities.');
      capabilities = { openVpn: supported.openVpn };
      let projection: VaultTunnelProjection = {
        name: '',
        kind: 0,
        settings: tunnelDefaultSettings(0),
        present: [],
      };
      if (selection) {
        const generated = await createTunnelEditorRecipient({
          workspaceId: context.workspaceId,
          requestId: context.requestId,
          tunnelId: selection.id,
          rowVersion: selection.rowVersion,
        });
        if (disposed) {
          generated.dispose();
          return;
        }
        recipient = generated;
        const response = await api.read(recipient.publicKey);
        if (disposed) return;
        bytes = await recipient.open(response);
        if (disposed) return;
        projection = consumeVaultTunnelProjection(bytes);
      }
      if (selection) original = projection;
      heading.textContent = selection ? 'Edit VPN tunnel' : 'Add VPN tunnel';
      name.value = projection.name;
      mount(projection, !selection);
      setControlsDisabled(false);
      status.textContent = save.disabled
        ? 'This build has no usable OpenVPN engine. Choose an available provider to create a different configuration.'
        : '';
      name.focus();
    } catch {
      if (!disposed)
        status.textContent =
          'The tunnel editor is unavailable. Close it, refresh the workspace and try again.';
    } finally {
      bytes?.fill(0);
      recipient?.dispose();
      recipient = undefined;
    }
  })();
  return dispose;
}
