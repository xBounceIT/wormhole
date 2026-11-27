import type { VaultBackendHost } from './vault-host.ts';
import {
  VaultNodeDisplayDialog,
  type VaultNodeDisplayOptions,
} from './vault-node-display-dialog.ts';
export class VaultNotesDialog extends VaultNodeDisplayDialog {
  constructor(options: VaultNodeDisplayOptions & { host: VaultBackendHost }) {
    super({ ...options, purpose: 'notes', read: (request) => options.host.displayNotes(request) });
  }
}
