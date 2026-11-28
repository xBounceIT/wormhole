import type { LinuxVaultClipboard } from './vault-linux-clipboard.ts';
import type { BrowserWindow } from 'electron';
import type { VaultBackendHost, VaultFreshAuthentication } from './vault-host.ts';
import {
  VaultNodeDisplayDialog,
  type VaultNodeDisplayOptions,
} from './vault-node-display-dialog.ts';
export class VaultCredentialsDialog extends VaultNodeDisplayDialog {
  constructor(
    options: VaultNodeDisplayOptions & {
      host: VaultBackendHost;
      linuxClipboard?: Pick<LinuxVaultClipboard, 'copy'>;
      authenticate(parent: BrowserWindow, accepted: () => boolean): VaultFreshAuthentication;
    },
  ) {
    super({
      ...options,
      purpose: 'credentials',
      copy: (context, field, parent, accepted) => {
        const copy =
          (options.platform ?? process.platform) === 'linux'
            ? options.linuxClipboard?.copy.bind(options.linuxClipboard)
            : options.host.copyCredential.bind(options.host);
        if (!copy) return Promise.reject(Error('Secure clipboard is unavailable.'));
        return copy(
          {
            workspaceId: context.workspaceId,
            nodeId: context.nodeId,
            rowVersion: context.rowVersion,
            field,
          },
          options.authenticate(parent, accepted),
          accepted,
        );
      },
      read: (request, parent, accepted) =>
        options.host.displayCredentials(request, options.authenticate(parent, accepted), accepted),
    });
  }
}
