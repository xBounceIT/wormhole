import {
  parseVaultBitwardenCLIPassword,
  parseVaultBitwardenCLISession,
  type VaultBitwardenCLIUnlockContext,
} from './vault-bitwarden-cli-unlock.ts';
import type { VaultBackendHost } from './vault-host.ts';
import { runVaultBitwardenExchange } from './vault-ssh-bitwarden.ts';

type UnlockRequest = {
  accepted: () => boolean;
  signal: AbortSignal;
  prompt: (context: VaultBitwardenCLIUnlockContext, signal: AbortSignal) => Promise<unknown>;
};
type Options = {
  host: Pick<VaultBackendHost, 'beginBitwardenCLIUnlock'>;
  executable: () => string;
  databasePath: () => string;
  exchange?: typeof runVaultBitwardenExchange;
};

export class VaultBitwardenCLIUnlockController {
  private current?: { abort: AbortController; finished: Promise<unknown> };
  private readonly options: Options;
  constructor(options: Options) {
    this.options = options;
  }

  async unlock(request: UnlockRequest): Promise<{ unlocked: true }> {
    if (this.current || request.signal.aborted || !request.accepted())
      throw Error('Bitwarden CLI unlock is unavailable.');
    const abort = new AbortController();
    const signal = AbortSignal.any([abort.signal, request.signal]);
    const accepted = () => !signal.aborted && request.accepted();
    const finished = this.exchange(request, signal, accepted);
    this.current = { abort, finished };
    try {
      return await finished;
    } finally {
      this.current = undefined;
    }
  }

  async stop(): Promise<void> {
    const current = this.current;
    current?.abort.abort();
    await current?.finished.catch(() => {});
  }

  private async exchange(
    request: UnlockRequest,
    signal: AbortSignal,
    accepted: () => boolean,
  ): Promise<{ unlocked: true }> {
    const grant = await this.options.host.beginBitwardenCLIUnlock(accepted);
    let committed = false;
    try {
      if (!accepted()) throw Error('Bitwarden CLI unlock is unavailable.');
      const session = await (this.options.exchange ?? runVaultBitwardenExchange)({
        executable: this.options.executable(),
        databasePath: this.options.databasePath(),
        signal,
        mode: 'unlock',
        otherRecipient: grant.binding.vaultKey,
        prepare: async (publicKey, active) => {
          if (!accepted()) throw Error('Bitwarden CLI unlock is unavailable.');
          const password = parseVaultBitwardenCLIPassword(
            await request.prompt({ binding: grant.binding, publicKey }, active),
          );
          if (!password || !accepted()) throw Error('Bitwarden CLI unlock is unavailable.');
          return { binding: grant.binding, password };
        },
        parse: parseVaultBitwardenCLISession,
      });
      if (!accepted()) throw Error('Bitwarden CLI unlock is unavailable.');
      await grant.commit(session);
      committed = true;
      return { unlocked: true };
    } finally {
      if (!committed) await grant.cancel();
    }
  }
}
