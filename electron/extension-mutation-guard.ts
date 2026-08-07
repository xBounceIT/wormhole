const extensionInUseMessage =
  'Close every HTTPS tab using the Bitwarden browser extension before installing or importing an extension update.';
const extensionMutationMessage =
  'The Bitwarden browser extension is being updated. Retry the HTTPS connection when the update finishes.';

export class ExtensionMutationGuard {
  private activeUses = 0;
  private mutationActive = false;

  get canAutoMutate(): boolean {
    return this.activeUses === 0 && !this.mutationActive;
  }

  reserveUse(): () => void {
    if (this.mutationActive) throw new Error(extensionMutationMessage);
    return this.trackUse();
  }

  private trackUse(): () => void {
    this.activeUses++;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.activeUses--;
    };
  }

  async runMutation<TResult>(
    waitForPendingWork: () => Promise<void>,
    operation: () => Promise<TResult>,
  ): Promise<TResult> {
    if (!this.canAutoMutate) throw new Error(extensionInUseMessage);
    this.mutationActive = true;
    try {
      await waitForPendingWork();
      if (this.activeUses !== 0) throw new Error(extensionInUseMessage);
      return await operation();
    } finally {
      this.mutationActive = false;
    }
  }
}
