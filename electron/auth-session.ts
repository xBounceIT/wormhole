export type AuthSessionState = {
  configured: boolean;
};

type UnlockListener = () => void;

export class AuthSession {
  private initialized = false;
  private configured = false;
  private unlocked = false;
  private epoch = 0;
  private lockHolds = 0;
  private readonly unlockListeners = new Set<UnlockListener>();

  get isInitialized(): boolean {
    return this.initialized;
  }

  get isAccessAllowed(): boolean {
    return this.lockHolds === 0 && this.initialized && (!this.configured || this.unlocked);
  }

  get authorizationEpoch(): number {
    return this.epoch;
  }

  onUnlocked(listener: UnlockListener): () => void {
    this.unlockListeners.add(listener);
    return () => this.unlockListeners.delete(listener);
  }

  remember(state: AuthSessionState, assumeUnlocked: boolean): void {
    const wasAccessAllowed = this.isAccessAllowed;
    const sameConfiguration = this.initialized && this.configured === state.configured;
    this.initialized = true;
    this.configured = state.configured;
    this.unlocked = state.configured
      ? assumeUnlocked || (sameConfiguration && this.unlocked)
      : true;
    if (wasAccessAllowed && !this.isAccessAllowed) this.epoch++;
    this.notifyUnlockIfNeeded(wasAccessAllowed);
  }

  markUnlocked(verificationEpoch = this.epoch): void {
    if (!this.initialized) throw new Error('Authentication state is not initialized.');
    this.requireVerificationEpoch(verificationEpoch);
    const wasAccessAllowed = this.isAccessAllowed;
    this.unlocked = true;
    this.notifyUnlockIfNeeded(wasAccessAllowed);
  }

  requireVerificationEpoch(verificationEpoch: number): void {
    if (this.lockHolds > 0 || verificationEpoch !== this.epoch) {
      throw new Error('Wormhole was locked during verification. Please unlock again.');
    }
  }

  lock(): void {
    if (this.configured) {
      this.unlocked = false;
      // Even a repeated lock invalidates verification already in flight.
      this.epoch++;
    }
  }

  // Keep all callers denied while asynchronous lock cleanup drains mutations.
  // A legacy settings response cannot bypass this barrier by disabling auth.
  holdLock(): () => void {
    this.lockHolds++;
    this.epoch++;
    let held = true;
    return () => {
      if (!held) return;
      held = false;
      this.lockHolds--;
    };
  }

  requireUnlocked(): void {
    if (!this.initialized) throw new Error('Authentication state is not initialized.');
    if (this.lockHolds > 0 || (this.configured && !this.unlocked)) {
      throw new Error('Authentication is required before accessing the Wormhole workspace.');
    }
  }

  private notifyUnlockIfNeeded(wasAccessAllowed: boolean): void {
    if (wasAccessAllowed || !this.isAccessAllowed) return;
    for (const listener of this.unlockListeners) listener();
  }
}
