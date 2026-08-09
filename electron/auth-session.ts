export type AuthSessionState = {
  configured: boolean;
};

type UnlockListener = () => void;

export class AuthSession {
  private initialized = false;
  private configured = false;
  private unlocked = false;
  private epoch = 0;
  private readonly unlockListeners = new Set<UnlockListener>();

  get isInitialized(): boolean {
    return this.initialized;
  }

  get isAccessAllowed(): boolean {
    return this.initialized && (!this.configured || this.unlocked);
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

  markUnlocked(): void {
    if (!this.initialized) throw new Error('Authentication state is not initialized.');
    const wasAccessAllowed = this.isAccessAllowed;
    this.unlocked = true;
    this.notifyUnlockIfNeeded(wasAccessAllowed);
  }

  lock(): void {
    const wasAccessAllowed = this.isAccessAllowed;
    if (this.configured) this.unlocked = false;
    if (wasAccessAllowed && !this.isAccessAllowed) this.epoch++;
  }

  requireUnlocked(): void {
    if (!this.initialized) throw new Error('Authentication state is not initialized.');
    if (this.configured && !this.unlocked) {
      throw new Error('Authentication is required before accessing the Wormhole workspace.');
    }
  }

  private notifyUnlockIfNeeded(wasAccessAllowed: boolean): void {
    if (wasAccessAllowed || !this.isAccessAllowed) return;
    for (const listener of this.unlockListeners) listener();
  }
}
