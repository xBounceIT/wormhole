export type AuthSessionState = {
  configured: boolean;
};

export class AuthSession {
  private initialized = false;
  private configured = false;
  private unlocked = false;

  get isInitialized(): boolean {
    return this.initialized;
  }

  get isAccessAllowed(): boolean {
    return this.initialized && (!this.configured || this.unlocked);
  }

  remember(state: AuthSessionState, assumeUnlocked: boolean): void {
    const sameConfiguration = this.initialized && this.configured === state.configured;
    this.initialized = true;
    this.configured = state.configured;
    this.unlocked = state.configured
      ? assumeUnlocked || (sameConfiguration && this.unlocked)
      : true;
  }

  markUnlocked(): void {
    if (!this.initialized) throw new Error('Authentication state is not initialized.');
    this.unlocked = true;
  }

  lock(): void {
    if (this.configured) this.unlocked = false;
  }

  requireUnlocked(): void {
    if (!this.initialized) throw new Error('Authentication state is not initialized.');
    if (this.configured && !this.unlocked) {
      throw new Error('Authentication is required before accessing the Wormhole workspace.');
    }
  }
}
