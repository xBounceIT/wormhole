export type McpApprovalWindow = {
  isDestroyed(): boolean;
  isMinimized(): boolean;
  isVisible(): boolean;
  restore(): void;
  show(): void;
  moveTop(): void;
  focus(): void;
};

export type McpApprovalBlockingWindow = McpApprovalWindow & {
  destroy(): void;
  hide(): void;
};

type PreemptibleOperation = {
  controller: AbortController;
  settled: Promise<void>;
};

function isUsableWindow(window: McpApprovalWindow): boolean {
  try {
    return !window.isDestroyed();
  } catch {
    return false;
  }
}

export function selectMcpApprovalWindow<TWindow extends McpApprovalWindow>(
  windows: readonly TWindow[],
  focusedWindow: TWindow | null | undefined,
  isMainWindow: (window: TWindow) => boolean,
): TWindow | undefined {
  if (focusedWindow && isUsableWindow(focusedWindow) && isMainWindow(focusedWindow)) {
    return focusedWindow;
  }
  return windows.find((window) => isUsableWindow(window) && isMainWindow(window));
}

function attemptWindowAction(action: () => void): void {
  try {
    action();
  } catch {
    // Foregrounding is best-effort and must never block delivery of the approval event.
  }
}

export function bringMcpApprovalWindowToFront(window: McpApprovalWindow): void {
  if (!isUsableWindow(window)) return;
  attemptWindowAction(() => {
    if (window.isMinimized()) window.restore();
  });
  attemptWindowAction(() => {
    if (!window.isVisible()) window.show();
  });
  attemptWindowAction(() => window.moveTop());
  attemptWindowAction(() => window.focus());
}

export class McpApprovalWindowCoordinator<TWindow extends McpApprovalBlockingWindow> {
  private readonly pendingApprovalIds = new Set<string>();
  private readonly deferredPresentations = new Map<string, () => void>();
  private readonly tunnelAuthWindows = new Set<TWindow>();
  private readonly preemptibleOperations = new Set<PreemptibleOperation>();
  private activeNativeDialogs = 0;

  get hasPendingApprovals(): boolean {
    return this.pendingApprovalIds.size > 0;
  }

  presentTunnelAuthWindow(window: TWindow): void {
    if (!isUsableWindow(window)) return;
    this.tunnelAuthWindows.add(window);
    if (this.pendingApprovalIds.size === 0) attemptWindowAction(() => window.show());
  }

  forgetTunnelAuthWindow(window: TWindow): void {
    this.tunnelAuthWindows.delete(window);
  }

  beginApproval(approvalId: string): Promise<void> {
    this.pendingApprovalIds.add(approvalId);
    for (const window of this.tunnelAuthWindows) {
      if (isUsableWindow(window)) attemptWindowAction(() => window.hide());
    }
    return this.cancelPreemptibleOperations();
  }

  async runPreemptibleOperation<TResult>(
    operation: (signal: AbortSignal) => Promise<TResult>,
  ): Promise<TResult> {
    const controller = new AbortController();
    let markSettled!: () => void;
    const activeOperation: PreemptibleOperation = {
      controller,
      settled: new Promise<void>((resolve) => {
        markSettled = resolve;
      }),
    };
    this.preemptibleOperations.add(activeOperation);
    if (this.pendingApprovalIds.size > 0) controller.abort();
    try {
      return await operation(controller.signal);
    } finally {
      this.preemptibleOperations.delete(activeOperation);
      markSettled();
    }
  }

  presentApprovalWhenNativeDialogsClose(approvalId: string, present: () => void): void {
    if (!this.pendingApprovalIds.has(approvalId)) return;
    if (this.activeNativeDialogs > 0) {
      this.deferredPresentations.set(approvalId, present);
      return;
    }
    attemptWindowAction(present);
  }

  async runNativeDialog<TResult>(open: () => Promise<TResult>): Promise<TResult> {
    this.activeNativeDialogs++;
    try {
      return await open();
    } finally {
      this.activeNativeDialogs--;
      if (this.activeNativeDialogs === 0) this.presentDeferredApprovals();
    }
  }

  finishApproval(approvalId: string): void {
    this.deferredPresentations.delete(approvalId);
    if (!this.pendingApprovalIds.delete(approvalId) || this.pendingApprovalIds.size > 0) return;
    for (const window of this.tunnelAuthWindows) {
      if (!isUsableWindow(window)) {
        this.tunnelAuthWindows.delete(window);
        continue;
      }
      attemptWindowAction(() => window.show());
      attemptWindowAction(() => window.focus());
    }
  }

  reset(): void {
    void this.cancelPreemptibleOperations();
    this.pendingApprovalIds.clear();
    this.deferredPresentations.clear();
    for (const window of this.tunnelAuthWindows) {
      if (isUsableWindow(window)) attemptWindowAction(() => window.destroy());
    }
    this.tunnelAuthWindows.clear();
  }

  private async cancelPreemptibleOperations(): Promise<void> {
    const operations = [...this.preemptibleOperations];
    for (const operation of operations) operation.controller.abort();
    await Promise.all(operations.map((operation) => operation.settled));
  }

  private presentDeferredApprovals(): void {
    const presentations = [...this.deferredPresentations.values()];
    this.deferredPresentations.clear();
    for (const present of presentations) attemptWindowAction(present);
  }
}
