import type { ChildProcess } from 'node:child_process';
import { hasNativeProcessExitProof } from './vault-process-exit.ts';
export type ChildExitState = Pick<ChildProcess, 'exitCode' | 'signalCode'> & {
  readonly pid?: number;
};

// Never interpret a signal-zero error or an exit status as a kernel wait result.
// Native process notifications or the independent Go wait proof own this state.
export function hasChildExited(child: ChildExitState): boolean {
  return child.exitCode != null || child.signalCode != null || hasNativeProcessExitProof(child);
}
