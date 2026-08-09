export type LogLevel = 'info' | 'debug';

export type LogLevelSaveState = {
  desired: LogLevel;
  persisted: LogLevel;
};

export function isLogLevel(value: unknown): value is LogLevel {
  return value === 'info' || value === 'debug';
}

export function createLogLevelSaveState(initialValue: LogLevel): LogLevelSaveState {
  return { desired: initialValue, persisted: initialValue };
}

export async function drainLogLevelChanges(
  state: LogLevelSaveState,
  persist: (level: LogLevel) => Promise<unknown>,
  onPersisted: (level: LogLevel) => void,
): Promise<void> {
  while (state.desired !== state.persisted) {
    const target = state.desired;
    const persisted = await persist(target);
    if (!isLogLevel(persisted) || persisted !== target) {
      throw new Error('The log level response is invalid.');
    }
    state.persisted = persisted;
    onPersisted(persisted);
  }
}
