export type MRemoteImportPhase = 'idle' | 'selecting' | 'analyzing' | 'committing';

export function canAnalyzeMRemoteImport(
  inspection: WormholeMRemoteImportInspection | null,
  phase: MRemoteImportPhase,
  passwordProvided: boolean,
  structureOnly: boolean,
): boolean {
  return Boolean(
    inspection &&
    phase === 'idle' &&
    !inspection.fullFileEncrypted &&
    (!inspection.passwordRequired || structureOnly || passwordProvided),
  );
}

export function mremoteImportProgress(
  phase: MRemoteImportPhase,
  hasInspection: boolean,
  hasPlan: boolean,
  complete: boolean,
): number {
  if (complete) return 100;
  if (phase === 'committing') return 75;
  if (phase === 'analyzing') return 35;
  if (phase === 'selecting') return 10;
  if (hasPlan) return 60;
  return hasInspection ? 20 : 0;
}

export function importErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'The mRemoteNG import failed.';
}
