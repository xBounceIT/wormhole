export function selectDialogVisuals<T>(open: boolean | undefined, current: T, retained: T): T {
  return open === false ? retained : current;
}
