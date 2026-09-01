export function updateOpenOverlayIds(
  current: ReadonlySet<string>,
  overlayId: string,
  open: boolean,
): Set<string> {
  const next = new Set(current);
  if (open) {
    next.add(overlayId);
  } else {
    next.delete(overlayId);
  }
  return next;
}

export function hasOpenOverlay(openOverlayIds: ReadonlySet<string>): boolean {
  return openOverlayIds.size > 0;
}
