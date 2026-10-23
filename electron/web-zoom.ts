export function adjustWebZoom(
  contents: Pick<Electron.WebContents, 'getZoomFactor' | 'setZoomFactor'>,
  operation: 'zoom-in' | 'zoom-out',
): void {
  const step = operation === 'zoom-in' ? 1 : -1;
  const factor = Math.round(contents.getZoomFactor() * 10 + step) / 10;
  contents.setZoomFactor(Math.min(3, Math.max(0.5, factor)));
}
