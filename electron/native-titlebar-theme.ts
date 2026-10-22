export function nativeTitlebarOverlay(theme: 'light' | 'dark') {
  return {
    color: '#0a0a0a00',
    symbolColor: theme === 'light' ? '#0a0a0a' : '#ffffff',
    height: 48,
  };
}

interface TitlebarWindow {
  isDestroyed(): boolean;
  setTitleBarOverlay(options: ReturnType<typeof nativeTitlebarOverlay>): void;
}

export function syncNativeTitlebarTheme(
  window: TitlebarWindow | null,
  theme: unknown,
  platform: NodeJS.Platform,
): void {
  if (theme !== 'light' && theme !== 'dark') return;
  if (platform === 'darwin' || !window || window.isDestroyed()) return;
  window.setTitleBarOverlay(nativeTitlebarOverlay(theme));
}
