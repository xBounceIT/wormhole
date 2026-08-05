export type Theme = 'system' | 'light' | 'dark';
export type ResolvedTheme = Exclude<Theme, 'system'>;

export const themeStorageKey = 'wormhole-theme';

export function isTheme(value: string | null): value is Theme {
  return value === 'system' || value === 'light' || value === 'dark';
}

export function getInitialTheme(): Theme {
  if (typeof window === 'undefined') return 'dark';

  const storedTheme = window.localStorage.getItem(themeStorageKey);
  return isTheme(storedTheme) ? storedTheme : 'dark';
}

export function getSystemTheme(): ResolvedTheme {
  if (typeof window === 'undefined') return 'light';

  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

/**
 * Applies the resolved theme to the document root. Called before React's first
 * render (in main.tsx) so the very first painted frame already has the correct
 * background — without this, the app flashes the light theme until the `.dark`
 * class lands after mount.
 */
export function applyTheme(theme: Theme): void {
  const resolved = theme === 'system' ? getSystemTheme() : theme;
  const root = document.documentElement;
  root.classList.toggle('dark', resolved === 'dark');
  root.style.colorScheme = resolved;
}
