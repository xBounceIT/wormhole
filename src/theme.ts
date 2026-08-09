export type Theme = 'system' | 'light' | 'dark';
export type ResolvedTheme = Exclude<Theme, 'system'>;

export const themeStorageKey = 'wormhole-theme';

type ThemeStorage = Pick<Storage, 'getItem' | 'removeItem'>;

export function isTheme(value: string | null): value is Theme {
  return value === 'system' || value === 'light' || value === 'dark';
}

export function readLegacyTheme(storage?: ThemeStorage): Theme | null {
  if (!storage && typeof window === 'undefined') return null;
  try {
    const storedTheme = (storage ?? window.localStorage).getItem(themeStorageKey);
    return isTheme(storedTheme) ? storedTheme : null;
  } catch {
    return null;
  }
}

export function clearLegacyTheme(storage?: ThemeStorage): void {
  if (!storage && typeof window === 'undefined') return;
  try {
    (storage ?? window.localStorage).removeItem(themeStorageKey);
  } catch {
    // A disabled storage area must not block startup after Go accepted the migration.
  }
}

export function getInitialTheme(legacyTheme: Theme | null): Theme {
  return legacyTheme ?? 'system';
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
