import { isAppTheme, type AppTheme } from '../electron/theme-settings.ts';

export type Theme = AppTheme;
export { isAppTheme as isTheme };

export const themeStorageKey = 'wormhole-theme';

type ThemeStorage = Pick<Storage, 'getItem' | 'removeItem'>;

export function readLegacyTheme(storage?: ThemeStorage): Theme | null {
  if (!storage && typeof window === 'undefined') return null;
  try {
    const storedTheme = (storage ?? window.localStorage).getItem(themeStorageKey);
    return isAppTheme(storedTheme) ? storedTheme : null;
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

export function getSystemTheme(): 'light' | 'dark' {
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
  const oled = resolved === 'oled';
  const dark = resolved !== 'light';
  const colorScheme = dark ? 'dark' : 'light';
  const changed =
    root.classList.contains('dark') !== dark || root.classList.contains('oled') !== oled;
  if (changed) root.dataset.themeChanging = '';
  root.classList.toggle('dark', dark);
  root.classList.toggle('oled', oled);
  root.style.colorScheme = colorScheme;
  if (changed) {
    // Commit the new palette before re-enabling the navigation interaction transitions.
    root.getBoundingClientRect();
    delete root.dataset.themeChanging;
  }
  window.wormhole?.setTitlebarTheme(resolved);
}
