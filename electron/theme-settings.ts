export type AppTheme = 'system' | 'light' | 'dark';

export function isAppTheme(value: unknown): value is AppTheme {
  return value === 'system' || value === 'light' || value === 'dark';
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function parseThemeStartupRequest(value: unknown): { legacyTheme?: AppTheme } {
  if (value === undefined) return {};
  if (!isPlainRecord(value) || Object.keys(value).some((key) => key !== 'legacyTheme')) {
    throw new Error('Startup settings request is invalid.');
  }
  if (value.legacyTheme === undefined) return {};
  if (!isAppTheme(value.legacyTheme)) throw new Error('Legacy application theme is invalid.');
  return { legacyTheme: value.legacyTheme };
}
