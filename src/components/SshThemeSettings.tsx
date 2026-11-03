import { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { Label } from './ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import {
  defaultSshTerminalTheme,
  isSshTerminalTheme,
  sshTerminalColors,
  sshTerminalThemes,
  type SshTerminalTheme,
} from '../terminal-themes';
import { setSshTerminalTheme } from '../xterm-terminal';

export function useSshTerminalTheme(initialTheme: unknown) {
  const [theme, setTheme] = useState<SshTerminalTheme>(
    isSshTerminalTheme(initialTheme) ? initialTheme : defaultSshTerminalTheme,
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const saving = useRef(false);
  useEffect(() => {
    setSshTerminalTheme(theme);
  }, [theme]);

  async function changeTheme(value: string) {
    if (!isSshTerminalTheme(value) || saving.current || value === theme) return;
    saving.current = true;
    setBusy(true);
    setError('');
    setTheme(value);
    try {
      if (!window.wormhole) throw new Error('Settings unavailable');
      await window.wormhole.setSshTerminalTheme(value);
    } catch {
      setTheme(theme);
      setError('Could not save the SSH theme. Try again.');
    } finally {
      saving.current = false;
      setBusy(false);
    }
  }
  return { theme, busy, error, changeTheme };
}

export function SshThemeSettings({
  theme,
  busy,
  error,
  onChange,
}: {
  theme: SshTerminalTheme;
  busy: boolean;
  error: string;
  onChange: (value: string) => void;
}) {
  const colors = sshTerminalColors(theme);
  return (
    <div className="grid max-w-sm gap-2">
      <Label htmlFor="settings-ssh-theme">SSH color theme</Label>
      <Select value={theme} disabled={busy} onValueChange={onChange}>
        <SelectTrigger id="settings-ssh-theme" className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {sshTerminalThemes.map((item) => (
            <SelectItem key={item.id} value={item.id}>
              {item.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <p className="text-[11px] text-muted-foreground">
        Applies to all SSH sessions immediately. Low-contrast text is adjusted for readability.
      </p>
      <div
        aria-label="SSH theme preview"
        className="overflow-hidden rounded-md border p-3"
        style={{ background: colors.background, color: colors.foreground }}
      >
        <SshThemePreview theme={theme} />
      </div>
      {error && (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}

function SshThemePreview({ theme }: { theme: SshTerminalTheme }) {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const preview = new Terminal({
      cols: 38,
      rows: 3,
      scrollback: 0,
      disableStdin: true,
      fontFamily: '"Cascadia Mono", "Consolas", monospace',
      fontSize: 12,
      lineHeight: 1.5,
      minimumContrastRatio: 4.5,
      theme: sshTerminalColors(theme),
    });
    preview.open(host.current!);
    preview.textarea!.tabIndex = -1;
    preview.write(
      '\x1b[?25l\x1b[92muser@server\x1b[0m:\x1b[94m~/projects\x1b[0m$ ls\r\n' +
        '\x1b[1;34mdocuments/\x1b[0m  README.md\r\n' +
        '\x1b[1;34;42mshared-777/\x1b[0m  drwxrwxrwx',
    );
    return () => preview.dispose();
  }, [theme]);
  return <div ref={host} />;
}
