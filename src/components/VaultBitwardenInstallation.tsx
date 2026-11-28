import { useEffect, useRef, useState } from 'react';
import { Button } from './ui/button';

// Mount only in an unlocked native workspace. The bridge returns public package
// metadata; folder selection and authentication remain in their native dialogs.
export function VaultBitwardenInstallation() {
  const [version, setVersion] = useState<string | null>();
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [cliAvailable, setCLIAvailable] = useState(false);
  const lifetime = useRef({ active: false });
  const pending = useRef(false);
  useEffect(() => {
    const current = { active: true };
    lifetime.current = current;
    void window.wormhole?.vaultBitwardenCLIAvailable?.().then(
      (available) => {
        if (current.active) setCLIAvailable(available === true);
      },
      () => {},
    );
    void (async () => {
      try {
        if (!window.wormhole) throw Error('Unavailable');
        const plan = await window.wormhole.readVaultBitwardenInstallation();
        if (current.active) setVersion(plan.installation?.version ?? null);
      } catch {
        if (current.active) setError('Could not verify the installed extension.');
      } finally {
        if (current.active) setBusy(false);
      }
    })();
    return () => {
      current.active = false;
    };
  }, []);
  async function run(action: 'folder' | 'zip' | 'cleanup' | 'unlock') {
    const current = lifetime.current;
    if (busy || pending.current || !current.active) return;
    pending.current = true;
    setBusy(true);
    setError('');
    setMessage('');
    try {
      if (!window.wormhole) throw Error('Unavailable');
      if (action === 'unlock') {
        const result = await window.wormhole.unlockVaultBitwardenCLI();
        if (result.unlocked !== true) throw Error('Unavailable');
        if (current.active) setMessage('Bitwarden CLI session saved in the vault.');
        return;
      }
      if (action === 'cleanup') {
        await window.wormhole.cleanupVaultBitwardenInstallations();
        if (current.active) setMessage('Old extension packages cleaned.');
        return;
      }
      const plan =
        action === 'zip'
          ? await window.wormhole.installVaultBitwardenZip()
          : await window.wormhole.installVaultBitwardenFolder();
      if (current.active && plan) setVersion(plan.installation?.version ?? null);
    } catch {
      if (current.active && action === 'unlock') {
        setError(
          'Could not unlock Bitwarden CLI. Check that the configured CLI is signed in and try again.',
        );
      } else if (current.active) {
        setVersion(undefined);
        setError(
          action === 'cleanup'
            ? 'Could not confirm package cleanup.'
            : 'Could not confirm extension installation.',
        );
      }
    } finally {
      pending.current = false;
      if (current.active) setBusy(false);
    }
  }
  return (
    <div className="space-y-3">
      <p role="status" className="text-xs text-muted-foreground">
        {busy
          ? 'Working…'
          : version
            ? `Installed version: ${version}`
            : version === null
              ? 'No extension installed.'
              : 'Installation status unavailable.'}
      </p>
      <p className="text-xs text-muted-foreground">
        Bitwarden is not yet available in encrypted vault browser windows. You can prepare its
        extension package here.
      </p>
      <Button disabled={busy} onClick={() => void run('folder')} type="button" variant="outline">
        Use folder
      </Button>
      <Button disabled={busy} onClick={() => void run('zip')} type="button" variant="outline">
        Import ZIP
      </Button>
      <Button disabled={busy} onClick={() => void run('cleanup')} type="button" variant="outline">
        Clean old packages
      </Button>
      {cliAvailable ? (
        <div>
          <Button
            disabled={busy}
            onClick={() => void run('unlock')}
            type="button"
            variant="outline"
          >
            Unlock Bitwarden CLI
          </Button>
          <p className="text-xs text-muted-foreground">
            Renew the session used by saved SSH and SFTP connections.
          </p>
        </div>
      ) : null}
      {message ? (
        <p role="status" className="text-xs text-muted-foreground">
          {message}
        </p>
      ) : null}
      {error ? (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      ) : null}
    </div>
  );
}
