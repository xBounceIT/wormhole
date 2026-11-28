import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import type { VaultPresenceStatus } from '../electron/vault-presence.js';

export function VaultPresenceSettings({ disabled }: { disabled: boolean }) {
  const platform = window.wormhole?.platform;
  const label = platform === 'darwin' ? 'Touch ID' : 'Windows Hello';
  const [status, setStatus] = useState<VaultPresenceStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState('');
  useEffect(() => {
    const api = window.wormhole;
    if ((platform !== 'win32' && platform !== 'darwin') || !api?.vaultPresenceStatus) return;
    let current = true;
    void api.vaultPresenceStatus().then(
      (result) => {
        if (current) setStatus(result);
      },
      () => undefined,
    );
    return () => {
      current = false;
    };
  }, [platform]);

  if (!status) return null;
  const configure = async () => {
    const api = window.wormhole;
    if (!api || busy || disabled) return;
    setBusy(true);
    setFeedback('');
    try {
      const result = await api.configureVaultPresence(status.enrolled ? 'remove' : 'enroll');
      if ('enrolled' in result) {
        setStatus({ ...status, enrolled: true });
        setFeedback(`${label} is ready to unlock this vault.`);
      } else if ('removed' in result) {
        setStatus({ ...status, enrolled: false });
        setFeedback(
          result.keyDeleted
            ? `${label} was removed from this vault.`
            : `${label} was removed from this vault. The system credential could still be present.`,
        );
      } else {
        setFeedback(
          {
            'remote-desktop': 'Windows Hello is unavailable in Remote Desktop.',
            canceled: `${label} setup was canceled.`,
            'not-repeatable':
              'This Windows Hello credential cannot unlock the vault. Use your password or recovery code.',
            unavailable: `${label} is unavailable on this device.`,
          }[result.status],
        );
      }
    } catch {
      setFeedback(`The ${label} change did not complete.`);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      {status.enrolled || status.availability === 'ready' ? (
        <Button
          type="button"
          variant="outline"
          disabled={busy || disabled}
          onClick={() => void configure()}
        >
          {status.enrolled ? `Remove ${label}…` : `Set up ${label}…`}
        </Button>
      ) : null}
      {feedback ? <p role="status">{feedback}</p> : null}
    </>
  );
}
