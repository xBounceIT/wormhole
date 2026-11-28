import { useEffect, useRef, useState } from 'react';
import { LockKeyhole } from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { VaultProfileStatus } from '../electron/vault-security';

export type VaultProfileAPI = Pick<
  NonNullable<Window['wormhole']>,
  'getVaultSecurityProfile' | 'onVaultSecurityProfileChanged'
>;

const names = {
  default: 'Default',
  standard: 'Standard',
  hardened: 'Hardened',
  paranoid: 'Paranoid',
};
const sources = { os: 'Device policy', workspace: 'Workspace policy', user: 'Your preference' };

function ProfileChoice({
  tighten,
  disabled,
  shared,
}: {
  tighten: () => Promise<void>;
  disabled: boolean;
  shared: boolean;
}) {
  const [changing, setChanging] = useState(false);
  const [failure, setFailure] = useState(false);
  const pending = useRef(false);
  async function confirmStandard() {
    if (pending.current) return;
    pending.current = true;
    setChanging(true);
    setFailure(false);
    try {
      await tighten();
    } catch {
      setFailure(true);
    } finally {
      pending.current = false;
      setChanging(false);
    }
  }
  return (
    <div className="space-y-1">
      <Button
        type="button"
        variant="outline"
        disabled={disabled || changing}
        onClick={confirmStandard}
      >
        {shared
          ? 'Use Standard on this device and lock workspace…'
          : 'Use Standard protection and lock vault…'}
      </Button>
      {failure && (
        <p role="status" className="text-xs">
          Standard protection could not be confirmed.
        </p>
      )}
    </div>
  );
}

export function VaultSecurityProfile({
  api,
  shared = false,
  tighten,
  disabled = false,
}: {
  api: VaultProfileAPI;
  shared?: boolean;
  tighten?: () => Promise<void>;
  disabled?: boolean;
}) {
  const [status, setStatus] = useState<VaultProfileStatus | null>();
  useEffect(() => {
    let revision = 0;
    const refresh = () => {
      const request = ++revision;
      void api.getVaultSecurityProfile().then(
        (value) => {
          if (request === revision) setStatus(value);
        },
        () => {
          if (request === revision) setStatus(null);
        },
      );
    };
    const unsubscribe = api.onVaultSecurityProfileChanged(refresh);
    refresh();
    return () => {
      revision++;
      unsubscribe();
    };
  }, [api]);

  const managed = status && (status.source === 'os' || (shared && status.source === 'workspace'));
  return (
    <div className="space-y-2">
      <div role="status" aria-label="Effective security profile" className="space-y-1 text-xs">
        <p>
          Effective security profile{' '}
          <strong>
            {status ? names[status.effective] : status === null ? 'Unavailable' : 'Loading…'}
          </strong>
        </p>
        {status && (
          <p className="flex flex-wrap items-center gap-x-2 text-muted-foreground">
            <span>{sources[status.source]}</span>
            {managed && !status.retainedUntilLock && (
              <span className="inline-flex items-center gap-1">
                <LockKeyhole aria-hidden="true" size={13} />
                Set by your organization
              </span>
            )}
            {status.retainedUntilLock && (
              <span>This profile stays active until you lock the vault.</span>
            )}
          </p>
        )}
      </div>
      {status?.canTightenToStandard && tighten && (
        <ProfileChoice tighten={tighten} disabled={disabled} shared={shared} />
      )}
    </div>
  );
}
