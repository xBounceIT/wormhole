import { useEffect, useRef, useState } from 'react';
import { Button } from './ui/button';

export function VaultProtectionNotice() {
  const [protection, setProtection] = useState<{ protected: boolean; lockedMemory: boolean }>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const lifetime = useRef({ active: false });
  useEffect(() => {
    const operation = { active: true };
    lifetime.current = operation;
    void (async () => {
      try {
        if (!window.wormhole) throw Error('Vault bridge unavailable.');
        const [result, status] = await Promise.all([
          window.wormhole.loadVaultProtection(),
          window.wormhole.getVaultStatus(),
        ]);
        if (!status.unlocked) throw Error('Vault owner unavailable.');
        if (operation.active)
          setProtection({ protected: result.protected, lockedMemory: status.lockedMemory });
      } catch {
        if (operation.active)
          setError('Workspace protection could not be checked. Lock and reopen Wormhole.');
      }
    })();
    return () => {
      operation.active = false;
    };
  }, []);
  if (protection?.protected && protection.lockedMemory) return null;
  const prepare = async () => {
    if (pending.current || protection?.protected !== false) return;
    pending.current = true;
    setBusy(true);
    setError('');
    const operation = lifetime.current;
    try {
      const prepared = await window.wormhole!.prepareUnprotectedVaultProtection();
      if (prepared) return;
    } catch {
      if (operation.active) setError('Protection setup could not start. Try again.');
    }
    if (operation.active) {
      pending.current = false;
      setBusy(false);
    }
  };
  return (
    <div
      role="status"
      className="flex shrink-0 items-center justify-between gap-3 border-b border-amber-500/30 bg-amber-500/10 px-4 py-2 text-sm"
    >
      <span>
        {protection?.protected === false
          ? "Wormhole isn't locked. Anyone using this computer can open your connections."
          : error || (!protection && 'Checking workspace protection…')}
        {protection?.lockedMemory === false && (
          <span className={protection.protected ? undefined : 'ml-2'}>
            Wormhole could not lock vault keys in memory. The operating system may page them to
            disk.
          </span>
        )}
        {protection?.protected === false && error && (
          <span role="alert" className="ml-2">
            {error}
          </span>
        )}
      </span>
      {protection?.protected === false && (
        <Button variant="outline" size="sm" disabled={busy} onClick={() => void prepare()}>
          {busy ? 'Preparing…' : 'Protect now'}
        </Button>
      )}
    </div>
  );
}
