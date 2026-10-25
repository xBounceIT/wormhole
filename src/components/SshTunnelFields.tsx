import { useEffect, useMemo, useState } from 'react';
import { sshJumpCandidates, type JumpNode } from '../ssh-tunnel-state';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { SearchableCombobox } from './SearchableCombobox';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';

export function SshTunnelFields({
  settings,
  tunnelId,
  tree,
  credentials,
  tunnels,
  pin,
  onChange,
  onForgetPin,
}: {
  settings: Record<string, unknown>;
  tunnelId?: string;
  tree: JumpNode[];
  credentials: { id: string; name: string }[];
  tunnels: { id: string; kind: string }[];
  pin: string;
  onChange: (key: string, value: unknown) => void;
  onForgetPin: () => void;
}) {
  const [catalog, setCatalog] = useState<Record<string, Record<string, unknown> | null>>({});
  const [loadError, setLoadError] = useState('');
  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const entries = await Promise.all(
          tunnels.map(
            async (tunnel) =>
              [
                tunnel.id,
                tunnel.kind === 'SSH tunnel (jump host)'
                  ? (await window.wormhole!.readTunnel(tunnel.id)).settings
                  : null,
              ] as const,
          ),
        );
        if (active) {
          setCatalog(Object.fromEntries(entries));
          setLoadError('');
        }
      } catch {
        if (active) setLoadError('Could not load SSH jump routes. Reopen the editor to retry.');
      }
    }
    void load();
    return () => {
      active = false;
    };
  }, [tunnels]);
  const options = useMemo(
    () => sshJumpCandidates(tree, tunnelId, catalog),
    [tree, tunnelId, catalog],
  );
  const connectionMode = settings.Mode === 'connection';
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <div className="grid gap-2 md:col-span-2">
        <Label htmlFor="ssh-tunnel-mode">Jump host source</Label>
        <Select value={String(settings.Mode)} onValueChange={(value) => onChange('Mode', value)}>
          <SelectTrigger id="ssh-tunnel-mode">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="connection">Use an existing SSH connection</SelectItem>
            <SelectItem value="manual">Manual</SelectItem>
          </SelectContent>
        </Select>
      </div>
      {connectionMode ? (
        <div className="grid gap-2 md:col-span-2">
          <Label htmlFor="ssh-tunnel-connection">SSH connection</Label>
          <SearchableCombobox
            id="ssh-tunnel-connection"
            options={options}
            value={String(settings.JumpConnectionId ?? '')}
            onValueChange={(value) => onChange('JumpConnectionId', value)}
            placeholder="Select a saved SSH connection"
            searchPlaceholder="Search SSH connections…"
            emptyMessage="No eligible SSH connections."
          />
          <p className="text-[11px] text-muted-foreground">
            Reuses its saved or inherited credential and route. Connections that create a cycle or
            exceed three tunnel hops are excluded.
          </p>
          {loadError ? (
            <p role="alert" className="text-xs text-destructive">
              {loadError}
            </p>
          ) : null}
        </div>
      ) : (
        <>
          <div className="grid gap-2">
            <Label htmlFor="ssh-tunnel-host">Host</Label>
            <Input
              id="ssh-tunnel-host"
              value={String(settings.Host ?? '')}
              onChange={(event) => onChange('Host', event.target.value)}
              placeholder="bastion.example.com"
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="ssh-tunnel-port">Port</Label>
            <Input
              id="ssh-tunnel-port"
              type="number"
              min={1}
              max={65535}
              value={String(settings.Port ?? 22)}
              onChange={(event) => onChange('Port', event.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="ssh-tunnel-username">Username</Label>
            <Input
              id="ssh-tunnel-username"
              value={String(settings.Username ?? '')}
              onChange={(event) => onChange('Username', event.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="ssh-tunnel-credential">Saved SSH credential</Label>
            <SearchableCombobox
              id="ssh-tunnel-credential"
              options={credentials.map((credential) => ({
                value: credential.id,
                label: credential.name,
              }))}
              value={String(settings.CredentialId ?? '')}
              onValueChange={(value) => onChange('CredentialId', value)}
              placeholder="Select a credential"
              searchPlaceholder="Search SSH credentials…"
              emptyMessage="No local SSH credentials."
            />
          </div>
        </>
      )}
      <div className="grid gap-2 md:col-span-2">
        <Label htmlFor="ssh-tunnel-pin">Pinned host key (SHA-256)</Label>
        <div className="flex gap-2">
          <Input
            id="ssh-tunnel-pin"
            readOnly
            value={pin}
            placeholder="Confirm the fingerprint on first use"
          />
          <Button type="button" variant="outline" disabled={!pin} onClick={onForgetPin}>
            Forget pin
          </Button>
        </div>
        <p className="text-[11px] text-muted-foreground">
          Only trust a fingerprint verified with your administrator. Forgetting a saved connection’s
          pin also affects that connection. Bitwarden credentials are not yet supported.
        </p>
      </div>
      <div className="grid gap-2">
        <Label htmlFor="ssh-tunnel-keepalive">Keepalive (seconds)</Label>
        <Input
          id="ssh-tunnel-keepalive"
          type="number"
          min={1}
          max={3600}
          value={String(settings.KeepaliveSeconds ?? 30)}
          onChange={(event) => onChange('KeepaliveSeconds', event.target.value)}
        />
      </div>
    </div>
  );
}
