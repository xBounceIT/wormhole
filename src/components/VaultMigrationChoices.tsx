import { useEffect, useRef, useState } from 'react';
import type { VaultMigrationChoice, VaultMigrationReport } from '../../electron/vault-migration';
import { Button } from './ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';

type Props = {
  nodeId: string;
  rowVersion: string;
  disabled: boolean;
  beginChange(): boolean;
  endChange(): void;
  onCommitted(rowVersion: string): void;
  refreshAfterFailure(): Promise<void>;
};
const labels = {
  ssh: 'SSH',
  sftp: 'SFTP',
  rdp: 'Remote Desktop',
  'rdp-gateway': 'Remote Desktop gateway',
  vnc: 'VNC',
  reveal: 'Credential reveal',
};

export function VaultMigrationChoices({
  nodeId,
  rowVersion,
  disabled,
  beginChange,
  endChange,
  onCommitted,
  refreshAfterFailure,
}: Props) {
  const [report, setReport] = useState<VaultMigrationReport>();
  const [choices, setChoices] = useState<VaultMigrationChoice[]>([]);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const refresh = useRef(refreshAfterFailure);
  refresh.current = refreshAfterFailure;
  const lifetime = useRef({ active: false }),
    pending = useRef(false);
  useEffect(() => {
    const operation = { active: true };
    lifetime.current = operation;
    setLoading(true);
    setReport(undefined);
    setChoices([]);
    setError('');
    setSaved(false);
    void (async () => {
      try {
        if (!window.wormhole) throw Error('Unavailable');
        const value = await window.wormhole.readVaultMigrationReport({ nodeId, rowVersion });
        if (!operation.active) return;
        setReport(value);
        setChoices(value.entries.map(({ protocolPath, choice }) => ({ protocolPath, choice })));
      } catch {
        if (operation.active) {
          try {
            await refresh.current();
          } catch {
            /* The original error remains actionable. */
          }
        }
        if (operation.active)
          setError(
            'Imported credential choices could not be loaded. Close and reopen the connection to refresh.',
          );
      } finally {
        if (operation.active) setLoading(false);
      }
    })();
    return () => {
      operation.active = false;
    };
  }, [nodeId, rowVersion]);
  async function apply() {
    if (pending.current || disabled || !report?.canDecide || !report.fingerprint || !changed)
      return;
    if (!beginChange()) return;
    pending.current = true;
    setSaving(true);
    setError('');
    setSaved(false);
    const operation = lifetime.current;
    try {
      if (!window.wormhole) throw Error('Unavailable');
      const result = await window.wormhole.decideVaultMigration({
        nodeId: report.nodeId,
        rowVersion: report.rowVersion,
        fingerprint: report.fingerprint,
        choices,
      });
      if (!operation.active) return;
      setReport({
        ...report,
        rowVersion: result.rowVersion,
        entries: report.entries.map((entry) => ({
          ...entry,
          choice: choices.find((choice) => choice.protocolPath === entry.protocolPath)!.choice,
        })),
      });
      setSaved(true);
      onCommitted(result.rowVersion);
    } catch {
      if (operation.active) {
        try {
          await refresh.current();
        } catch {
          /* Keep the original revision and error. */
        }
      }
      if (operation.active)
        setError(
          'The choices could not be saved. The connection may have changed; close and reopen it before trying again.',
        );
    } finally {
      pending.current = false;
      if (operation.active) setSaving(false);
      endChange();
    }
  }
  const changed = Boolean(
    report &&
    choices.some(
      (choice) =>
        report.entries.find((entry) => entry.protocolPath === choice.protocolPath)?.choice !==
        choice.choice,
    ),
  );
  if (loading)
    return (
      <p className="text-xs text-muted-foreground" role="status">
        Checking imported credential choices…
      </p>
    );
  if (!report)
    return (
      <p className="text-xs text-destructive" role="alert">
        {error}
      </p>
    );
  if (!report.entries.length) return null;
  return (
    <section
      className="grid gap-3 rounded-md border border-border p-3"
      aria-label="Imported credential choices"
    >
      <div>
        <h3 className="text-sm font-medium">Imported credential choices</h3>
        <p className="text-xs text-muted-foreground">
          Previous credentials were kept to preserve connection behavior. Choose which rules each
          connection action should use.
        </p>
        <p className="text-xs text-muted-foreground">
          These choices save separately. Connection settings can be edited after all actions use
          current inheritance.
        </p>
      </div>
      {report.entries.map((entry) => (
        <div className="grid gap-1" key={entry.protocolPath}>
          <span className="text-xs font-medium" id={`migration-${entry.protocolPath}`}>
            {labels[entry.protocolPath]}
          </span>
          <p className="text-xs text-muted-foreground">
            Changed during import:{' '}
            {[
              entry.credentialChanged ? 'saved credential' : '',
              entry.usernameChanged ? 'username' : '',
              entry.domainChanged ? 'domain' : '',
              entry.sourceChanged ? 'credential source' : '',
            ]
              .filter(Boolean)
              .join(', ')}
            .
          </p>
          <Select
            disabled={disabled || saving || !report.canDecide}
            value={choices.find((choice) => choice.protocolPath === entry.protocolPath)?.choice}
            onValueChange={(value) => {
              if (value === 'keep' || value === 'new') {
                setSaved(false);
                setChoices((current) =>
                  current.map((choice) =>
                    choice.protocolPath === entry.protocolPath
                      ? { ...choice, choice: value }
                      : choice,
                  ),
                );
              }
            }}
          >
            <SelectTrigger aria-labelledby={`migration-${entry.protocolPath}`} size="sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="keep">Keep previous credentials</SelectItem>
              <SelectItem value="new">Use current inheritance</SelectItem>
            </SelectContent>
          </Select>
        </div>
      ))}
      {!report.canDecide ? (
        <p className="text-xs text-muted-foreground">
          This security profile requires fresh authentication to change these choices. That flow is
          not available yet.
        </p>
      ) : null}
      {error ? (
        <p className="text-xs text-destructive" role="alert">
          {error}
        </p>
      ) : null}
      {saved ? (
        <p className="text-xs text-muted-foreground" role="status">
          Credential choices saved.
        </p>
      ) : null}
      <Button
        type="button"
        size="sm"
        variant="outline"
        disabled={disabled || saving || !report.canDecide || !changed}
        onClick={() => void apply()}
      >
        {saving ? 'Saving choices…' : 'Apply credential choices'}
      </Button>
    </section>
  );
}
