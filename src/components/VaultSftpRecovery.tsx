import { useEffect, useRef, useState } from 'react';
import type { VaultRecoveryRecords } from '../../electron/vault-sftp-recovery';
import { Button } from './ui/button';

export function VaultSftpRecovery() {
  const [nodes, setNodes] = useState<string[]>([]);
  const [names, setNames] = useState<Record<string, string>>({});
  const [scopeAfter, setScopeAfter] = useState('');
  const [node, setNode] = useState('');
  const [page, setPage] = useState<VaultRecoveryRecords>({ edits: [], after: '', busy: false });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const generation = useRef(0);
  const scopes = useRef(0);
  const mounted = useRef(true);
  const message = (e: unknown) => (e instanceof Error ? e.message : 'Recovery is unavailable.');

  useEffect(() => {
    mounted.current = true;
    void window.wormhole
      ?.loadVaultCatalog()
      .then((catalog) => {
        if (mounted.current) setNames(Object.fromEntries(catalog.nodes.map((n) => [n.id, n.name])));
      })
      .catch(() => {});
    return () => {
      mounted.current = false;
      generation.current++;
      scopes.current++;
    };
  }, []);

  async function selectNode(id: string, after = '', append = false) {
    const version = ++generation.current;
    setNode(id);
    setLoading(true);
    setError('');
    if (!append) setPage({ edits: [], after: '', busy: false });
    try {
      const result = await window.wormhole!.vaultSftpRecovery({
        nodeId: id,
        operation: 'list',
        after,
      });
      if (!mounted.current || generation.current !== version) return;
      setPage((current) => ({
        ...result,
        edits: append ? [...current.edits, ...result.edits] : result.edits,
      }));
    } catch (e) {
      if (mounted.current && generation.current === version) setError(message(e));
    } finally {
      if (mounted.current && generation.current === version) setLoading(false);
    }
  }

  async function loadScopes(after = '') {
    const version = ++scopes.current;
    setLoading(true);
    setError('');
    try {
      const result = await window.wormhole!.readVaultSftpRecoveryScopes(after);
      if (!mounted.current || scopes.current !== version) return;
      setNodes(result.nodeIds);
      setScopeAfter(result.after);
      generation.current++;
      setNode('');
      setPage({ edits: [], after: '', busy: false });
      if (result.nodeIds[0]) await selectNode(result.nodeIds[0]);
    } catch (e) {
      if (mounted.current && scopes.current === version) setError(message(e));
    } finally {
      if (mounted.current && scopes.current === version) setLoading(false);
    }
  }

  useEffect(() => {
    void loadScopes();
  }, []);

  async function act(operation: 'reveal' | 'discard', id: string, name: string) {
    if (
      operation === 'discard' &&
      !window.confirm(`Permanently discard the working copy of ${name}?`)
    )
      return;
    const version = ++generation.current;
    const selected = node;
    setLoading(true);
    setError('');
    try {
      const q =
        operation === 'discard'
          ? { nodeId: selected, operation, editId: id, decision: 'discard' as const }
          : { nodeId: selected, operation, editId: id };
      const result = await window.wormhole!.vaultSftpRecovery(q);
      if (!mounted.current || generation.current !== version) return;
      if (result.busy) {
        setPage({ edits: [], after: '', busy: true });
        return;
      }
      if (operation === 'discard')
        setPage((current) => ({
          ...current,
          edits: current.edits.filter((file) => file.id !== id),
        }));
    } catch (e) {
      if (mounted.current && generation.current === version) setError(message(e));
    } finally {
      if (mounted.current && generation.current === version) setLoading(false);
    }
  }

  return (
    <section className="space-y-3" aria-label="Vault file recovery">
      <h3 className="text-sm font-semibold">Recover edited files</h3>
      <p className="text-xs text-muted-foreground">
        Working copies remain on disk under your OS account’s file permissions, including while the
        vault is locked. Open their folder or discard them here. Reconnect to the original server
        and route to recover and upload from its File transfer tab.
      </p>
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="outline" disabled={loading} onClick={() => void loadScopes()}>
          Refresh recovery
        </Button>
        {scopeAfter ? (
          <Button
            size="sm"
            variant="outline"
            disabled={loading}
            onClick={() => void loadScopes(scopeAfter)}
          >
            Next connections
          </Button>
        ) : null}
      </div>
      {nodes.length ? (
        <label className="grid gap-1 text-xs">
          Connection
          <select
            aria-label="Recovery connection"
            className="rounded-md border border-input bg-background p-2"
            disabled={loading}
            value={node}
            onChange={(event) => void selectNode(event.target.value)}
          >
            {nodes.map((id, index) => (
              <option key={id} value={id}>
                {names[id] ?? `Unavailable connection ${index + 1}`}
              </option>
            ))}
          </select>
        </label>
      ) : !loading ? (
        <p className="text-xs">No recovery archives on this page.</p>
      ) : null}
      {loading ? (
        <p role="status" className="text-xs">
          Loading recovery…
        </p>
      ) : null}
      {page.busy ? (
        <p role="status" className="text-xs">
          This connection is active. Manage its working copies in its File transfer tab, or
          disconnect and refresh.
        </p>
      ) : null}
      {!loading && node && !page.busy && !page.edits.length ? (
        <p className="text-xs">No retained files for this connection.</p>
      ) : null}
      {page.edits.map((file) => (
        <div
          key={file.id}
          className="flex flex-wrap items-center gap-2 border-t border-border py-2 text-xs"
        >
          <div className="min-w-32 flex-1">
            <p className="font-medium">{file.name}</p>
            <p className="break-all text-muted-foreground">
              {file.remotePath} · {file.editor}
            </p>
          </div>
          <Button
            size="sm"
            variant="ghost"
            disabled={loading}
            onClick={() => void act('reveal', file.id, file.name)}
          >
            Open folder
          </Button>
          <Button
            size="sm"
            variant="destructive"
            disabled={loading}
            onClick={() => void act('discard', file.id, file.name)}
          >
            Discard
          </Button>
        </div>
      ))}
      {page.after ? (
        <Button
          size="sm"
          variant="outline"
          disabled={loading}
          onClick={() => void selectNode(node, page.after, true)}
        >
          More retained files
        </Button>
      ) : null}
      {error ? (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      ) : null}
    </section>
  );
}
