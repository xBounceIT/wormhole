import { useEffect, useRef, useState } from 'react';
import { AlertCircle, CheckCircle2, FileSearch, LoaderCircle, Upload, X } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  canAnalyzeMRemoteImport,
  importErrorMessage,
  mremoteImportProgress,
  type MRemoteImportPhase,
} from '../mremote-import-state';

export function MRemoteImportDialog({
  open,
  onOpenChange,
  onImported,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onImported: (workspace: WormholeWorkspaceSnapshot) => void;
}) {
  const [inspection, setInspection] = useState<WormholeMRemoteImportInspection | null>(null);
  const [plan, setPlan] = useState<WormholeMRemoteImportPlan | null>(null);
  const [result, setResult] = useState<WormholeMRemoteImportResult | null>(null);
  const passwordInput = useRef<HTMLInputElement>(null);
  const operationGeneration = useRef(0);
  const [passwordProvided, setPasswordProvided] = useState(false);
  const [structureOnly, setStructureOnly] = useState(false);
  const [phase, setPhase] = useState<MRemoteImportPhase>('idle');
  const [commitProgress, setCommitProgress] = useState<WormholeOperationProgress | null>(null);
  const [commitCancelling, setCommitCancelling] = useState(false);
  const [error, setError] = useState('');
  const busy = phase !== 'idle';

  function reset(clearSelection = true) {
    operationGeneration.current += 1;
    if (clearSelection) window.wormhole?.clearMRemoteImport();
    setInspection(null);
    setPlan(null);
    setResult(null);
    if (passwordInput.current) passwordInput.current.value = '';
    setPasswordProvided(false);
    setStructureOnly(false);
    setPhase('idle');
    setCommitProgress(null);
    setCommitCancelling(false);
    setError('');
  }

  useEffect(() => {
    if (!open) reset();
  }, [open]);

  useEffect(() => {
    return window.wormhole?.onOperationProgress((event) => {
      if (event.kind === 'mremote-import') setCommitProgress(event);
    });
  }, []);

  function close(nextOpen: boolean) {
    if (nextOpen) {
      onOpenChange(true);
      return;
    }
    if (phase === 'committing') {
      void cancelCommit();
      return;
    }
    if (phase === 'analyzing') window.wormhole?.cancelMRemoteImportAnalysis();
    reset();
    onOpenChange(false);
  }

  async function chooseFile() {
    const api = window.wormhole;
    if (!api || busy) return;
    const generation = ++operationGeneration.current;
    setPhase('selecting');
    setError('');
    setPlan(null);
    setResult(null);
    if (passwordInput.current) passwordInput.current.value = '';
    setPasswordProvided(false);
    try {
      const selected = await api.selectMRemoteImport();
      if (generation !== operationGeneration.current) return;
      if (selected) {
        setInspection(selected);
        setStructureOnly(false);
        if (selected.fullFileEncrypted) {
          setError(
            'This export uses full-file encryption. Re-export it with “Encrypt Connections File” disabled.',
          );
        }
      }
    } catch (selectionError) {
      if (generation !== operationGeneration.current) return;
      setError(importErrorMessage(selectionError));
    } finally {
      if (generation === operationGeneration.current) setPhase('idle');
    }
  }

  function changeOptions(nextStructureOnly = structureOnly) {
    setStructureOnly(nextStructureOnly);
    setPlan(null);
    setResult(null);
    setError('');
  }

  async function analyze() {
    const api = window.wormhole;
    if (!api || !inspection || busy || inspection.fullFileEncrypted) return;
    const generation = ++operationGeneration.current;
    setPhase('analyzing');
    setError('');
    setPlan(null);
    try {
      const analyzed = await api.analyzeMRemoteImport({
        password: structureOnly ? '' : (passwordInput.current?.value ?? ''),
        structureOnly,
      });
      if (generation === operationGeneration.current) setPlan(analyzed);
    } catch (analysisError) {
      if (generation !== operationGeneration.current) return;
      setError(importErrorMessage(analysisError));
    } finally {
      if (generation === operationGeneration.current) setPhase('idle');
    }
  }

  async function commit() {
    const api = window.wormhole;
    if (!api || !plan || busy) return;
    const generation = ++operationGeneration.current;
    setPhase('committing');
    setCommitProgress(null);
    setCommitCancelling(false);
    setError('');
    try {
      const imported = await api.commitMRemoteImport({
        password: structureOnly ? '' : (passwordInput.current?.value ?? ''),
        structureOnly,
      });
      if (generation !== operationGeneration.current) return;
      setResult(imported);
      setPlan(null);
      if (passwordInput.current) passwordInput.current.value = '';
      setPasswordProvided(false);
      try {
        onImported(await api.loadWorkspace());
      } catch {
        setError(
          'Import completed, but the workspace could not refresh. Restart Wormhole to show the imported items.',
        );
      }
    } catch (commitError) {
      if (generation !== operationGeneration.current) return;
      const message = importErrorMessage(commitError);
      if (/cancel/i.test(message)) {
        setError('Import cancelled; the verified plan was not saved.');
      } else {
        setPlan(null);
        setError(message);
      }
    } finally {
      if (generation === operationGeneration.current) setPhase('idle');
    }
  }

  async function cancelCommit() {
    if (phase !== 'committing' || commitCancelling || !window.wormhole) return;
    setCommitCancelling(true);
    try {
      await window.wormhole.cancelMRemoteImportCommit();
    } catch (cancelError) {
      setError(importErrorMessage(cancelError));
    } finally {
      setCommitCancelling(false);
    }
  }

  const percent =
    phase === 'committing' && commitProgress
      ? commitProgress.percent
      : mremoteImportProgress(phase, Boolean(inspection), Boolean(plan), Boolean(result));

  return (
    <Dialog onOpenChange={close} open={open}>
      <DialogContent className="flex max-h-[88vh] flex-col overflow-hidden border-border/70 bg-card text-card-foreground sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Import from mRemoteNG</DialogTitle>
          <DialogDescription>
            Analyze an mRemoteNG XML connections file, review the planned folders and connections,
            then import it atomically.
          </DialogDescription>
        </DialogHeader>

        <div className="grid min-h-0 gap-4 overflow-y-auto pr-1">
          <div className="flex items-center gap-3 rounded-md border border-border/70 p-3">
            <FileSearch className="size-5 shrink-0 text-muted-foreground" />
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium">
                {inspection?.fileName ?? 'No file selected'}
              </p>
              {inspection ? (
                <p className="text-xs text-muted-foreground">
                  mRemoteNG {inspection.confVersion || 'unknown version'} ·{' '}
                  {(inspection.fileSize / 1024).toFixed(1)} KiB
                </p>
              ) : null}
            </div>
            <Button
              disabled={busy}
              onClick={() => void chooseFile()}
              size="sm"
              type="button"
              variant="outline"
            >
              {phase === 'selecting' ? <LoaderCircle className="animate-spin" /> : <Upload />}
              {inspection ? 'Choose another…' : 'Choose file…'}
            </Button>
          </div>

          {inspection?.passwordRequired ? (
            <div className="grid gap-2">
              <Label htmlFor="mremote-import-password">mRemoteNG encryption password</Label>
              <Input
                autoComplete="off"
                disabled={busy || structureOnly}
                id="mremote-import-password"
                onChange={(event) => {
                  setPasswordProvided(event.target.value.length > 0);
                  changeOptions();
                }}
                placeholder="The default is mR3m"
                type="password"
                ref={passwordInput}
              />
              <label className="flex items-start gap-2 text-xs text-muted-foreground">
                <Checkbox
                  checked={structureOnly}
                  disabled={busy}
                  onCheckedChange={(checked) => {
                    if (passwordInput.current) passwordInput.current.value = '';
                    setPasswordProvided(false);
                    changeOptions(checked === true);
                  }}
                />
                <span>
                  Import structure only. Encrypted passwords are skipped and never stored.
                </span>
              </label>
            </div>
          ) : null}

          {inspection && !result ? (
            <div aria-live="polite" className="grid gap-1">
              <div className="flex justify-between text-xs text-muted-foreground">
                <span>
                  {phase === 'analyzing'
                    ? 'Analyzing and decrypting…'
                    : phase === 'committing'
                      ? commitCancelling
                        ? 'Cancelling import…'
                        : (commitProgress?.detail ?? 'Saving the verified plan…')
                      : plan
                        ? 'Analysis complete'
                        : 'Ready to analyze'}
                </span>
                <span>{percent}%</span>
              </div>
              <progress
                aria-label="Import progress"
                className="h-2 w-full"
                max={100}
                value={percent}
              />
            </div>
          ) : null}

          {plan ? (
            <div className="grid gap-3 rounded-md border border-border/70 p-3">
              <div className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
                <ImportCount label="Folders" value={plan.folders} />
                <ImportCount label="Connections" value={plan.connections} />
                <ImportCount label="Credentials" value={plan.credentials} />
                <ImportCount label="Skipped" value={plan.skippedUnsupported} />
              </div>
              <div>
                <p className="mb-2 text-xs font-medium">Plan preview</p>
                <ScrollArea className="h-44 rounded border border-border/60 bg-background/40">
                  <ul className="py-1 text-xs">
                    {plan.preview.map((node, index) => (
                      <li
                        className="flex items-center gap-2 px-2 py-1"
                        key={`${index}-${node.depth}-${node.name}`}
                        style={{ paddingLeft: `${Math.min(node.depth, 12) * 12}px` }}
                      >
                        <span className="text-muted-foreground">
                          {node.kind === 'folder'
                            ? 'Folder'
                            : (node.protocol?.toUpperCase() ?? 'Connection')}
                        </span>
                        <span className="truncate">{node.name}</span>
                      </li>
                    ))}
                  </ul>
                </ScrollArea>
                {plan.previewTruncated ? (
                  <p className="mt-1 text-xs text-muted-foreground">
                    Preview truncated; all validated items will still be imported.
                  </p>
                ) : null}
              </div>
              {plan.warnings.length > 0 || plan.skippedUnsupportedSamples.length > 0 ? (
                <Alert>
                  <AlertCircle />
                  <AlertTitle>Review warnings</AlertTitle>
                  <AlertDescription>
                    {[
                      ...plan.warnings.slice(0, 3),
                      ...plan.skippedUnsupportedSamples.map((item) => `Unsupported: ${item}`),
                    ]
                      .slice(0, 5)
                      .join(' ')}
                    {plan.droppedWarnings > 0
                      ? ` ${plan.droppedWarnings} additional warnings were omitted.`
                      : ''}
                  </AlertDescription>
                </Alert>
              ) : null}
            </div>
          ) : null}

          {result ? (
            <Alert>
              <CheckCircle2 />
              <AlertTitle>Import complete</AlertTitle>
              <AlertDescription>
                Created {result.foldersCreated} folders, {result.connectionsCreated} connections,
                and {result.credentialsCreated} protected credentials. Skipped{' '}
                {result.skippedUnsupported} unsupported connections.
                {result.warnings.length > 0 ? ` ${result.warnings.slice(0, 3).join(' ')}` : ''}
                {result.warnings.length > 3 || result.droppedWarnings > 0
                  ? ` ${Math.max(0, result.warnings.length - 3) + result.droppedWarnings} additional warnings were omitted.`
                  : ''}
              </AlertDescription>
            </Alert>
          ) : null}

          {error ? (
            <Alert variant="destructive">
              <AlertCircle />
              <AlertTitle>Import could not continue</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}
        </div>

        <DialogFooter>
          {phase === 'analyzing' ? (
            <Button
              onClick={() => window.wormhole?.cancelMRemoteImportAnalysis()}
              type="button"
              variant="outline"
            >
              <X />
              Cancel analysis
            </Button>
          ) : null}
          {phase === 'committing' ? (
            <Button
              disabled={commitCancelling}
              onClick={() => void cancelCommit()}
              type="button"
              variant="outline"
            >
              {commitCancelling ? <LoaderCircle className="animate-spin" /> : <X />}
              {commitCancelling ? 'Cancelling…' : 'Cancel import'}
            </Button>
          ) : null}
          {phase !== 'committing' ? (
            <Button onClick={() => close(false)} type="button" variant="ghost">
              {result ? 'Close' : 'Cancel'}
            </Button>
          ) : null}
          {!result && inspection ? (
            <Button
              disabled={
                plan
                  ? busy
                  : !canAnalyzeMRemoteImport(inspection, phase, passwordProvided, structureOnly)
              }
              onClick={() => void (plan ? commit() : analyze())}
              type="button"
            >
              {busy ? <LoaderCircle className="animate-spin" /> : null}
              {plan ? 'Import plan' : 'Analyze file'}
            </Button>
          ) : null}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ImportCount({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded bg-muted/50 px-2 py-1.5">
      <p className="text-lg font-semibold">{value}</p>
      <p className="text-xs text-muted-foreground">{label}</p>
    </div>
  );
}
