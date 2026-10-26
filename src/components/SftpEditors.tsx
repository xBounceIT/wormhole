import { useCallback, useEffect, useRef, useState } from 'react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Textarea } from './ui/textarea';
import { Switch } from './ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';

export function SftpEditorSettings() {
  const [settings, setSettings] = useState<WormholeSftpEditorSettings>();
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    void window.wormhole
      ?.readSftpEditorSettings()
      .then(setSettings)
      .catch((error: unknown) => setMessage(String(error)));
  }, []);
  if (!settings)
    return <p className="text-xs text-muted-foreground">{message || 'Loading editor settings…'}</p>;
  function updateEditor(
    id: string,
    change: Partial<WormholeSftpEditorSettings['editors'][number]>,
  ) {
    setSettings(
      (current) =>
        current && {
          ...current,
          editors: current.editors.map((editor) =>
            editor.id === id ? { ...editor, ...change } : editor,
          ),
        },
    );
  }
  return (
    <section className="max-w-3xl space-y-5" aria-label="File transfer editor settings">
      <h2 className="text-sm font-semibold">Editors</h2>
      <p className="text-xs text-muted-foreground">
        Remote files open as private working copies. Saving in the editor uploads changes while this
        connection is open.
      </p>
      <div className="grid gap-2">
        <Label htmlFor="sftp-default-editor">Default editor</Label>
        <Select
          value={settings.defaultEditor}
          onValueChange={(value) => setSettings({ ...settings, defaultEditor: value })}
        >
          <SelectTrigger id="sftp-default-editor" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="auto">Detect a text editor</SelectItem>
            <SelectItem value="system">System default application</SelectItem>
            {settings.editors.map((editor) => (
              <SelectItem key={editor.id} value={editor.id}>
                {editor.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="grid max-w-xs gap-2">
        <Label htmlFor="sftp-edit-size">Maximum editing size (MiB)</Label>
        <Input
          id="sftp-edit-size"
          type="number"
          min={1}
          max={1024}
          value={settings.maxFileSize / 1048576}
          onChange={(event) =>
            setSettings({ ...settings, maxFileSize: Number(event.target.value) * 1048576 })
          }
        />
      </div>
      <label className="flex items-center gap-2 text-xs">
        <Switch
          checked={settings.swapPanels}
          onCheckedChange={(checked) => setSettings({ ...settings, swapPanels: checked })}
        />
        Show remote files on the left
      </label>
      {settings.editors.map((editor, index) => (
        <div className="grid gap-3 rounded-md border border-border p-4" key={editor.id}>
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold">Editor {index + 1}</h3>
            <Button
              size="sm"
              variant="ghost"
              onClick={() =>
                setSettings({
                  ...settings,
                  defaultEditor:
                    settings.defaultEditor === editor.id ? 'auto' : settings.defaultEditor,
                  editors: settings.editors.filter((candidate) => candidate.id !== editor.id),
                })
              }
            >
              Remove
            </Button>
          </div>
          <Label htmlFor={`${editor.id}-name`}>Name</Label>
          <Input
            id={`${editor.id}-name`}
            value={editor.name}
            onChange={(event) => updateEditor(editor.id, { name: event.target.value })}
          />
          <Label htmlFor={`${editor.id}-exe`}>Executable or macOS application</Label>
          <Input
            id={`${editor.id}-exe`}
            placeholder="Absolute path or command on PATH"
            value={editor.executable}
            onChange={(event) => updateEditor(editor.id, { executable: event.target.value })}
          />
          <Label htmlFor={`${editor.id}-args`}>Arguments (one per line)</Label>
          <Textarea
            id={`${editor.id}-args`}
            className="min-h-20 font-mono text-xs"
            value={editor.arguments.join('\n')}
            onChange={(event) =>
              updateEditor(editor.id, { arguments: event.target.value.split('\n') })
            }
          />
          <p className="text-[11px] text-muted-foreground">
            Use {'{file}'} on its own line for the file. Paths with spaces stay in one argument. The
            file is appended when no placeholder is present.
          </p>
          <Label htmlFor={`${editor.id}-patterns`}>File name patterns (optional)</Label>
          <Input
            id={`${editor.id}-patterns`}
            placeholder="*.conf;*.yml;*.sh"
            value={editor.patterns}
            onChange={(event) => updateEditor(editor.id, { patterns: event.target.value })}
          />
        </div>
      ))}
      <div className="flex gap-2">
        <Button
          size="sm"
          variant="outline"
          disabled={settings.editors.length >= 32}
          onClick={() =>
            setSettings({
              ...settings,
              editors: [
                ...settings.editors,
                {
                  id: crypto.randomUUID(),
                  name: 'New editor',
                  executable: '',
                  arguments: ['{file}'],
                  patterns: '',
                },
              ],
            })
          }
        >
          Add editor
        </Button>
        <Button
          size="sm"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            setMessage('');
            void window.wormhole
              ?.writeSftpEditorSettings(settings)
              .then(() => setMessage('Editor settings saved.'))
              .catch((error: unknown) =>
                setMessage(error instanceof Error ? error.message : String(error)),
              )
              .finally(() => setBusy(false));
          }}
        >
          Save editor settings
        </Button>
      </div>
      {message ? (
        <p role="status" className="text-xs">
          {message}
        </p>
      ) : null}
      <SftpEditedFiles sessionId="sftp-recovery" recovery />
    </section>
  );
}

export function SftpEditedFiles({
  sessionId,
  recovery = false,
}: {
  sessionId: string;
  recovery?: boolean;
}) {
  const [files, setFiles] = useState<WormholeSftpEditView[]>([]);
  const [error, setError] = useState('');
  const [saveAs, setSaveAs] = useState<{ id: string; path: string }>();
  const requests = useRef({
    version: 0,
    action: 0,
    pending: new Set<symbol>(),
    completed: new Set<string>(),
  }).current;
  const remember = useCallback(
    (requestId: string | undefined) => {
      if (!requestId) return;
      requests.completed.add(requestId);
      if (requests.completed.size > 256)
        requests.completed.delete(requests.completed.values().next().value!);
    },
    [requests],
  );
  useEffect(() => {
    let active = true;
    const listToken = Symbol();
    requests.pending.add(listToken);
    const initialVersion = ++requests.version;
    setFiles([]);
    setError('');
    setSaveAs(undefined);
    void window.wormhole
      ?.sftpEdit?.(sessionId, { operation: 'list' })
      .then((event) => {
        remember(event.requestId);
        if (active && requests.version === initialVersion) {
          setFiles(event.edits);
          setError(event.error ?? '');
        }
      })
      .catch((failure: unknown) => {
        if (active && requests.version === initialVersion)
          setError(failure instanceof Error ? failure.message : String(failure));
      })
      .finally(() => requests.pending.delete(listToken));
    const unsubscribe = window.wormhole?.onSshEvent((event) => {
      if (event.type !== 'sftp.edit') return;
      if (event.requestId) {
        if (requests.completed.has(event.requestId)) return;
        if (event.sessionId === sessionId && !recovery) {
          if (requests.pending.size || (event.error && !event.edits.length)) return;
          requests.version++;
          setFiles(event.edits);
          setError(event.error ?? '');
        } else if (recovery || event.sessionId !== sessionId) {
          if (event.error && !event.edits.length) return;
          requests.version++;
          setFiles((current) => [
            ...current.filter((file) => !file.recovered && file.sessionId === sessionId),
            ...event.edits.filter((file) => file.recovered),
          ]);
        }
      } else if (event.sessionId === sessionId || recovery) {
        requests.version++;
        setFiles((current) => {
          const next = new Map(current.map((file) => [file.id, file]));
          for (const file of event.edits) next.set(file.id, file);
          return [...next.values()];
        });
      }
    });
    return () => {
      active = false;
      requests.version++;
      requests.action = 0;
      requests.pending.clear();
      requests.completed.clear();
      unsubscribe?.();
    };
  }, [sessionId, recovery, requests, remember]);
  const run = (request: WormholeSftpEditRequest) => {
    const requestVersion = ++requests.version;
    requests.action = requestVersion;
    const token = Symbol();
    requests.pending.add(token);
    setError('');
    void window.wormhole
      ?.sftpEdit?.(sessionId, request)
      .then((event) => {
        remember(event.requestId);
        // Progress emitted by this command may advance the stream version. The
        // command's final snapshot is still authoritative unless a newer action
        // or a session change has superseded it.
        if (requests.action !== requestVersion) return;
        if (!event.error || event.edits.length) setFiles(event.edits);
        setError(event.error ?? '');
      })
      .catch((failure: unknown) => {
        if (requests.action === requestVersion)
          setError(failure instanceof Error ? failure.message : String(failure));
      })
      .finally(() => requests.pending.delete(token));
  };
  const visible = files.filter((file) =>
    recovery ? file.recovered || file.pending : file.sessionId === sessionId || file.recovered,
  );
  if (!visible.length && !error) return null;
  return (
    <section
      aria-label={recovery ? 'Recover edited files' : 'Edited files'}
      className="max-h-48 shrink-0 overflow-auto rounded-md border border-border p-2"
    >
      <h3 className="mb-1 text-xs font-semibold">
        {recovery ? 'Recover edited files' : 'Edited files'}
      </h3>
      {recovery ? (
        <p className="mb-2 text-[11px] text-muted-foreground">
          Working copies were kept. Connect to the original server, then choose Recover in its File
          transfer tab to upload. Open folder reveals the private copy.
        </p>
      ) : null}
      {visible.map((file) => (
        <div
          key={file.id}
          className="flex flex-wrap items-center gap-2 border-t border-border py-2 text-[11px]"
        >
          <div className="min-w-32 flex-1">
            <p className="truncate font-medium" title={file.remotePath}>
              {file.name}
            </p>
            <p className="truncate text-muted-foreground" title={file.remotePath}>
              {file.remotePath} · {file.editor}
            </p>
          </div>
          <span role="status">
            {file.state === 'Uploaded' && file.uploadedAt
              ? `Uploaded ${new Date(file.uploadedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`
              : file.state}
          </span>
          {file.recovered && !recovery ? (
            <Button
              size="sm"
              variant="outline"
              onClick={() => run({ operation: 'recover', editId: file.id })}
            >
              Recover
            </Button>
          ) : null}
          {!file.recovered && !recovery ? (
            <>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => run({ operation: 'upload', editId: file.id })}
              >
                Upload now
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => run({ operation: 'stop', editId: file.id })}
              >
                Stop editing
              </Button>
            </>
          ) : null}
          <Button
            size="sm"
            variant="ghost"
            onClick={() => run({ operation: 'reveal', editId: file.id })}
          >
            Open folder
          </Button>
          {file.state === 'Conflict' && !recovery ? (
            <>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  if (window.confirm(`Overwrite ${file.remotePath} with your working copy?`))
                    run({ operation: 'upload', editId: file.id, decision: 'overwrite' });
                }}
              >
                Overwrite remote
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setSaveAs({ id: file.id, path: file.remotePath })}
              >
                Save as
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  if (window.confirm('Discard local changes and re-download the remote file?'))
                    run({ operation: 'reload', editId: file.id, decision: 'discard' });
                }}
              >
                Re-download
              </Button>
            </>
          ) : null}
          {file.recovered ? (
            <Button
              size="sm"
              variant="destructive"
              onClick={() => {
                if (window.confirm(`Permanently discard the working copy of ${file.name}?`))
                  run({ operation: 'discard', editId: file.id, decision: 'discard' });
              }}
            >
              Discard
            </Button>
          ) : null}
          {file.error ? <p className="basis-full text-destructive">{file.error}</p> : null}
        </div>
      ))}
      {saveAs ? (
        <form
          className="flex gap-2 py-2"
          onSubmit={(event) => {
            event.preventDefault();
            run({ operation: 'upload', editId: saveAs.id, destinationPath: saveAs.path });
            setSaveAs(undefined);
          }}
        >
          <Input
            aria-label="Save edited file as remote path"
            value={saveAs.path}
            onChange={(event) => setSaveAs({ ...saveAs, path: event.target.value })}
          />
          <Button size="sm" type="submit">
            Save as
          </Button>
          <Button size="sm" type="button" variant="ghost" onClick={() => setSaveAs(undefined)}>
            Cancel
          </Button>
        </form>
      ) : null}
      {error ? (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      ) : null}
    </section>
  );
}

export function SftpRecoveryNotice() {
  const [count, setCount] = useState(0);
  useEffect(() => {
    let active = true;
    let updated = false;
    void window.wormhole
      ?.sftpEdit?.('sftp-recovery', { operation: 'list' })
      .then((event) => {
        if (active && !updated) setCount(event.edits.filter((file) => file.recovered).length);
      })
      .catch(() => undefined);
    const unsubscribe = window.wormhole?.onSshEvent((event) => {
      if (event.type !== 'sftp.edit' || !event.requestId || (event.error && !event.edits.length))
        return;
      updated = true;
      setCount(event.edits.filter((file) => file.recovered).length);
    });
    return () => {
      active = false;
      unsubscribe?.();
    };
  }, []);
  return count ? (
    <div className="border-b border-border bg-accent px-4 py-2 text-xs" role="status">
      {count} edited working copy/copies can be recovered. Open Settings → File transfer to reveal
      or discard them, or reconnect to recover and upload.
    </div>
  ) : null;
}
