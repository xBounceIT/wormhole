import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('wormhole', {
  loadWorkspace: () => ipcRenderer.invoke('workspace:load'),
  openSshSession: (request: { sessionId: string; nodeId: string; columns: number; rows: number }) =>
    ipcRenderer.invoke('ssh:open', request),
  sendSshInput: (sessionId: string, data: string) =>
    ipcRenderer.invoke('ssh:input', sessionId, data),
  resizeSshSession: (sessionId: string, columns: number, rows: number) =>
    ipcRenderer.invoke('ssh:resize', sessionId, columns, rows),
  closeSshSession: (sessionId: string) => ipcRenderer.invoke('ssh:close', sessionId),
  onSshEvent: (
    listener: (event: {
      type: 'connected' | 'data' | 'closed' | 'error';
      sessionId: string;
      host?: string;
      port?: number;
      username?: string;
      fingerprint?: string;
      data?: string;
      error?: string;
    }) => void,
  ) => {
    const handler = (_event: Electron.IpcRendererEvent, value: unknown) => {
      listener(value as Parameters<typeof listener>[0]);
    };
    ipcRenderer.on('ssh:event', handler);
    return () => ipcRenderer.removeListener('ssh:event', handler);
  },
});
