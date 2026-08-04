import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('wormhole', {
  loadWorkspace: () => ipcRenderer.invoke('workspace:load'),
});
