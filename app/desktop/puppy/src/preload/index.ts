import { contextBridge, ipcRenderer } from 'electron'
import { electronAPI } from '@electron-toolkit/preload'
import { IpcChannels, type PuppyApi, type AppConfig, type ConnectionConfig } from '@shared/types'

const api: PuppyApi = {
  config: {
    get: () => ipcRenderer.invoke(IpcChannels.CONFIG_GET) as Promise<AppConfig>,
    set: (cfg: AppConfig) => ipcRenderer.invoke(IpcChannels.CONFIG_SET, cfg) as Promise<void>
  },
  connection: {
    test: (cfg?: ConnectionConfig) => ipcRenderer.invoke(IpcChannels.CONNECTION_TEST, cfg)
  },
  api: {
    getSystem: () => ipcRenderer.invoke(IpcChannels.API_SYSTEM),
    getStats: () => ipcRenderer.invoke(IpcChannels.API_STATS),
    getFrontends: () => ipcRenderer.invoke(IpcChannels.API_FRONTENDS),
    getBackends: () => ipcRenderer.invoke(IpcChannels.API_BACKENDS),
    getConfig: () => ipcRenderer.invoke(IpcChannels.API_CONFIG)
  },
  server: {
    start: () => ipcRenderer.invoke(IpcChannels.SERVER_START),
    stop: () => ipcRenderer.invoke(IpcChannels.SERVER_STOP),
    status: () => ipcRenderer.invoke(IpcChannels.SERVER_STATUS),
    logs: () => ipcRenderer.invoke(IpcChannels.SERVER_LOGS)
  }
}

if (process.contextIsolated) {
  try {
    contextBridge.exposeInMainWorld('electron', electronAPI)
    contextBridge.exposeInMainWorld('api', api)
  } catch (error) {
    console.error(error)
  }
} else {
  // @ts-ignore (define in dts)
  window.electron = electronAPI
  // @ts-ignore (define in dts)
  window.api = api
}
