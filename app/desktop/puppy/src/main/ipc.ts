import { ipcMain, dialog, BrowserWindow } from 'electron'
import { getConfig, setConfig } from './config/store'
import {
  getBackends,
  getConfigEndpoint,
  getFrontends,
  getStats,
  getSystem,
  testConnection
} from './api/handlers'
import { getLogs, getStatus, start, stop } from './server/manager'
import { IpcChannels, type AppConfig, type ConnectionConfig } from '@shared/types'

export function registerIpc(): void {
  ipcMain.handle(IpcChannels.CONFIG_GET, () => getConfig())
  ipcMain.handle(IpcChannels.CONFIG_SET, (_e, cfg: AppConfig) => {
    setConfig(cfg)
    return undefined
  })

  ipcMain.handle(IpcChannels.CONNECTION_TEST, (_e, cfg?: ConnectionConfig) => testConnection(cfg))

  ipcMain.handle(IpcChannels.API_SYSTEM, () => getSystem())
  ipcMain.handle(IpcChannels.API_STATS, () => getStats())
  ipcMain.handle(IpcChannels.API_FRONTENDS, () => getFrontends())
  ipcMain.handle(IpcChannels.API_BACKENDS, () => getBackends())
  ipcMain.handle(IpcChannels.API_CONFIG, () => getConfigEndpoint())

  ipcMain.handle(IpcChannels.SERVER_START, () => start())
  ipcMain.handle(IpcChannels.SERVER_STOP, () => stop())
  ipcMain.handle(IpcChannels.SERVER_STATUS, () => getStatus())
  ipcMain.handle(IpcChannels.SERVER_LOGS, () => getLogs())

  ipcMain.handle('dialog:openFile', async (e) => {
    const win = BrowserWindow.fromWebContents(e.sender)
    const res = win
      ? await dialog.showOpenDialog(win, { properties: ['openFile'] })
      : await dialog.showOpenDialog({ properties: ['openFile'] })
    return res.canceled ? '' : res.filePaths[0]
  })
}
