import { ElectronAPI } from '@electron-toolkit/preload'
import type { PuppyApi } from '@shared/types'

declare global {
  interface Window {
    electron: ElectronAPI
    api: PuppyApi
  }
}
