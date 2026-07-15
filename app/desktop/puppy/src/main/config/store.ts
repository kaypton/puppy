import Store from 'electron-store'
import type { AppConfig } from '@shared/types'

const DEFAULT_CONFIG: AppConfig = {
  connection: {
    baseUrl: 'https://127.0.0.1:8443',
    token: '',
    ignoreTls: true
  },
  server: {
    binaryPath: '',
    configPath: '',
    autoStart: false
  }
}

let store: Store<AppConfig> | null = null

function getStore(): Store<AppConfig> {
  if (!store) {
    store = new Store<AppConfig>({
      name: 'puppy-config',
      defaults: DEFAULT_CONFIG
    })
  }
  return store
}

export function getConfig(): AppConfig {
  return getStore().store
}

export function setConfig(cfg: AppConfig): void {
  getStore().store = cfg
}

export function getDefaultConfig(): AppConfig {
  return structuredClone(DEFAULT_CONFIG)
}
