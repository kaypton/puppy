import { getConfig } from '../config/store'
import { apiGet } from './client'
import type {
  BackendsResponse,
  ConfigResponse,
  ConnectionConfig,
  FrontendsResponse,
  IpcResult,
  Stats,
  SystemInfo
} from '@shared/types'

function connectionConfig(): ConnectionConfig {
  return getConfig().connection
}

export function getSystem(): Promise<IpcResult<SystemInfo>> {
  return apiGet<SystemInfo>('/system', connectionConfig())
}

export function getStats(): Promise<IpcResult<Stats>> {
  return apiGet<Stats>('/stats', connectionConfig())
}

export function getFrontends(): Promise<IpcResult<FrontendsResponse>> {
  return apiGet<FrontendsResponse>('/frontends', connectionConfig())
}

export function getBackends(): Promise<IpcResult<BackendsResponse>> {
  return apiGet<BackendsResponse>('/backends', connectionConfig())
}

export function getConfigEndpoint(): Promise<IpcResult<ConfigResponse>> {
  return apiGet<ConfigResponse>('/config', connectionConfig())
}

export function testConnection(cfg?: ConnectionConfig): Promise<IpcResult<SystemInfo>> {
  return apiGet<SystemInfo>('/system', cfg ?? connectionConfig())
}
