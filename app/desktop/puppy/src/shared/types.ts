// Puppy dashboard HTTP API 数据传输对象与 IPC 契约类型。
// 对应 docs/HTTP-API.md，Base URL: https://<host>:<port>/api/v1

// ---------------------------------------------------------------------------
// API DTO
// ---------------------------------------------------------------------------

export interface SystemInfo {
  version: string
  rust_version: string
  started_at: string
  uptime_seconds: number
  pid: number
  active_connections: number
  sse_subscribers: number
}

export interface Stats {
  total_connections: number
  active_connections: number
  dial_successes: number
  dial_failures: number
  bytes_in: number
  bytes_out: number
  started_at: string
  uptime_seconds: number
}

export interface FrontendSummary {
  name: string
  type: string
}

export interface FrontendsResponse {
  count: number
  frontends: FrontendSummary[]
}

export interface BackendCapability {
  network: string
  protocol: string
}

export interface BackendSummary {
  name: string
  type: string
  capabilities: BackendCapability[]
}

export interface BackendsResponse {
  count: number
  backends: BackendSummary[]
}

// /config 返回脱敏后的运行时配置，结构松散，直接保留原始 JSON。
export type ConfigResponse = Record<string, unknown>

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

export interface ApiErrorBody {
  error: string
}

// ---------------------------------------------------------------------------
// 连接配置（应用本地存储）
// ---------------------------------------------------------------------------

export interface ConnectionConfig {
  baseUrl: string
  token: string
  ignoreTls: boolean
}

export interface ServerProcessConfig {
  binaryPath: string
  configPath: string
  autoStart: boolean
}

export interface AppConfig {
  connection: ConnectionConfig
  server: ServerProcessConfig
}

// ---------------------------------------------------------------------------
// IPC 结果包装
// ---------------------------------------------------------------------------

export type IpcResult<T> = { ok: true; data: T } | { ok: false; status?: number; error: string }

// ---------------------------------------------------------------------------
// 本地 server 进程状态
// ---------------------------------------------------------------------------

export interface ServerProcessStatus {
  running: boolean
  pid?: number
  startTime?: number
  exitCode?: number
  signal?: string
}

export interface ServerLogEntry {
  stream: 'stdout' | 'stderr'
  text: string
  ts: number
}

// ---------------------------------------------------------------------------
// IPC 通道名称
// ---------------------------------------------------------------------------

export const IpcChannels = {
  // 配置
  CONFIG_GET: 'config:get',
  CONFIG_SET: 'config:set',
  // 连接
  CONNECTION_TEST: 'connection:test',
  // API
  API_SYSTEM: 'api:system',
  API_STATS: 'api:stats',
  API_FRONTENDS: 'api:frontends',
  API_BACKENDS: 'api:backends',
  API_CONFIG: 'api:config',
  // 进程管理
  SERVER_START: 'server:start',
  SERVER_STOP: 'server:stop',
  SERVER_STATUS: 'server:status',
  SERVER_LOGS: 'server:logs'
} as const

// ---------------------------------------------------------------------------
// window.api 类型（由 preload 暴露）
// ---------------------------------------------------------------------------

export interface PuppyApi {
  config: {
    get(): Promise<AppConfig>
    set(cfg: AppConfig): Promise<void>
  }
  connection: {
    test(cfg?: ConnectionConfig): Promise<IpcResult<SystemInfo>>
  }
  api: {
    getSystem(): Promise<IpcResult<SystemInfo>>
    getStats(): Promise<IpcResult<Stats>>
    getFrontends(): Promise<IpcResult<FrontendsResponse>>
    getBackends(): Promise<IpcResult<BackendsResponse>>
    getConfig(): Promise<IpcResult<ConfigResponse>>
  }
  server: {
    start(): Promise<IpcResult<ServerProcessStatus>>
    stop(): Promise<IpcResult<ServerProcessStatus>>
    status(): Promise<ServerProcessStatus>
    logs(): Promise<ServerLogEntry[]>
  }
}
