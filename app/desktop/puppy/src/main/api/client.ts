import https from 'node:https'
import http from 'node:http'
import { URL } from 'node:url'
import type { ConnectionConfig, IpcResult } from '@shared/types'

const API_PREFIX = '/api/v1'

export interface RequestOptions {
  method: 'GET' | 'POST' | 'DELETE'
  path: string
  config?: ConnectionConfig
  timeoutMs?: number
}

export interface RawResponse {
  status: number
  body: unknown
}

function buildUrl(baseUrl: string, path: string): URL {
  const trimmedBase = baseUrl.replace(/\/+$/, '')
  return new URL(`${trimmedBase}${API_PREFIX}${path}`)
}

function makeRequest(opts: RequestOptions): Promise<RawResponse> {
  const cfg = opts.config
  if (!cfg) {
    throw new Error('connection config required')
  }

  const url = buildUrl(cfg.baseUrl, opts.path)
  const isHttps = url.protocol === 'https:'
  const lib = isHttps ? https : http

  return new Promise((resolve, reject) => {
    const req = lib.request(
      url,
      {
        method: opts.method,
        rejectUnauthorized: isHttps ? !cfg.ignoreTls : undefined,
        headers: {
          Accept: 'application/json',
          ...(cfg.token ? { Authorization: `Bearer ${cfg.token}` } : {})
        }
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (c: Buffer) => chunks.push(c))
        res.on('end', () => {
          const buf = Buffer.concat(chunks)
          const text = buf.toString('utf8')
          let parsed: unknown = null
          if (text.length > 0) {
            try {
              parsed = JSON.parse(text)
            } catch {
              parsed = text
            }
          }
          resolve({ status: res.statusCode ?? 0, body: parsed })
        })
        res.on('error', reject)
      }
    )

    req.on('error', reject)
    if (opts.timeoutMs) {
      req.setTimeout(opts.timeoutMs, () => {
        req.destroy(new Error('request timeout'))
      })
    }
    req.end()
  })
}

export async function apiGet<T>(path: string, cfg?: ConnectionConfig): Promise<IpcResult<T>> {
  try {
    const res = await makeRequest({ method: 'GET', path, config: cfg })
    if (res.status >= 200 && res.status < 300) {
      return { ok: true, data: res.body as T }
    }
    const errBody = res.body as { error?: string } | string | null
    let message: string
    if (typeof errBody === 'object' && errBody && 'error' in errBody && errBody.error) {
      message = errBody.error
    } else if (typeof errBody === 'string' && errBody.length > 0) {
      message = errBody
    } else {
      message = `HTTP ${res.status}`
    }
    return { ok: false, status: res.status, error: message }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) }
  }
}
