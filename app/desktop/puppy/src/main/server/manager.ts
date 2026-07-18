import { readFile } from 'node:fs/promises'
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { app } from 'electron'
import { getConfig } from '../config/store'
import type { IpcResult, ServerLogEntry, ServerProcessStatus } from '@shared/types'

const __dirname = dirname(fileURLToPath(import.meta.url))

const MAX_LOG_LINES = 1000

let child: ChildProcess | null = null
let startTime: number | undefined
let lastExitCode: number | undefined
let lastSignal: string | undefined
const logBuffer: ServerLogEntry[] = []

function pushLog(stream: 'stdout' | 'stderr', text: string): void {
  logBuffer.push({ stream, text, ts: Date.now() })
  while (logBuffer.length > MAX_LOG_LINES) {
    logBuffer.shift()
  }
}

export function getStatus(): ServerProcessStatus {
  if (child && !child.killed && child.exitCode === null) {
    return { running: true, pid: child.pid, startTime }
  }
  return { running: false, exitCode: lastExitCode, signal: lastSignal }
}

export function getLogs(): ServerLogEntry[] {
  return logBuffer.slice()
}

async function resolveBundledConfig(): Promise<string | null> {
  // Packaged app: the default config sits next to process.resourcesPath
  // (copied via electron-builder extraResources) and is extracted on first use
  // into the user's app data directory so it can be edited independently.
  const bundled = join(process.resourcesPath, 'config.toml')
  if (!existsSync(bundled)) return null

  const configDir = join(app.getPath('userData'), 'puppy')
  const extracted = join(configDir, 'config.toml')
  if (!existsSync(extracted)) {
    try {
      mkdirSync(configDir, { recursive: true })
      const contents = await readFile(bundled)
      writeFileSync(extracted, contents)
    } catch {
      // If extraction fails, fall back to the read-only bundled file so the
      // server can still start with the default configuration.
      return bundled
    }
  }
  return extracted
}

function resolveDefaultConfig(): string | null {
  // Development: from this file (app/desktop/puppy/src/main/server/manager.ts)
  // walk up to the repository root and look for config.toml in the app dir.
  let dir = dirname(dirname(dirname(dirname(__dirname))))
  for (let i = 0; i < 6; i++) {
    const candidate = join(dir, 'config.toml')
    if (existsSync(candidate)) return candidate

    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return null
}

function resolveDefaultBinary(): string | null {
  const binaryName = `puppy-server-${process.platform}-${process.arch}`
  const bundled = join(process.resourcesPath, 'bin', binaryName)
  if (existsSync(bundled)) return bundled

  // Development: from this file (app/desktop/puppy/src/main/server/manager.ts)
  // walk up to the repository root and look for the same platform/arch binary.
  let dir = dirname(dirname(dirname(dirname(__dirname))))
  for (let i = 0; i < 6; i++) {
    const candidate = join(dir, 'bin', binaryName)
    if (existsSync(candidate)) return candidate

    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return null
}

export function start(): Promise<IpcResult<ServerProcessStatus>> {
  return new Promise((resolve) => {
    void (async (): Promise<void> => {
      if (child && child.exitCode === null && !child.killed) {
        resolve({ ok: false, error: 'server already running' })
        return
      }

      const cfg = getConfig().server
      const binaryPath = cfg.binaryPath || resolveDefaultBinary()
      if (!binaryPath || !existsSync(binaryPath)) {
        resolve({
          ok: false,
          error: cfg.binaryPath
            ? `binary not found at ${cfg.binaryPath}`
            : 'binary path not configured and bundled bin/puppy-server not found'
        })
        return
      }
      const configPath = cfg.configPath || (await resolveBundledConfig()) || resolveDefaultConfig()
      if (!configPath || !existsSync(configPath)) {
        resolve({
          ok: false,
          error: cfg.configPath
            ? `config not found at ${cfg.configPath}`
            : 'config file path not configured and default config.toml not found'
        })
        return
      }

      try {
        child = spawn(binaryPath, ['--config', configPath], {
          stdio: ['ignore', 'pipe', 'pipe']
        })
        startTime = Date.now()
        lastExitCode = undefined
        lastSignal = undefined
      } catch (e) {
        resolve({ ok: false, error: e instanceof Error ? e.message : String(e) })
        return
      }

      child.stdout?.on('data', (d: Buffer) => {
        d.toString('utf8')
          .split(/\r?\n/)
          .forEach((line) => {
            if (line.length > 0) pushLog('stdout', line)
          })
      })
      child.stderr?.on('data', (d: Buffer) => {
        d.toString('utf8')
          .split(/\r?\n/)
          .forEach((line) => {
            if (line.length > 0) pushLog('stderr', line)
          })
      })
      child.on('exit', (code, signal) => {
        lastExitCode = code ?? undefined
        lastSignal = signal ?? undefined
        pushLog('stderr', `process exited code=${code} signal=${signal}`)
        child = null
      })
      child.on('error', (err) => {
        pushLog('stderr', `spawn error: ${err.message}`)
        child = null
      })

      // Give spawn a moment to surface an immediate failure.
      setTimeout(() => {
        if (child && child.exitCode === null) {
          resolve({ ok: true, data: getStatus() })
        } else {
          resolve({ ok: false, error: 'process exited immediately; check logs' })
        }
      }, 300)
    })()
  })
}

export async function stop(): Promise<IpcResult<ServerProcessStatus>> {
  if (!child || child.killed || child.exitCode !== null) {
    return { ok: false, error: 'server not running' }
  }
  return new Promise((resolve) => {
    const proc = child
    if (!proc) {
      resolve({ ok: false, error: 'server not running' })
      return
    }
    const onExit = (): void => {
      proc.removeListener('exit', onExit)
      resolve({ ok: true, data: getStatus() })
    }
    proc.on('exit', onExit)
    // Prefer SIGTERM for graceful shutdown, then SIGKILL after 3s.
    proc.kill('SIGTERM')
    setTimeout(() => {
      if (proc.exitCode === null && !proc.killed) {
        proc.kill('SIGKILL')
      }
    }, 3000)
  })
}

export async function shutdown(): Promise<void> {
  if (child && child.exitCode === null && !child.killed) {
    await stop()
  }
}
