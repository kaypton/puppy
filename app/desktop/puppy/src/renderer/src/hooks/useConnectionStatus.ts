import { useEffect, useRef, useState } from 'react'
import type { SystemInfo } from '@shared/types'

export type ConnectionStatus = 'unknown' | 'online' | 'offline'

export interface ConnectionStatusState {
  status: ConnectionStatus
  system: SystemInfo | null
  error: string | null
  lastUpdated: number | null
}

export function useConnectionStatus(intervalMs = 5000): ConnectionStatusState {
  const [state, setState] = useState<ConnectionStatusState>({
    status: 'unknown',
    system: null,
    error: null,
    lastUpdated: null
  })
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true

    const poll = async (): Promise<void> => {
      const res = await window.api.connection.test()
      if (!mountedRef.current) return
      if (res.ok) {
        setState({
          status: 'online',
          system: res.data,
          error: null,
          lastUpdated: Date.now()
        })
      } else {
        setState({
          status: 'offline',
          system: null,
          error: res.error,
          lastUpdated: Date.now()
        })
      }
    }

    poll()
    const timer = setInterval(poll, intervalMs)
    return () => {
      mountedRef.current = false
      clearInterval(timer)
    }
  }, [intervalMs])

  return state
}
