import { useCallback, useEffect, useRef, useState } from 'react'
import type { IpcResult } from '@shared/types'

interface AsyncState<T> {
  data: T | null
  loading: boolean
  error: string | null
  status?: number
}

export interface UseAsyncResult<T> extends AsyncState<T> {
  refetch: () => Promise<void>
  setData: (data: T | null) => void
}

export function useAsync<T>(
  fn: () => Promise<IpcResult<T>>,
  deps: unknown[] = [],
  opts?: { intervalMs?: number }
): UseAsyncResult<T> {
  const [state, setState] = useState<AsyncState<T>>({
    data: null,
    loading: true,
    error: null
  })
  const fnRef = useRef(fn)
  const mountedRef = useRef(true)
  useEffect(() => {
    fnRef.current = fn
  })

  const run = useCallback(async () => {
    setState((s) => ({ ...s, loading: true, error: null }))
    const res = await fnRef.current()
    if (!mountedRef.current) return
    if (res.ok) {
      setState({ data: res.data, loading: false, error: null })
    } else {
      setState({ data: null, loading: false, error: res.error, status: res.status })
    }
  }, [])

  useEffect(() => {
    mountedRef.current = true
    // 数据获取 effect：调用 setState 是合理用法
    // eslint-disable-next-line react-hooks/set-state-in-effect
    run()
    let timer: ReturnType<typeof setInterval> | undefined
    if (opts?.intervalMs && opts.intervalMs > 0) {
      timer = setInterval(run, opts.intervalMs)
    }
    return () => {
      mountedRef.current = false
      if (timer) clearInterval(timer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  const setData = useCallback((data: T | null) => {
    setState({ data, loading: false, error: null })
  }, [])

  return { ...state, refetch: run, setData }
}
