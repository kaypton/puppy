import { useMemo, useState } from 'react'
import Box from '@mui/material/Box'
import Toolbar from '@mui/material/Toolbar'
import Typography from '@mui/material/Typography'
import LinearProgress from '@mui/material/LinearProgress'
import Sidebar, { type PageKey } from './components/Sidebar'
import { useConnectionStatus } from './hooks/useConnectionStatus'
import OverviewPage from './pages/OverviewPage'
import StatsPage from './pages/StatsPage'
import FrontendsPage from './pages/FrontendsPage'
import BackendsPage from './pages/BackendsPage'
import ConfigPage from './pages/ConfigPage'
import SettingsPage from './pages/SettingsPage'

const PAGE_TITLES: Record<PageKey, string> = {
  overview: '系统概览',
  stats: '统计',
  frontends: 'Frontends',
  backends: 'Backends',
  config: '配置',
  settings: '设置'
}

export default function App(): React.JSX.Element {
  const [page, setPage] = useState<PageKey>('overview')
  const conn = useConnectionStatus(5000)

  const body = useMemo(() => {
    switch (page) {
      case 'overview':
        return <OverviewPage />
      case 'stats':
        return <StatsPage />
      case 'frontends':
        return <FrontendsPage />
      case 'backends':
        return <BackendsPage />
      case 'config':
        return <ConfigPage />
      case 'settings':
        return <SettingsPage />
    }
  }, [page])

  return (
    <Box sx={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      <Sidebar current={page} onChange={setPage} status={conn.status} />
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden'
        }}
      >
        <Toolbar
          sx={{
            borderBottom: '1px solid',
            borderColor: 'divider',
            gap: 2,
            minHeight: '56px !important'
          }}
        >
          <Typography variant="subtitle1" fontWeight={600}>
            {PAGE_TITLES[page]}
          </Typography>
          <Box sx={{ flexGrow: 1 }} />
          <Typography variant="caption" color="text.secondary">
            {conn.status === 'online'
              ? `已连接 · ${conn.lastUpdated ? new Date(conn.lastUpdated).toLocaleTimeString() : ''}`
              : conn.status === 'offline'
                ? `离线${conn.error ? ` · ${conn.error}` : ''}`
                : '检测中…'}
          </Typography>
        </Toolbar>
        {conn.status === 'offline' && page !== 'settings' && (
          <LinearProgress color="error" sx={{ height: 2 }} />
        )}
        <Box sx={{ flexGrow: 1, overflow: 'auto', p: 3 }}>{body}</Box>
      </Box>
    </Box>
  )
}
