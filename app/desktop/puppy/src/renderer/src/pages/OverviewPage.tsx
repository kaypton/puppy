import Grid from '@mui/material/Grid2'
import IconButton from '@mui/material/IconButton'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import PageHeader from '@renderer/components/PageHeader'
import FieldCard from '@renderer/components/FieldCard'
import LoadingState from '@renderer/components/LoadingState'
import { useAsync } from '@renderer/hooks/useAsync'
import { formatTime, formatUptime } from '@renderer/utils/format'
import type { SystemInfo } from '@shared/types'

export default function OverviewPage(): React.JSX.Element {
  const { data, loading, error, refetch } = useAsync<SystemInfo>(
    () => window.api.api.getSystem(),
    [],
    { intervalMs: 5000 }
  )

  return (
    <div>
      <PageHeader
        title="系统概览"
        subtitle="GET /system — 服务器运行信息"
        action={
          <IconButton onClick={refetch} aria-label="refresh">
            <RefreshRoundedIcon />
          </IconButton>
        }
      />
      <LoadingState loading={loading && !data} error={error && !data ? error : null} />
      {data && (
        <Grid container spacing={2}>
          <Grid size={{ xs: 12, md: 6 }}>
            <FieldCard
              title="运行时"
              fields={[
                { label: 'API 版本', value: data.version },
                { label: 'Rust 版本', value: data.rust_version },
                { label: 'PID', value: data.pid },
                { label: '启动时间', value: formatTime(data.started_at) },
                { label: '运行时长', value: formatUptime(data.uptime_seconds) }
              ]}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 6 }}>
            <FieldCard
              title="连接"
              fields={[
                { label: '活跃连接', value: data.active_connections },
                { label: 'SSE 订阅者', value: data.sse_subscribers }
              ]}
            />
          </Grid>
        </Grid>
      )}
    </div>
  )
}
