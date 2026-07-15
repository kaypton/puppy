import Grid from '@mui/material/Grid2'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Typography from '@mui/material/Typography'
import LinearProgress from '@mui/material/LinearProgress'
import IconButton from '@mui/material/IconButton'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import PageHeader from '@renderer/components/PageHeader'
import LoadingState from '@renderer/components/LoadingState'
import { useAsync } from '@renderer/hooks/useAsync'
import { formatBytes, formatTime, formatUptime } from '@renderer/utils/format'
import type { Stats } from '@shared/types'

interface Metric {
  label: string
  value: string
}

function StatCard({ label, value }: Metric): React.JSX.Element {
  return (
    <Card>
      <CardContent>
        <Typography variant="caption" color="text.secondary">
          {label}
        </Typography>
        <Typography variant="h5" fontWeight={600} mt={0.5} sx={{ wordBreak: 'break-all' }}>
          {value}
        </Typography>
      </CardContent>
    </Card>
  )
}

export default function StatsPage(): React.JSX.Element {
  const { data, loading, error, refetch } = useAsync<Stats>(() => window.api.api.getStats(), [], {
    intervalMs: 5000
  })

  const dialTotal = data ? data.dial_successes + data.dial_failures : 0
  const successRate = dialTotal > 0 ? (data!.dial_successes / dialTotal) * 100 : 0

  return (
    <div>
      <PageHeader
        title="统计"
        subtitle="GET /stats — 全局统计快照"
        action={
          <IconButton onClick={refetch} aria-label="refresh">
            <RefreshRoundedIcon />
          </IconButton>
        }
      />
      <LoadingState loading={loading && !data} error={error && !data ? error : null} />
      {data && (
        <>
          <Grid container spacing={2} mb={2}>
            <Grid size={{ xs: 6, md: 3 }}>
              <StatCard label="累计连接" value={data.total_connections.toLocaleString()} />
            </Grid>
            <Grid size={{ xs: 6, md: 3 }}>
              <StatCard label="活跃连接" value={data.active_connections.toLocaleString()} />
            </Grid>
            <Grid size={{ xs: 6, md: 3 }}>
              <StatCard label="拨号成功" value={data.dial_successes.toLocaleString()} />
            </Grid>
            <Grid size={{ xs: 6, md: 3 }}>
              <StatCard label="拨号失败" value={data.dial_failures.toLocaleString()} />
            </Grid>
            <Grid size={{ xs: 6, md: 3 }}>
              <StatCard label="入站字节" value={formatBytes(data.bytes_in)} />
            </Grid>
            <Grid size={{ xs: 6, md: 3 }}>
              <StatCard label="出站字节" value={formatBytes(data.bytes_out)} />
            </Grid>
            <Grid size={{ xs: 6, md: 3 }}>
              <StatCard label="启动时间" value={formatTime(data.started_at)} />
            </Grid>
            <Grid size={{ xs: 6, md: 3 }}>
              <StatCard label="运行时长" value={formatUptime(data.uptime_seconds)} />
            </Grid>
          </Grid>
          <Card>
            <CardContent>
              <Typography variant="subtitle2" mb={1}>
                拨号成功率
              </Typography>
              <Typography variant="body2" color="text.secondary" mb={1}>
                {dialTotal > 0
                  ? `${successRate.toFixed(2)}% (${data.dial_successes}/${dialTotal})`
                  : '暂无拨号数据'}
              </Typography>
              <LinearProgress
                variant="determinate"
                value={successRate}
                color={successRate >= 95 ? 'success' : successRate >= 80 ? 'warning' : 'error'}
              />
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}
