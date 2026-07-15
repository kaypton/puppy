import IconButton from '@mui/material/IconButton'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import Alert from '@mui/material/Alert'
import Paper from '@mui/material/Paper'
import Typography from '@mui/material/Typography'
import PageHeader from '@renderer/components/PageHeader'
import LoadingState from '@renderer/components/LoadingState'
import { useAsync } from '@renderer/hooks/useAsync'
import type { ConfigResponse } from '@shared/types'

export default function ConfigPage(): React.JSX.Element {
  const { data, loading, error, status, refetch } = useAsync<ConfigResponse>(() =>
    window.api.api.getConfig()
  )

  const notImplemented = status === 501

  return (
    <div>
      <PageHeader
        title="配置"
        subtitle="GET /config — 当前生效的脱敏配置"
        action={
          <IconButton onClick={refetch} aria-label="refresh">
            <RefreshRoundedIcon />
          </IconButton>
        }
      />
      {loading && !data ? (
        <LoadingState loading error={null} />
      ) : notImplemented ? (
        <Alert severity="info">配置端点未配置（501 Not Implemented）</Alert>
      ) : error ? (
        <LoadingState loading={false} error={error} />
      ) : (
        data && (
          <Paper variant="outlined" sx={{ p: 2, overflow: 'auto' }}>
            <Typography
              component="pre"
              sx={{
                fontFamily: 'monospace',
                fontSize: 13,
                margin: 0,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word'
              }}
            >
              {JSON.stringify(data, null, 2)}
            </Typography>
          </Paper>
        )
      )}
    </div>
  )
}
