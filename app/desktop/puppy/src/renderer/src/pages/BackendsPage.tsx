import IconButton from '@mui/material/IconButton'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import PageHeader from '@renderer/components/PageHeader'
import LoadingState from '@renderer/components/LoadingState'
import { useAsync } from '@renderer/hooks/useAsync'
import type { BackendsResponse } from '@shared/types'

import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import Paper from '@mui/material/Paper'
import Chip from '@mui/material/Chip'
import Box from '@mui/material/Box'

export default function BackendsPage(): React.JSX.Element {
  const { data, loading, error, refetch } = useAsync<BackendsResponse>(() =>
    window.api.api.getBackends()
  )

  return (
    <div>
      <PageHeader
        title="Backends"
        subtitle="GET /backends — 已配置的 backend 及能力"
        action={
          <IconButton onClick={refetch} aria-label="refresh">
            <RefreshRoundedIcon />
          </IconButton>
        }
      />
      <LoadingState
        loading={loading && !data}
        error={error && !data ? error : null}
        empty={!!data && data.count === 0}
        emptyText="未配置任何 backend"
      />
      {data && data.count > 0 && (
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>名称</TableCell>
                <TableCell>类型</TableCell>
                <TableCell>能力 (network/protocol)</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.backends.map((b) => (
                <TableRow key={b.name}>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{b.name}</TableCell>
                  <TableCell>
                    <Chip size="small" label={b.type} />
                  </TableCell>
                  <TableCell>
                    <Box display="flex" flexWrap="wrap" gap={0.5}>
                      {b.capabilities.map((c, i) => (
                        <Chip
                          key={i}
                          size="small"
                          variant="outlined"
                          label={`${c.network}/${c.protocol}`}
                        />
                      ))}
                    </Box>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </div>
  )
}
