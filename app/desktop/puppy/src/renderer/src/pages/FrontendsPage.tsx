import IconButton from '@mui/material/IconButton'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import PageHeader from '@renderer/components/PageHeader'
import LoadingState from '@renderer/components/LoadingState'
import { useAsync } from '@renderer/hooks/useAsync'
import type { FrontendsResponse } from '@shared/types'

import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import Paper from '@mui/material/Paper'
import Chip from '@mui/material/Chip'

export default function FrontendsPage(): React.JSX.Element {
  const { data, loading, error, refetch } = useAsync<FrontendsResponse>(() =>
    window.api.api.getFrontends()
  )

  return (
    <div>
      <PageHeader
        title="Frontends"
        subtitle="GET /frontends — 已配置的 frontend 列表"
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
        emptyText="未配置任何 frontend"
      />
      {data && data.count > 0 && (
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>名称</TableCell>
                <TableCell>类型</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.frontends.map((f) => (
                <TableRow key={f.name}>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{f.name}</TableCell>
                  <TableCell>
                    <Chip size="small" label={f.type} />
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
