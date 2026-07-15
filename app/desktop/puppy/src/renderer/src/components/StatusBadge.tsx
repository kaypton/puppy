import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import type { ConnectionStatus } from '@renderer/hooks/useConnectionStatus'

interface Props {
  status: ConnectionStatus
}

export default function StatusBadge({ status }: Props): React.JSX.Element {
  const color: 'success' | 'error' | 'default' =
    status === 'online' ? 'success' : status === 'offline' ? 'error' : 'default'
  const label = status === 'online' ? '在线' : status === 'offline' ? '离线' : '检测中'
  return (
    <Box>
      <Chip
        size="small"
        color={color}
        label={label}
        variant={status === 'unknown' ? 'outlined' : 'filled'}
      />
    </Box>
  )
}
