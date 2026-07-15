import Alert from '@mui/material/Alert'
import CircularProgress from '@mui/material/CircularProgress'
import Box from '@mui/material/Box'

interface Props {
  loading: boolean
  error: string | null
  empty?: boolean
  emptyText?: string
}

export default function LoadingState({
  loading,
  error,
  empty,
  emptyText
}: Props): React.JSX.Element | null {
  if (loading) {
    return (
      <Box display="flex" justifyContent="center" py={4}>
        <CircularProgress size={28} />
      </Box>
    )
  }
  if (error) {
    return (
      <Alert severity="error" sx={{ mt: 1 }}>
        {error}
      </Alert>
    )
  }
  if (empty) {
    return (
      <Alert severity="info" sx={{ mt: 1 }}>
        {emptyText ?? '无数据'}
      </Alert>
    )
  }
  return null
}
