import Typography from '@mui/material/Typography'
import Box from '@mui/material/Box'

interface Props {
  title: string
  subtitle?: string
  action?: React.ReactNode
}

export default function PageHeader({ title, subtitle, action }: Props): React.JSX.Element {
  return (
    <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={2.5}>
      <Box>
        <Typography variant="h5" fontWeight={600}>
          {title}
        </Typography>
        {subtitle && (
          <Typography variant="body2" color="text.secondary" mt={0.5}>
            {subtitle}
          </Typography>
        )}
      </Box>
      {action}
    </Box>
  )
}
