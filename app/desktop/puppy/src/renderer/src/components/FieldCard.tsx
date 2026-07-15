import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Typography from '@mui/material/Typography'
import Box from '@mui/material/Box'
import Stack from '@mui/material/Stack'

export interface FieldItem {
  label: string
  value: React.ReactNode
}

interface Props {
  title: string
  fields: FieldItem[]
  action?: React.ReactNode
}

export default function FieldCard({ title, fields, action }: Props): React.JSX.Element {
  return (
    <Card>
      <CardContent>
        <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1.5}>
          <Typography variant="subtitle1" fontWeight={600}>
            {title}
          </Typography>
          {action}
        </Stack>
        <Box display="grid" gridTemplateColumns="repeat(auto-fit, minmax(220px, 1fr))" gap={1.5}>
          {fields.map((f) => (
            <Box key={f.label}>
              <Typography variant="caption" color="text.secondary">
                {f.label}
              </Typography>
              <Typography variant="body2" fontWeight={500} sx={{ wordBreak: 'break-all' }}>
                {f.value}
              </Typography>
            </Box>
          ))}
        </Box>
      </CardContent>
    </Card>
  )
}
