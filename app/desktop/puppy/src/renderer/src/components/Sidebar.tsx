import List from '@mui/material/List'
import ListItem from '@mui/material/ListItem'
import ListItemButton from '@mui/material/ListItemButton'
import ListItemIcon from '@mui/material/ListItemIcon'
import ListItemText from '@mui/material/ListItemText'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import Divider from '@mui/material/Divider'
import DashboardRoundedIcon from '@mui/icons-material/DashboardRounded'
import BarChartRoundedIcon from '@mui/icons-material/BarChartRounded'
import SettingsInputComponentRoundedIcon from '@mui/icons-material/SettingsInputComponentRounded'
import DnsRoundedIcon from '@mui/icons-material/DnsRounded'
import SettingsRoundedIcon from '@mui/icons-material/SettingsRounded'
import DescriptionRoundedIcon from '@mui/icons-material/DescriptionRounded'
import StatusBadge from './StatusBadge'
import type { ConnectionStatus } from '@renderer/hooks/useConnectionStatus'

export type PageKey = 'overview' | 'stats' | 'frontends' | 'backends' | 'config' | 'settings'

interface NavItem {
  key: PageKey
  label: string
  icon: React.ReactNode
}

const NAV: NavItem[] = [
  { key: 'overview', label: '系统概览', icon: <DashboardRoundedIcon /> },
  { key: 'stats', label: '统计', icon: <BarChartRoundedIcon /> },
  { key: 'frontends', label: 'Frontends', icon: <SettingsInputComponentRoundedIcon /> },
  { key: 'backends', label: 'Backends', icon: <DnsRoundedIcon /> },
  { key: 'config', label: '配置', icon: <DescriptionRoundedIcon /> },
  { key: 'settings', label: '设置', icon: <SettingsRoundedIcon /> }
]

interface Props {
  current: PageKey
  onChange: (page: PageKey) => void
  status: ConnectionStatus
}

export default function Sidebar({ current, onChange, status }: Props): React.JSX.Element {
  return (
    <Box
      sx={{
        width: 240,
        flexShrink: 0,
        borderRight: '1px solid',
        borderColor: 'divider',
        display: 'flex',
        flexDirection: 'column',
        bgcolor: 'background.paper'
      }}
    >
      <Box px={2} py={2.5}>
        <Typography variant="h6" fontWeight={700} letterSpacing={0.5}>
          Puppy
        </Typography>
        <Typography variant="caption" color="text.secondary">
          Dashboard
        </Typography>
      </Box>
      <Divider />
      <Box px={2} py={1.5}>
        <StatusBadge status={status} />
      </Box>
      <List sx={{ px: 1, flex: 1 }}>
        {NAV.map((item) => (
          <ListItem key={item.key} disablePadding>
            <ListItemButton
              selected={current === item.key}
              onClick={() => onChange(item.key)}
              sx={{ borderRadius: 1, mb: 0.5 }}
            >
              <ListItemIcon sx={{ minWidth: 36 }}>{item.icon}</ListItemIcon>
              <ListItemText primary={item.label} />
            </ListItemButton>
          </ListItem>
        ))}
      </List>
    </Box>
  )
}
