import { useEffect, useState } from 'react'
import Grid from '@mui/material/Grid2'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import CardHeader from '@mui/material/CardHeader'
import TextField from '@mui/material/TextField'
import Button from '@mui/material/Button'
import Switch from '@mui/material/Switch'
import FormControlLabel from '@mui/material/FormControlLabel'
import Stack from '@mui/material/Stack'
import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import Alert from '@mui/material/Alert'
import IconButton from '@mui/material/IconButton'
import Typography from '@mui/material/Typography'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import PlayArrowRoundedIcon from '@mui/icons-material/PlayArrowRounded'
import StopRoundedIcon from '@mui/icons-material/StopRounded'
import FolderOpenRoundedIcon from '@mui/icons-material/FolderOpenRounded'
import PageHeader from '@renderer/components/PageHeader'
import { formatTime } from '@renderer/utils/format'
import type {
  AppConfig,
  IpcResult,
  ServerLogEntry,
  ServerProcessStatus,
  SystemInfo
} from '@shared/types'

export default function SettingsPage(): React.JSX.Element {
  const [cfg, setCfg] = useState<AppConfig | null>(null)
  const [saving, setSaving] = useState(false)
  const [savedMsg, setSavedMsg] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<IpcResult<SystemInfo> | null>(null)
  const [testing, setTesting] = useState(false)

  const [procStatus, setProcStatus] = useState<ServerProcessStatus | null>(null)
  const [procMsg, setProcMsg] = useState<string | null>(null)
  const [logs, setLogs] = useState<ServerLogEntry[]>([])

  useEffect(() => {
    window.api.config.get().then(setCfg)
    window.api.server.status().then(setProcStatus)
  }, [])

  const refreshStatus = (): void => {
    window.api.server.status().then(setProcStatus)
  }

  const refreshLogs = (): void => {
    window.api.server.logs().then(setLogs)
  }

  const handleSave = async (): Promise<void> => {
    if (!cfg) return
    setSaving(true)
    setSavedMsg(null)
    await window.api.config.set(cfg)
    setSaving(false)
    setSavedMsg('已保存')
    setTimeout(() => setSavedMsg(null), 2000)
  }

  const handleTest = async (): Promise<void> => {
    if (!cfg) return
    setTesting(true)
    setTestResult(null)
    const res = await window.api.connection.test(cfg.connection)
    setTestResult(res)
    setTesting(false)
  }

  const handleStart = async (): Promise<void> => {
    setProcMsg(null)
    const res = await window.api.server.start()
    refreshStatus()
    refreshLogs()
    if (!res.ok) setProcMsg(res.error)
  }

  const handleStop = async (): Promise<void> => {
    setProcMsg(null)
    const res = await window.api.server.stop()
    refreshStatus()
    refreshLogs()
    if (!res.ok) setProcMsg(res.error)
  }

  const pickFile = async (setter: (path: string) => void): Promise<void> => {
    const path = await window.electron.ipcRenderer.invoke('dialog:openFile')
    if (typeof path === 'string' && path.length > 0) setter(path)
  }

  if (!cfg) return <div>Loading…</div>

  return (
    <div>
      <PageHeader title="设置" subtitle="连接配置、本地进程管理" />

      <Grid container spacing={2}>
        {/* 连接配置 */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardHeader title="服务器连接" />
            <CardContent>
              <Stack spacing={2}>
                <TextField
                  label="Base URL"
                  value={cfg.connection.baseUrl}
                  onChange={(e) =>
                    setCfg({
                      ...cfg,
                      connection: { ...cfg.connection, baseUrl: e.target.value }
                    })
                  }
                  size="small"
                  fullWidth
                  helperText="如 https://127.0.0.1:8443"
                />
                <TextField
                  label="Token"
                  value={cfg.connection.token}
                  onChange={(e) =>
                    setCfg({
                      ...cfg,
                      connection: { ...cfg.connection, token: e.target.value }
                    })
                  }
                  size="small"
                  fullWidth
                  helperText="Bearer token；为空表示不认证"
                />
                <FormControlLabel
                  control={
                    <Switch
                      checked={cfg.connection.ignoreTls}
                      onChange={(e) =>
                        setCfg({
                          ...cfg,
                          connection: {
                            ...cfg.connection,
                            ignoreTls: e.target.checked
                          }
                        })
                      }
                    />
                  }
                  label="忽略 TLS 证书校验（自签证书）"
                />
                <Stack direction="row" spacing={1} alignItems="center">
                  <Button variant="contained" size="small" onClick={handleSave} disabled={saving}>
                    保存
                  </Button>
                  <Button variant="outlined" size="small" onClick={handleTest} disabled={testing}>
                    {testing ? '测试中…' : '测试连接'}
                  </Button>
                  {savedMsg && <Alert severity="success">{savedMsg}</Alert>}
                </Stack>
                {testResult && (
                  <Alert severity={testResult.ok ? 'success' : 'error'}>
                    {testResult.ok
                      ? `连接成功 — puppy ${testResult.data.version ?? ''}`
                      : `连接失败：${testResult.error}`}
                  </Alert>
                )}
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        {/* 进程管理 */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardHeader
              title="本地进程"
              action={
                <IconButton onClick={refreshStatus} aria-label="refresh">
                  <RefreshRoundedIcon />
                </IconButton>
              }
            />
            <CardContent>
              <Stack spacing={2}>
                <Stack direction="row" spacing={1} alignItems="center">
                  <Typography variant="body2" mr={1}>
                    状态：
                  </Typography>
                  {procStatus?.running ? (
                    <Chip
                      size="small"
                      color="success"
                      label={`运行中 PID ${procStatus.pid ?? ''}`}
                    />
                  ) : (
                    <Chip
                      size="small"
                      color="default"
                      label={
                        procStatus?.exitCode !== undefined
                          ? `已停止 (code=${procStatus.exitCode})`
                          : '未运行'
                      }
                    />
                  )}
                </Stack>
                <TextField
                  label="二进制路径"
                  value={cfg.server.binaryPath}
                  onChange={(e) =>
                    setCfg({
                      ...cfg,
                      server: { ...cfg.server, binaryPath: e.target.value }
                    })
                  }
                  size="small"
                  fullWidth
                  helperText="留空时开发期自动查找仓库 bin/puppy-server"
                  InputProps={{
                    endAdornment: (
                      <IconButton
                        size="small"
                        onClick={() =>
                          pickFile((p) =>
                            setCfg({
                              ...cfg,
                              server: { ...cfg.server, binaryPath: p }
                            })
                          )
                        }
                      >
                        <FolderOpenRoundedIcon fontSize="small" />
                      </IconButton>
                    )
                  }}
                />
                <TextField
                  label="配置文件路径"
                  value={cfg.server.configPath}
                  onChange={(e) =>
                    setCfg({
                      ...cfg,
                      server: { ...cfg.server, configPath: e.target.value }
                    })
                  }
                  size="small"
                  fullWidth
                  helperText="puppy-server --config 指向的 TOML 文件"
                  InputProps={{
                    endAdornment: (
                      <IconButton
                        size="small"
                        onClick={() =>
                          pickFile((p) =>
                            setCfg({
                              ...cfg,
                              server: { ...cfg.server, configPath: p }
                            })
                          )
                        }
                      >
                        <FolderOpenRoundedIcon fontSize="small" />
                      </IconButton>
                    )
                  }}
                />
                <FormControlLabel
                  control={
                    <Switch
                      checked={cfg.server.autoStart}
                      onChange={(e) =>
                        setCfg({
                          ...cfg,
                          server: { ...cfg.server, autoStart: e.target.checked }
                        })
                      }
                    />
                  }
                  label="应用启动时自动拉起 server"
                />
                <Stack direction="row" spacing={1}>
                  <Button
                    variant="contained"
                    color="success"
                    size="small"
                    startIcon={<PlayArrowRoundedIcon />}
                    onClick={handleStart}
                    disabled={!!procStatus?.running}
                  >
                    启动
                  </Button>
                  <Button
                    variant="outlined"
                    color="error"
                    size="small"
                    startIcon={<StopRoundedIcon />}
                    onClick={handleStop}
                    disabled={!procStatus?.running}
                  >
                    停止
                  </Button>
                  <Button size="small" onClick={handleSave} disabled={saving}>
                    保存配置
                  </Button>
                </Stack>
                {procMsg && <Alert severity="warning">{procMsg}</Alert>}
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        {/* 日志 */}
        <Grid size={{ xs: 12 }}>
          <Card>
            <CardHeader
              title="进程日志"
              subheader={`最近 ${logs.length} 行`}
              action={
                <IconButton onClick={refreshLogs} aria-label="refresh logs">
                  <RefreshRoundedIcon />
                </IconButton>
              }
            />
            <CardContent>
              <Box
                sx={{
                  maxHeight: 280,
                  overflow: 'auto',
                  bgcolor: '#1e1e1e',
                  color: '#d4d4d4',
                  p: 1.5,
                  borderRadius: 1,
                  fontFamily: 'monospace',
                  fontSize: 12,
                  lineHeight: 1.6
                }}
              >
                {logs.length === 0 ? (
                  <Typography sx={{ color: '#888' }}>暂无日志</Typography>
                ) : (
                  logs.map((l, i) => (
                    <Box key={i}>
                      <span style={{ color: '#888' }}>
                        [{formatTime(new Date(l.ts).toISOString())}]
                      </span>{' '}
                      <span style={{ color: l.stream === 'stderr' ? '#f48771' : '#d4d4d4' }}>
                        {l.text}
                      </span>
                    </Box>
                  ))
                )}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </div>
  )
}
