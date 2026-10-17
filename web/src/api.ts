export interface Verdict {
  verdict?: 'malicious' | 'suspicious' | 'benign'
  confidence?: number
  summary?: string
  kill_chain?: string[]
  actions?: string[]
  error?: string
  raw?: string
}

export interface GraphNode {
  id: string
  type: 'asset' | 'process' | 'alert' | string
  label: string
}

export interface GraphEdge {
  from: string
  to: string
  rel: string
}

export interface Graph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  overflow: number
}

export interface IncidentSummary {
  id: string
  createdAt: string
  status: string
  title: string | null
  aiVerdict: Verdict | null
  alertCount: number
  severity: number
}

export interface AlertRow {
  id: string
  ts: string
  lastTs: string | null
  count: number
  severity: number
  ruleId: string
  ruleTitle: string | null
  event: unknown
}

export interface IncidentDetail extends Omit<IncidentSummary, 'alertCount'> {
  graph: Graph
  assetId: string | null
  alerts: AlertRow[]
}

// 会话失效时抛出，App 捕获后切回登录页
export class Unauthorized extends Error {}

function check(r: Response) {
  if (r.status === 401) throw new Unauthorized()
}

async function get<T>(url: string): Promise<T> {
  const r = await fetch(url)
  check(r)
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return r.json()
}

async function post(url: string, body?: unknown): Promise<Response> {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  check(r)
  return r
}

export interface Me {
  username: string
  role: 'admin' | 'analyst' | 'viewer'
}

export const fetchMe = () => get<Me>('/api/me')

export async function login(username: string, password: string): Promise<Me> {
  const r = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export const logout = () => post('/api/logout')

export const fetchIncidents = (status?: string, assetId?: string) => {
  const qs = new URLSearchParams()
  if (status) qs.set('status', status)
  if (assetId) qs.set('assetId', assetId)
  return get<IncidentSummary[]>(`/api/incidents?${qs}`)
}

export const fetchIncident = (id: string) => get<IncidentDetail>(`/api/incidents/${id}`)

export async function setIncidentStatus(id: string, status: string): Promise<void> {
  const r = await post(`/api/incidents/${id}/status`, { status })
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
}

// 报告是文件下载：拿到 blob 后用临时链接触发浏览器保存
export async function downloadReport(id: string, title: string | null): Promise<void> {
  const r = await fetch(`/api/incidents/${id}/report`)
  check(r)
  if (!r.ok) throw new Error(await r.text())
  const url = URL.createObjectURL(await r.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = `${(title ?? id).replace(/[/\\?%*:|"<>]/g, '-')}.md`
  a.click()
  URL.revokeObjectURL(url)
}

export interface CommandRow {
  id: string
  createdAt: string
  kind: string
  status: string
  dryRun: boolean
  assetId: string
  incidentId: string | null
  issuedBy: string
  detail: string | null
  completedAt: string | null
}

export const fetchCommands = (filter: { incidentId?: string; assetId?: string }) =>
  get<CommandRow[]>(`/api/commands?${new URLSearchParams(filter as Record<string, string>)}`)

export async function issueCommand(body: {
  kind: string
  assetId: string
  incidentId?: string
  pid?: number
  dryRun: boolean
}): Promise<CommandRow> {
  const r = await post('/api/commands', body)
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export interface Suppression {
  id: string
  createdAt: string
  ruleId: string
  ruleTitle: string | null
  assetId: string | null
  reason: string | null
  createdBy: string
  expiresAt: string | null
  matchedCount: number
  lastMatchedAt: string | null
}

export interface Asset {
  id: string
  hostname: string
  os: string | null
  ipAddrs: string[] | null
  agentId: string | null
  firstSeen: string
  lastSeen: string
  groupId: string | null
  // 已发出失联通知的起始时刻，恢复后为 null
  silentSince: string | null
  agentVersion: string | null
}

export const fetchAssets = () => get<Asset[]>('/api/assets')

export const fetchSuppressions = () => get<Suppression[]>('/api/suppressions')

export async function createSuppression(body: {
  ruleId: string
  assetId?: string | null
  reason?: string
  expiresInDays?: number
}): Promise<Suppression> {
  const r = await post('/api/suppressions', body)
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export async function deleteSuppression(id: string): Promise<void> {
  const r = await fetch(`/api/suppressions/${id}`, { method: 'DELETE' })
  check(r)
  if (!r.ok) throw new Error(await r.text())
}

export interface Stats {
  events24h: number
  alerts24h: number
  openIncidents: number
  incidentsByStatus: Record<string, number>
  alertTrend: { hour: string; count: number }[]
  topRules: { ruleId: string; ruleTitle: string | null; count: number }[]
  alertsBySeverity: Record<string, number>
  assetsTotal: number
  assetsOnline: number
}

export const fetchStats = () => get<Stats>('/api/stats')

export interface EventRow {
  id: string
  ts: string
  classUid: number
  source: string
  assetId: string | null
  username: string | null
  connTuple: string | null
  raw: unknown
}

export const searchEvents = (params: {
  assetId?: string
  q?: string
  source?: string
  classUid?: number
  hours?: number
}) => {
  const qs = new URLSearchParams()
  if (params.q) qs.set('q', params.q)
  if (params.assetId) qs.set('assetId', params.assetId)
  if (params.source) qs.set('source', params.source)
  if (params.classUid) qs.set('classUid', String(params.classUid))
  if (params.hours)
    qs.set('from', new Date(Date.now() - params.hours * 3_600_000).toISOString())
  qs.set('limit', '200')
  return get<EventRow[]>(`/api/events?${qs}`)
}

export interface AttackCoverage {
  tactics: {
    tactic: string
    rules: number
    techniques: { id: string; rules: number; hasData: boolean }[] | null
  }[]
  untagged: number
  noDataSource: number
}

export const fetchAttack = () => get<AttackCoverage>('/api/attack')

export interface RuleRow {
  id: string
  title: string
  severity: number
  classUid: number
  product: string
  ingested: boolean
  source: string
}

export const fetchRules = () => get<RuleRow[]>('/api/rules')

export interface IntelRow {
  id: string
  createdAt: string
  kind: 'ip' | 'domain' | 'hash'
  value: string
  source: string
  severity: number
  note: string | null
  expiresAt: string | null
  matchedCount: number
  lastMatchedAt: string | null
}

export const fetchIntel = () => get<IntelRow[]>('/api/intel')

// 情报订阅：内置公开源的开关与同步状态，以及命中过的订阅情报
export interface IntelFeed {
  id: string
  name: string
  url: string
  severity: number
  enabled: boolean
  count: number
  hits: number
  syncedAt: string | null
  error?: string
}
export interface IntelFeeds {
  feeds: IntelFeed[]
  hits: IntelRow[]
  intervalHours: number
}
export const fetchIntelFeeds = () => get<IntelFeeds>('/api/intel/feeds')
export const saveIntelFeeds = async (enabled: string[]): Promise<IntelFeeds> =>
  (await send('PUT', '/api/intel/feeds', { enabled })).json()
export const syncIntelFeeds = async (): Promise<IntelFeeds> => (await send('POST', '/api/intel/feeds/sync')).json()

export async function importIntel(body: {
  text: string
  source?: string
  severity?: number
  expiresInDays?: number
}): Promise<{ imported: number; skipped: number }> {
  const r = await post('/api/intel/import', body)
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export async function deleteIntel(id: string): Promise<void> {
  const r = await fetch(`/api/intel/${id}`, { method: 'DELETE' })
  check(r)
  if (!r.ok) throw new Error(await r.text())
}

export interface UserRow {
  id: string
  createdAt: string
  username: string
  role: string
}

export const fetchUsers = () => get<UserRow[]>('/api/users')

export async function createUser(body: {
  username: string
  password: string
  role: string
}): Promise<UserRow> {
  const r = await post('/api/users', body)
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export async function deleteUser(id: string): Promise<void> {
  const r = await fetch(`/api/users/${id}`, { method: 'DELETE' })
  check(r)
  if (!r.ok) throw new Error(await r.text())
}

export async function resetUserPassword(id: string, password: string): Promise<void> {
  const r = await post(`/api/users/${id}/password`, { password })
  if (!r.ok) throw new Error(await r.text())
}

export interface AuditRow {
  id: string
  ts: string
  username: string
  action: string
  target: string | null
  detail: string | null
  remoteAddr: string
}

export const fetchAudit = () => get<AuditRow[]>('/api/audit')

// 资产组：组是纳管与授权单位，role 为当前用户在组内的有效角色
export interface GroupRow {
  id: string
  createdAt: string
  name: string
  role: 'admin' | 'analyst' | 'viewer'
  assetCount: number
}

export interface MemberRow {
  userId: string
  username: string
  role: string
}

async function send(method: string, url: string, body?: unknown): Promise<Response> {
  const r = await fetch(url, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  check(r)
  if (!r.ok) throw new Error(await r.text())
  return r
}

export const fetchGroups = () => get<GroupRow[]>('/api/groups')
export const createGroup = async (name: string): Promise<GroupRow> =>
  (await send('POST', '/api/groups', { name })).json()
export const deleteGroup = (id: string) => send('DELETE', `/api/groups/${id}`)
export const fetchMembers = (groupId: string) => get<MemberRow[]>(`/api/groups/${groupId}/members`)
export const setMember = (groupId: string, userId: string, role: string) =>
  send('PUT', `/api/groups/${groupId}/members/${userId}`, { role })
export const removeMember = (groupId: string, userId: string) =>
  send('DELETE', `/api/groups/${groupId}/members/${userId}`)
// 通知配置：控制台保存的为准，未保存过时后端返回环境变量默认值
export interface NotifySettings {
  url: string
  format: 'generic' | 'dingtalk' | 'feishu' | 'wecom'
  linkBase: string
  minSeverity: number
}
export const fetchNotifySettings = () => get<NotifySettings>('/api/settings/notify')
export const saveNotifySettings = (s: NotifySettings) => send('PUT', '/api/settings/notify', s)
export const testNotifySettings = (s: NotifySettings) => send('POST', '/api/settings/notify/test', s)

// 主机接入：令牌按组签发，明文只在创建时返回一次
export interface EnrollStatus {
  enabled: boolean
  reason: string
  platforms: string[]
}
export interface EnrollToken {
  id: string
  groupId: string
  createdBy: string
  createdAt: string
  expiresAt: string
  revoked: boolean
  uses: number
  token?: string
}
export const fetchEnrollStatus = () => get<EnrollStatus>('/api/enroll-tokens/status')
export const fetchEnrollTokens = (groupId: string) => get<EnrollToken[]>(`/api/enroll-tokens?groupId=${groupId}`)
export const createEnrollToken = async (groupId: string, days: number): Promise<EnrollToken> =>
  (await send('POST', '/api/enroll-tokens', { groupId, days })).json()
export const revokeEnrollToken = (id: string) => send('DELETE', `/api/enroll-tokens/${id}`)

export const assignAsset = (groupId: string, assetId: string) =>
  send('PUT', `/api/groups/${groupId}/assets/${assetId}`)
export const unassignAsset = (groupId: string, assetId: string) =>
  send('DELETE', `/api/groups/${groupId}/assets/${assetId}`)

// Pi 会话。后端直接返回 ent 实体，字段是 snake_case
export interface AgentSession {
  id: string
  created_at: string
  kind: 'chat' | 'task'
  group_id: string
  initiator: string
  model: string
  title?: string
  status: 'running' | 'idle' | 'succeeded' | 'failed'
  error?: string
  dry_run?: boolean
}

// Pi 原生消息，原样存库、原样回放
export type ContentPart =
  | { type: 'text'; text: string }
  | { type: 'thinking'; thinking: string }
  | { type: 'toolCall'; id: string; name: string; arguments: Record<string, unknown> }
  | { type: 'image' }

export type PiMessage =
  | { role: 'user'; content: string | ContentPart[] }
  | { role: 'assistant'; content: ContentPart[]; stopReason?: string; errorMessage?: string }
  | { role: 'toolResult'; toolCallId: string; toolName: string; content: ContentPart[]; isError: boolean }

export interface SessionMessage {
  id: string
  created_at: string
  seq: number
  role: string
  content: PiMessage
}

export const fetchAgentSessions = (groupId: string) =>
  get<AgentSession[]>(`/api/agent-sessions?groupId=${groupId}`)

export const createAgentSession = async (body: {
  groupId: string
  title?: string
  dryRun: boolean
}): Promise<AgentSession> => (await send('POST', '/api/agent-sessions', body)).json()

export const fetchSessionMessages = (id: string) =>
  get<SessionMessage[]>(`/api/agent-sessions/${id}/messages`)

// 流式事件：pi 为 runner 原始事件；done / error 才是本轮的终态
export type ChatEvent =
  | { event: 'pi'; data: { type: string; event?: PiEvent } }
  | { event: 'done'; data: { StopReason: string } }
  | { event: 'error'; data: { error: string } }
  | { event: 'session' | 'heartbeat'; data: unknown }

export interface PiEvent {
  type: string
  message?: PiMessage
  toolName?: string
  toolCallId?: string
}

// POST SSE：EventSource 只支持 GET，只能自己读流按空行切帧
export async function sendSessionMessage(
  id: string,
  prompt: string,
  onEvent: (e: ChatEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const r = await fetch(`/api/agent-sessions/${id}/messages`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt }),
    signal,
  })
  check(r)
  if (!r.ok || !r.body) throw new Error(await r.text())
  const reader = r.body.pipeThrough(new TextDecoderStream()).getReader()
  let buf = ''
  for (;;) {
    const { value, done } = await reader.read()
    if (done) return
    buf += value
    let i
    while ((i = buf.indexOf('\n\n')) >= 0) {
      const frame = buf.slice(0, i)
      buf = buf.slice(i + 2)
      let event = 'message'
      let data = ''
      for (const line of frame.split('\n')) {
        if (line.startsWith('event: ')) event = line.slice(7)
        else if (line.startsWith('data: ')) data += line.slice(6)
      }
      onEvent({ event, data: data ? JSON.parse(data) : null } as ChatEvent)
    }
  }
}

// 审批与命令名单（组 admin）。实体字段 snake_case
export interface Approval {
  id: string
  created_at: string
  group_id: string
  session_id?: string
  asset_id: string
  requested_by: string
  origin: 'ai' | 'human'
  cmd: string
  timeout_ms: number
  dry_run: boolean
  status: 'pending' | 'approved' | 'rejected' | 'expired' | 'cancelled' | 'consumed'
  expires_at: string
  decided_by?: string
  decided_at?: string
}

export interface CommandPolicy {
  id: string
  created_at: string
  group_id: string
  origin: 'ai' | 'human'
  mode: 'allow' | 'deny'
  pattern: string
}

export const fetchApprovals = (groupId: string) => get<Approval[]>(`/api/approvals?groupId=${groupId}`)
export const decideApproval = (id: string, approve: boolean) =>
  send('POST', `/api/approvals/${id}/decision`, { approve })
export const fetchPolicies = (groupId: string) =>
  get<CommandPolicy[]>(`/api/command-policies?groupId=${groupId}`)
export const createPolicy = (groupId: string, origin: 'ai' | 'human', pattern: string) =>
  send('POST', '/api/command-policies', { groupId, origin, pattern })
export const deletePolicy = (id: string) => send('DELETE', `/api/command-policies/${id}`)

// Pi 报告：库里只有 Markdown，HTML / PDF 由后端按需渲染
export interface AgentReport {
  id: string
  created_at: string
  session_id: string
  group_id: string
  title: string
  markdown: string
}

export const fetchAgentReports = (groupId: string) =>
  get<AgentReport[]>(`/api/agent-reports?groupId=${groupId}`)
export const reportHtmlUrl = (id: string) => `/api/agent-reports/${id}/html`

// 走 fetch 而不是直接跳转：没装 Chromium 时后端回 503，要能在界面上报错
export async function downloadAgentPdf(r: AgentReport): Promise<void> {
  const resp = await fetch(`/api/agent-reports/${r.id}/pdf`)
  check(resp)
  if (!resp.ok) throw new Error(await resp.text())
  const url = URL.createObjectURL(await resp.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = `${r.title.replace(/[/\\?%*:|"<>]/g, '-')}.pdf`
  a.click()
  URL.revokeObjectURL(url)
}

// 预设任务：定义在仓库 YAML，界面只能启停与改周期（admin）
export interface TaskRow {
  id: string
  name: string
  schedule: string
  customSchedule: string | null
  enabled: boolean
  model: string
  targetGroup: string
  prompt: string
}

export interface TaskRunRow {
  id: string
  taskId: string
  groupId: string
  sessionId: string | null
  startedAt: string
  finishedAt: string | null
  status: 'running' | 'succeeded' | 'failed'
  error: string | null
}

export const fetchTasks = () => get<TaskRow[]>('/api/tasks')
export const updateTask = async (
  id: string,
  body: { enabled?: boolean; customSchedule?: string },
): Promise<TaskRow> => (await send('PATCH', `/api/tasks/${id}`, body)).json()
export const fetchTaskRuns = (id: string) => get<TaskRunRow[]>(`/api/tasks/${id}/runs`)

// 采集配置：随 Register 下发给 agent；字段缺省表示用 agent 内置默认
export interface AgentConfig {
  fileWatchDirs?: string[]
  collectFiles?: boolean
  collectAuth?: boolean
  collectPersist?: boolean
  collectNetwork?: boolean
}

export const fetchAgentConfig = (assetId: string) => get<AgentConfig>(`/api/assets/${assetId}/config`)
export const saveAgentConfig = async (assetId: string, cfg: AgentConfig): Promise<AgentConfig> =>
  (await send('PUT', `/api/assets/${assetId}/config`, cfg)).json()

export interface ImportedHost {
  hostname: string; address: string; os: string; port: number; username: string
  kind: 'none' | 'password' | 'private_key'; hostKey: string
}
export interface HostImportPreview { digest: string; hosts: ImportedHost[] }
export interface HostCredential extends ImportedHost { id: string; assetId: string }
export const fetchHostImportStatus = () => get<{ credentialStorage: boolean; sshEnrollment: boolean }>('/api/host-import/status')
export const fetchHostCredentials = (groupId: string) => get<HostCredential[]>(`/api/host-import/credentials?groupId=${encodeURIComponent(groupId)}`)
export async function previewHostImport(groupId: string, document: string): Promise<HostImportPreview> {
  const r = await post('/api/host-import/preview', { groupId, document })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}
export async function commitHostImport(groupId: string, document: string, digest: string): Promise<{ assetIds: string[] }> {
  const r = await post('/api/host-import/commit', { groupId, document, digest })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}
export async function enrollHostCredential(id: string, fingerprint: string): Promise<{ status: string; message: string }> {
  const r = await post(`/api/host-import/credentials/${id}/enroll`, { fingerprint })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}
export async function deleteHostCredential(id: string): Promise<void> {
  const r = await fetch(`/api/host-import/credentials/${id}`, { method: 'DELETE' })
  check(r)
  if (!r.ok) throw new Error(await r.text())
}
