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
  // 告警主机所在组，逐行判断能否处置
  groupId: string | null
  // 结案：谁、何时、为什么
  resolution: string | null
  resolvedBy: string | null
  resolvedAt: string | null
  // AI 的结案建议：人一键采纳（结案仍记在人名下）或忽略
  closureProposal: ClosureProposal | null
}

export interface ClosureProposal {
  status: 'closed' | 'false_positive'
  note: string
  sessionId: string
  reportId?: string
  at: string
}

export interface AlertRow {
  id: string
  ts: string
  lastTs: string | null
  count: number
  severity: number
  ruleId: string
  ruleTitle: string | null
  // 规则作者：社区规则（DRL 1.1）要求命中展示时保留
  ruleAuthor?: string
  event: unknown
}

export interface IncidentDetail extends Omit<IncidentSummary, 'alertCount'> {
  graph: Graph
  assetId: string | null
  alerts: AlertRow[]
}

// 会话失效时抛出，App 捕获后切回登录页
export class Unauthorized extends Error {}
export const SESSION_EXPIRED = 'openxdr:session-expired'

// 接口报错：保留状态码与后端给的说明，界面按状态码选文案（见 components/format errText）
export class HttpError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

function check(r: Response) {
  if (r.status === 401) {
    window.dispatchEvent(new Event(SESSION_EXPIRED))
    throw new Unauthorized()
  }
}

async function fail(r: Response): Promise<never> {
  throw new HttpError(r.status, (await r.text()).trim() || r.statusText)
}

async function get<T>(url: string): Promise<T> {
  const r = await fetch(url)
  check(r)
  if (!r.ok) await fail(r)
  return r.json()
}

// 列表接口：后端会截断（limit），总数走 X-Total-Count、截断走 X-Truncated，界面据此提示而不是假装看全了
export interface Page<T> {
  items: T[]
  total?: number
  truncated: boolean
}

async function list<T>(url: string): Promise<Page<T>> {
  const r = await fetch(url)
  check(r)
  if (!r.ok) await fail(r)
  const total = r.headers.get('X-Total-Count')
  return { items: await r.json(), total: total === null ? undefined : Number(total), truncated: r.headers.get('X-Truncated') === '1' }
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
  if (!r.ok) await fail(r)
  return r.json()
}

export const logout = () => send('POST', '/api/logout')

// status 可取 unresolved（open + triaged，未人工结案）、review（未结案里需要人复核的）；按 offset/limit 翻页，total 是筛选后的总数
export const fetchIncidents = (params: { status?: string; assetId?: string; limit?: number; offset?: number } = {}) => {
  const qs = new URLSearchParams()
  if (params.status) qs.set('status', params.status)
  if (params.assetId) qs.set('assetId', params.assetId)
  qs.set('limit', String(params.limit ?? 50))
  if (params.offset) qs.set('offset', String(params.offset))
  return list<IncidentSummary>(`/api/incidents?${qs}`)
}

export const fetchIncident = (id: string) => get<IncidentDetail>(`/api/incidents/${id}`)

// 结案（closed / false_positive）必须带结论备注，改回 open 不用
export const dismissClosureProposal = (id: string) => send('DELETE', `/api/incidents/${id}/closure-proposal`)

export async function setIncidentStatus(id: string, status: string, note?: string): Promise<void> {
  const r = await post(`/api/incidents/${id}/status`, { status, note })
  if (!r.ok) await fail(r)
}

// 运维待办：巡检 AI 登记与复查；人标已处理或忽略（须写原因，忽略原因会告诉 AI）
export interface FindingRow {
  id: string
  groupId: string
  assetId: string
  hostname: string
  key: string
  title: string
  detail: string
  severity: 'info' | 'low' | 'medium' | 'high'
  status: 'open' | 'resolved' | 'ignored'
  firstSeen: string
  lastSeen: string
  sessionId: string | null
  resolvedAt: string | null
  resolvedBy: string | null
  note: string | null
}

export const fetchFindings = (status?: string) => get<FindingRow[]>(`/api/findings${status ? `?status=${status}` : ''}`)
export const setFindingStatus = (id: string, status: string, note?: string) =>
  send('POST', `/api/findings/${id}/status`, { status, note })

// 报告是文件下载：拿到 blob 后用临时链接触发浏览器保存
export async function downloadReport(id: string, title: string | null): Promise<void> {
  const r = await fetch(`/api/incidents/${id}/report`)
  check(r)
  if (!r.ok) await fail(r)
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
  assetId: string
  incidentId: string | null
  issuedBy: string
  detail: string | null
  completedAt: string | null
  // 这条指令拉起的进程触发的检测（来源已知，不进事件）
  detections?: { ruleId: string; title?: string; author?: string; count: number }[]
}

export const fetchCommands = (filter: { incidentId?: string; assetId?: string }) =>
  get<CommandRow[]>(`/api/commands?${new URLSearchParams(filter as Record<string, string>)}`)

export async function issueCommand(body: {
  kind: string
  assetId: string
  incidentId?: string
  pid?: number
}): Promise<CommandRow> {
  const r = await post('/api/commands', body)
  if (!r.ok) await fail(r)
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
  // active 生效 / proposed AI 提议待组管理员批准 / rejected 已拒绝
  status: 'active' | 'proposed' | 'rejected'
  sessionId: string | null
  reviewedBy: string | null
  reviewedAt: string | null
  // 字段条件（AND）：只压字段对得上的命中；为空表示整条规则
  conditions: SuppressCondition[] | null
}

export interface SuppressCondition {
  field: string
  op: 'equals' | 'contains' | 'endswith'
  value: string
}

export const reviewSuppression = (id: string, decision: 'approve' | 'reject') =>
  send('POST', `/api/suppressions/${id}/review`, { decision })

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
  conditions?: SuppressCondition[]
}): Promise<Suppression> {
  const r = await post('/api/suppressions', body)
  if (!r.ok) await fail(r)
  return r.json()
}

export async function deleteSuppression(id: string): Promise<void> {
  const r = await fetch(`/api/suppressions/${id}`, { method: 'DELETE' })
  check(r)
  if (!r.ok) await fail(r)
}

export interface Stats {
  events24h: number
  alerts24h: number
  openIncidents: number
  // 未结案里需要人看的：AI 非良性，或良性但高危及以上（与通知策略同一口径）
  reviewIncidents: number
  incidentsByStatus: Record<string, number>
  alertTrend: { hour: string; count: number }[]
  topRules: { ruleId: string; ruleTitle: string | null; ruleAuthor?: string; count: number }[]
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

// 问 AI：related 是查库得出的确定关联（父进程链、同一进程、子进程、同一连接、同一远端、前后同主机）；
// explain 是模型读这条日志与候选后的解读，挑出的相关日志只会来自候选
export type Relation = 'ancestor' | 'process' | 'child' | 'connection' | 'peer' | 'nearby'
export interface RelatedGroup { relation: Relation; events: EventRow[] }
export interface EventExplanation {
  verdict: 'benign' | 'suspicious' | 'malicious' | 'unknown'
  title: string; summary: string; points: string[]; next: string[]
  related: { id: string; why: string }[]
}
export const fetchRelatedEvents = (id: string) => get<RelatedGroup[]>(`/api/events/${id}/related`)
// 后台 AI 任务：发起后立即返回，结果在服务端，前端轮询；换页、刷新都能接着看
export interface AIJob<T> { id?: string; status: 'none' | 'running' | 'done' | 'failed'; result?: T; error?: string; createdAt?: string; finishedAt?: string }
export const fetchExplain = (id: string, lang: string) => get<AIJob<EventExplanation>>(`/api/events/${id}/explain?lang=${lang}`)
export const startExplain = async (id: string, lang: string, refresh = false): Promise<AIJob<EventExplanation>> =>
  (await send('POST', `/api/events/${id}/explain?lang=${lang}${refresh ? '&refresh=1' : ''}`)).json()

export const searchEvents = (params: {
  assetId?: string
  q?: string
  source?: string
  classUid?: number
  hours?: number
  // 给了精确时间窗就不看 hours（事件详情跳"日志上下文"用）
  from?: string
  to?: string
}) => {
  const qs = new URLSearchParams()
  if (params.q) qs.set('q', params.q)
  if (params.assetId) qs.set('assetId', params.assetId)
  if (params.source) qs.set('source', params.source)
  if (params.classUid) qs.set('classUid', String(params.classUid))
  if (params.from) {
    qs.set('from', params.from)
    if (params.to) qs.set('to', params.to)
  } else if (params.hours)
    qs.set('from', new Date(Date.now() - params.hours * 3_600_000).toISOString())
  qs.set('limit', '200')
  return list<EventRow>(`/api/events?${qs}`)
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
  author?: string
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
  if (!r.ok) await fail(r)
  return r.json()
}

export async function deleteIntel(id: string): Promise<void> {
  const r = await fetch(`/api/intel/${id}`, { method: 'DELETE' })
  check(r)
  if (!r.ok) await fail(r)
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
  if (!r.ok) await fail(r)
  return r.json()
}

export async function deleteUser(id: string): Promise<void> {
  const r = await fetch(`/api/users/${id}`, { method: 'DELETE' })
  check(r)
  if (!r.ok) await fail(r)
}

export async function resetUserPassword(id: string, password: string): Promise<void> {
  const r = await post(`/api/users/${id}/password`, { password })
  if (!r.ok) await fail(r)
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

// 关键词在后端匹配（用户、动作、对象、详情），最多返回最近 500 条
export const fetchAudit = (q?: string) => list<AuditRow>(`/api/audit${q ? `?q=${encodeURIComponent(q)}` : ''}`)

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
  if (!r.ok) await fail(r)
  return r
}

export interface MemoryRow {
  id: string
  groupId: string
  assetId: string | null
  hostname?: string
  content: string
  source: 'ai' | 'human'
  author: string
  sessionId: string | null
  createdAt: string
  updatedAt: string
}

// 组内长期记忆：AI 在会话里记下的环境知识，人可以补充、改正、删除
export const fetchMemories = () => get<MemoryRow[]>('/api/memories')
export const createMemory = (body: { groupId: string; assetId?: string; content: string }) => send('POST', '/api/memories', body)
export const updateMemory = (id: string, content: string) => send('PATCH', `/api/memories/${id}`, { content })
export const deleteMemory = (id: string) => send('DELETE', `/api/memories/${id}`)

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

// AI 与外部情报配置：密钥只回是否已设与末四位；source 标明每项来自控制台还是环境变量
export interface AISettings {
  baseUrl: string; model: string; piModel: string; ptr: boolean; vtAlertMin: number
  apiKeySet: boolean; apiKeyHint?: string; vtKeySet: boolean; vtKeyHint?: string
  source: Record<string, 'console' | 'env'>
  canSaveSecrets: boolean
}
// 只发改动的项；密钥传空串表示清空；reset 里的项回到环境变量
export interface AISettingsPatch {
  baseUrl?: string; model?: string; piModel?: string; ptr?: boolean; vtAlertMin?: number; apiKey?: string; vtKey?: string; reset?: string[]
}
export const fetchAISettings = () => get<AISettings>('/api/settings/ai')
export const saveAISettings = async (p: AISettingsPatch): Promise<AISettings> => (await send('PUT', '/api/settings/ai', p)).json()
export const testAISettings = async (p: AISettingsPatch & { target: 'model' | 'piModel' | 'vt' }): Promise<{ ms: number; reply: string }> =>
  (await send('POST', '/api/settings/ai/test', p)).json()

// AI 用量：按天、用途、模型聚合；用途 chat AI 助手 / task 定时任务 / triage 事件研判 / annotate 资产标注
export interface AIUsageRow { day: string; feature: 'chat' | 'task' | 'triage' | 'annotate' | 'explain'; model: string; input: number; output: number; cacheRead: number; calls: number }
export interface AIUsageTop { id: string; title: string; kind: string; group: string; model: string; tokens: number; calls: number; lastAt: string }
export const fetchAIUsage = (days: number) =>
  get<{ rows: AIUsageRow[]; top: AIUsageTop[] }>(`/api/settings/ai/usage?days=${days}&tz=${encodeURIComponent(Intl.DateTimeFormat().resolvedOptions().timeZone)}`)

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
  // 「交给 AI」绑定的对象：incident:<id> / finding:<id>
  subjects?: string[]
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

// 列表只有最近 100 个，深链接必须按 id 直接取
export const fetchAgentSession = (id: string) => get<AgentSession>(`/api/agent-sessions/${id}`)

export const createAgentSession = async (body: {
  groupId: string
  title?: string
  subjects?: string[]
}): Promise<AgentSession> => (await send('POST', '/api/agent-sessions', body)).json()

export const fetchSessionMessages = (id: string, afterSeq = 0) =>
  get<SessionMessage[]>(`/api/agent-sessions/${id}/messages${afterSeq ? `?afterSeq=${afterSeq}` : ''}`)

// 发消息只是让后台开跑：会话切到 running 就返回，运行不随页面走；进度靠轮询会话与消息
export const startSessionMessage = (id: string, prompt: string) =>
  send('POST', `/api/agent-sessions/${id}/messages`, { prompt })

// 停止：写一条停止请求，后台运行所在节点几秒内收手，会话回到空闲可以接着问
export const cancelSession = (id: string) => send('POST', `/api/agent-sessions/${id}/cancel`)

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
  if (!resp.ok) await fail(resp)
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
  // 按当前周期算的下一次运行时间；停用时为空
  nextRun: string | null
}

export interface TaskRunRow {
  reportId: string | null
  reportTitle: string | null
  // 这一轮做了多少步（工具调用次数）
  steps: number
  id: string
  taskId: string
  groupId: string
  sessionId: string | null
  startedAt: string
  finishedAt: string | null
  // interrupted：被停机打断，接手的调度器稍后重跑
  status: 'running' | 'succeeded' | 'failed' | 'interrupted'
  error: string | null
}

export const fetchTasks = () => get<TaskRow[]>('/api/tasks')
export const updateTask = async (
  id: string,
  body: { enabled?: boolean; customSchedule?: string },
): Promise<TaskRow> => (await send('PATCH', `/api/tasks/${id}`, body)).json()
export const fetchTaskRuns = (id: string) => get<TaskRunRow[]>(`/api/tasks/${id}/runs`)
// 立即运行只是记下请求，调度器下一次检查（默认 30 秒内）拉起
export const runTask = (id: string) => send('POST', `/api/tasks/${id}/run`)

// 采集配置：随 Register 下发给 agent；字段缺省表示用 agent 内置默认
export interface AgentConfig {
  fileWatchDirs?: string[]
  collectFiles?: boolean
  collectAuth?: boolean
  collectPersist?: boolean
  collectNetwork?: boolean
  collectInventory?: boolean
  collapsePeriodic?: boolean
}

export const fetchAgentConfig = (assetId: string) => get<AgentConfig>(`/api/assets/${assetId}/config`)
export const saveAgentConfig = async (assetId: string, cfg: AgentConfig): Promise<AgentConfig> =>
  (await send('PUT', `/api/assets/${assetId}/config`, cfg)).json()

export interface ImportedHost {
  hostname: string; address: string; os: string; port: number; username: string
  kind: 'none' | 'password' | 'private_key'; hostKey: string
}
export interface ReviewedHost extends ImportedHost { credentialToken?: string; images?: number[]; lines: number[]; needsReview: boolean; issues: string[]; reviewId?: string }
export interface HostImportPreview { hosts: ReviewedHost[] }
export interface HostCredential extends ImportedHost { id: string; assetId: string }
export const fetchHostImportStatus = () => get<{ credentialStorage: boolean; sshEnrollment: boolean; aiParsing: boolean }>('/api/host-import/status')
export const fetchHostCredentials = (groupId: string) => get<HostCredential[]>(`/api/host-import/credentials?groupId=${encodeURIComponent(groupId)}`)
export async function startHostImport(groupId: string, document: string, images: HostDocumentImage[] = []): Promise<AIJob<HostImportPreview>> {
  const r = await post('/api/host-import/analyze', { groupId, document, images })
  if (!r.ok) await fail(r)
  return r.json()
}
export const fetchHostImportJob = (groupId: string) => get<AIJob<HostImportPreview>>(`/api/host-import/analyze?groupId=${encodeURIComponent(groupId)}`)
export const discardHostImportJob = (groupId: string) => send('DELETE', `/api/host-import/analyze?groupId=${encodeURIComponent(groupId)}`)
export async function commitHostImport(groupId: string, hosts: ReviewedHost[]): Promise<{ assetIds: string[] }> {
  const r = await post('/api/host-import/confirm', { groupId, hosts, confirmed: true })
  if (!r.ok) await fail(r)
  return r.json()
}
export async function enrollHostCredential(id: string, fingerprint: string): Promise<{ status: string; message: string }> {
  const r = await post(`/api/host-import/credentials/${id}/enroll`, { fingerprint })
  if (!r.ok) await fail(r)
  return r.json()
}
export async function deleteHostCredential(id: string): Promise<void> {
  const r = await fetch(`/api/host-import/credentials/${id}`, { method: 'DELETE' })
  check(r)
  if (!r.ok) await fail(r)
}

// 资产图谱与攻击面。区域 name 为空表示自动划分，按 kind 显示内置名称；云上自动划分时 name 是云厂商
export type ZoneKind = 'internal' | 'dmz' | 'external' | 'cloud'
export type ExposureLevel = 'internet' | 'dmz' | 'internal'
export interface ZoneRef { id?: string; name: string; kind: ZoneKind; source: 'manual' | 'cidr' | 'cloud' | 'auto' }
export interface ZoneRow { id: string; group_id: string; name: string; kind: ZoneKind; cidrs?: string[] }

export interface MapNode {
  id: string
  kind: 'asset' | 'discovered' | 'managed' | 'internet'
  label: string
  zone: ZoneRef
  exposure?: ExposureLevel
  role?: string
  criticality?: number
  os?: string
  online?: boolean
  listening?: number
  ports?: string[]
}
// 公网目的地址：按地址合并的外联明细，带反向解析、VirusTotal 信息与 AI 给的用途
export interface PublicDest {
  ip: string; ports: string[]; processes?: string[]; count: number; lastSeen: string
  ptr?: string; owner?: string; country?: string; malicious?: number; suspicious?: number; domains?: string[]; checked?: boolean; purpose?: string
  // 上机调查或人工给的结论，优先于 AI 推断的 purpose
  note?: ServiceNote
}
export interface MapEdge {
  from: string; to: string; ports: string[]; processes: string[]; count: number; lastSeen: string; note?: string; targets?: PublicDest[]
}
export interface AssetMap { nodes: MapNode[]; edges: MapEdge[] }

export interface PortService { name: string; category: string; risk: 'high' | 'medium' | 'low' }
export interface ExposedService {
  assetId: string; hostname: string; zone: ZoneRef; level: ExposureLevel; proto: string; addrs: string[]; port: number
  process?: string; service: PortService; criticality?: number; score: number; peers: string[] | null; peerCount: number; fromPublic: boolean
  note?: ServiceNote
}
// 服务说明：端口表认不出时靠它命名；来源优先级 human > investigation > ai
export interface ServiceNote { name: string; note?: string; risk?: 'high' | 'medium' | 'low'; source: 'ai' | 'investigation' | 'human'; by?: string; at: string }
export interface SurfacePeer { id: string; label: string; kind: 'asset' | 'discovered' | 'managed' | 'internet'; zone: ZoneRef }
export interface SurfacePath { from: string; assetId: string; service: string; count: number }
export interface BlindSpot { ip: string; zone: ZoneRef; ports: string[]; accessed: string[]; seenBy: string[]; count: number; lastSeen: string }
export interface AttackSurface {
  summary: { internet: number; dmz: number; internal: number; high: number; blind: number; noInventory: string[] }
  exposures: ExposedService[]
  blind: BlindSpot[]
  peers: SurfacePeer[]
  paths: SurfacePath[]
}

export interface Listener { proto: string; addr: string; port: number; pid?: number; process?: string; path?: string }
export interface CloudInfo { provider: string; instanceId: string; region?: string; publicIp?: string }
export interface AssetProfile {
  zone: ZoneRef
  exposure: ExposureLevel
  cloud?: CloudInfo | null
  listening: Listener[] | null
  inventoryAt?: string | null
  services?: Record<string, ServiceNote> | null
  outbound: string[] | null
  inbound: string[] | null
  publicDestinations: number
  public?: PublicDest[] | null
  role?: string | null
  summary?: string | null
  criticality?: number | null
  reason?: string | null
  relationNotes?: Record<string, string> | null
  lockedFields?: string[] | null
  annotatedAt?: string | null
  annotateRequestedAt?: string | null
  aiEnabled: boolean
}
export type ProfileEdit = { role?: string; summary?: string; criticality?: number; unlock?: string[] }

export const fetchAssetMap = (groupId: string) => get<AssetMap>(`/api/asset-map?groupId=${groupId}`)
export const fetchAttackSurface = (groupId: string) => get<AttackSurface>(`/api/attack-surface?groupId=${groupId}`)
export const fetchZones = (groupId: string) => get<ZoneRow[]>(`/api/zones?groupId=${groupId}`)
export const createZone = async (z: { groupId: string; name: string; kind: ZoneKind; cidrs: string[] }) => { await send('POST', '/api/zones', z) }
export const updateZone = async (id: string, z: { name: string; kind: ZoneKind; cidrs: string[] }) => { await send('PUT', `/api/zones/${id}`, z) }
export const deleteZone = async (id: string) => { await send('DELETE', `/api/zones/${id}`) }
export const fetchAssetProfile = (id: string) => get<AssetProfile>(`/api/assets/${id}/profile`)
export const saveAssetProfile = async (id: string, edit: ProfileEdit) => { await send('PUT', `/api/assets/${id}/profile`, edit) }
export const assignAssetZone = async (id: string, zoneId: string | null) => { await send('PUT', `/api/assets/${id}/zone`, { zoneId }) }
export const saveServiceNote = async (id: string, body: { port: string; name: string; note?: string; risk?: string }) => {
  await send('PUT', `/api/assets/${id}/services`, body)
}
export const requestAnnotate = async (id: string) => { await send('POST', `/api/assets/${id}/annotate`) }

export interface HostDocumentImage { name: string; dataUrl: string }
export async function extractHostDocument(groupId: string, file: File): Promise<{ document: string; images: HostDocumentImage[] | null }> {
  const body = new FormData()
  body.append('groupId', groupId)
  body.append('file', file)
  const r = await fetch('/api/host-import/extract', { method: 'POST', body })
  check(r)
  if (!r.ok) await fail(r)
  return await r.json()
}
