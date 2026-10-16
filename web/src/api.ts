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

export const fetchIncidents = (status?: string) =>
  get<IncidentSummary[]>(status ? `/api/incidents?status=${status}` : '/api/incidents')

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

export const fetchCommands = (incidentId: string) =>
  get<CommandRow[]>(`/api/commands?incidentId=${incidentId}`)

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
  q?: string
  source?: string
  classUid?: number
  hours?: number
}) => {
  const qs = new URLSearchParams()
  if (params.q) qs.set('q', params.q)
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

export interface HuntStep {
  tool: string
  args: string
}

export async function hunt(question: string): Promise<{ answer: string; steps: HuntStep[] | null }> {
  const r = await post('/api/hunt', { question })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

// 狩猎结论 → Sigma 规则草稿（只起草，不落盘）
export async function draftRule(question: string, answer: string): Promise<{ yaml: string }> {
  const r = await post('/api/hunt/rule', { question, answer })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

// 保存规则到检测面，热重载后生效
export async function saveRule(yaml: string): Promise<{ id: string; title: string }> {
  const r = await post('/api/rules', { yaml })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

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
