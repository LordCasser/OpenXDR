import {
  ArrowDownOutlined, MenuOutlined, AlertOutlined, CloudServerOutlined, GlobalOutlined, LoginOutlined, PlusOutlined, PushpinOutlined, RobotOutlined, SendOutlined, StopOutlined,
} from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, App, Button, Card, Col, Drawer, Empty, Flex, Grid, Input, Result, Row, Segmented, Space, Spin, Tag, Tooltip, Typography, theme,
} from 'antd'
import { useCallback, useEffect, useRef, useState, type ReactNode, type Dispatch, type SetStateAction } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router'
import {
  createAgentSession, fetchAgentSession, fetchAgentSessions, fetchApprovals, fetchAssets, fetchSessionMessages,
  startSessionMessage, cancelSession, type AgentSession, type Approval, type PiMessage,
} from '../api'
import { useRemember } from '../app/recent'
import { useSession } from '../app/session'
import { ChatConversation, textOf, type ChatRow } from '../components/ChatConversation'
import { ApprovalActions } from '../components/ApprovalActions'
import { SubjectsBar } from '../components/Handoff'
import { SessionStatusTag, fmtTime, errText } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

// 常用提问模板：空会话时给出，点了只是填进输入框，发不发由人决定
const TEMPLATES: { key: string; icon: ReactNode; title: MsgKey; prompt: MsgKey }[] = [
  { key: 'inspect', icon: <CloudServerOutlined />, title: 'tplInspectTitle', prompt: 'tplInspectPrompt' },
  { key: 'login', icon: <LoginOutlined />, title: 'tplLoginTitle', prompt: 'tplLoginPrompt' },
  { key: 'network', icon: <GlobalOutlined />, title: 'tplNetworkTitle', prompt: 'tplNetworkPrompt' },
  { key: 'incident', icon: <AlertOutlined />, title: 'tplIncidentTitle', prompt: 'tplIncidentPrompt' },
]

function Templates({ onPick }: { onPick: (prompt: string) => void }) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  return (
    <Row gutter={[12, 12]} style={{ maxWidth: 760, width: '100%' }}>
      {TEMPLATES.map(x => (
        <Col key={x.key} xs={24} md={12}>
          <Card size="small" hoverable role="button" tabIndex={0} aria-label={t(x.title)}
            onKeyDown={e => {
              if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onPick(t(x.prompt)) }
            }} onClick={() => onPick(t(x.prompt))} style={{ height: '100%' }}>
            <Space align="start">
              <span style={{ color: token.colorPrimary, fontSize: 18 }}>{x.icon}</span>
              <div>
                <Typography.Text strong>{t(x.title)}</Typography.Text>
                <Typography.Paragraph type="secondary" ellipsis={{ rows: 2 }} style={{ margin: 0, fontSize: 12 }}>{t(x.prompt)}</Typography.Paragraph>
              </div>
            </Space>
          </Card>
        </Col>
      ))}
    </Row>
  )
}

// 对话里卡着的审批：组 admin 直接在这里批，不用跳审批中心
function InlineApprovals({ rows, hosts, onDecided }: { rows: Approval[]; hosts: Record<string, string>; onDecided: () => void }) {
  const { t } = useI18n()
  return rows.map(a => (
    <Alert
      key={a.id}
      type="warning"
      showIcon
      className="chat-indent"
      title={t('apInline', { host: hosts[a.asset_id] ?? a.asset_id })}
      description={<pre className="chat-code">{a.cmd}</pre>}
      action={
        <ApprovalActions approval={a} host={hosts[a.asset_id] ?? a.asset_id} onDecided={onDecided} vertical />
      }
    />
  ))
}

// 输入框：欢迎页与会话里共用，Enter 发送、Shift+Enter 换行，输入法组字时不发
function Composer({ value, onChange, onSubmit, disabled, placeholder, inputRef, action }: {
  value: string
  onChange: (v: string) => void
  onSubmit: () => void
  disabled: boolean
  placeholder: string
  inputRef: { current: HTMLTextAreaElement | null }
  action: ReactNode
}) {
  return (
    <div className="chat-composer">
      <Input.TextArea
        aria-label={placeholder}
        ref={r => { inputRef.current = r?.resizableTextArea?.textArea ?? null }}
        value={value}
        disabled={disabled}
        autoSize={{ minRows: 2, maxRows: 8 }}
        placeholder={placeholder}
        onChange={e => onChange(e.target.value)}
        onKeyDown={e => {
          if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
            e.preventDefault()
            onSubmit()
          }
        }}
      />
      {action}
    </div>
  )
}

// AI 助手：平台主入口。左侧会话、右侧对话；会话绑定当前组
export function ChatPage() {
  const { sessionId = '' } = useParams()
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  // 会话列表的筛选跨会话保留，不随 key 重置。
  const [filter, setFilter] = useState<SessionFilter>({ search: '', kind: '' })
  const setPrompt = useCallback((value: SetStateAction<string>) => setDrafts(previous => ({
    ...previous,
    [sessionId]: typeof value === 'function' ? value(previous[sessionId] ?? '') : value,
  })), [sessionId])
  // 每段会话独立持有请求、滚动和错误状态，草稿在切换后仍保留。
  return <ChatWorkspace key={sessionId} prompt={drafts[sessionId] ?? ''} setPrompt={setPrompt} filter={filter} setFilter={setFilter} />
}

type SessionFilter = { search: string; kind: '' | 'chat' | 'task' }

function ChatWorkspace({ prompt, setPrompt, filter, setFilter }: {
  prompt: string
  setPrompt: Dispatch<SetStateAction<string>>
  filter: SessionFilter
  setFilter: Dispatch<SetStateAction<SessionFilter>>
}) {
  const { t } = useI18n()
  const { me, group, setGroupId } = useSession()
  const { sessionId } = useParams()
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const client = useQueryClient()
  const { message } = App.useApp()
  const { token } = theme.useToken()
  const [busy, setBusy] = useState(false)
  const [pending, setPending] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const { search, kind } = filter
  const wide = !!Grid.useBreakpoint().lg
  const [sessionsOpen, setSessionsOpen] = useState(false)
  const log = useRef<HTMLDivElement>(null)
  const follow = useRef(true)
  const [away, setAway] = useState(false)
  const scrollLatest = () => {
    if (log.current) log.current.scrollTop = log.current.scrollHeight
    follow.current = true
    setAway(false)
  }
  const input = useRef<HTMLTextAreaElement>(null)
  const pendingAfter = useRef(0)

  const sessions = useQuery({
    queryKey: ['sessions', group?.id],
    queryFn: () => fetchAgentSessions(group!.id),
    enabled: !!group,
  })
  // 会话按 id 直接取：列表只有最近 100 个，通知与报告里的旧链接靠它才打得开；运行中轮询状态
  const current = useQuery({
    queryKey: ['session', sessionId],
    queryFn: () => fetchAgentSession(sessionId!),
    enabled: !!sessionId,
    // 运行在后台：跑着的时候勤看一眼，任何页面切回来都能看到最新进度
    refetchInterval: q => (q.state.data?.status === 'running' ? 1_500 : false),
  })
  const session = current.data
  useRemember(session?.title ? { to: `/chat/${session.id}`, label: session.title, kind: 'session' } : undefined)
  const isRunning = busy || session?.status === 'running'
  const shown = (sessions.data ?? []).filter(s =>
    (!kind || s.kind === kind) && (!search || (s.title ?? '').toLowerCase().includes(search.toLowerCase())),
  )
  // 置顶存在本地，按用户分开；其余按今天 / 昨天 / 更早分组
  const pinKey = `pinnedSessions:${me.username}`
  const [pinned, setPinned] = useState<string[]>(() => {
    try {
      const value: unknown = JSON.parse(localStorage.getItem(pinKey) ?? '[]')
      return Array.isArray(value) ? value.filter((id): id is string => typeof id === 'string') : []
    } catch { return [] }
  })
  const togglePin = (id: string) => {
    const next = pinned.includes(id) ? pinned.filter(x => x !== id) : [id, ...pinned]
    localStorage.setItem(pinKey, JSON.stringify(next))
    setPinned(next)
  }
  const dayStart = new Date().setHours(0, 0, 0, 0)
  const buckets: { key: MsgKey; items: AgentSession[] }[] = [
    { key: 'sessionsPinned', items: shown.filter(s => pinned.includes(s.id)) },
    { key: 'sessionsToday', items: shown.filter(s => !pinned.includes(s.id) && Date.parse(s.created_at) >= dayStart) },
    { key: 'sessionsYesterday', items: shown.filter(s => !pinned.includes(s.id) && Date.parse(s.created_at) < dayStart && Date.parse(s.created_at) >= dayStart - 86_400_000) },
    { key: 'sessionsEarlier', items: shown.filter(s => !pinned.includes(s.id) && Date.parse(s.created_at) < dayStart - 86_400_000) },
  ]

  // 别的标签页或定时任务正在跑时，本页没有流，靠轮询跟上
  const messages = useQuery({
    queryKey: ['messages', sessionId],
    queryFn: () => fetchSessionMessages(sessionId!).then(ms => ms.map((m): ChatRow => ({ message: m.content, at: m.created_at }))),
    enabled: !!session,
    refetchInterval: session?.status === 'running' ? 1_500 : false,
  })
  const { data: hosts = {} } = useQuery({
    queryKey: ['assets'],
    queryFn: fetchAssets,
    select: as => Object.fromEntries(as.map(a => [a.id, a.hostname])),
  })
  const isGroupAdmin = group?.role === 'admin'
  const approvals = useQuery({
    queryKey: ['approvals', group?.id],
    queryFn: () => fetchApprovals(group!.id),
    enabled: !!group && isGroupAdmin && isRunning,
    refetchInterval: 2_000,
  })
  const inline = approvals.data?.filter(a => a.status === 'pending' && a.session_id === sessionId) ?? []

  // 打开别组的会话链接时跟到它的组；之后用户在顶栏换组，就回到新组的会话列表
  const synced = useRef<string | null>(null)
  useEffect(() => {
    if (!session) return
    if (synced.current !== session.id) {
      synced.current = session.id
      if (session.group_id !== group?.id) setGroupId(session.group_id)
      return
    }
    if (group && group.id !== session.group_id) navigate('/chat')
  }, [session, group, setGroupId, navigate])

  // 会话跑完（含定时任务）列表里的状态标签跟着刷新
  useEffect(() => {
    if (session && session.status !== 'running') {
      client.invalidateQueries({ queryKey: ['sessions', session.group_id] })
      client.invalidateQueries({ queryKey: ['messages', session.id] })
    }
  }, [session?.status, session?.group_id, client, session])

  // 从资产详情"一键排查"或模板进来时带 ?prompt=，填进输入框后从地址栏拿掉；
  // 「交给 AI」还带 send=1，会话就绪后直接发出去，人到了对话页 AI 已经在干活
  const [autoSend, setAutoSend] = useState<string | null>(null)
  useEffect(() => {
    const p = params.get('prompt')
    if (!p || !session) return
    if (params.get('send') === '1') setAutoSend(p)
    else {
      setPrompt(p)
      input.current?.focus()
    }
    setParams({}, { replace: true })
  }, [params, session, setParams, setPrompt])

  // 宽屏进欢迎页（含点「新对话」）光标直接落在输入框；窄屏不弹键盘
  useEffect(() => {
    if (!sessionId && wide) input.current?.focus()
  }, [sessionId, wide])

  useEffect(() => {
    if (follow.current) scrollLatest()
  }, [messages.data, pending, inline.length])

  const canChat = group?.role === 'admin' || group?.role === 'analyst'
  const canSend = !!session && canChat && session.initiator === me.username && session.status === 'idle' && !busy
  // 停止：发起人或组管理员；只是写停止请求，后台几秒内收手
  const canStop = !!session && isRunning && (session.initiator === me.username || group?.role === 'admin')

  // 欢迎页直接提问：发出时才建会话（标题由首句生成），进会话后自动发出，不留空会话
  const startWith = async () => {
    const text = prompt.trim()
    if (!group || !canChat || !text || busy) return
    setBusy(true)
    try {
      const s = await createAgentSession({ groupId: group.id })
      setPrompt('')
      client.invalidateQueries({ queryKey: ['sessions', group.id] })
      navigate(`/chat/${s.id}?${new URLSearchParams({ prompt: text, send: '1' })}`)
    } catch (e) {
      message.error(errText(e, t))
      setBusy(false)
    }
  }

  // 发出去就交给后台：会话切到 running 后由轮询跟进度，离开页面不影响
  const submit = async (override?: string) => {
    const text = (override ?? prompt).trim()
    if (!session || !text || !canSend) return
    follow.current = true
    setBusy(true)
    setError(null)
    pendingAfter.current = messages.data?.length ?? 0
    setPending(text)
    try {
      await startSessionMessage(session.id, text)
      if (override === undefined) setPrompt(value => value.trim() === text ? '' : value)
    } catch (e) {
      setError(errText(e, t))
      setPending(null)
    } finally {
      await client.invalidateQueries({ queryKey: ['session', session.id] })
      client.invalidateQueries({ queryKey: ['sessions', group?.id] })
      setBusy(false)
    }
  }

  const stop = async () => {
    if (!session) return
    try {
      await cancelSession(session.id)
      message.info(t('stopRequested'))
    } catch (e) {
      message.error(errText(e, t))
    }
  }

  // 会话可发言了就把「交给 AI」带来的第一句发出去，只发一次
  useEffect(() => {
    if (!autoSend || !canSend) return
    setAutoSend(null)
    void submit(autoSend)
  }, [autoSend, canSend]) // eslint-disable-line react-hooks/exhaustive-deps

  const history = messages.data ?? []
  // 首条 user 消息入库前先占位，避免发出去的话"消失"一下
  const showPending = pending && !history.slice(pendingAfter.current).some(r => r.message.role === 'user' && textOf(r.message.content) === pending)
  const rows: ChatRow[] = [
    ...history,
    ...(showPending ? [{ message: { role: 'user', content: pending } as PiMessage }] : []),
  ]

  if (!group) {
    return <Empty style={{ marginTop: 120 }} description={t('noGroupsHint')} />
  }

  const sessionList = (
      <Card
        className="chat-sessions"
        title={t('sessions')}
        size="small"
        extra={canChat && <Button type="primary" size="small" icon={<PlusOutlined />} onClick={() => { navigate('/chat'); setSessionsOpen(false) }}>{t('newChat')}</Button>}
        styles={{ body: { padding: 0, overflow: 'auto', flex: 1, display: 'flex', flexDirection: 'column' } }}
      >
        <div className="chat-session-filter">
          <Input.Search size="small" allowClear value={search} placeholder={t('searchSessions')} onChange={e => setFilter(f => ({ ...f, search: e.target.value }))} />
          <Segmented size="small" block value={kind} onChange={v => setFilter(f => ({ ...f, kind: v as SessionFilter['kind'] }))}
            options={[{ value: '', label: t('all') }, { value: 'chat', label: t('chatSession') }, { value: 'task', label: t('taskSession') }]} />
        </div>
        <div style={{ overflow: 'auto', flex: 1 }}>
          {sessions.isError && <Alert type="error" showIcon title={errText(sessions.error, t)} />}
          {sessions.isPending && <Spin style={{ display: 'block', margin: 24 }} />}
          {sessions.data && shown.length === 0 && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noSessions')} />}
          {buckets.filter(b => b.items.length).map(b => (
            <div key={b.key}>
              <div className="chat-session-bucket">{t(b.key)}</div>
              {b.items.map(s => (
                <div key={s.id} className="chat-session-entry" style={s.id === sessionId ? { background: token.controlItemBgActive } : undefined}>
                <button
                  type="button"
                  aria-current={s.id === sessionId ? 'page' : undefined}
                  className="chat-session-item"
                  onClick={() => { navigate(`/chat/${s.id}`); setSessionsOpen(false) }}
                >
                  <Flex align="center" gap={4}>
                    <Typography.Text ellipsis strong style={{ flex: 1 }}>
                      {s.title || t(s.kind === 'task' ? 'taskSession' : 'chatSession')}
                    </Typography.Text>

                  </Flex>
                  <Space size={4} wrap style={{ marginTop: 4 }}>
                    <SessionStatusTag value={s.id === sessionId && isRunning ? 'running' : s.status} />
                    {s.kind === 'task' && <Tag>{t('taskSession')}</Tag>}
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>{fmtTime(s.created_at).slice(b.key === 'sessionsEarlier' || b.key === 'sessionsPinned' ? 5 : 11, 16)}</Typography.Text>
                  </Space>
                </button>
                    <Tooltip title={t(pinned.includes(s.id) ? 'unpin' : 'pin')}>
                      <button type="button" aria-label={t(pinned.includes(s.id) ? 'unpin' : 'pin')}
                        className={pinned.includes(s.id) ? 'session-pin pinned' : 'session-pin'}
                        onClick={() => togglePin(s.id)}>
                        <PushpinOutlined />
                      </button>
                    </Tooltip>
                </div>
              ))}
            </div>
          ))}
        </div>
      </Card>
  )

  return (
    <div className="chat-page">
      {wide ? sessionList : <Drawer title={t('sessions')} open={sessionsOpen} onClose={() => setSessionsOpen(false)} placement="left" size={320} styles={{ body: { padding: 0, display: 'flex' } }}>{sessionList}</Drawer>}

      <Card className="chat-main" size="small" styles={{ body: { display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0, padding: 0 } }}
        // 欢迎页不要空标题栏；窄屏仍保留打开会话列表的按钮
        title={(session || !wide) && (
          <Space style={{ maxWidth: '100%' }}>
            {!wide && <Button type="text" icon={<MenuOutlined />} aria-label={t('sessions')} onClick={() => setSessionsOpen(true)} />}
            {session && <>
            <span>{session.title || t('chatSession')}</span>
            <SessionStatusTag value={isRunning ? 'running' : session.status} />
            </>}
          </Space>
        )}
        extra={wide && session && <Typography.Text type="secondary">{session.initiator} · {session.model}</Typography.Text>}
      >
        {sessionId && current.isError ? (
          <Result status="warning" title={t('sessionGone')} subTitle={errText(current.error, t)} extra={<Button onClick={() => navigate('/chat')}>{t('backToList')}</Button>} />
        ) : sessionId && !session ? <Spin style={{ margin: 'auto' }} /> : !session ? (
          <Flex vertical align="center" gap={20} className="chat-welcome">
            <RobotOutlined style={{ fontSize: 48, color: token.colorPrimary }} />
            <div style={{ textAlign: 'center' }}>
              <Typography.Title level={4} style={{ margin: 0 }}>{t('welcomeTitle')}</Typography.Title>
              <Typography.Text type="secondary">{t('welcomeSubtitle', { name: group.name })}</Typography.Text>
            </div>
            {canChat ? (
              <>
                <div className="welcome-composer">
                  <Composer value={prompt} onChange={setPrompt} onSubmit={startWith} disabled={busy} placeholder={t('chatPlaceholder')} inputRef={input}
                    action={<Button type="primary" icon={<SendOutlined />} loading={busy} disabled={!prompt.trim()} onClick={startWith}>{t('send')}</Button>} />
                  <Typography.Text type="secondary" className="welcome-hint">{t('sessionExecHint')}</Typography.Text>
                </div>
                <Templates onPick={p => { setPrompt(p); input.current?.focus() }} />
              </>
            ) : <Alert type="info" showIcon title={t('chatReadonly')} />}
          </Flex>
        ) : (
          <>
            {!!session.subjects?.length && <SubjectsBar subjects={session.subjects} groupId={session.group_id} />}
            <div className="chat-log" ref={log} onScroll={e => {
              const el = e.currentTarget
              follow.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80
              setAway(!follow.current)
            }}>
              {messages.isPending && <Spin />}
              {messages.isError && <Alert type="error" showIcon title={errText(messages.error, t)} />}
              {messages.isSuccess && rows.length === 0 && canSend && (
                <Flex vertical align="center" gap={16} className="chat-welcome">
                  <Typography.Text type="secondary">{t('templatesHint')}</Typography.Text>
                  <Templates onPick={p => { setPrompt(p); input.current?.focus() }} />
                </Flex>
              )}
              <ChatConversation rows={rows} hosts={hosts} />
              <InlineApprovals rows={inline} hosts={hosts} onDecided={() => approvals.refetch()} />
              {isRunning && !isGroupAdmin && <Alert className="chat-indent" type="info" showIcon title={t('chatNeedsApprover')} />}
              {isRunning && (
                <Space className="chat-indent" style={{ color: token.colorTextSecondary }}><Spin size="small" />{t('thinking')}</Space>
              )}
              {session.error && <Alert className="chat-indent" type="error" showIcon title={session.error} />}
              {error && <Alert className="chat-indent" type="error" showIcon title={error} />}

            </div>
            {away && <Button className="chat-latest" size="small" icon={<ArrowDownOutlined />} onClick={scrollLatest}>{t('backToLatest')}</Button>}
            <div style={{ borderTop: `1px solid ${token.colorBorderSecondary}` }}>
              <Composer value={prompt} onChange={setPrompt} onSubmit={() => submit()} disabled={!canSend} inputRef={input}
                placeholder={canSend ? t('chatPlaceholder') : isRunning ? t('runningInBackground') : t('chatReadonly')}
                action={canStop
                  ? <Button danger icon={<StopOutlined />} onClick={stop}>{t('stop')}</Button>
                  : <Button type="primary" icon={<SendOutlined />} disabled={!canSend || !prompt.trim()} onClick={() => submit()}>{t('send')}</Button>} />
            </div>
          </>
        )}
      </Card>

    </div>
  )
}
