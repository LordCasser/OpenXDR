import {
  AlertOutlined, CloudServerOutlined, GlobalOutlined, LoginOutlined, PlusOutlined, PushpinOutlined, RobotOutlined, SendOutlined, StopOutlined,
} from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, App, Button, Card, Col, Empty, Flex, Form, Input, Modal, Result, Row, Segmented, Space, Spin, Tag, Tooltip, Typography, theme,
} from 'antd'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router'
import {
  createAgentSession, decideApproval, fetchAgentSession, fetchAgentSessions, fetchApprovals, fetchAssets, fetchSessionMessages,
  sendSessionMessage, type AgentSession, type Approval, type PiMessage,
} from '../api'
import { useSession } from '../app/session'
import { ChatConversation, textOf, type ChatRow } from '../components/ChatConversation'
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
  const { modal, message } = App.useApp()
  const decide = (a: Approval, approve: boolean) => {
    const host = hosts[a.asset_id] ?? a.asset_id
    const go = () => decideApproval(a.id, approve).then(onDecided).catch(e => message.error(errText(e, t)))
    if (!approve) return go()
    modal.confirm({
      title: t('apConfirmLiveTitle', { host }),
      content: <pre className="chat-code">{a.cmd}</pre>,
      okButtonProps: { danger: true },
      onOk: go,
    })
  }
  return rows.map(a => (
    <Alert
      key={a.id}
      type="warning"
      showIcon
      className="chat-indent"
      title={t('apInline', { host: hosts[a.asset_id] ?? a.asset_id })}
      description={<pre className="chat-code">{a.cmd}</pre>}
      action={
        <Space orientation="vertical">
          <Button size="small" type="primary" onClick={() => decide(a, true)}>{t('apApprove')}</Button>
          <Button size="small" danger onClick={() => decide(a, false)}>{t('apReject')}</Button>
        </Space>
      }
    />
  ))
}

function NewSessionModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (s: AgentSession) => void }) {
  const { t } = useI18n()
  const { group } = useSession()
  const [form] = Form.useForm<{ title?: string }>()
  const [busy, setBusy] = useState(false)
  const { message } = App.useApp()

  const submit = async (v: { title?: string }) => {
    if (!group) return
    setBusy(true)
    try {
      onCreated(await createAgentSession({ groupId: group.id, title: v.title?.trim() || undefined }))
      form.resetFields()
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal open={open} title={t('newChat')} onCancel={onClose} onOk={() => form.submit()} confirmLoading={busy} okText={t('create')} destroyOnHidden>
      <Form form={form} layout="vertical" onFinish={submit}>
        <Form.Item label={t('group')}>
          <Typography.Text strong>{group?.name}</Typography.Text>
        </Form.Item>
        <Form.Item name="title" label={t('sessionTitle')} extra={t('sessionTitleHint')}>
          <Input maxLength={80} />
        </Form.Item>
        <Alert type="info" showIcon title={t('sessionExecHint')} />
      </Form>
    </Modal>
  )
}

// AI 助手：平台主入口。左侧会话、右侧对话；会话绑定当前组
export function ChatPage() {
  const { t } = useI18n()
  const { me, group, setGroupId } = useSession()
  const { sessionId } = useParams()
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const client = useQueryClient()
  const { message } = App.useApp()
  const { token } = theme.useToken()
  const [creating, setCreating] = useState(false)
  const [prompt, setPrompt] = useState('')
  const [busy, setBusy] = useState(false)
  const [pending, setPending] = useState<string | null>(null)
  // 流式中的消息：message_update 给的是累积的完整消息，直接替换
  const [live, setLive] = useState<PiMessage | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [kind, setKind] = useState<'' | 'chat' | 'task'>('')
  const abort = useRef<AbortController | null>(null)
  const bottom = useRef<HTMLDivElement>(null)
  const input = useRef<HTMLTextAreaElement>(null)

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
    refetchInterval: q => (q.state.data?.status === 'running' && !busy ? 3_000 : false),
  })
  const session = current.data
  const isRunning = busy || session?.status === 'running'
  const shown = (sessions.data ?? []).filter(s =>
    (!kind || s.kind === kind) && (!search || (s.title ?? '').toLowerCase().includes(search.toLowerCase())),
  )
  // 置顶存在本地，按用户分开；其余按今天 / 昨天 / 更早分组
  const pinKey = `pinnedSessions:${me.username}`
  const [pinned, setPinned] = useState<string[]>(() => JSON.parse(localStorage.getItem(pinKey) ?? '[]'))
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
    refetchInterval: session?.status === 'running' && !busy ? 3_000 : false,
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
    if (session && session.status !== 'running') client.invalidateQueries({ queryKey: ['sessions', session.group_id] })
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
  }, [params, session, setParams])

  useEffect(() => {
    bottom.current?.scrollIntoView({ block: 'end' })
  }, [messages.data, live, pending, inline.length])

  // 切会话或离开页面就中止流：后端随之取消推理与审批等待
  useEffect(() => () => abort.current?.abort(), [sessionId])

  const canChat = group?.role === 'admin' || group?.role === 'analyst'
  const canSend = !!session && canChat && session.initiator === me.username && session.status === 'idle' && !busy

  // 没选会话时点模板：直接新建一个会话，把模板填进去
  const startWith = async (text: string) => {
    if (!group || !canChat) return
    try {
      const s = await createAgentSession({ groupId: group.id })
      client.invalidateQueries({ queryKey: ['sessions', group.id] })
      navigate(`/chat/${s.id}?prompt=${encodeURIComponent(text)}`)
    } catch (e) {
      message.error(errText(e, t))
    }
  }

  const submit = async (override?: string) => {
    const text = (override ?? prompt).trim()
    if (!session || !text) return
    if (override === undefined) setPrompt('')
    setBusy(true)
    setError(null)
    setPending(text)
    const ctl = new AbortController()
    abort.current = ctl
    try {
      await sendSessionMessage(session.id, text, e => {
        if (e.event === 'error') setError(e.data.error)
        if (e.event !== 'pi' || e.data.type !== 'event' || !e.data.event) return
        const ev = e.data.event
        if (ev.type === 'message_update' && ev.message) setLive(ev.message)
        if (ev.type === 'message_end') {
          setLive(null)
          client.invalidateQueries({ queryKey: ['messages', session.id] })
        }
      }, ctl.signal)
    } catch (e) {
      if (!ctl.signal.aborted) setError(errText(e, t))
    } finally {
      // 以库里的完整历史为准，流里拼出来的只是过程
      await client.invalidateQueries({ queryKey: ['messages', session.id] })
      await client.invalidateQueries({ queryKey: ['session', session.id] })
      await client.invalidateQueries({ queryKey: ['sessions', group?.id] })
      setLive(null)
      setPending(null)
      setBusy(false)
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
  const showPending = pending && !history.some(r => r.message.role === 'user' && textOf(r.message.content) === pending)
  const rows: ChatRow[] = [
    ...history,
    ...(showPending ? [{ message: { role: 'user', content: pending } as PiMessage }] : []),
    ...(live ? [{ message: live }] : []),
  ]
  const lastIsAssistant = rows.at(-1)?.message.role === 'assistant'

  if (!group) {
    return <Empty style={{ marginTop: 120 }} description={t('noGroupsHint')} />
  }

  return (
    <div className="chat-page">
      <Card
        className="chat-sessions"
        title={t('sessions')}
        size="small"
        extra={canChat && <Button type="primary" size="small" icon={<PlusOutlined />} onClick={() => setCreating(true)}>{t('newChat')}</Button>}
        styles={{ body: { padding: 0, overflow: 'auto', flex: 1, display: 'flex', flexDirection: 'column' } }}
      >
        <div className="chat-session-filter">
          <Input.Search size="small" allowClear placeholder={t('searchSessions')} onChange={e => setSearch(e.target.value)} />
          <Segmented size="small" block value={kind} onChange={v => setKind(v as '' | 'chat' | 'task')}
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
                <button
                  type="button"
                  aria-current={s.id === sessionId ? 'page' : undefined}
                  key={s.id}
                  className="chat-session-item"
                  style={s.id === sessionId ? { background: token.controlItemBgActive } : undefined}
                  onClick={() => navigate(`/chat/${s.id}`)}
                >
                  <Flex align="center" gap={4}>
                    <Typography.Text ellipsis strong style={{ flex: 1 }}>
                      {s.title || t(s.kind === 'task' ? 'taskSession' : 'chatSession')}
                    </Typography.Text>
                    <Tooltip title={t(pinned.includes(s.id) ? 'unpin' : 'pin')}>
                      <span role="button" tabIndex={0} aria-label={t(pinned.includes(s.id) ? 'unpin' : 'pin')}
                        className={pinned.includes(s.id) ? 'session-pin pinned' : 'session-pin'}
                        onClick={e => { e.stopPropagation(); togglePin(s.id) }}
                        onKeyDown={e => { if (e.key === 'Enter') { e.stopPropagation(); togglePin(s.id) } }}>
                        <PushpinOutlined />
                      </span>
                    </Tooltip>
                  </Flex>
                  <Space size={4} wrap style={{ marginTop: 4 }}>
                    <SessionStatusTag value={s.id === sessionId && isRunning ? 'running' : s.status} />
                    {s.kind === 'task' && <Tag>{t('taskSession')}</Tag>}
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>{fmtTime(s.created_at).slice(b.key === 'sessionsEarlier' || b.key === 'sessionsPinned' ? 5 : 11, 16)}</Typography.Text>
                  </Space>
                </button>
              ))}
            </div>
          ))}
        </div>
      </Card>

      <Card className="chat-main" size="small" styles={{ body: { display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0, padding: 0 } }}
        title={session && (
          <Space>
            <span>{session.title || t('chatSession')}</span>
            <SessionStatusTag value={isRunning ? 'running' : session.status} />
          </Space>
        )}
        extra={session && <Typography.Text type="secondary">{session.initiator} · {session.model}</Typography.Text>}
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
            {canChat ? <Templates onPick={startWith} /> : <Alert type="info" showIcon title={t('chatReadonly')} />}
          </Flex>
        ) : (
          <>
            {!!session.subjects?.length && <SubjectsBar subjects={session.subjects} groupId={session.group_id} />}
            <div className="chat-log">
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
              {busy && !lastIsAssistant && (
                <Space className="chat-indent" style={{ color: token.colorTextSecondary }}><Spin size="small" />{t('thinking')}</Space>
              )}
              {session.error && <Alert className="chat-indent" type="error" showIcon title={session.error} />}
              {error && <Alert className="chat-indent" type="error" showIcon title={error} />}
              <div ref={bottom} />
            </div>
            <div className="chat-composer" style={{ borderTop: `1px solid ${token.colorBorderSecondary}` }}>
              <Input.TextArea
                aria-label={t('chatPlaceholder')}
                ref={r => { input.current = r?.resizableTextArea?.textArea ?? null }}
                value={prompt}
                disabled={!canSend}
                autoSize={{ minRows: 2, maxRows: 8 }}
                placeholder={canSend ? t('chatPlaceholder') : busy ? t('thinking') : t('chatReadonly')}
                onChange={e => setPrompt(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
                    e.preventDefault()
                    submit()
                  }
                }}
              />
              {busy ? (
                <Button danger icon={<StopOutlined />} onClick={() => abort.current?.abort()}>{t('stop')}</Button>
              ) : (
                <Button type="primary" icon={<SendOutlined />} disabled={!canSend || !prompt.trim()} onClick={() => submit()}>{t('send')}</Button>
              )}
            </div>
          </>
        )}
      </Card>

      <NewSessionModal
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={s => {
          setCreating(false)
          client.invalidateQueries({ queryKey: ['sessions', group.id] })
          navigate(`/chat/${s.id}`)
        }}
      />
    </div>
  )
}
