import {
  AlertOutlined, CloudServerOutlined, GlobalOutlined, LoginOutlined, PlusOutlined, RobotOutlined, SendOutlined, StopOutlined,
} from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, App, Button, Card, Col, Empty, Flex, Form, Input, Modal, Radio, Row, Segmented, Space, Spin, Tag, Typography, theme,
} from 'antd'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router'
import {
  createAgentSession, decideApproval, fetchAgentSessions, fetchApprovals, fetchAssets, fetchSessionMessages,
  sendSessionMessage, type AgentSession, type Approval, type PiMessage,
} from '../api'
import { useSession } from '../app/session'
import { ChatConversation, textOf, type ChatRow } from '../components/ChatConversation'
import { SessionStatusTag, fmtTime } from '../components/format'
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
          <Card size="small" hoverable onClick={() => onPick(t(x.prompt))} style={{ height: '100%' }}>
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
    const go = () => decideApproval(a.id, approve).then(onDecided).catch(e => message.error(String(e)))
    if (!approve) return go()
    modal.confirm({
      title: t(a.dry_run ? 'apConfirmDryTitle' : 'apConfirmLiveTitle', { host }),
      content: <pre className="chat-code">{a.cmd}</pre>,
      okButtonProps: { danger: !a.dry_run },
      onOk: go,
    })
  }
  return rows.map(a => (
    <Alert
      key={a.id}
      type="warning"
      showIcon
      className="chat-indent"
      title={<Space>{t('apInline', { host: hosts[a.asset_id] ?? a.asset_id })}<Tag color={a.dry_run ? 'default' : 'red'}>{t(a.dry_run ? 'dryRun' : 'liveRun')}</Tag></Space>}
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
  const [form] = Form.useForm<{ title?: string; mode: 'dry' | 'live' }>()
  const mode = Form.useWatch('mode', form)
  const [busy, setBusy] = useState(false)
  const { message } = App.useApp()

  const submit = async (v: { title?: string; mode: 'dry' | 'live' }) => {
    if (!group) return
    setBusy(true)
    try {
      onCreated(await createAgentSession({ groupId: group.id, title: v.title?.trim() || undefined, dryRun: v.mode !== 'live' }))
      form.resetFields()
    } catch (e) {
      message.error(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal open={open} title={t('newChat')} onCancel={onClose} onOk={() => form.submit()} confirmLoading={busy} okText={t('create')} destroyOnHidden>
      <Form form={form} layout="vertical" initialValues={{ mode: 'dry' }} onFinish={submit}>
        <Form.Item label={t('group')}>
          <Typography.Text strong>{group?.name}</Typography.Text>
        </Form.Item>
        <Form.Item name="title" label={t('sessionTitle')} extra={t('sessionTitleHint')}>
          <Input maxLength={80} />
        </Form.Item>
        <Form.Item name="mode" label={t('execMode')}>
          <Radio.Group
            options={[
              { value: 'dry', label: t('dryRun') },
              { value: 'live', label: t('liveRun') },
            ]}
            optionType="button"
          />
        </Form.Item>
        <Alert type={mode === 'live' ? 'warning' : 'info'} showIcon title={t(mode === 'live' ? 'liveRunHint' : 'dryRunHint')} />
      </Form>
    </Modal>
  )
}

// AI 助手：平台主入口。左侧会话、右侧对话；会话绑定当前组
export function ChatPage() {
  const { t } = useI18n()
  const { me, group, groups, setGroupId } = useSession()
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
  const session = sessions.data?.find(s => s.id === sessionId)
  const isRunning = busy || session?.status === 'running'
  const shown = (sessions.data ?? []).filter(s =>
    (!kind || s.kind === kind) && (!search || (s.title ?? '').toLowerCase().includes(search.toLowerCase())),
  )

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

  // 通知链接里的会话可能在别的组：逐组找，找到就切过去
  useEffect(() => {
    if (!sessionId || !sessions.data || session) return
    let stale = false
    ;(async () => {
      for (const g of groups) {
        if (g.id === group?.id) continue
        const list = await fetchAgentSessions(g.id).catch(() => [])
        if (stale) return
        if (list.some(s => s.id === sessionId)) return setGroupId(g.id)
      }
    })()
    return () => { stale = true }
  }, [sessionId, sessions.data, session, groups, group, setGroupId])

  // 从资产详情"一键排查"或模板进来时带 ?prompt=，填进输入框后从地址栏拿掉
  useEffect(() => {
    const p = params.get('prompt')
    if (!p || !session) return
    setPrompt(p)
    setParams({}, { replace: true })
    input.current?.focus()
  }, [params, session, setParams])

  useEffect(() => {
    bottom.current?.scrollIntoView({ block: 'end' })
  }, [messages.data, live, pending, inline.length])

  // 切会话或离开页面就中止流：后端随之取消推理与审批等待
  useEffect(() => () => abort.current?.abort(), [sessionId])

  const canChat = group?.role === 'admin' || group?.role === 'analyst'
  const canSend = !!session && canChat && session.initiator === me.username && session.status === 'idle' && !busy

  // 没选会话时点模板：直接新建一个演练会话，把模板填进去
  const startWith = async (text: string) => {
    if (!group || !canChat) return
    try {
      const s = await createAgentSession({ groupId: group.id, dryRun: true })
      client.invalidateQueries({ queryKey: ['sessions', group.id] })
      navigate(`/chat/${s.id}?prompt=${encodeURIComponent(text)}`)
    } catch (e) {
      message.error(String(e))
    }
  }

  const submit = async () => {
    const text = prompt.trim()
    if (!session || !text) return
    setPrompt('')
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
      if (!ctl.signal.aborted) setError(String(e))
    } finally {
      // 以库里的完整历史为准，流里拼出来的只是过程
      await client.invalidateQueries({ queryKey: ['messages', session.id] })
      await client.invalidateQueries({ queryKey: ['sessions', group?.id] })
      setLive(null)
      setPending(null)
      setBusy(false)
    }
  }

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
          {sessions.isPending && <Spin style={{ display: 'block', margin: 24 }} />}
          {sessions.data && shown.length === 0 && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noSessions')} />}
          {shown.map(s => (
            <div
              key={s.id}
              className="chat-session-item"
              style={s.id === sessionId ? { background: token.controlItemBgActive } : undefined}
              onClick={() => navigate(`/chat/${s.id}`)}
            >
              <Typography.Text ellipsis strong style={{ display: 'block' }}>
                {s.title || t(s.kind === 'task' ? 'taskSession' : 'chatSession')}
              </Typography.Text>
              <Space size={4} wrap style={{ marginTop: 4 }}>
                <SessionStatusTag value={s.status} />
                {s.kind === 'task' && <Tag>{t('taskSession')}</Tag>}
                {s.dry_run === false && <Tag color="red">{t('liveRun')}</Tag>}
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>{fmtTime(s.created_at)}</Typography.Text>
              </Space>
            </div>
          ))}
        </div>
      </Card>

      <Card className="chat-main" size="small" styles={{ body: { display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0, padding: 0 } }}
        title={session && (
          <Space>
            <span>{session.title || t('chatSession')}</span>
            <SessionStatusTag value={session.status} />
            <Tag color={session.dry_run === false ? 'red' : 'default'}>{t(session.dry_run === false ? 'liveRun' : 'dryRun')}</Tag>
          </Space>
        )}
        extra={session && <Typography.Text type="secondary">{session.initiator} · {session.model}</Typography.Text>}
      >
        {!session ? (
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
            <div className="chat-log">
              {messages.isPending && <Spin />}
              {!messages.isPending && rows.length === 0 && canSend && (
                <Flex vertical align="center" gap={16} className="chat-welcome">
                  <Typography.Text type="secondary">{t('templatesHint')}</Typography.Text>
                  <Templates onPick={p => { setPrompt(p); input.current?.focus() }} />
                </Flex>
              )}
              <ChatConversation rows={rows} hosts={hosts} />
              <InlineApprovals rows={inline} hosts={hosts} onDecided={() => approvals.refetch()} />
              {busy && !lastIsAssistant && (
                <Space className="chat-indent" style={{ color: token.colorTextSecondary }}><Spin size="small" />{t('thinking')}</Space>
              )}
              {session.error && <Alert className="chat-indent" type="error" showIcon title={session.error} />}
              {error && <Alert className="chat-indent" type="error" showIcon title={error} />}
              <div ref={bottom} />
            </div>
            <div className="chat-composer" style={{ borderTop: `1px solid ${token.colorBorderSecondary}` }}>
              <Input.TextArea
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
                <Button type="primary" icon={<SendOutlined />} disabled={!canSend || !prompt.trim()} onClick={submit}>{t('send')}</Button>
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
