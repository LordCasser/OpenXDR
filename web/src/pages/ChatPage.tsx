import {
  CheckOutlined, CodeOutlined, FileTextOutlined, PlusOutlined, RobotOutlined,
  SendOutlined, StopOutlined, UserOutlined, WarningOutlined,
} from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, App, Avatar, Button, Card, Collapse, Empty, Flex, Form, Input, Modal, Radio, Space, Spin, Tag,
  Typography, theme,
} from 'antd'
import { useEffect, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router'
import {
  createAgentSession, decideApproval, fetchAgentSessions, fetchApprovals, fetchAssets, fetchSessionMessages,
  sendSessionMessage, type AgentSession, type Approval, type ContentPart, type PiMessage,
} from '../api'
import { useSession } from '../app/session'
import { Markdown } from '../components/Markdown'
import { SessionStatusTag, fmtTime } from '../components/format'
import { useI18n } from '../i18n'

const textOf = (content: string | ContentPart[]) =>
  typeof content === 'string' ? content : content.map(p => (p.type === 'text' ? p.text : '')).join('')

// 工具调用卡片：exec 显示主机与命令，report 显示标题、正文可展开，其余原样给参数
function ToolCall({ name, args, hosts }: { name: string; args: Record<string, unknown>; hosts: Record<string, string> }) {
  const { t } = useI18n()
  if (name === 'report') {
    return (
      <Collapse
        size="small"
        className="chat-tool"
        items={[{
          key: 'r',
          label: <Space><FileTextOutlined />{t('toolReport', { title: String(args.title ?? '') })}</Space>,
          children: <Markdown text={String(args.markdown ?? '')} />,
        }]}
      />
    )
  }
  const host = String(args.host ?? '')
  return (
    <Card size="small" className="chat-tool">
      <Space size={6} className="chat-tool-title">
        <CodeOutlined />
        {name === 'exec' ? t('toolExec', { host: hosts[host] ?? host }) : t('toolCall', { name })}
      </Space>
      <pre className="chat-code">{name === 'exec' ? String(args.cmd ?? '') : JSON.stringify(args, null, 2)}</pre>
    </Card>
  )
}

function Bubble({ m, hosts }: { m: PiMessage; hosts: Record<string, string> }) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  if (m.role === 'user') {
    return (
      <Flex justify="flex-end" gap={8} className="chat-row">
        <div className="chat-bubble chat-bubble-user" style={{ background: token.colorPrimaryBg }}>{textOf(m.content)}</div>
        <Avatar icon={<UserOutlined />} />
      </Flex>
    )
  }
  if (m.role === 'toolResult') {
    return (
      <div className="chat-indent">
        <Collapse
          size="small"
          className="chat-tool"
          items={[{
            key: 'r',
            label: (
              <Space>
                {m.isError ? <WarningOutlined style={{ color: token.colorError }} /> : <CheckOutlined style={{ color: token.colorSuccess }} />}
                {t(m.isError ? 'toolFailed' : 'toolResult', { name: m.toolName })}
              </Space>
            ),
            children: <pre className="chat-code">{textOf(m.content)}</pre>,
          }]}
        />
      </div>
    )
  }
  const parts = m.content.filter(p => (p.type === 'text' && p.text) || p.type === 'toolCall')
  return (
    <Flex gap={8} className="chat-row">
      <Avatar icon={<RobotOutlined />} style={{ background: token.colorPrimary, flex: 'none' }} />
      <Flex vertical gap={8} style={{ minWidth: 0, maxWidth: '85%' }}>
        {parts.map((p, i) =>
          p.type === 'text' ? (
            <div key={i} className="chat-bubble" style={{ background: token.colorFillQuaternary }}>
              <Markdown text={p.text} />
            </div>
          ) : p.type === 'toolCall' ? (
            <ToolCall key={i} name={p.name} args={p.arguments ?? {}} hosts={hosts} />
          ) : null,
        )}
        {m.errorMessage && <Alert type="error" showIcon title={m.errorMessage} />}
        {(m.stopReason === 'length' || m.stopReason === 'max_turns') && (
          <Alert type="warning" showIcon title={t('chatTruncated')} />
        )}
      </Flex>
    </Flex>
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
  const navigate = useNavigate()
  const client = useQueryClient()
  const { token } = theme.useToken()
  const [creating, setCreating] = useState(false)
  const [prompt, setPrompt] = useState('')
  const [busy, setBusy] = useState(false)
  const [pending, setPending] = useState<string | null>(null)
  // 流式中的消息：message_update 给的是累积的完整消息，直接替换
  const [live, setLive] = useState<PiMessage | null>(null)
  const [runningTool, setRunningTool] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const abort = useRef<AbortController | null>(null)
  const bottom = useRef<HTMLDivElement>(null)

  const sessions = useQuery({
    queryKey: ['sessions', group?.id],
    queryFn: () => fetchAgentSessions(group!.id),
    enabled: !!group,
  })
  const session = sessions.data?.find(s => s.id === sessionId)
  const isRunning = busy || session?.status === 'running'

  // 别的标签页或定时任务正在跑时，本页没有流，靠轮询跟上
  const messages = useQuery({
    queryKey: ['messages', sessionId],
    queryFn: () => fetchSessionMessages(sessionId!).then(ms => ms.map(m => m.content)),
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

  useEffect(() => {
    bottom.current?.scrollIntoView({ block: 'end' })
  }, [messages.data, live, pending, inline.length])

  // 切会话或离开页面就中止流：后端随之取消推理与审批等待
  useEffect(() => () => abort.current?.abort(), [sessionId])

  const canChat = group?.role === 'admin' || group?.role === 'analyst'
  const canSend = !!session && canChat && session.initiator === me.username && session.status === 'idle' && !busy

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
        if (ev.type === 'tool_execution_start') setRunningTool(ev.toolName ?? '')
        if (ev.type === 'tool_execution_end') setRunningTool(null)
      }, ctl.signal)
    } catch (e) {
      if (!ctl.signal.aborted) setError(String(e))
    } finally {
      // 以库里的完整历史为准，流里拼出来的只是过程
      await client.invalidateQueries({ queryKey: ['messages', session.id] })
      await client.invalidateQueries({ queryKey: ['sessions', group?.id] })
      setLive(null)
      setPending(null)
      setRunningTool(null)
      setBusy(false)
    }
  }

  const history = messages.data ?? []
  // 首条 user 消息入库前先占位，避免发出去的话"消失"一下
  const showPending = pending && !history.some(m => m.role === 'user' && textOf(m.content) === pending)

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
        styles={{ body: { padding: 0, overflow: 'auto', flex: 1 } }}
      >
        {sessions.isPending && <Spin style={{ display: 'block', margin: 24 }} />}
        {sessions.data?.length === 0 && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noSessions')} />}
        {sessions.data?.map(s => (
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
          <Empty style={{ margin: 'auto' }} image={<RobotOutlined style={{ fontSize: 56, color: token.colorPrimary }} />} description={t('pickSession')}>
            {canChat && <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreating(true)}>{t('newChat')}</Button>}
          </Empty>
        ) : (
          <>
            <div className="chat-log">
              {messages.isPending && <Spin />}
              {history.map((m, i) => <Bubble key={i} m={m} hosts={hosts} />)}
              {showPending && <Bubble m={{ role: 'user', content: pending }} hosts={hosts} />}
              {live && <Bubble m={live} hosts={hosts} />}
              <InlineApprovals rows={inline} hosts={hosts} onDecided={() => approvals.refetch()} />
              {runningTool !== null && (
                <Space className="chat-indent" style={{ color: token.colorTextSecondary }}>
                  <Spin size="small" />{t('toolRunning', { name: runningTool })}
                </Space>
              )}
              {busy && runningTool === null && !live && (
                <Space className="chat-indent" style={{ color: token.colorTextSecondary }}><Spin size="small" />{t('thinking')}</Space>
              )}
              {session.error && <Alert className="chat-indent" type="error" showIcon title={session.error} />}
              {error && <Alert className="chat-indent" type="error" showIcon title={error} />}
              <div ref={bottom} />
            </div>
            <div className="chat-composer" style={{ borderTop: `1px solid ${token.colorBorderSecondary}` }}>
              <Input.TextArea
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

