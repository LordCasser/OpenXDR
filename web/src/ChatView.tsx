import { useCallback, useEffect, useRef, useState } from 'react'
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { ApprovalsView } from './ApprovalsView'
import { ReportsView } from './ReportsView'
import { TasksView } from './TasksView'
import {
  createAgentSession, decideApproval, fetchAgentSessions, fetchApprovals, fetchAssets, fetchGroups,
  fetchSessionMessages, sendSessionMessage,
  type AgentSession, type Approval, type ContentPart, type GroupRow, type Me, type PiMessage,
} from './api'
import { useI18n, type MsgKey } from './i18n'

const fmt = (iso: string) => new Date(iso).toLocaleString()

const STATUS_KEY: Record<string, MsgKey> = {
  running: 'sessionRunning',
  idle: 'sessionIdle',
  succeeded: 'sessionSucceeded',
  failed: 'sessionFailed',
}

const textOf = (content: string | ContentPart[]) =>
  typeof content === 'string'
    ? content
    : content.map(p => (p.type === 'text' ? p.text : '')).join('')

// 模型输出不可信：react-markdown 默认不渲染原始 HTML，并过滤 javascript: 等链接
const Md = ({ text }: { text: string }) => (
  <div className="markdown"><Markdown remarkPlugins={[remarkGfm]}>{text}</Markdown></div>
)

// 工具调用卡片：exec 显示主机名与命令，report 显示标题、正文可展开，其余原样给参数
function ToolCall({ name, args, hosts }: { name: string; args: Record<string, unknown>; hosts: Record<string, string> }) {
  const { t } = useI18n()
  if (name === 'exec') {
    const host = String(args.host ?? '')
    return (
      <div className="tool-card">
        <div className="tool-name">{t('toolExec', { host: hosts[host] ?? host })}</div>
        <pre>{String(args.cmd ?? '')}</pre>
      </div>
    )
  }
  if (name === 'report') {
    return (
      <details className="tool-card">
        <summary>{t('toolReport', { title: String(args.title ?? '') })}</summary>
        <Md text={String(args.markdown ?? '')} />
      </details>
    )
  }
  return (
    <div className="tool-card">
      <div className="tool-name">{t('toolCall', { name })}</div>
      <pre>{JSON.stringify(args, null, 2)}</pre>
    </div>
  )
}

// 一条 Pi 消息：正文按 Markdown 渲染，工具调用与结果渲染成卡片
function Message({ m, hosts }: { m: PiMessage; hosts: Record<string, string> }) {
  const { t } = useI18n()
  if (m.role === 'user') return <div className="msg msg-user">{textOf(m.content)}</div>
  if (m.role === 'toolResult') {
    return (
      <details className={`tool-card ${m.isError ? 'tool-error' : ''}`}>
        <summary>{t(m.isError ? 'toolFailed' : 'toolResult', { name: m.toolName })}</summary>
        <pre>{textOf(m.content)}</pre>
      </details>
    )
  }
  return (
    <>
      {m.content.map((p, i) =>
        p.type === 'text' && p.text ? (
          <div key={i} className="msg msg-assistant"><Md text={p.text} /></div>
        ) : p.type === 'toolCall' ? (
          <ToolCall key={i} name={p.name} args={p.arguments ?? {}} hosts={hosts} />
        ) : null,
      )}
      {m.errorMessage && <div className="error">{m.errorMessage}</div>}
      {(m.stopReason === 'length' || m.stopReason === 'max_turns') && (
        <div className="error">{t('chatTruncated')}</div>
      )}
    </>
  )
}

// 对话里卡着的审批：组 admin 直接在这里批，不用另开审批页
function InlineApprovals({ groupId, sessionId, hosts }: { groupId: string; sessionId: string; hosts: Record<string, string> }) {
  const { t } = useI18n()
  const [rows, setRows] = useState<Approval[]>([])
  const [error, setError] = useState<string | null>(null)

  const poll = useCallback(() => {
    fetchApprovals(groupId)
      .then(a => setRows(a.filter(x => x.status === 'pending' && x.session_id === sessionId)))
      .catch(() => {})
  }, [groupId, sessionId])

  useEffect(() => {
    poll()
    const timer = setInterval(poll, 2_000)
    return () => clearInterval(timer)
  }, [poll])

  const decide = async (a: Approval, approve: boolean) => {
    const host = hosts[a.asset_id] ?? a.asset_id
    if (approve && !confirm(t(a.dry_run ? 'apConfirmDry' : 'apConfirmLive', { cmd: a.cmd, host }))) return
    setError(null)
    try {
      await decideApproval(a.id, approve)
    } catch (e) {
      setError(String(e))
    }
    poll()
  }

  return (
    <>
      {rows.map(a => (
        <div key={a.id} className="tool-card tool-approval">
          <div className="tool-name">
            {t('apInline', { host: hosts[a.asset_id] ?? a.asset_id })}
            {' · '}{t(a.dry_run ? 'apDryRun' : 'liveRun')}
          </div>
          <pre>{a.cmd}</pre>
          <div className="actions">
            <button onClick={() => decide(a, true)}>{t('apApprove')}</button>
            <button onClick={() => decide(a, false)}>{t('apReject')}</button>
          </div>
        </div>
      ))}
      {error && <div className="error">{error}</div>}
    </>
  )
}

// Agent 对话页：主入口。左侧选组与会话，右侧对话；专家模式是原有的事件视图
export function ChatView({ me, initialSession, onExpert, onLogout }: {
  me: Me
  initialSession: string | null
  onExpert: () => void
  onLogout: () => void
}) {
  const { t, locale, setLocale } = useI18n()
  const [groups, setGroups] = useState<GroupRow[]>([])
  const [groupId, setGroupId] = useState<string | null>(null)
  const [sessions, setSessions] = useState<AgentSession[]>([])
  const [sessionId, setSessionId] = useState<string | null>(initialSession)
  const [messages, setMessages] = useState<PiMessage[]>([])
  // 流式中的消息：message_update 给的是累积的完整消息，直接替换
  const [live, setLive] = useState<PiMessage | null>(null)
  const [runningTool, setRunningTool] = useState<string | null>(null)
  const [prompt, setPrompt] = useState('')
  const [busy, setBusy] = useState(false)
  const [liveRun, setLiveRun] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [modal, setModal] = useState<'approvals' | 'reports' | 'tasks' | null>(null)
  const [pendingCount, setPendingCount] = useState(0)
  const abort = useRef<AbortController | null>(null)
  // 流结束时用户可能已切到别的会话，别把旧会话的历史刷进当前视图
  const current = useRef(sessionId)
  const bottom = useRef<HTMLDivElement>(null)

  const [hosts, setHosts] = useState<Record<string, string>>({})

  useEffect(() => {
    fetchAssets().then(as => setHosts(Object.fromEntries(as.map(a => [a.id, a.hostname])))).catch(() => {})
    fetchGroups().then(async g => {
      setGroups(g)
      // 通知链接带 ?session=，会话可能不在第一个组里：逐组找到它所在的组
      let gid = g[0]?.id ?? null
      if (initialSession) {
        for (const x of g) {
          const list = await fetchAgentSessions(x.id).catch(() => [])
          if (list.some(s => s.id === initialSession)) { gid = x.id; break }
        }
      }
      setGroupId(gid)
    }).catch(e => setError(String(e)))
  }, [initialSession])

  const loadSessions = useCallback(async () => {
    if (!groupId) return
    try {
      setSessions(await fetchAgentSessions(groupId))
    } catch (e) {
      setError(String(e))
    }
  }, [groupId])

  useEffect(() => {
    loadSessions()
  }, [loadSessions])

  const loadMessages = useCallback(async (id: string) => {
    try {
      setMessages((await fetchSessionMessages(id)).map(m => m.content))
    } catch (e) {
      setError(String(e))
    }
  }, [])

  useEffect(() => {
    current.current = sessionId
    setLive(null)
    setMessages([])
    if (sessionId) loadMessages(sessionId)
  }, [sessionId, loadMessages])

  useEffect(() => {
    bottom.current?.scrollIntoView({ block: 'end' })
  }, [messages, live])

  // 切走或卸载时中止流：后端会随之取消推理与审批等待
  useEffect(() => () => abort.current?.abort(), [sessionId])

  const group = groups.find(g => g.id === groupId)
  const session = sessions.find(s => s.id === sessionId)
  const isGroupAdmin = group?.role === 'admin'

  // 组 admin 才能审批；待审批数挂在入口上，Pi 正阻塞等着人
  useEffect(() => {
    setPendingCount(0)
    if (!groupId || !isGroupAdmin) return
    const poll = () => fetchApprovals(groupId)
      .then(a => setPendingCount(a.filter(x => x.status === 'pending').length))
      .catch(() => {})
    poll()
    const timer = setInterval(poll, 10_000)
    return () => clearInterval(timer)
  }, [groupId, isGroupAdmin])

  const openSession = (gid: string, sid: string) => {
    setModal(null)
    setGroupId(gid)
    setSessionId(sid)
  }
  const canChat = group?.role === 'admin' || group?.role === 'analyst'
  const canSend = !!session && canChat && session.initiator === me.username &&
    session.status === 'idle' && !busy

  const newSession = async () => {
    if (!groupId) return
    setError(null)
    try {
      const s = await createAgentSession({ groupId, dryRun: !liveRun })
      await loadSessions()
      setSessionId(s.id)
    } catch (e) {
      setError(String(e))
    }
  }

  const submit = async () => {
    if (!session || !prompt.trim()) return
    const text = prompt.trim()
    setPrompt('')
    setBusy(true)
    setError(null)
    setMessages(ms => [...ms, { role: 'user', content: text }])
    const ctl = new AbortController()
    abort.current = ctl
    try {
      await sendSessionMessage(session.id, text, e => {
        if (e.event === 'error') setError(e.data.error)
        if (e.event !== 'pi' || e.data.type !== 'event' || !e.data.event) return
        const ev = e.data.event
        if (ev.type === 'message_update' && ev.message) setLive(ev.message)
        if (ev.type === 'tool_execution_start') setRunningTool(ev.toolName ?? '')
        if (ev.type === 'tool_execution_end') setRunningTool(null)
      }, ctl.signal)
    } catch (e) {
      if (!ctl.signal.aborted) setError(String(e))
    } finally {
      // 以库里的完整历史为准，流里拼出来的只是过程
      setLive(null)
      setRunningTool(null)
      setBusy(false)
      if (current.current === session.id) await loadMessages(session.id)
      await loadSessions()
    }
  }

  return (
    <div className="layout">
      <aside className="sidebar">
        <header>
          <h1>OpenXDR</h1>
          <div className="header-actions">
            <button className="link" onClick={() => setLocale(locale === 'zh' ? 'en' : 'zh')}>
              {locale === 'zh' ? 'EN' : '中文'}
            </button>
            <span className="muted">{me.username}</span>
            <button className="link" onClick={onLogout}>{t('logout')}</button>
          </div>
        </header>
        <div className="header-actions subnav">
          <button className="link" onClick={onExpert}>{t('expertMode')}</button>
          {isGroupAdmin && (
            <button className="link" onClick={() => setModal('approvals')}>
              {t('approvals')}{pendingCount > 0 && <span className="badge-count">{pendingCount}</span>}
            </button>
          )}
          {group && <button className="link" onClick={() => setModal('reports')}>{t('reports')}</button>}
          <button className="link" onClick={() => setModal('tasks')}>{t('tasks')}</button>
        </div>
        <div className="field chat-controls">
          <select value={groupId ?? ''} onChange={e => { setGroupId(e.target.value); setSessionId(null) }}>
            {groups.length === 0 && <option value="">{t('noGroups')}</option>}
            {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
          {canChat && (
            <>
              <label className="muted" title={t('liveRunHint')}>
                <input type="checkbox" checked={liveRun} onChange={e => setLiveRun(e.target.checked)} />
                {t('liveRun')}
              </label>
              <button onClick={newSession}>{t('newChat')}</button>
            </>
          )}
        </div>
        {sessions.map(s => (
          <button
            key={s.id}
            className={`incident-item ${s.id === sessionId ? 'selected' : ''}`}
            onClick={() => setSessionId(s.id)}
          >
            <div className="incident-title">{s.title || (s.kind === 'task' ? t('taskSession') : t('chatSession'))}</div>
            <div className="incident-meta">
              <span className={`status status-session-${s.status}`}>{STATUS_KEY[s.status] ? t(STATUS_KEY[s.status]) : s.status}</span>
              {s.dry_run === false && <span className="status status-open">{t('liveRun')}</span>}
              <span className="muted">{s.initiator} · {fmt(s.created_at)}</span>
            </div>
          </button>
        ))}
        {groupId && sessions.length === 0 && <div className="muted empty">{t('noSessions')}</div>}
      </aside>

      <main className="main chat-main">
        {!session ? (
          <div className="muted empty">{groups.length === 0 ? t('noGroupsHint') : t('pickSession')}</div>
        ) : (
          <>
            <div className="chat-log">
              {messages.map((m, i) => <Message key={i} m={m} hosts={hosts} />)}
              {live && <Message m={live} hosts={hosts} />}
              {isGroupAdmin && (busy || session.status === 'running') && (
                <InlineApprovals groupId={session.group_id} sessionId={session.id} hosts={hosts} />
              )}
              {runningTool !== null && (
                <div className="muted">{t('toolRunning', { name: runningTool })}</div>
              )}
              {session.error && <div className="error">{session.error}</div>}
              <div ref={bottom} />
            </div>
            {error && <div className="error">{error}</div>}
            <div className="chat-input">
              <textarea
                value={prompt}
                disabled={!canSend}
                placeholder={canSend ? t('chatPlaceholder') : t('chatReadonly')}
                onChange={e => setPrompt(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
                    e.preventDefault()
                    submit()
                  }
                }}
              />
              {busy ? (
                <button onClick={() => abort.current?.abort()}>{t('stop')}</button>
              ) : (
                <button disabled={!canSend || !prompt.trim()} onClick={submit}>{t('send')}</button>
              )}
            </div>
          </>
        )}
      </main>

      {modal === 'approvals' && group && (
        <ApprovalsView
          groupId={group.id}
          groupName={group.name}
          onOpenSession={id => openSession(group.id, id)}
          onClose={() => setModal(null)}
        />
      )}
      {modal === 'reports' && group && (
        <ReportsView
          groupId={group.id}
          groupName={group.name}
          onOpenSession={id => openSession(group.id, id)}
          onClose={() => setModal(null)}
        />
      )}
      {modal === 'tasks' && (
        <TasksView isAdmin={me.role === 'admin'} groups={groups} onOpenSession={openSession} onClose={() => setModal(null)} />
      )}
    </div>
  )
}
