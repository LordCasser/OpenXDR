import { useCallback, useEffect, useRef, useState } from 'react'
import { ApprovalsView } from './ApprovalsView'
import { ReportsView } from './ReportsView'
import { TasksView } from './TasksView'
import {
  createAgentSession, fetchAgentSessions, fetchApprovals, fetchGroups, fetchSessionMessages, sendSessionMessage,
  type AgentSession, type ContentPart, type GroupRow, type Me, type PiMessage,
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

// 一条 Pi 消息：正文按纯文本显示，工具调用与结果渲染成卡片
function Message({ m }: { m: PiMessage }) {
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
          <div key={i} className="msg msg-assistant">{p.text}</div>
        ) : p.type === 'toolCall' ? (
          <div key={i} className="tool-card">
            <div className="tool-name">{t('toolCall', { name: p.name })}</div>
            <pre>{JSON.stringify(p.arguments, null, 2)}</pre>
          </div>
        ) : null,
      )}
      {m.errorMessage && <div className="error">{m.errorMessage}</div>}
      {(m.stopReason === 'length' || m.stopReason === 'max_turns') && (
        <div className="error">{t('chatTruncated')}</div>
      )}
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

  useEffect(() => {
    fetchGroups().then(g => {
      setGroups(g)
      setGroupId(id => id ?? g[0]?.id ?? null)
    }).catch(e => setError(String(e)))
  }, [])

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
            <div className="incident-title">{s.title ?? (s.kind === 'task' ? t('taskSession') : t('chatSession'))}</div>
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
              {messages.map((m, i) => <Message key={i} m={m} />)}
              {live && <Message m={live} />}
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
