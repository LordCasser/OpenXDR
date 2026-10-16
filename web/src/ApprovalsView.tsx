import { useCallback, useEffect, useState } from 'react'
import {
  createPolicy, decideApproval, deletePolicy, fetchApprovals, fetchAssets, fetchPolicies,
  type Approval, type CommandPolicy,
} from './api'
import { useI18n, type MsgKey } from './i18n'

const fmt = (iso: string) => new Date(iso).toLocaleString()

const STATUS_KEY: Record<Approval['status'], MsgKey> = {
  pending: 'apPending',
  approved: 'apApproved',
  rejected: 'apRejected',
  expired: 'apExpired',
  cancelled: 'apCancelled',
  consumed: 'apConsumed',
}

// 名单：AI 走白名单（命中才免审批），人工走黑名单（命中才要审批）
function PolicyList({ groupId, origin, rows, onChange }: {
  groupId: string
  origin: 'ai' | 'human'
  rows: CommandPolicy[]
  onChange: (fn: () => Promise<unknown>) => void
}) {
  const { t } = useI18n()
  const [pattern, setPattern] = useState('')
  return (
    <>
      <h4>{t(origin === 'ai' ? 'policyAiTitle' : 'policyHumanTitle')}</h4>
      <p className="muted">{t(origin === 'ai' ? 'policyAiHint' : 'policyHumanHint')}</p>
      <table>
        <tbody>
          {rows.filter(p => p.origin === origin).map(p => (
            <tr key={p.id}>
              <td><code>{p.pattern}</code></td>
              <td><button onClick={() => onChange(() => deletePolicy(p.id))}>{t('del')}</button></td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="field">
        <input placeholder={t('policyPattern')} value={pattern} onChange={e => setPattern(e.target.value)} />
        <button
          disabled={!pattern.trim()}
          onClick={() => onChange(async () => { await createPolicy(groupId, origin, pattern.trim()); setPattern('') })}
        >
          {t('create')}
        </button>
      </div>
    </>
  )
}

// 审批与命令名单。只有组 admin 能打开；待审批列表轮询，Pi 那边正阻塞等着
export function ApprovalsView({ groupId, groupName, onOpenSession, onClose }: {
  groupId: string
  groupName: string
  onOpenSession: (id: string) => void
  onClose: () => void
}) {
  const { t } = useI18n()
  const [tab, setTab] = useState<'approvals' | 'policies'>('approvals')
  const [approvals, setApprovals] = useState<Approval[]>([])
  const [policies, setPolicies] = useState<CommandPolicy[]>([])
  const [hosts, setHosts] = useState<Record<string, string>>({})
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      const [a, p] = await Promise.all([fetchApprovals(groupId), fetchPolicies(groupId)])
      setApprovals(a)
      setPolicies(p)
    } catch (e) {
      setError(String(e))
    }
  }, [groupId])

  useEffect(() => {
    refresh()
    const timer = setInterval(refresh, 3_000)
    return () => clearInterval(timer)
  }, [refresh])

  useEffect(() => {
    fetchAssets().then(as => setHosts(Object.fromEntries(as.map(a => [a.id, a.hostname])))).catch(() => {})
  }, [])

  const run = async (fn: () => Promise<unknown>) => {
    setError(null)
    try {
      await fn()
    } catch (e) {
      setError(String(e))
    }
    await refresh()
  }

  const decide = (a: Approval, approve: boolean) => {
    const host = hosts[a.asset_id] ?? a.asset_id
    if (approve && !confirm(t(a.dry_run ? 'apConfirmDry' : 'apConfirmLive', { cmd: a.cmd, host }))) return
    run(() => decideApproval(a.id, approve))
  }

  const pending = approvals.filter(a => a.status === 'pending')
  const history = approvals.filter(a => a.status !== 'pending')

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={e => e.stopPropagation()}>
        <h3>{t('approvalsTitle', { name: groupName })}</h3>
        <div className="filter-tabs">
          <button className={`filter-tab ${tab === 'approvals' ? 'active' : ''}`} onClick={() => setTab('approvals')}>
            {t('apTabQueue', { n: pending.length })}
          </button>
          <button className={`filter-tab ${tab === 'policies' ? 'active' : ''}`} onClick={() => setTab('policies')}>
            {t('apTabPolicies')}
          </button>
        </div>

        {tab === 'approvals' ? (
          <>
            {pending.length === 0 && <p className="muted">{t('apNone')}</p>}
            {pending.map(a => (
              <div key={a.id} className="card approval-card">
                <pre>{a.cmd}</pre>
                <div className="incident-meta">
                  <span>{hosts[a.asset_id] ?? a.asset_id}</span>
                  <span className={`status ${a.dry_run ? '' : 'status-open'}`}>{t(a.dry_run ? 'apDryRun' : 'liveRun')}</span>
                  <span className="muted">
                    {t(a.origin === 'ai' ? 'apByAi' : 'apByHuman', { who: a.requested_by })}
                    {' · '}{t('apExpiresAt', { time: fmt(a.expires_at) })}
                  </span>
                </div>
                <div className="actions">
                  <button onClick={() => decide(a, true)}>{t('apApprove')}</button>
                  <button onClick={() => decide(a, false)}>{t('apReject')}</button>
                  {a.session_id && (
                    <button className="link" onClick={() => onOpenSession(a.session_id!)}>{t('apOpenSession')}</button>
                  )}
                </div>
              </div>
            ))}
            {history.length > 0 && (
              <table>
                <thead>
                  <tr><th>{t('thTime')}</th><th>{t('thHostname')}</th><th>{t('apCmd')}</th><th>{t('thStatus')}</th><th>{t('apDecidedBy')}</th></tr>
                </thead>
                <tbody>
                  {history.map(a => (
                    <tr key={a.id}>
                      <td className="muted">{fmt(a.created_at)}</td>
                      <td>{hosts[a.asset_id] ?? a.asset_id}</td>
                      <td><code>{a.cmd}</code></td>
                      <td>{t(STATUS_KEY[a.status])}</td>
                      <td className="muted">{a.decided_by ?? '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        ) : (
          <>
            <p className="muted">{t('policyRegexHint')}</p>
            <PolicyList groupId={groupId} origin="ai" rows={policies} onChange={run} />
            <PolicyList groupId={groupId} origin="human" rows={policies} onChange={run} />
          </>
        )}

        {error && <div className="error">{error}</div>}
        <div className="actions modal-actions">
          <button onClick={onClose}>{t('close')}</button>
        </div>
      </div>
    </div>
  )
}
