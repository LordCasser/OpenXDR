import { useEffect, useState } from 'react'
import { downloadAgentPdf, fetchAgentReports, reportHtmlUrl, type AgentReport } from './api'
import { useI18n } from './i18n'

const fmt = (iso: string) => new Date(iso).toLocaleString()

// Pi 报告列表：HTML 新标签页打开（后端带 CSP），PDF 直接下载
export function ReportsView({ groupId, groupName, onOpenSession, onClose }: {
  groupId: string
  groupName: string
  onOpenSession: (id: string) => void
  onClose: () => void
}) {
  const { t } = useI18n()
  const [rows, setRows] = useState<AgentReport[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchAgentReports(groupId).then(setRows).catch(e => setError(String(e)))
  }, [groupId])

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={e => e.stopPropagation()}>
        <h3>{t('reportsTitle', { name: groupName, n: rows.length })}</h3>
        {rows.length === 0 && !error && <p className="muted">{t('noReports')}</p>}
        {rows.length > 0 && (
          <table>
            <thead>
              <tr><th>{t('thTime')}</th><th>{t('reportTitle')}</th><th></th></tr>
            </thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.id}>
                  <td className="muted">{fmt(r.created_at)}</td>
                  <td>{r.title}</td>
                  <td>
                    <div className="actions">
                      <button onClick={() => window.open(reportHtmlUrl(r.id), '_blank', 'noopener')}>{t('reportView')}</button>
                      <button onClick={() => downloadAgentPdf(r).catch(e => setError(String(e)))}>PDF</button>
                      <button className="link" onClick={() => onOpenSession(r.session_id)}>{t('apOpenSession')}</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {error && <div className="error">{error}</div>}
        <div className="actions modal-actions">
          <button onClick={onClose}>{t('close')}</button>
        </div>
      </div>
    </div>
  )
}
