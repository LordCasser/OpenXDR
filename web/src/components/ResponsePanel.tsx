import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Card, Empty, Space, Typography } from 'antd'
import { useState } from 'react'
import { fetchCommands, issueCommand } from '../api'
import { useI18n } from '../i18n'
import { CommandStatusTag, commandKind, fmtTime, errText } from './format'

// 响应处置：每个动作都在主机上真实生效，下发前必须二次确认，避免手滑隔离生产主机
export function ResponsePanel({ incidentId, assetId, canAct }: { incidentId: string; assetId: string | null; canAct: boolean }) {
  const { t } = useI18n()
  const { modal, message } = App.useApp()
  const client = useQueryClient()
  const [busy, setBusy] = useState(false)
  const history = useQuery({ queryKey: ['commands', incidentId], queryFn: () => fetchCommands({ incidentId }), refetchInterval: 5_000 })

  const issue = (kind: string) => {
    if (!assetId) return
    const go = async () => {
      setBusy(true)
      try {
        await issueCommand({ kind, assetId, incidentId })
        message.success(t('cmdIssuedLive'))
      } catch (e) {
        message.error(errText(e, t))
      } finally {
        setBusy(false)
        client.invalidateQueries({ queryKey: ['commands', incidentId] })
      }
    }
    modal.confirm({ title: t('confirmLive', { kind: commandKind(kind, t) }), okButtonProps: { danger: true }, onOk: go })
  }

  return (
    <Card title={t('responseTitle')}>
      {!assetId ? (
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noAssetForResponse')} />
      ) : (
        <Space orientation="vertical" style={{ width: '100%' }}>
          {canAct && (
            <>
              <Space wrap>
                <Button danger loading={busy} onClick={() => issue('isolate_host')}>{t('isolateHost')}</Button>
                <Button loading={busy} onClick={() => issue('unisolate_host')}>{t('unisolateHost')}</Button>
              </Space>
              <Typography.Text type="secondary">{t('liveWarning')}</Typography.Text>
            </>
          )}
          {/* 右侧窄栏放不下表格，记录按行排：动作 · 状态，下一行时间与结果 */}
          {history.isPending ? null : (history.data ?? []).length === 0 ? (
            <Typography.Text type="secondary">{t('noCommands')}</Typography.Text>
          ) : (
            <div className="cmd-list">
              {history.data!.map(c => (
                <div key={c.id} className="cmd-item">
                  <Space size={6} wrap>
                    <Typography.Text strong>{commandKind(c.kind, t)}</Typography.Text>
                    <CommandStatusTag value={c.status} />
                  </Space>
                  <Typography.Text type="secondary" style={{ display: 'block', fontSize: 12 }}>
                    {fmtTime(c.createdAt)}{c.issuedBy ? ` · ${c.issuedBy}` : ''}
                  </Typography.Text>
                  {c.detail && <Typography.Text style={{ fontSize: 12 }} ellipsis={{ tooltip: c.detail }}>{c.detail}</Typography.Text>}
                </div>
              ))}
            </div>
          )}
        </Space>
      )}
    </Card>
  )
}
