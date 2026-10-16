import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Card, Empty, Space, Switch, Tag, Typography } from 'antd'
import { useState } from 'react'
import { fetchCommands, issueCommand } from '../api'
import { useI18n, type MsgKey } from '../i18n'
import { fmtTime } from './format'

const STATUS: Record<string, { key: MsgKey; color: string }> = {
  pending: { key: 'cmdPending', color: 'default' },
  sent: { key: 'cmdSent', color: 'processing' },
  succeeded: { key: 'cmdSucceeded', color: 'success' },
  failed: { key: 'cmdFailed', color: 'error' },
  unsupported: { key: 'cmdUnsupported', color: 'warning' },
  unknown: { key: 'cmdUnknown', color: 'warning' },
}

const KIND: Record<string, MsgKey> = {
  kill_process: 'killProcess',
  isolate_host: 'isolateHost',
  unisolate_host: 'unisolateHost',
  exec: 'execCommand',
}

// 响应处置：默认演练，真执行必须先打开开关并二次确认，避免手滑隔离生产主机
export function ResponsePanel({ incidentId, assetId, canAct }: { incidentId: string; assetId: string | null; canAct: boolean }) {
  const { t } = useI18n()
  const { modal, message } = App.useApp()
  const client = useQueryClient()
  const [live, setLive] = useState(false)
  const [busy, setBusy] = useState(false)
  const history = useQuery({ queryKey: ['commands', incidentId], queryFn: () => fetchCommands(incidentId), refetchInterval: 5_000 })

  const issue = (kind: string) => {
    if (!assetId) return
    const go = async () => {
      setBusy(true)
      try {
        await issueCommand({ kind, assetId, incidentId, dryRun: !live })
        message.success(t(live ? 'cmdIssuedLive' : 'cmdIssuedDry'))
      } catch (e) {
        message.error(String(e))
      } finally {
        setBusy(false)
        client.invalidateQueries({ queryKey: ['commands', incidentId] })
      }
    }
    if (!live) return go()
    modal.confirm({ title: t('confirmLive', { kind: t(KIND[kind]) }), okButtonProps: { danger: true }, onOk: go })
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
                <Switch checked={live} onChange={setLive} checkedChildren={t('liveRun')} unCheckedChildren={t('dryRun')} />
                <Button danger={live} loading={busy} onClick={() => issue('isolate_host')}>{t('isolateHost')}</Button>
                <Button loading={busy} onClick={() => issue('unisolate_host')}>{t('unisolateHost')}</Button>
              </Space>
              {!live && <Typography.Text type="secondary">{t('drillNote')}</Typography.Text>}
              {live && <Alert type="warning" showIcon title={t('liveWarning')} />}
            </>
          )}
          {/* 右侧窄栏放不下表格，记录按行排：动作 · 模式 · 状态，下一行时间与结果 */}
          {history.isPending ? null : (history.data ?? []).length === 0 ? (
            <Typography.Text type="secondary">{t('noCommands')}</Typography.Text>
          ) : (
            <div className="cmd-list">
              {history.data!.map(c => (
                <div key={c.id} className="cmd-item">
                  <Space size={6} wrap>
                    <Typography.Text strong>{KIND[c.kind] ? t(KIND[c.kind]) : c.kind}</Typography.Text>
                    <Tag color={c.dryRun ? 'default' : 'red'}>{t(c.dryRun ? 'dryRun' : 'liveRun')}</Tag>
                    <Tag color={STATUS[c.status]?.color}>{STATUS[c.status] ? t(STATUS[c.status].key) : c.status}</Tag>
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
