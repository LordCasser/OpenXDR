import { Alert, Card, Descriptions, Space, Table, Tag, Typography } from 'antd'
import { useEffect, useState } from 'react'
import type { Asset, CollectorCapability } from '../api'
import { useI18n, type MsgKey } from '../i18n'
import { fmtTime } from './format'

const states: Record<string, { label: MsgKey; color?: string }> = {
  active: { label: 'collectorActive', color: 'blue' },
  degraded: { label: 'collectorDegraded', color: 'warning' },
  unavailable: { label: 'collectorUnavailable', color: 'error' },
  disabled: { label: 'collectorDisabled' },
  unknown: { label: 'collectorUnknown' },
}
const names: Record<string, MsgKey> = {
  process: 'collectorProcess', files: 'collectorFiles', network: 'collectorNetwork', dns: 'collectorDNS',
  powershell: 'collectorPowerShell', auth: 'collectorAuth', inventory: 'collectorInventory', 'local-accounts': 'collectorLocalAccounts', persist: 'collectorPersist', kmod: 'collectorKmod',
}
const size = (n: number) => `${(n / 1048576).toFixed(2)} MiB`

export function CollectorHealth({ asset }: { asset: Asset }) {
  const { t } = useI18n()
  const [now, setNow] = useState(Date.now)
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 15000); return () => clearInterval(timer) }, [])
  const health = asset.collectorHealth
  if (!health) return <Card title={t('collectorTitle')} size="small"><Typography.Text type="secondary">{t('collectorNoReport')}</Typography.Text></Card>
  const received = Date.parse(health.receivedAt)
  const stale = !Number.isFinite(received) || now - received > 90000 || received > now + 300000
  const rows = Object.entries(health.capabilities ?? {}).map(([name, value]) => ({ name, ...value }))
  return <Card title={t('collectorTitle')} size="small">
    <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
      {stale && <Alert type="warning" showIcon title={t('collectorStale')} />}
      {health.writeBlocked && <Alert type="error" showIcon title={t('collectorBlocked')} />}
      <Descriptions size="small" column={{ xs: 1, sm: 2, lg: 4 }} items={[
        { key: 'received', label: t('collectorReceived'), children: fmtTime(health.receivedAt) },
        { key: 'receipts', label: t('collectorReceipts'), children: health.receipts ? `${health.receipts.pending} / ${health.receipts.incomplete}` : '—' },
        { key: 'queue', label: t('collectorQueue'), children: `${health.queueBatches} · ${size(health.queueBytes)}` },
        { key: 'limit', label: t('collectorLimit'), children: size(health.queueLimitBytes) },
        { key: 'dropped', label: t('collectorDropped'), children: <Typography.Text type={health.droppedEvents ? 'danger' : undefined}>{health.droppedEvents}</Typography.Text> },
      ]} />
      {health.receipts && health.receipts.incomplete > 0 && <Alert type="warning" showIcon title={t('collectorReceiptIncomplete')} />}
      <Table<CollectorCapability & { name: string }> size="small" rowKey="name" pagination={false} dataSource={rows} columns={[
        { title: t('collectorComponent'), dataIndex: 'name', render: (name: string) => names[name] ? t(names[name]) : name },
        { title: t('collectorPath'), dataIndex: 'path', render: (path: string) => path || '—' },
        { title: t('collectorState'), dataIndex: 'state', render: (value: string) => { const state = states[value] ?? states.unknown; return <Tag color={stale ? undefined : state.color}>{t(state.label)}</Tag> } },
      ]} />
      <Typography.Text type="secondary">{t('collectorEvidenceHint')}</Typography.Text>
    </Space>
  </Card>
}
