import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Segmented, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { fetchFindings, setFindingStatus, type FindingRow } from '../api'
import { useCanAct, useSession } from '../app/session'
import { HostLink } from '../components/HostLink'
import { FilterCard, Page } from '../components/Page'
import { ResolveModal } from '../components/ResolveModal'
import { fmtTime } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

const SEVERITY: Record<FindingRow['severity'], { key: MsgKey; color: string }> = {
  info: { key: 'sev1', color: 'default' },
  low: { key: 'sev2', color: 'blue' },
  medium: { key: 'sev3', color: 'gold' },
  high: { key: 'sev4', color: 'orange' },
}

const STATUS: Record<FindingRow['status'], { key: MsgKey; color: string }> = {
  open: { key: 'findingOpen', color: 'orange' },
  resolved: { key: 'findingResolved', color: 'green' },
  ignored: { key: 'findingIgnored', color: 'default' },
}

// 运维待办：巡检 AI 登记、下一轮逐条复查；人标已处理或忽略，忽略原因会告诉 AI
export function FindingsPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { groups } = useSession()
  const canAct = useCanAct()
  const [params, setParams] = useSearchParams()
  const status = params.get('status') ?? 'open'
  const [acting, setActing] = useState<{ row: FindingRow; next: 'resolved' | 'ignored' } | null>(null)
  const { data, isPending } = useQuery({
    queryKey: ['findings', status],
    queryFn: () => fetchFindings(status === 'all' ? undefined : status),
    refetchInterval: 30_000,
  })

  const change = async (row: FindingRow, next: string, note?: string) => {
    try {
      await setFindingStatus(row.id, next, note)
      setActing(null)
      client.invalidateQueries({ queryKey: ['findings'] })
    } catch (e) {
      message.error(String(e))
    }
  }

  return (
    <Page title={t('navFindings')} subtitle={t('findingsSubtitle')}>
      <FilterCard
        filters={
          <Segmented
            value={status}
            onChange={v => setParams({ status: String(v) })}
            options={[
              ...(['open', 'resolved', 'ignored'] as const).map(s => ({ value: s, label: t(STATUS[s].key) })),
              { value: 'all', label: t('all') },
            ]}
          />
        }
      >
        <Table<FindingRow>
          rowKey="id"
          loading={isPending}
          dataSource={data ?? []}
          pagination={{ pageSize: 20, hideOnSinglePage: true }}
          locale={{ emptyText: t('noFindings') }}
          expandable={{ expandedRowRender: f => <pre className="tooltip-pre">{f.detail || '-'}</pre> }}
          columns={[
            { title: t('thSeverity'), dataIndex: 'severity', width: 90, render: (v: FindingRow['severity']) => <Tag color={SEVERITY[v]?.color}>{t(SEVERITY[v]?.key ?? 'sev1')}</Tag> },
            { title: t('thTitle'), dataIndex: 'title', render: (v, f) => <Space orientation="vertical" size={0}><span>{v}</span><Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>{f.key}</Typography.Text></Space> },
            { title: t('thHostname'), dataIndex: 'assetId', width: 140, render: v => <HostLink id={v} /> },
            { title: t('group'), dataIndex: 'groupId', width: 120, render: v => groups.find(g => g.id === v)?.name ?? v.slice(0, 8) },
            { title: t('thFirstSeen'), dataIndex: 'firstSeen', width: 170, render: fmtTime },
            { title: t('thLastConfirmed'), dataIndex: 'lastSeen', width: 170, render: fmtTime },
            {
              title: t('thStatus'), dataIndex: 'status', width: 110,
              render: (v: FindingRow['status'], f) => (
                <Tooltip title={f.note && `${f.resolvedBy ?? ''}：${f.note}`}>
                  <Tag color={STATUS[v].color}>{t(STATUS[v].key)}</Tag>
                </Tooltip>
              ),
            },
            {
              title: '', width: 200,
              render: (_, f) => (
                <Space size={4}>
                  {f.sessionId && <Link to={`/chat/${f.sessionId}`}>{t('openSession')}</Link>}
                  {canAct(f.groupId) && f.status === 'open' && <Button size="small" onClick={() => setActing({ row: f, next: 'resolved' })}>{t('markResolved')}</Button>}
                  {canAct(f.groupId) && f.status === 'open' && <Button size="small" onClick={() => setActing({ row: f, next: 'ignored' })}>{t('markIgnored')}</Button>}
                  {canAct(f.groupId) && f.status !== 'open' && <Button size="small" onClick={() => change(f, 'open')}>{t('reopen')}</Button>}
                </Space>
              ),
            },
          ]}
        />
      </FilterCard>
      <ResolveModal
        open={!!acting}
        title={`${t(acting?.next === 'ignored' ? 'findingIgnoreTitle' : 'findingResolveTitle')} · ${acting?.row.title ?? ''}`}
        hint={t(acting?.next === 'ignored' ? 'findingIgnoreHint' : 'findingResolveHint')}
        onCancel={() => setActing(null)}
        onSubmit={note => change(acting!.row, acting!.next, note)}
      />
    </Page>
  )
}
