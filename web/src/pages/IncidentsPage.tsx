import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Badge, Button, Segmented, Space, Table, Tooltip, Typography } from 'antd'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { fetchIncidents, setIncidentStatus, type IncidentSummary } from '../api'
import { useSession } from '../app/session'
import { ResolveModal } from '../components/ResolveModal'
import { INCIDENT_STATUSES, IncidentStatusTag, SeverityTag, fmtTime, incidentStatusKey } from '../components/format'
import { FilterCard, Page } from '../components/Page'
import { useI18n, type MsgKey } from '../i18n'

const VERDICT: Record<string, { key: MsgKey; status: 'error' | 'warning' | 'success' }> = {
  malicious: { key: 'verdictMalicious', status: 'error' },
  suspicious: { key: 'verdictSuspicious', status: 'warning' },
  benign: { key: 'verdictBenign', status: 'success' },
}

// 安全事件：告警经去重与关联后的产物，"一万条进三个出"的那三个
export function IncidentsPage() {
  const { t } = useI18n()
  const [params, setParams] = useSearchParams()
  const status = params.get('status') ?? ''
  const { data, isPending } = useQuery({
    queryKey: ['incidents', status],
    queryFn: () => fetchIncidents(status || undefined),
    refetchInterval: 10_000,
  })

  const { message } = App.useApp()
  const client = useQueryClient()
  const { canWrite } = useSession()
  const [selected, setSelected] = useState<string[]>([])
  const [resolving, setResolving] = useState<'closed' | 'false_positive' | null>(null)
  const open = (data ?? []).filter(r => r.status !== 'closed' && r.status !== 'false_positive')

  // 逐条走单个接口：组内权限与审计照旧，没权限的那几条单独报出来
  const batch = async (next: string, note: string) => {
    const results = await Promise.allSettled(selected.map(id => setIncidentStatus(id, next, note)))
    const failed = results.filter(r => r.status === 'rejected')
    if (failed.length) message.error(t('batchFailed', { n: failed.length, err: String((failed[0] as PromiseRejectedResult).reason) }))
    if (failed.length < results.length) message.success(t('batchDone', { n: results.length - failed.length }))
    setSelected([])
    setResolving(null)
    client.invalidateQueries({ queryKey: ['incidents'] })
  }

  return (
    <Page title={t('navIncidents')} subtitle={t('incidentsSubtitle')}>
      <FilterCard
        extra={canWrite && (
          <Space>
            <Button size="small" onClick={() => setSelected(open.filter(r => r.aiVerdict?.verdict === 'benign').map(r => r.id))}>{t('selectBenign')}</Button>
            {selected.length > 0 && (
              <>
                <Typography.Text type="secondary">{t('batchSelected', { n: selected.length })}</Typography.Text>
                <Button size="small" onClick={() => setResolving('closed')}>{t('close')}</Button>
                <Button size="small" danger onClick={() => setResolving('false_positive')}>{t('markFp')}</Button>
              </>
            )}
          </Space>
        )}
        filters={
          <Segmented
            value={status}
            onChange={v => setParams(v ? { status: String(v) } : {})}
            options={[{ value: '', label: t('all') }, ...INCIDENT_STATUSES.map(s => ({ value: s, label: t(incidentStatusKey(s)!) }))]}
          />
        }
      >
        <Table<IncidentSummary>
          rowKey="id"
          loading={isPending}
          dataSource={data ?? []}
          pagination={{ pageSize: 20, hideOnSinglePage: true }}
          rowSelection={canWrite ? {
            selectedRowKeys: selected,
            onChange: keys => setSelected(keys as string[]),
            getCheckboxProps: r => ({ disabled: r.status === 'closed' || r.status === 'false_positive' }),
          } : undefined}
          columns={[
            { title: t('thSeverity'), dataIndex: 'severity', width: 90, render: v => <SeverityTag value={v} />, sorter: (a, b) => a.severity - b.severity },
            { title: t('thTitle'), dataIndex: 'title', render: (v, r) => <Link to={`/incidents/${r.id}`}>{v ?? r.id}</Link> },
            { title: t('thStatus'), dataIndex: 'status', width: 100, render: v => <IncidentStatusTag value={v} /> },
            {
              title: t('thVerdict'), width: 160,
              render: (_, r) => {
                const v = VERDICT[r.aiVerdict?.verdict ?? '']
                if (!v) return <Badge status="default" text={t('waitingVerdict')} />
                return (
                  <Tooltip title={r.aiVerdict?.summary}>
                    <Badge status={v.status} text={`${t(v.key)} · ${r.aiVerdict?.confidence ?? '-'}`} />
                  </Tooltip>
                )
              },
            },
            { title: t('thAlerts'), dataIndex: 'alertCount', width: 90, align: 'right' },
            { title: t('thCreatedAt'), dataIndex: 'createdAt', width: 180, render: fmtTime, defaultSortOrder: 'descend', sorter: (a, b) => a.createdAt.localeCompare(b.createdAt) },
          ]}
        />
      </FilterCard>
      <ResolveModal
        open={!!resolving}
        title={`${t(resolving === 'closed' ? 'resolveClosedTitle' : 'resolveFpTitle')} · ${t('batchSelected', { n: selected.length })}`}
        hint={t('resolveHint')}
        onCancel={() => setResolving(null)}
        onSubmit={note => batch(resolving!, note)}
      />
    </Page>
  )
}
