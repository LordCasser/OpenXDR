import { useQuery } from '@tanstack/react-query'
import { Badge, Card, Segmented, Table, Tooltip } from 'antd'
import { Link, useSearchParams } from 'react-router'
import { fetchIncidents, type IncidentSummary } from '../api'
import { INCIDENT_STATUSES, IncidentStatusTag, SeverityTag, fmtTime, incidentStatusKey } from '../components/format'
import { Page } from '../components/Page'
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

  return (
    <Page title={t('navIncidents')} subtitle={t('incidentsSubtitle')}>
      <Card styles={{ body: { padding: 0 } }}
        title={
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
      </Card>
    </Page>
  )
}
