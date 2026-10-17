import { useQuery } from '@tanstack/react-query'
import { Alert, Input, Select, Space, Table, Tag, Typography } from 'antd'
import { useState } from 'react'
import { useSearchParams } from 'react-router'
import { fetchAssets, searchEvents, type EventRow } from '../api'
import { HostLink } from '../components/HostLink'
import { LoadError } from '../components/LoadError'
import { eventSummary } from '../components/eventSummary'
import { CLASS_KEY, fmtTime } from '../components/format'
import { FilterCard, Page } from '../components/Page'
import { useI18n } from '../i18n'

// 日志检索：告警只是线索，取证要能沿着一个 IP、一段命令行翻出原始遥测
export function EventsPage() {
  const { t } = useI18n()
  // 筛选条件放在 URL 里：刷新不丢，链接发给别人能看到同一份结果
  const [params, setParams] = useSearchParams()
  const filter = {
    q: params.get('q') ?? '',
    source: params.get('source') ?? '',
    classUid: Number(params.get('classUid') ?? 0),
    hours: Number(params.get('hours') ?? 24),
    assetId: params.get('assetId') ?? '',
    from: params.get('from') ?? '',
    to: params.get('to') ?? '',
  }
  const setFilter = (patch: Partial<typeof filter>) => {
    const next = { ...filter, ...patch }
    setParams(Object.fromEntries(Object.entries(next).filter(([k, v]) => v && !(k === 'hours' && v === 24)).map(([k, v]) => [k, String(v)])))
  }
  const [draft, setDraft] = useState(filter.q)
  const { data, isFetching, isError, error, refetch } = useQuery({ queryKey: ['events', filter], queryFn: () => searchEvents(filter) })
  const assets = useQuery({ queryKey: ['assets'], queryFn: fetchAssets })

  return (
    <Page title={t('navEvents')} subtitle={t('eventsSubtitle')}>
      <FilterCard
        filters={
          <Space wrap>
            <Input.Search
              allowClear
              style={{ width: 360 }}
              placeholder={t('eventSearchHint')}
              value={draft}
              onChange={e => setDraft(e.target.value)}
              onSearch={q => setFilter({ q })}
            />
            <Select
              style={{ width: 160 }}
              showSearch
              optionFilterProp="label"
              value={filter.assetId}
              onChange={assetId => setFilter({ assetId })}
              options={[{ value: '', label: t('allHosts') }, ...(assets.data ?? []).map(a => ({ value: a.id, label: a.hostname }))]}
            />
            <Select
              style={{ width: 140 }}
              value={filter.classUid}
              onChange={classUid => setFilter({ classUid })}
              options={[{ value: 0, label: t('allClasses') }, ...Object.entries(CLASS_KEY).map(([uid, key]) => ({ value: Number(uid), label: t(key) }))]}
            />
            <Select
              style={{ width: 130 }}
              value={filter.source}
              onChange={source => setFilter({ source })}
              options={[{ value: '', label: t('allSources') }, ...['agent', 'sensor', 'syslog'].map(s => ({ value: s, label: s }))]}
            />
            {filter.from ? (
              <Tag closable color="blue" onClose={() => setFilter({ from: '', to: '' })} style={{ padding: '4px 8px' }}>
                {fmtTime(filter.from)} ~ {filter.to ? fmtTime(filter.to).slice(11) : t('now')}
              </Tag>
            ) : <Select
              style={{ width: 140 }}
              value={filter.hours}
              onChange={hours => setFilter({ hours })}
              options={[1, 6, 24, 72, 168].map(n => ({ value: n, label: t('lastHours', { n }) }))}
            />}
          </Space>
        }
        extra={<Typography.Text type="secondary">{t('eventCount', { n: data ? `${data.items.length}${data.truncated ? '+' : ''}` : 0 })}</Typography.Text>}
      >
        {data?.truncated && <Alert type="info" banner showIcon title={t('listTruncated', { n: data.items.length })} />}
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<EventRow>
          size="small"
          rowKey="id"
          loading={isFetching}
          dataSource={data?.items ?? []}
          pagination={{ pageSize: 50, hideOnSinglePage: true }}
          expandable={{ expandedRowRender: r => <pre className="json-block">{JSON.stringify(r.raw, null, 2)}</pre> }}
          columns={[
            { title: t('thTime'), dataIndex: 'ts', render: fmtTime, width: 170 },
            { title: t('thClass'), dataIndex: 'classUid', width: 100, render: v => (CLASS_KEY[v] ? t(CLASS_KEY[v]) : v) },
            { title: t('thHostname'), dataIndex: 'assetId', width: 130, render: v => <HostLink id={v} /> },
            {
              title: t('thSummary'), key: 'summary', ellipsis: { showTitle: false },
              render: (_, r) => {
                const text = eventSummary(r.classUid, r.raw, t) || r.connTuple || '-'
                return (
                  <Typography.Text className="mono" copyable={{ text }} ellipsis={{ tooltip: { title: text, placement: 'topLeft' } }} style={{ width: '100%' }}>
                    {text}
                  </Typography.Text>
                )
              },
            },
            { title: t('thUser'), dataIndex: 'username', width: 110, render: v => v || '-' },
          ]}
        />}
      </FilterCard>
    </Page>
  )
}
