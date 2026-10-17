import { useQuery } from '@tanstack/react-query'
import { Input, Select, Space, Table, Tooltip, Typography } from 'antd'
import { useState } from 'react'
import { fetchAssets, searchEvents, type EventRow } from '../api'
import { HostLink } from '../components/HostLink'
import { eventSummary } from '../components/eventSummary'
import { CLASS_KEY, fmtTime } from '../components/format'
import { FilterCard, Page } from '../components/Page'
import { useI18n } from '../i18n'

// 日志检索：告警只是线索，取证要能沿着一个 IP、一段命令行翻出原始遥测
export function EventsPage() {
  const { t } = useI18n()
  const [draft, setDraft] = useState('')
  const [filter, setFilter] = useState({ q: '', source: '', classUid: 0, hours: 24, assetId: '' })
  const { data, isFetching } = useQuery({ queryKey: ['events', filter], queryFn: () => searchEvents(filter) })
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
              onSearch={q => setFilter(f => ({ ...f, q }))}
            />
            <Select
              style={{ width: 160 }}
              showSearch
              optionFilterProp="label"
              value={filter.assetId}
              onChange={assetId => setFilter(f => ({ ...f, assetId }))}
              options={[{ value: '', label: t('allHosts') }, ...(assets.data ?? []).map(a => ({ value: a.id, label: a.hostname }))]}
            />
            <Select
              style={{ width: 140 }}
              value={filter.classUid}
              onChange={classUid => setFilter(f => ({ ...f, classUid }))}
              options={[{ value: 0, label: t('allClasses') }, ...Object.entries(CLASS_KEY).map(([uid, key]) => ({ value: Number(uid), label: t(key) }))]}
            />
            <Select
              style={{ width: 130 }}
              value={filter.source}
              onChange={source => setFilter(f => ({ ...f, source }))}
              options={[{ value: '', label: t('allSources') }, ...['agent', 'sensor', 'syslog'].map(s => ({ value: s, label: s }))]}
            />
            <Select
              style={{ width: 140 }}
              value={filter.hours}
              onChange={hours => setFilter(f => ({ ...f, hours }))}
              options={[1, 6, 24, 72, 168].map(n => ({ value: n, label: t('lastHours', { n }) }))}
            />
          </Space>
        }
        extra={<Typography.Text type="secondary">{t('eventCount', { n: data?.length ?? 0 })}</Typography.Text>}
      >
        <Table<EventRow>
          size="small"
          rowKey="id"
          loading={isFetching}
          dataSource={data ?? []}
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
                return <Tooltip placement="topLeft" title={text}><span className="mono">{text}</span></Tooltip>
              },
            },
            { title: t('thUser'), dataIndex: 'username', width: 110, render: v => v || '-' },
          ]}
        />
      </FilterCard>
    </Page>
  )
}
