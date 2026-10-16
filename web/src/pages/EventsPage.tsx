import { useQuery } from '@tanstack/react-query'
import { Input, Select, Space, Table, Typography } from 'antd'
import { useState } from 'react'
import { searchEvents, type EventRow } from '../api'
import { HostLink } from '../components/HostLink'
import { CLASS_KEY, fmtTime } from '../components/format'
import { FilterCard, Page } from '../components/Page'
import { useI18n } from '../i18n'

// 日志检索：告警只是线索，取证要能沿着一个 IP、一段命令行翻出原始遥测
export function EventsPage() {
  const { t } = useI18n()
  const [draft, setDraft] = useState('')
  const [filter, setFilter] = useState({ q: '', source: '', classUid: 0, hours: 24 })
  const { data, isFetching } = useQuery({ queryKey: ['events', filter], queryFn: () => searchEvents(filter) })

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
            { title: t('thTime'), dataIndex: 'ts', render: fmtTime, width: 180 },
            { title: t('thClass'), dataIndex: 'classUid', width: 110, render: v => (CLASS_KEY[v] ? t(CLASS_KEY[v]) : v) },
            { title: t('thSource'), dataIndex: 'source', width: 90 },
            { title: t('thHostname'), dataIndex: 'assetId', width: 160, render: v => <HostLink id={v} /> },
            { title: t('thUser'), dataIndex: 'username', width: 140, render: v => v ?? '-' },
            { title: t('thConn'), dataIndex: 'connTuple', ellipsis: true, render: v => <span className="mono">{v ?? '-'}</span> },
          ]}
        />
      </FilterCard>
    </Page>
  )
}
