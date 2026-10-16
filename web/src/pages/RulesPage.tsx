import { useQuery } from '@tanstack/react-query'
import { Input, Select, Space, Table, Tag, Tooltip } from 'antd'
import { useState } from 'react'
import { fetchRules, type RuleRow } from '../api'
import { CLASS_KEY, SeverityTag } from '../components/format'
import { FilterCard, Page } from '../components/Page'
import { useI18n } from '../i18n'

// 检测规则：规则库热重载，这里看到的就是引擎里正在跑的版本；
// "无数据源"提醒运营：规则加载了，但没有采集面供数，纯摆设
export function RulesPage() {
  const { t } = useI18n()
  const [q, setQ] = useState('')
  const [sev, setSev] = useState(0)
  const { data, isPending } = useQuery({ queryKey: ['rules'], queryFn: fetchRules })
  const rows = (data ?? []).filter(r =>
    (!q || (r.title + r.id).toLowerCase().includes(q.toLowerCase())) && (!sev || r.severity === sev),
  )
  const noData = (data ?? []).filter(r => !r.ingested).length

  return (
    <Page title={t('navRules')} subtitle={t('rulesSummary', { n: data?.length ?? 0, nodata: noData })}>
      <FilterCard
        filters={
          <Space wrap>
            <Input.Search allowClear style={{ width: 280 }} placeholder={t('ruleSearchHint')} onSearch={setQ} onChange={e => !e.target.value && setQ('')} />
            <Select style={{ width: 140 }} value={sev} onChange={setSev} options={[{ value: 0, label: t('allSeverities') }, ...[5, 4, 3, 2, 1].map(n => ({ value: n, label: t(`sev${n}` as 'sev1') }))]} />
          </Space>
        }
      >
        <Table<RuleRow>
          size="small"
          rowKey="id"
          loading={isPending}
          dataSource={rows}
          pagination={{ pageSize: 30, hideOnSinglePage: true }}
          columns={[
            { title: t('thRule'), dataIndex: 'title', render: (v, r) => <Tooltip title={r.id}>{v || r.id}</Tooltip> },
            { title: t('thSeverity'), dataIndex: 'severity', width: 90, render: v => <SeverityTag value={v} />, sorter: (a, b) => a.severity - b.severity },
            { title: t('thClass'), dataIndex: 'classUid', width: 110, render: v => (CLASS_KEY[v] ? t(CLASS_KEY[v]) : v || t('allClasses')) },
            { title: t('thPlatform'), dataIndex: 'product', width: 110, render: v => v || '-' },
            { title: t('thDataSource'), width: 140, render: (_, r) => (r.ingested ? <Tag>{r.source}</Tag> : <Tag color="warning">{t('noDataSource')}</Tag>) },
          ]}
        />
      </FilterCard>
    </Page>
  )
}
