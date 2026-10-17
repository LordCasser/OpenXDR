import { RobotOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Badge, Button, Segmented, Space, Table, Tooltip, Typography } from 'antd'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { fetchIncidents, setIncidentStatus, type IncidentSummary } from '../api'
import { useCanAct, useSession } from '../app/session'
import { Ago, EmptyHint, Refreshed } from '../components/Ago'
import { useCanChat, useHandoff } from '../components/Handoff'
import { LoadError } from '../components/LoadError'
import { ResolveModal } from '../components/ResolveModal'
import { INCIDENT_STATUSES, IncidentStatusTag, SeverityTag, errText, incidentStatusKey } from '../components/format'
import { FilterCard, Page } from '../components/Page'
import { useI18n, type MsgKey } from '../i18n'

const VERDICT: Record<string, { key: MsgKey; status: 'error' | 'warning' | 'success' }> = {
  malicious: { key: 'verdictMalicious', status: 'error' },
  suspicious: { key: 'verdictSuspicious', status: 'warning' },
  benign: { key: 'verdictBenign', status: 'success' },
}

const PAGE_SIZE = 50
const done = (r: IncidentSummary) => r.status === 'closed' || r.status === 'false_positive'

// 安全事件：告警经去重与关联后的产物，"一万条进三个出"的那三个。默认看未结案的，后端分页
export function IncidentsPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { groups } = useSession()
  const canAct = useCanAct()
  const [params, setParams] = useSearchParams()
  const status = params.get('status') ?? 'review'
  const page = Number(params.get('page') ?? 1)
  const [selected, setSelected] = useState<string[]>([])
  const [resolving, setResolving] = useState<'closed' | 'false_positive' | null>(null)
  const query = useQuery({
    queryKey: ['incidents', status, page],
    queryFn: () => fetchIncidents({ status: status === 'all' ? undefined : status, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE }),
    refetchInterval: 10_000,
  })
  const rows = query.data?.items ?? []
  const actable = (r: IncidentSummary) => !done(r) && canAct(r.groupId)
  const canChat = useCanChat()
  const handoff = useHandoff()
  // 多选交给 AI：一个会话属于一个组，选中的必须同组
  const picked = rows.filter(r => selected.includes(r.id))
  const pickedGroup = picked[0]?.groupId
  const sameGroup = picked.length > 0 && picked.every(r => r.groupId === pickedGroup)
  const handTo = (list: IncidentSummary[]) => handoff.start(list[0].groupId!, list.map(r => `incident:${r.id}`),
    list.length === 1 ? t('handoffIncidentTitle', { title: list[0].title ?? list[0].id }) : t('handoffIncidentsTitle', { n: list.length }),
    t('handoffIncidentPrompt'))
  const anyActable = rows.some(actable)

  // 换筛选或翻页就清掉勾选，批量操作只作用于看得见的行
  const go = (next: { status?: string; page?: number }) => {
    setSelected([])
    const s = next.status ?? status
    setParams({ ...(s !== 'review' && { status: s }), ...((next.page ?? 1) > 1 && { page: String(next.page) }) })
  }

  // 逐条走单个接口：组内权限与审计照旧。失败的留在勾选里、弹窗不关，备注不丢
  const batch = async (next: string, note: string) => {
    const results = await Promise.allSettled(selected.map(id => setIncidentStatus(id, next, note)))
    const failed = selected.filter((_, i) => results[i].status === 'rejected')
    client.invalidateQueries({ queryKey: ['incidents'] })
    if (failed.length < results.length) message.success(t('batchDone', { n: results.length - failed.length }))
    setSelected(failed)
    if (failed.length) {
      const reason = (results.find(r => r.status === 'rejected') as PromiseRejectedResult).reason
      message.error(t('batchFailed', { n: failed.length, err: errText(reason, t) }))
      throw reason
    }
    setResolving(null)
  }

  return (
    <Page title={t('navIncidents')} subtitle={t('incidentsSubtitle')}>
      <FilterCard
        extra={(
          <Space>
            <Refreshed at={query.dataUpdatedAt} fetching={query.isFetching} onRefresh={() => query.refetch()} />
            {anyActable && <Button size="small" onClick={() => setSelected(rows.filter(r => actable(r) && r.aiVerdict?.verdict === 'benign').map(r => r.id))}>{t('selectBenign')}</Button>}
            {selected.length > 0 && (
              <>
                <Typography.Text type="secondary">{t('batchSelected', { n: selected.length })}</Typography.Text>
                <Tooltip title={!sameGroup ? t('handoffSameGroup') : picked.length > 10 ? t('handoffMax') : undefined}>
                  <Button size="small" type="primary" icon={<RobotOutlined />} loading={handoff.busy}
                    disabled={!sameGroup || picked.length > 10 || !canChat(pickedGroup)} onClick={() => handTo(picked)}>{t('handoffToAI')}</Button>
                </Tooltip>
                <Button size="small" onClick={() => setResolving('closed')}>{t('close')}</Button>
                <Button size="small" danger onClick={() => setResolving('false_positive')}>{t('markFp')}</Button>
              </>
            )}
          </Space>
        )}
        filters={
          <Segmented
            value={status}
            onChange={v => go({ status: String(v) })}
            options={[
              { value: 'review', label: t('statusReview') },
              { value: 'unresolved', label: t('statusUnresolved') },
              ...INCIDENT_STATUSES.map(s => ({ value: s, label: t(incidentStatusKey(s)!) })),
              { value: 'all', label: t('all') },
            ]}
          />
        }
      >
        {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : (
          <Table<IncidentSummary>
            rowKey="id"
            loading={query.isPending}
            dataSource={rows}
            locale={{ emptyText: <EmptyHint title={t(status === 'review' ? 'noReview' : status === 'unresolved' ? 'noUnresolved' : 'noIncidents')} hint={status === 'review' || status === 'unresolved' ? t('noUnresolvedHint') : undefined} /> }}
            pagination={{
              current: page, pageSize: PAGE_SIZE, total: query.data?.total ?? rows.length,
              hideOnSinglePage: true, showSizeChanger: false, onChange: p => go({ page: p }),
              showTotal: n => t('totalCount', { n }),
            }}
            rowSelection={anyActable ? {
              selectedRowKeys: selected,
              onChange: keys => setSelected(keys as string[]),
              getCheckboxProps: r => ({ disabled: !actable(r) }),
            } : undefined}
            columns={[
              { title: t('thSeverity'), dataIndex: 'severity', width: 90, render: v => <SeverityTag value={v} /> },
              { title: t('thTitle'), dataIndex: 'title', ellipsis: true, render: (v, r) => <Link to={`/incidents/${r.id}`}>{v ?? r.id}</Link> },
              { title: t('group'), dataIndex: 'groupId', width: 140, ellipsis: true, render: v => groups.find(g => g.id === v)?.name ?? '-' },
              { title: t('thStatus'), dataIndex: 'status', width: 100, render: v => <IncidentStatusTag value={v} /> },
              {
                title: t('thVerdict'), width: 150,
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
              { title: t('thAlerts'), dataIndex: 'alertCount', width: 80, align: 'right' },
              { title: t('thCreatedAt'), dataIndex: 'createdAt', width: 110, render: v => <Ago iso={v} /> },
              ...(anyActable ? [{
                title: '', width: 170,
                // 单条处理不用先勾选：直接点，弹窗写结论
                render: (_: unknown, r: IncidentSummary) => actable(r) && (
                  <Space size={0} className="row-actions">
                    {canChat(r.groupId) && <Button type="link" size="small" icon={<RobotOutlined />} onClick={() => handTo([r])}>AI</Button>}
                    <Button type="link" size="small" onClick={() => { setSelected([r.id]); setResolving('closed') }}>{t('close')}</Button>
                    <Button type="link" size="small" danger onClick={() => { setSelected([r.id]); setResolving('false_positive') }}>{t('markFpShort')}</Button>
                  </Space>
                ),
              }] : []),
            ]}
          />
        )}
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
