import { TableActions } from '../components/TableActions'
import { RobotOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Segmented, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { fetchFindings, setFindingStatus, type FindingRow } from '../api'
import { useCanAct, useSession } from '../app/session'
import { useCanChat, useHandoff } from '../components/Handoff'
import { HostLink } from '../components/HostLink'
import { FilterCard, Page, useWideTable } from '../components/Page'
import { Ago, EmptyHint, Refreshed } from '../components/Ago'
import { LoadError } from '../components/LoadError'
import { ResolveModal } from '../components/ResolveModal'
import { errText } from '../components/format'
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
  const wideTable = useWideTable()
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { groups } = useSession()
  const canAct = useCanAct()
  const [params, setParams] = useSearchParams()
  const status = params.get('status') ?? 'open'
  const [acting, setActing] = useState<{ row: FindingRow; next: 'resolved' | 'ignored' } | null>(null)
  const [selectedKeys, setSelected] = useState<string[]>([])
  const canChat = useCanChat()
  const handoff = useHandoff()
  const { data, isPending, isError, error, refetch, dataUpdatedAt, isFetching } = useQuery({
    queryKey: ['findings', status],
    queryFn: () => fetchFindings(status === 'all' ? undefined : status),
    refetchInterval: 30_000,
  })

  // 返回是否成功：弹窗靠它决定关不关、原因留不留
  const change = async (row: FindingRow, next: string, note?: string) => {
    try {
      await setFindingStatus(row.id, next, note)
    } catch (e) {
      message.error(errText(e, t))
      return false
    }
    setActing(null)
    client.invalidateQueries({ queryKey: ['findings'] })
    return true
  }

  useEffect(() => { setSelected([]); setActing(null) }, [status])
  const picked = (data ?? []).filter(f => selectedKeys.includes(f.id) && f.status === 'open' && canChat(f.groupId))
  const selected = picked.map(f => f.id)
  const sameGroup = picked.length > 0 && picked.every(f => f.groupId === picked[0].groupId)
  const handTo = (list: FindingRow[]) => handoff.start(list[0].groupId, list.map(f => `finding:${f.id}`),
    list.length === 1 ? t('handoffFindingTitle', { title: list[0].title }) : t('handoffFindingsTitle', { n: list.length }),
    t('handoffFindingPrompt'))

  return (
    <Page title={t('navFindings')} subtitle={t('findingsSubtitle')}>
      <FilterCard
        extra={(
          <Space wrap>
            {selected.length > 0 && (
              <Tooltip title={!sameGroup ? t('handoffSameGroup') : picked.length > 10 ? t('handoffMax') : undefined}>
                <Button size="small" type="primary" icon={<RobotOutlined />} loading={handoff.busy}
                  disabled={!sameGroup || picked.length > 10 || !canChat(picked[0]?.groupId)} onClick={() => handTo(picked)}>
                  {t('handoffToAI')}（{selected.length}）
                </Button>
              </Tooltip>
            )}
            <Refreshed at={dataUpdatedAt} fetching={isFetching} onRefresh={() => refetch()} />
          </Space>
        )}
        filters={
          <Segmented
            value={status}
            onChange={v => { setSelected([]); setParams({ status: String(v) }) }}
            options={[
              ...(['open', 'resolved', 'ignored'] as const).map(s => ({ value: s, label: t(STATUS[s].key) })),
              { value: 'all', label: t('all') },
            ]}
          />
        }
      >
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<FindingRow>
          scroll={{ x: 1400 }}
          tableLayout="fixed"
          rowKey="id"
          rowSelection={{ selectedRowKeys: selected, onChange: keys => setSelected(keys as string[]), getCheckboxProps: f => ({ disabled: f.status !== 'open' || !canChat(f.groupId) }) }}
          loading={isPending}
          dataSource={data ?? []}
          pagination={{ pageSize: 20, hideOnSinglePage: true }}
          locale={{ emptyText: <EmptyHint title={t('noFindings')} hint={t('noFindingsHint')} action={<Link to="/tasks">{t('goTasks')}</Link>} /> }}
          expandable={{ expandedRowRender: f => <pre className="tooltip-pre">{f.detail || '-'}</pre> }}
          columns={[
            { title: t('thSeverity'), dataIndex: 'severity', width: 90, render: (v: FindingRow['severity']) => <Tag color={SEVERITY[v]?.color}>{t(SEVERITY[v]?.key ?? 'sev1')}</Tag> },
            { title: t('thTitle'), dataIndex: 'title', render: (v, f) => <Space orientation="vertical" size={0} style={{ width: '100%', overflowWrap: 'anywhere' }}><span>{v}</span><Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>{f.key}</Typography.Text></Space> },
            { title: t('thHostname'), dataIndex: 'assetId', width: 140, render: (v, f) => <HostLink id={v} fallback={f.hostname} /> },
            { title: t('group'), dataIndex: 'groupId', width: 120, render: v => groups.find(g => g.id === v)?.name ?? v.slice(0, 8) },
            { title: t('thFirstSeen'), dataIndex: 'firstSeen', width: 110, render: v => <Ago iso={v} /> },
            { title: t('thLastConfirmed'), dataIndex: 'lastSeen', width: 110, render: v => <Ago iso={v} /> },
            {
              title: t('thStatus'), dataIndex: 'status', width: 110,
              render: (v: FindingRow['status'], f) => (
                <Tooltip title={f.note && t('noteBy', { who: f.resolvedBy ?? '', note: f.note })}>
                  <Tag color={STATUS[v].color}>{t(STATUS[v].key)}</Tag>
                </Tooltip>
              ),
            },
            {
              title: t('actions'), width: 300, fixed: wideTable ? 'right' : undefined,
              render: (_, f) => (
                <TableActions>
                  {f.sessionId && <Link to={`/chat/${f.sessionId}`}>{t('openSession')}</Link>}
                  {canChat(f.groupId) && f.status === 'open' && <Button size="small" icon={<RobotOutlined />} onClick={() => handTo([f])}>AI</Button>}
                  {canAct(f.groupId) && f.status === 'open' && <Button size="small" onClick={() => setActing({ row: f, next: 'resolved' })}>{t('markResolved')}</Button>}
                  {canAct(f.groupId) && f.status === 'open' && <Button size="small" onClick={() => setActing({ row: f, next: 'ignored' })}>{t('markIgnored')}</Button>}
                  {canAct(f.groupId) && f.status !== 'open' && <Button size="small" onClick={() => change(f, 'open')}>{t('reopen')}</Button>}
                </TableActions>
              ),
            },
          ]}
        />}
      </FilterCard>
      <ResolveModal
        open={!!acting}
        title={`${t(acting?.next === 'ignored' ? 'findingIgnoreTitle' : 'findingResolveTitle')} · ${acting?.row.title ?? ''}`}
        hint={t(acting?.next === 'ignored' ? 'findingIgnoreHint' : 'findingResolveHint')}
        onCancel={() => setActing(null)}
        onSubmit={async note => { if (!await change(acting!.row, acting!.next, note)) throw new Error() }}
      />
    </Page>
  )
}
