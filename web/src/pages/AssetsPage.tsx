import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ImportOutlined, PlusOutlined, RobotOutlined } from '@ant-design/icons'
import { App, Button, Input, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { Ago, EmptyHint, Refreshed } from '../components/Ago'
import { assignAsset, fetchAssets, unassignAsset, type Asset } from '../api'
import { useSession } from '../app/session'
import { useCanChat, useHandoff } from '../components/Handoff'
import { ImportHostsModal } from '../components/ImportHostsModal'
import { LoadError } from '../components/LoadError'
import { AddHostModal } from '../components/AddHostModal'
import { errText, HostStateBadge, hostState } from '../components/format'
import { FilterCard, Page, STICKY_HEADER, WIDE_ONLY, useWideTable } from '../components/Page'
import { useRowLink } from '../components/rowLink'
import { useI18n } from '../i18n'

// 心跳超过 5 分钟视为失联——agent 掉线本身就是值得注意的信号
const UNGROUPED = '__none__'

export function AssetsPage() {
  const { t } = useI18n()
  const { message, modal } = App.useApp()
  const client = useQueryClient()
  const { groups, isAdmin } = useSession()
  // 搜索与组筛选放 URL：从详情页返回、刷新都还在
  const [params, setParams] = useSearchParams()
  const q = params.get('q') ?? ''
  const [draft, setDraft] = useState(q)
  useEffect(() => setDraft(q), [q])
  const groupFilter = params.get('group') ?? ''
  const setFilter = (patch: { q?: string; group?: string }) =>
    setParams(Object.fromEntries(Object.entries({ q, group: groupFilter, ...patch }).filter(([, v]) => v)), { replace: true })
  const [adding, setAdding] = useState(false)
  const [importing, setImporting] = useState(false)
  // 组 admin 才能为本组签发接入令牌
  const canAdd = groups.some(g => g.role === 'admin')
  const { data, isPending, isFetching, isError, error, dataUpdatedAt, refetch } = useQuery({ queryKey: ['assets'], queryFn: fetchAssets, refetchInterval: 30_000 })

  const wideTable = useWideTable()
  const rowLink = useRowLink<Asset>(a => `/assets/${a.id}`)
  // 批量：多台同组主机一起交给 AI 巡检；管理员可以一起移组
  const [selected, setSelected] = useState<string[]>([])
  const canChat = useCanChat()
  const handoff = useHandoff()
  const imported = (a: Asset) => hostState(a) === 'imported'
  const rows = (data ?? []).filter(a =>
    (!q || a.hostname.toLowerCase().includes(q.toLowerCase()) || a.ipAddrs?.some(ip => ip.includes(q))) &&
    (!groupFilter || (groupFilter === UNGROUPED ? !a.groupId : a.groupId === groupFilter)),
  )

  // 归组只有全局 admin 能改：一台主机只属于一个组，选新组即离开旧组，原组成员当场失去权限，先确认
  const move = (a: Asset, target: string) => modal.confirm({
    title: t('regroupConfirm', { host: a.hostname }),
    content: a.groupId ? t('regroupLeave', { from: groups.find(g => g.id === a.groupId)?.name ?? '-' }) : undefined,
    onOk: () => doMove(a, target),
  })
  const doMove = async (a: Asset, target: string) => {
    try {
      if (target === UNGROUPED) await unassignAsset(a.groupId!, a.id)
      else await assignAsset(target, a.id)
      await client.invalidateQueries({ queryKey: ['assets'] })
      client.invalidateQueries({ queryKey: ['groups'] })
    } catch (e) {
      message.error(errText(e, t))
    }
  }

  const picked = (data ?? []).filter(a => selected.includes(a.id))
  const pickedGroup = picked[0]?.groupId
  const sameGroup = picked.length > 0 && picked.every(a => a.groupId && a.groupId === pickedGroup)
  const handTo = () => handoff.start(pickedGroup!, [], t('handoffHostsTitle', { n: picked.length }),
    t('handoffHostsPrompt', { hosts: picked.map(a => `${a.hostname} (${a.id})`).join(', ') }))
  const moveMany = (target: string) => modal.confirm({
    title: t('regroupManyConfirm', { n: picked.length }),
    content: picked.some(a => a.groupId) ? t('regroupLeaveMany') : undefined,
    onOk: async () => {
      for (const a of picked) if ((a.groupId ?? UNGROUPED) !== target) await doMove(a, target)
      setSelected([])
    },
  })
  const anyChat = groups.some(g => canChat(g.id))

  const groupOptions = [{ value: UNGROUPED, label: t('ungrouped') }, ...groups.map(g => ({ value: g.id, label: g.name }))]
  const total = data?.length ?? 0
  const up = (data ?? []).filter(a => hostState(a) === 'online').length

  return (
    <Page title={t('navAssets')} subtitle={t('assetsSummary', { total, online: up })}
      extra={canAdd && <Space wrap><Button icon={<ImportOutlined aria-hidden />} onClick={() => setImporting(true)}>{t('hostImport')}</Button><Button type="primary" icon={<PlusOutlined />} onClick={() => setAdding(true)}>{t('addHost')}</Button></Space>}>
      <ImportHostsModal open={importing} onClose={() => setImporting(false)} />
      <AddHostModal open={adding} onClose={() => setAdding(false)} />
      <FilterCard
        onReset={q || groupFilter || draft ? () => { setDraft(''); setParams({}, { replace: true }) } : undefined}
        extra={(
          <Space wrap>
            <Refreshed at={dataUpdatedAt} fetching={isFetching} onRefresh={() => refetch()} />
            {selected.length > 0 && (
              <>
                <Typography.Text type="secondary">{t('batchSelected', { n: selected.length })}</Typography.Text>
                <Tooltip title={!sameGroup ? t('handoffSameGroup') : picked.length > 10 ? t('handoffMax') : undefined}>
                  <Button size="small" type="primary" icon={<RobotOutlined />} loading={handoff.busy}
                    disabled={!sameGroup || picked.length > 10 || !canChat(pickedGroup)} onClick={handTo}>{t('handoffToAI')}</Button>
                </Tooltip>
                {isAdmin && <Select size="small" style={{ width: 160 }} placeholder={t('moveToGroup')} value={null} options={groupOptions} onChange={moveMany} />}
              </>
            )}
          </Space>
        )}
        filters={
          <Space wrap>
            <Input.Search allowClear style={{ width: 280 }} placeholder={t('assetSearchHint')} value={draft} onSearch={v => setFilter({ q: v })} onChange={e => { setDraft(e.target.value); if (!e.target.value) setFilter({ q: '' }) }} />
            <Select showSearch optionFilterProp="label" aria-label={t('group')} style={{ width: 180 }} value={groupFilter} onChange={v => setFilter({ group: v })} options={[{ value: '', label: t('allGroups') }, ...groupOptions]} />
          </Space>
        }
      >
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<Asset>
          sticky={STICKY_HEADER}
          scroll={wideTable ? { x: 1100 } : undefined}
          locale={{ emptyText: <EmptyHint title={t(q || groupFilter ? 'noMatch' : 'noAssets')} hint={q || groupFilter ? undefined : t('noAssetsHint')} /> }}
          rowKey="id"
          rowClassName="row-link"
          onRow={rowLink}
          rowSelection={anyChat || isAdmin ? { selectedRowKeys: selected, onChange: keys => setSelected(keys as string[]) } : undefined}
          loading={isPending}
          dataSource={rows}
          pagination={{ pageSize: 20, hideOnSinglePage: true }}
          columns={[
            {
              title: t('thStatus'), width: 100,
              // 已发过失联通知的标红：这是要人去处理的，不只是暂时没数据
              render: (_, a) => <HostStateBadge asset={a} />,
            },
            { title: t('thHostname'), dataIndex: 'hostname', sorter: (a, b) => a.hostname.localeCompare(b.hostname), render: (v, a) => <Link to={`/assets/${a.id}`}>{v}</Link> },
            { responsive: WIDE_ONLY, title: 'OS', dataIndex: 'os', width: 100, render: v => v ?? '-' },
            { responsive: WIDE_ONLY, title: t('thIP'), dataIndex: 'ipAddrs', render: v => v?.length ? <Typography.Text copyable={{ text: v.join(', ') }}>{v.join(', ')}</Typography.Text> : '-' },
            {
              responsive: WIDE_ONLY, title: t('group'), dataIndex: 'groupId', width: 200,
              render: (v, a) => isAdmin
                ? <Select size="small" style={{ width: 170 }} value={v ?? UNGROUPED} options={groupOptions} onChange={g => move(a, g)} />
                : groups.find(g => g.id === v)?.name ?? <Tag>{t('ungrouped')}</Tag>,
            },
            { responsive: WIDE_ONLY, title: t('thSource'), dataIndex: 'agentId', width: 90, render: (v, a) => <Tag>{v ? 'agent' : t(imported(a) ? 'hostImportedSource' : 'sourceLog')}</Tag> },
            { title: t('thLastSeen'), dataIndex: 'lastSeen', width: 180, render: (v, a) => imported(a) ? '—' : <Ago iso={v} />, sorter: (a, b) => a.lastSeen.localeCompare(b.lastSeen) },
          ]}
        />}
      </FilterCard>
    </Page>
  )
}
