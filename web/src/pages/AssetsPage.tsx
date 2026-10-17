import { useQuery, useQueryClient } from '@tanstack/react-query'
import { PlusOutlined } from '@ant-design/icons'
import { App, Badge, Button, Input, Select, Space, Table, Tag, Tooltip } from 'antd'
import { useState } from 'react'
import { Link } from 'react-router'
import { assignAsset, fetchAssets, unassignAsset, type Asset } from '../api'
import { useSession } from '../app/session'
import { ImportHostsModal } from '../components/ImportHostsModal'
import { AddHostModal } from '../components/AddHostModal'
import { fmtTime } from '../components/format'
import { FilterCard, Page } from '../components/Page'
import { useI18n } from '../i18n'

// 心跳超过 5 分钟视为失联——agent 掉线本身就是值得注意的信号
const STALE_MS = 5 * 60_000
const UNGROUPED = '__none__'

export function AssetsPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { groups, isAdmin } = useSession()
  const [q, setQ] = useState('')
  const [groupFilter, setGroupFilter] = useState<string>('')
  const [adding, setAdding] = useState(false)
  const [importing, setImporting] = useState(false)
  // 组 admin 才能为本组签发接入令牌
  const canAdd = groups.some(g => g.role === 'admin')
  const { data, isPending } = useQuery({ queryKey: ['assets'], queryFn: fetchAssets, refetchInterval: 30_000 })

  const imported = (a: Asset) => !a.agentId && Date.parse(a.lastSeen) === 0
  const online = (a: Asset) => Date.now() - Date.parse(a.lastSeen) < STALE_MS
  const rows = (data ?? []).filter(a =>
    (!q || a.hostname.toLowerCase().includes(q.toLowerCase()) || a.ipAddrs?.some(ip => ip.includes(q))) &&
    (!groupFilter || (groupFilter === UNGROUPED ? !a.groupId : a.groupId === groupFilter)),
  )

  // 归组只有全局 admin 能改：一台主机只属于一个组，选新组即离开旧组
  const move = async (a: Asset, target: string) => {
    try {
      if (target === UNGROUPED) await unassignAsset(a.groupId!, a.id)
      else await assignAsset(target, a.id)
      await client.invalidateQueries({ queryKey: ['assets'] })
      client.invalidateQueries({ queryKey: ['groups'] })
    } catch (e) {
      message.error(String(e))
    }
  }

  const groupOptions = [{ value: UNGROUPED, label: t('ungrouped') }, ...groups.map(g => ({ value: g.id, label: g.name }))]
  const total = data?.length ?? 0
  const up = (data ?? []).filter(online).length

  return (
    <Page title={t('navAssets')} subtitle={t('assetsSummary', { total, online: up })}
      extra={canAdd && <Space wrap><Button onClick={() => setImporting(true)}>{t('hostImport')}</Button><Button type="primary" icon={<PlusOutlined />} onClick={() => setAdding(true)}>{t('addHost')}</Button></Space>}>
      <ImportHostsModal open={importing} onClose={() => setImporting(false)} />
      <AddHostModal open={adding} onClose={() => setAdding(false)} />
      <FilterCard
        filters={
          <Space wrap>
            <Input.Search allowClear style={{ width: 280 }} placeholder={t('assetSearchHint')} onSearch={setQ} onChange={e => !e.target.value && setQ('')} />
            <Select style={{ width: 180 }} value={groupFilter} onChange={setGroupFilter} options={[{ value: '', label: t('allGroups') }, ...groupOptions]} />
          </Space>
        }
      >
        <Table<Asset>
          rowKey="id"
          loading={isPending}
          dataSource={rows}
          pagination={{ pageSize: 20, hideOnSinglePage: true }}
          columns={[
            {
              title: t('thStatus'), width: 100,
              // 已发过失联通知的标红：这是要人去处理的，不只是暂时没数据
              render: (_, a) => imported(a) ? <Badge status="default" text={t('hostNotEnrolled')} /> : a.silentSince
                ? <Tooltip title={t('silentSince', { time: fmtTime(a.silentSince) })}><Badge status="error" text={t('silent')} /></Tooltip>
                : <Badge status={online(a) ? 'success' : 'default'} text={t(online(a) ? 'online' : 'stale')} />,
            },
            { title: t('thHostname'), dataIndex: 'hostname', sorter: (a, b) => a.hostname.localeCompare(b.hostname), render: (v, a) => <Link to={`/assets/${a.id}`}>{v}</Link> },
            { title: 'OS', dataIndex: 'os', width: 100, render: v => v ?? '-' },
            { title: t('thIP'), dataIndex: 'ipAddrs', render: v => v?.join(', ') ?? '-' },
            {
              title: t('group'), dataIndex: 'groupId', width: 200,
              render: (v, a) => isAdmin
                ? <Select size="small" style={{ width: 170 }} value={v ?? UNGROUPED} options={groupOptions} onChange={g => move(a, g)} />
                : groups.find(g => g.id === v)?.name ?? <Tag>{t('ungrouped')}</Tag>,
            },
            { title: t('thSource'), dataIndex: 'agentId', width: 90, render: (v, a) => <Tag>{v ? 'agent' : t(imported(a) ? 'hostImportedSource' : 'sourceLog')}</Tag> },
            { title: t('thLastSeen'), dataIndex: 'lastSeen', width: 180, render: (v, a) => imported(a) ? '—' : fmtTime(v), sorter: (a, b) => a.lastSeen.localeCompare(b.lastSeen) },
          ]}
        />
      </FilterCard>
    </Page>
  )
}
