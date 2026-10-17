import { DeleteOutlined, PlusOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Card, Col, Empty, Input, Popconfirm, Result, Row, Space, Table, Tabs, Tag, Typography } from 'antd'
import { useState } from 'react'
import { Link } from 'react-router'
import { createPolicy, decideApproval, deletePolicy, fetchApprovals, fetchAssets, fetchPolicies, type Approval, type CommandPolicy } from '../api'
import { useSession } from '../app/session'
import { HostLink } from '../components/HostLink'
import { Page } from '../components/Page'
import { fmtTime, errText } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

const STATUS: Record<Approval['status'], { key: MsgKey; color: string }> = {
  pending: { key: 'apPending', color: 'processing' },
  approved: { key: 'apApproved', color: 'success' },
  rejected: { key: 'apRejected', color: 'error' },
  expired: { key: 'apExpired', color: 'default' },
  cancelled: { key: 'apCancelled', color: 'default' },
  consumed: { key: 'apConsumed', color: 'success' },
}

// 名单：AI 走白名单（命中才免审批），人工走黑名单（命中才要审批）
function PolicyCard({ groupId, origin, rows }: { groupId: string; origin: 'ai' | 'human'; rows: CommandPolicy[] }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const [pattern, setPattern] = useState('')
  const run = async (fn: () => Promise<unknown>) => {
    try {
      await fn()
      await client.invalidateQueries({ queryKey: ['policies', groupId] })
    } catch (e) {
      message.error(errText(e, t))
    }
  }
  const add = () => run(async () => { await createPolicy(groupId, origin, pattern.trim()); setPattern('') })

  return (
    <Card title={t(origin === 'ai' ? 'policyAiTitle' : 'policyHumanTitle')} style={{ height: '100%' }}>
      <Typography.Paragraph type="secondary">{t(origin === 'ai' ? 'policyAiHint' : 'policyHumanHint')}</Typography.Paragraph>
      <Table<CommandPolicy>
        size="small"
        bordered
        showHeader={false}
        rowKey="id"
        pagination={false}
        dataSource={rows.filter(p => p.origin === origin)}
        locale={{ emptyText: t('policyEmpty') }}
        columns={[
          { dataIndex: 'pattern', render: v => <code className="cmd-cell">{v}</code> },
          {
            width: 56,
            render: (_, p) => (
              <Popconfirm title={t('confirmDelete')} onConfirm={() => run(() => deletePolicy(p.id))}>
                <Button type="text" danger size="small" icon={<DeleteOutlined />} />
              </Popconfirm>
            ),
          },
        ]}
      />
      <Space.Compact style={{ width: '100%', marginTop: 12 }}>
        <Input className="mono" placeholder={t('policyPattern')} value={pattern} onChange={e => setPattern(e.target.value)} onPressEnter={() => pattern.trim() && add()} />
        <Button type="primary" icon={<PlusOutlined />} disabled={!pattern.trim()} onClick={add}>{t('add')}</Button>
      </Space.Compact>
    </Card>
  )
}

// 审批中心：名单外命令在这里放行或拒绝；命令名单也在这里配
export function ApprovalsPage() {
  const { t } = useI18n()
  const { message, modal } = App.useApp()
  const { group } = useSession()
  const isGroupAdmin = group?.role === 'admin'
  const approvals = useQuery({
    queryKey: ['approvals', group?.id],
    queryFn: () => fetchApprovals(group!.id),
    enabled: !!group && isGroupAdmin,
    refetchInterval: 3_000,
  })
  const policies = useQuery({ queryKey: ['policies', group?.id], queryFn: () => fetchPolicies(group!.id), enabled: !!group && isGroupAdmin })
  const { data: hosts = {} } = useQuery({ queryKey: ['assets'], queryFn: fetchAssets, select: as => Object.fromEntries(as.map(a => [a.id, a.hostname])) })

  if (!group) return <Empty style={{ marginTop: 120 }} description={t('noGroupsHint')} />
  if (!isGroupAdmin) return <Result status="403" title="403" subTitle={t('groupAdminOnly', { name: group.name })} />

  const decide = (a: Approval, approve: boolean) => {
    const go = () => decideApproval(a.id, approve).then(() => approvals.refetch()).catch(e => message.error(errText(e, t)))
    if (!approve) return go()
    modal.confirm({
      title: t(a.dry_run ? 'apConfirmDryTitle' : 'apConfirmLiveTitle', { host: hosts[a.asset_id] ?? a.asset_id }),
      content: <pre className="chat-code">{a.cmd}</pre>,
      okButtonProps: { danger: !a.dry_run },
      onOk: go,
    })
  }

  const all = approvals.data ?? []
  const pending = all.filter(a => a.status === 'pending')
  const columns = (withActions: boolean) => [
    { title: t('thTime'), dataIndex: 'created_at', width: 170, render: fmtTime },
    { title: t('thHostname'), dataIndex: 'asset_id', width: 140, render: (v: string) => <HostLink id={v} /> },
    { title: t('apCmd'), dataIndex: 'cmd', render: (v: string) => <code className="cmd-cell">{v}</code> },
    { title: t('thMode'), dataIndex: 'dry_run', width: 90, render: (v: boolean) => <Tag color={v ? 'default' : 'red'}>{t(v ? 'dryRun' : 'liveRun')}</Tag> },
    { title: t('apRequester'), width: 140, render: (_: unknown, a: Approval) => <Space size={4}><Tag>{a.origin === 'ai' ? 'AI' : t('human')}</Tag>{a.requested_by}</Space> },
    { title: t('apSession'), dataIndex: 'session_id', width: 100, render: (v?: string) => (v ? <Link to={`/chat/${v}`}>{t('openSession')}</Link> : '-') },
    ...(withActions
      ? [
          { title: t('apExpiresAt'), dataIndex: 'expires_at', width: 170, render: fmtTime },
          {
            title: t('actions'), width: 150,
            render: (_: unknown, a: Approval) => (
              <Space>
                <Button size="small" type="primary" onClick={() => decide(a, true)}>{t('apApprove')}</Button>
                <Button size="small" danger onClick={() => decide(a, false)}>{t('apReject')}</Button>
              </Space>
            ),
          },
        ]
      : [
          { title: t('thStatus'), dataIndex: 'status', width: 100, render: (v: Approval['status']) => <Tag color={STATUS[v].color}>{t(STATUS[v].key)}</Tag> },
          { title: t('apDecidedBy'), dataIndex: 'decided_by', width: 110, render: (v?: string) => v ?? '-' },
        ]),
  ]

  return (
    <Page title={t('navApprovals')} subtitle={t('approvalsSubtitle', { name: group.name })}>
      <Card>
        <Tabs
          items={[
            {
              key: 'pending',
              label: t('apTabQueue', { n: pending.length }),
              children: <Table<Approval> rowKey="id" size="small" loading={approvals.isPending} dataSource={pending} pagination={false} columns={columns(true)} locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('apNone')} /> }} />,
            },
            {
              key: 'history',
              label: t('apTabHistory'),
              children: <Table<Approval> rowKey="id" size="small" dataSource={all.filter(a => a.status !== 'pending')} pagination={{ pageSize: 20, hideOnSinglePage: true }} columns={columns(false)} />,
            },
            {
              key: 'policies',
              label: t('apTabPolicies'),
              children: (
                <Space orientation="vertical" size={16} style={{ width: '100%' }}>
                  <Alert type="info" showIcon title={t('policyRegexHint')} />
                  <Row gutter={16}>
                    <Col xs={24} lg={12}><PolicyCard groupId={group.id} origin="ai" rows={policies.data ?? []} /></Col>
                    <Col xs={24} lg={12}><PolicyCard groupId={group.id} origin="human" rows={policies.data ?? []} /></Col>
                  </Row>
                </Space>
              ),
            },
          ]}
        />
      </Card>
    </Page>
  )
}
