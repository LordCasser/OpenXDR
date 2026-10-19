import { ArrowLeftOutlined, RobotOutlined } from '@ant-design/icons'
import { AssetVulns } from '../components/AssetVulns'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, App, Button, Card, Col, Descriptions, Empty, Form, Result, Row, Select, Skeleton, Space, Switch, Table, Tabs, Tag, Tooltip, Typography,
  theme,
} from 'antd'
import { useEffect, useState, type ReactNode } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import {
  createAgentSession, fetchAgentConfig, fetchAssets, fetchCommands, fetchFindings, fetchIncidents, saveAgentConfig, searchEvents,
  type AgentConfig, type CommandRow, type FindingRow, type IncidentSummary,
} from '../api'
import { useRemember } from '../app/recent'
import { saveQueue } from '../components/incidentQueue'
import { useRowLink } from '../components/rowLink'
import { useCanActIn, useSession } from '../app/session'
import { CommandVerificationDrawer } from '../components/CommandVerificationDrawer'
import { LocalAccounts } from '../components/LocalAccounts'
import { IdentityObservations } from '../components/IdentityObservations'
import { TemporalGaps } from '../components/TemporalGaps'
import { CollectorHealth } from '../components/CollectorHealth'
import { AssetProfileView } from '../components/AssetProfile'
import { LoadError } from '../components/LoadError'
import { Page, WIDE_ONLY, useWideTable } from '../components/Page'
import { eventSummary } from '../components/eventSummary'
import {
  CLASS_KEY, CommandStatusTag, HostStateBadge, IncidentStatusTag, SeverityTag, commandKind, errText, fmtTime,
} from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

const FINDING_SEVERITY: Record<FindingRow['severity'], number> = { info: 1, low: 2, medium: 3, high: 4 }
const INCIDENT_PAGE = 10

// 详情页顶部的小指标：标签在上、数值在下，可点进对应标签页
function Stat({ label, value, tone, onClick }: { label: string; value: ReactNode; tone?: string; onClick?: () => void }) {
  const { token } = theme.useToken()
  return (
    <Card size="small" hoverable={!!onClick} onClick={onClick} styles={{ body: { padding: '14px 18px' } }}>
      <Typography.Text type="secondary" style={{ fontSize: 13 }}>{label}</Typography.Text>
      <div style={{ fontSize: 24, fontWeight: 600, marginTop: 2, color: tone ?? token.colorText, fontVariantNumeric: 'tabular-nums' }}>{value}</div>
    </Card>
  )
}
const SWITCHES: { name: keyof AgentConfig; key: MsgKey }[] = [
  { name: 'collectFiles', key: 'cfgFiles' },
  { name: 'collectAuth', key: 'cfgAuth' },
  { name: 'collectPersist', key: 'cfgPersist' },
  { name: 'collectNetwork', key: 'cfgNetwork' },
  { name: 'collectInventory', key: 'cfgInventory' },
  { name: 'collapsePeriodic', key: 'cfgCollapse' },
]

// 采集配置：开关缺省全开；目录为空表示用 agent 内置的敏感目录清单
function ConfigTab({ assetId, canEdit }: { assetId: string; canEdit: boolean }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const [form] = Form.useForm()
  const [saving, setSaving] = useState(false)
  const { data, isPending } = useQuery({ queryKey: ['agentConfig', assetId], queryFn: () => fetchAgentConfig(assetId) })

  useEffect(() => {
    if (!data) return
    form.setFieldsValue({
      ...Object.fromEntries(SWITCHES.map(s => [s.name, data[s.name] !== false])),
      fileWatchDirs: data.fileWatchDirs ?? [],
    })
  }, [data, form])

  const save = async (v: Record<string, unknown>) => {
    setSaving(true)
    try {
      const cfg: AgentConfig = { fileWatchDirs: (v.fileWatchDirs as string[]).length ? (v.fileWatchDirs as string[]) : undefined }
      // 只写关掉的开关，开着的留空 = 用 agent 默认，配置里不堆冗余字段
      for (const s of SWITCHES) if (v[s.name] === false) (cfg as Record<string, unknown>)[s.name] = false
      await saveAgentConfig(assetId, cfg)
      message.success(t('cfgSaved'))
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      setSaving(false)
    }
  }

  if (isPending) return <Skeleton active />
  return (
    <Form form={form} layout="horizontal" labelCol={{ span: 6 }} wrapperCol={{ span: 14 }} onFinish={save} disabled={!canEdit} style={{ maxWidth: 720 }}>
      <Alert type="info" showIcon title={t('cfgHint')} style={{ marginBottom: 20 }} />
      {SWITCHES.map(s => (
        <Form.Item key={s.name} name={s.name} label={t(s.key)} valuePropName="checked">
          <Switch />
        </Form.Item>
      ))}
      <Form.Item name="fileWatchDirs" label={t('cfgDirs')} extra={t('cfgDirsHint')}>
        <Select mode="tags" tokenSeparators={[',', ' ']} placeholder="/etc /root/.ssh" />
      </Form.Item>
      {canEdit && (
        <Form.Item wrapperCol={{ offset: 6 }}>
          <Button type="primary" htmlType="submit" loading={saving}>{t('save')}</Button>
        </Form.Item>
      )}
    </Form>
  )
}

export function AssetDetailPage() {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const { id } = useParams()
  const navigate = useNavigate()
  const client = useQueryClient()
  const { message } = App.useApp()
  const { groups, isAdmin } = useSession()
  const [starting, setStarting] = useState(false)
  // 从攻击面等处带 ?tab= 进来时直接打开对应标签
  const [tab, setTab] = useState(() => new URLSearchParams(window.location.search).get('tab') ?? 'incidents')
  const [verifying, setVerifying] = useState<CommandRow | null>(null)
  const [incPage, setIncPage] = useState(1)
  const assets = useQuery({ queryKey: ['assets'], queryFn: fetchAssets, refetchInterval: 15000 })
  const asset = assets.data?.find(a => a.id === id)
  const canAct = useCanActIn(asset?.groupId)
  const incidents = useQuery({
    queryKey: ['incidents', 'asset', id, incPage],
    queryFn: () => fetchIncidents({ assetId: id, limit: INCIDENT_PAGE, offset: (incPage - 1) * INCIDENT_PAGE }),
    enabled: !!asset,
  })
  const unresolved = useQuery({ queryKey: ['incidents', 'asset', id, 'unresolved'], queryFn: () => fetchIncidents({ assetId: id, status: 'unresolved', limit: 1 }), enabled: !!asset })
  const findings = useQuery({ queryKey: ['findings', 'all'], queryFn: () => fetchFindings(), enabled: !!asset, select: fs => fs.filter(f => f.assetId === id) })
  const events = useQuery({ queryKey: ['events', 'asset', id], queryFn: () => searchEvents({ assetId: id, hours: 168 }), enabled: !!asset })
  const commands = useQuery({ queryKey: ['commands', 'asset', id], queryFn: () => fetchCommands({ assetId: id! }), enabled: !!asset })

  // 手机上标题换行完整显示，不截断成看不出是什么的半句
  const wideTable = useWideTable()
  const rowLink = useRowLink<IncidentSummary>(r => `/incidents/${r.id}`)
  useEffect(() => { if (incidents.data) saveQueue(incidents.data.items) }, [incidents.data])
  useRemember(asset && { to: `/assets/${asset.id}`, label: asset.hostname, kind: 'asset' })

  if (assets.isPending) return <Skeleton active style={{ marginTop: 24 }} />
  if (assets.isError) return <LoadError error={assets.error} onRetry={() => assets.refetch()} />
  if (!asset) return <Result status="404" title={t('assetNotFound')} extra={<Button onClick={() => navigate('/assets')}>{t('backToList')}</Button>} />

  const group = groups.find(g => g.id === asset.groupId)
  // 对话只看组内角色（后端同口径），全局只读的组内分析师也能发起排查
  const canChat = group?.role === 'admin' || group?.role === 'analyst'
  const openFindings = (findings.data ?? []).filter(f => f.status === 'open')
  const eventCount = events.data ? `${events.data.items.length}${events.data.truncated ? '+' : ''}` : '-'

  // 一键排查：在主机所在组新建对话，把主机名预填进提问
  const investigate = async () => {
    if (!asset.groupId) return
    setStarting(true)
    try {
      const s = await createAgentSession({ groupId: asset.groupId, title: t('investigateTitle', { host: asset.hostname }) })
      client.invalidateQueries({ queryKey: ['sessions', asset.groupId] })
      navigate(`/chat/${s.id}?prompt=${encodeURIComponent(t('investigatePrompt', { host: asset.hostname }))}`)
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      setStarting(false)
    }
  }

  return (
    <Page
      crumb={asset.hostname}
      title={<Space><Button type="text" icon={<ArrowLeftOutlined />} onClick={() => navigate('/assets')} />{asset.hostname}<HostStateBadge asset={asset} /></Space>}
      subtitle={[asset.os, asset.ipAddrs?.join(', '), group?.name ?? t('ungrouped')].filter(Boolean).join(' · ')}
      extra={canChat && asset.groupId && <Button type="primary" icon={<RobotOutlined />} loading={starting} onClick={investigate}>{t('investigateHost')}</Button>}
    >
      {verifying?.assetId === asset.id && <CommandVerificationDrawer key={`${verifying.id}:${asset.groupId}`} command={verifying} canEdit={canAct} onClose={() => setVerifying(null)} />}
      <Row gutter={[16, 16]}>
        <Col xs={12} xl={6}>
          <Stat label={t('unresolvedIncidents')} value={unresolved.data?.total ?? '-'} tone={unresolved.data?.total ? token.colorError : undefined} onClick={() => setTab('incidents')} />
        </Col>
        <Col xs={12} xl={6}>
          <Stat label={t('navFindings')} value={findings.data ? openFindings.length : '-'} tone={openFindings.length ? token.colorWarning : undefined} onClick={() => setTab('findings')} />
        </Col>
        <Col xs={12} xl={6}>
          <Stat label={t('tabEvents')} value={eventCount} onClick={() => setTab('events')} />
        </Col>
        <Col xs={12} xl={6}>
          <Stat label={t('thLastSeen')} value={<span style={{ fontSize: 17 }}>{asset.agentId ? fmtTime(asset.lastSeen).slice(5) : '—'}</span>} />
        </Col>

        <Col span={24}><CollectorHealth asset={asset} /></Col>
        <Col xs={24} xl={17}>
          <Card styles={{ body: { paddingTop: 4 } }}>
            <Tabs
              activeKey={tab}
              onChange={setTab}
              items={[
                {
                  key: 'incidents',
                  label: t('tabIncidents', { n: incidents.data?.total ?? 0 }),
                  children: incidents.isError ? <LoadError error={incidents.error} onRetry={() => incidents.refetch()} /> : (
                    <Table<IncidentSummary> size="small" rowKey="id" rowClassName="row-link" onRow={rowLink} loading={incidents.isPending} dataSource={incidents.data?.items ?? []}
                      pagination={{ current: incPage, pageSize: INCIDENT_PAGE, total: incidents.data?.total, hideOnSinglePage: true, onChange: setIncPage }}
                      locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noIncidents')} /> }}
                      columns={[
                        { title: t('thSeverity'), dataIndex: 'severity', width: 90, render: v => <SeverityTag value={v} /> },
                        { title: t('thTitle'), dataIndex: 'title', ellipsis: wideTable, render: (v, r) => <Link to={`/incidents/${r.id}`}>{v ?? r.id}</Link> },
                        { title: t('thStatus'), dataIndex: 'status', width: 100, render: v => <IncidentStatusTag value={v} /> },
                        { responsive: WIDE_ONLY, title: t('thCreatedAt'), dataIndex: 'createdAt', width: 170, render: fmtTime },
                      ]} />
                  ),
                },
                {
                  key: 'findings',
                  label: t('tabFindings', { n: openFindings.length }),
                  children: (
                    <Table size="small" rowKey="id" loading={findings.isPending} dataSource={findings.data ?? []} pagination={{ pageSize: 10, hideOnSinglePage: true }}
                      locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noFindings')} /> }}
                      expandable={{ expandedRowRender: f => <pre className="tooltip-pre">{f.detail || '-'}</pre> }}
                      columns={[
                        { title: t('thSeverity'), dataIndex: 'severity', width: 90, render: v => <SeverityTag value={FINDING_SEVERITY[v as FindingRow['severity']]} /> },
                        { title: t('thTitle'), dataIndex: 'title', ellipsis: true },
                        { title: t('thStatus'), dataIndex: 'status', width: 100, render: v => <Tag>{t(FINDING_STATUS_KEY[v as FindingRow['status']])}</Tag> },
                        { title: t('thLastConfirmed'), dataIndex: 'lastSeen', width: 170, render: fmtTime },
                      ]} />
                  ),
                },
                {
                  key: 'events',
                  label: t('tabEvents'),
                  children: events.isError ? <LoadError error={events.error} onRetry={() => events.refetch()} /> : (
                    <>
                      {events.data?.truncated && <Alert type="info" showIcon title={t('listTruncated', { n: events.data.items.length })} style={{ marginBottom: 12 }} />}
                      <Table size="small" rowKey="id" loading={events.isPending} dataSource={events.data?.items ?? []} pagination={{ pageSize: 20, hideOnSinglePage: true }}
                        expandable={{ expandedRowRender: r => <pre className="json-block">{JSON.stringify(r.raw, null, 2)}</pre> }}
                        columns={[
                          { title: t('thTime'), dataIndex: 'ts', render: fmtTime, width: 170 },
                          { title: t('thClass'), dataIndex: 'classUid', width: 90, render: v => (CLASS_KEY[v] ? t(CLASS_KEY[v]) : v) },
                          { title: t('thDetail'), ellipsis: true, render: (_, r) => <span className="mono">{eventSummary(r.classUid, r.raw, t) || r.connTuple || '-'}</span> },
                          { title: t('thUser'), dataIndex: 'username', width: 120, render: v => v ?? '-' },
                        ]} />
                    </>
                  ),
                },
                {
                  key: 'commands',
                  label: t('tabCommands'),
                  children: commands.isError ? <LoadError error={commands.error} onRetry={() => commands.refetch()} /> : (
                    <Table size="small" rowKey="id" loading={commands.isPending} dataSource={commands.data ?? []} pagination={{ pageSize: 10, hideOnSinglePage: true }}
                      locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noCommands')} /> }}
                      columns={[
                        { title: t('thTime'), dataIndex: 'createdAt', render: fmtTime, width: 170 },
                        { title: t('thAction'), dataIndex: 'kind', width: 200, render: (v, c) => <>{commandKind(v, t)}{c.target && <Typography.Text className="mono" type="secondary" style={{ display: 'block', fontSize: 12 }}>{c.target}</Typography.Text>}</> },
                        { title: t('thStatus'), dataIndex: 'status', width: 100, render: v => <CommandStatusTag value={v} /> },
                        { title: t('thCreatedBy'), dataIndex: 'issuedBy', width: 110 },
                        { title: t('verificationTitle'), width: 100, render: (_, row: CommandRow) => <Button size="small" onClick={() => setVerifying(row)}>{t('verificationTitle')}</Button> },
                        { title: t('thResult'), dataIndex: 'detail', ellipsis: true },
                        {
                          title: t('thDetections'), dataIndex: 'detections', width: 220,
                          render: (v: CommandRow['detections']) => v?.length
                            ? <Tooltip title={t('commandDetectionsHint')}>{v.map(d => <Tag key={d.ruleId} color="orange" variant="filled" title={d.author && t('ruleBy', { author: d.author })}>{d.title || d.ruleId} ×{d.count}</Tag>)}</Tooltip>
                            : null,
                        },
                      ]} />
                  ),
                },
                { key: 'detectionGaps', label: t('temporalGapsTitle'), children: tab === 'detectionGaps' ? <TemporalGaps key={asset.id} asset={asset} /> : null },
                { key: 'localAccounts', label: t('collectorLocalAccounts'), children: tab === 'localAccounts' ? <LocalAccounts key={asset.id} asset={asset} /> : null },
                { key: 'identity', label: t('identityTitle'), children: tab === 'identity' ? <IdentityObservations key={asset.id} asset={asset} /> : null },
                { key: 'vulns', label: t('tabVulns'), children: tab === 'vulns' ? <AssetVulns key={asset.id} assetId={asset.id} /> : null },
                { key: 'config', label: t('tabConfig'), children: <ConfigTab assetId={asset.id} canEdit={canAct} /> },
              ]}
            />
          </Card>
        </Col>
        <Col xs={24} xl={7}>
          <Card title={t('profileTitle')} style={{ marginBottom: 16 }}>
            <AssetProfileView assetId={asset.id} hostname={asset.hostname} groupId={asset.groupId} canEdit={canAct} isGroupAdmin={isAdmin || group?.role === 'admin'} compact />
          </Card>
          <Card title={t('hostInfo')}>
            <Descriptions column={1} size="small">
              <Descriptions.Item label="OS">{asset.os ?? '-'}</Descriptions.Item>
              <Descriptions.Item label={t('thIP')}>{asset.ipAddrs?.join(', ') ?? '-'}</Descriptions.Item>
              <Descriptions.Item label={t('group')}>{group?.name ?? <Tag>{t('ungrouped')}</Tag>}</Descriptions.Item>
              <Descriptions.Item label={t('thSource')}>{asset.agentId ? 'agent' : t('sourceLog')}</Descriptions.Item>
              <Descriptions.Item label={t('agentVersion')}>{asset.agentVersion ?? '-'}</Descriptions.Item>
              <Descriptions.Item label={t('firstSeen')}>{fmtTime(asset.firstSeen)}</Descriptions.Item>
              <Descriptions.Item label={t('thLastSeen')}>{asset.agentId ? fmtTime(asset.lastSeen) : '—'}</Descriptions.Item>
              <Descriptions.Item label="Agent ID">{asset.agentId ? <Typography.Text className="mono" copyable ellipsis style={{ maxWidth: 200 }}>{asset.agentId}</Typography.Text> : '-'}</Descriptions.Item>
              <Descriptions.Item label="ID"><Typography.Text className="mono" copyable ellipsis style={{ maxWidth: 200 }}>{asset.id}</Typography.Text></Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
      </Row>
    </Page>
  )
}

const FINDING_STATUS_KEY: Record<FindingRow['status'], MsgKey> = { open: 'findingOpen', resolved: 'findingResolved', ignored: 'findingIgnored' }
