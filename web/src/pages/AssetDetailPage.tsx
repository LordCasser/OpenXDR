import { ArrowLeftOutlined, RobotOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, App, Badge, Button, Card, Col, Descriptions, Empty, Form, Result, Row, Select, Skeleton, Space, Switch, Table, Tabs, Tag, Tooltip,
  Typography,
} from 'antd'
import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import {
  createAgentSession, fetchAgentConfig, fetchAssets, fetchCommands, fetchIncidents, saveAgentConfig, searchEvents, type AgentConfig,
} from '../api'
import { useCanActIn, useSession } from '../app/session'
import { Page } from '../components/Page'
import { CLASS_KEY, IncidentStatusTag, SeverityTag, fmtTime } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

const STALE_MS = 5 * 60_000
const SWITCHES: { name: keyof AgentConfig; key: MsgKey }[] = [
  { name: 'collectFiles', key: 'cfgFiles' },
  { name: 'collectAuth', key: 'cfgAuth' },
  { name: 'collectPersist', key: 'cfgPersist' },
  { name: 'collectNetwork', key: 'cfgNetwork' },
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
      message.error(String(e))
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
  const { id } = useParams()
  const navigate = useNavigate()
  const client = useQueryClient()
  const { message } = App.useApp()
  const { groups } = useSession()
  const [starting, setStarting] = useState(false)
  const assets = useQuery({ queryKey: ['assets'], queryFn: fetchAssets })
  const asset = assets.data?.find(a => a.id === id)
  const canAct = useCanActIn(asset?.groupId)
  const incidents = useQuery({ queryKey: ['incidents', 'asset', id], queryFn: () => fetchIncidents(undefined, id), enabled: !!asset })
  const events = useQuery({ queryKey: ['events', 'asset', id], queryFn: () => searchEvents({ assetId: id, hours: 168 }), enabled: !!asset })
  const commands = useQuery({ queryKey: ['commands', 'asset', id], queryFn: () => fetchCommands({ assetId: id! }), enabled: !!asset })

  if (assets.isPending) return <Skeleton active style={{ marginTop: 24 }} />
  if (!asset) return <Result status="404" title={t('assetNotFound')} extra={<Button onClick={() => navigate('/assets')}>{t('backToList')}</Button>} />

  const online = Date.now() - Date.parse(asset.lastSeen) < STALE_MS
  const group = groups.find(g => g.id === asset.groupId)

  // 一键排查：在主机所在组新建对话（默认演练），把主机名预填进提问
  const investigate = async () => {
    if (!asset.groupId) return
    setStarting(true)
    try {
      const s = await createAgentSession({ groupId: asset.groupId, title: t('investigateTitle', { host: asset.hostname }), dryRun: true })
      client.invalidateQueries({ queryKey: ['sessions', asset.groupId] })
      navigate(`/chat/${s.id}?prompt=${encodeURIComponent(t('investigatePrompt', { host: asset.hostname }))}`)
    } catch (e) {
      message.error(String(e))
    } finally {
      setStarting(false)
    }
  }

  return (
    <Page
      crumb={asset.hostname}
      title={<Space><Button type="text" icon={<ArrowLeftOutlined />} onClick={() => navigate('/assets')} />{asset.hostname}{asset.silentSince
        ? <Tooltip title={t('silentSince', { time: fmtTime(asset.silentSince) })}><Badge status="error" text={t('silent')} /></Tooltip>
        : <Badge status={online ? 'success' : 'default'} text={t(online ? 'online' : 'stale')} />}</Space>}
      extra={canAct && asset.groupId && <Button type="primary" icon={<RobotOutlined />} loading={starting} onClick={investigate}>{t('investigateHost')}</Button>}
    >
      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card>
            <Descriptions column={{ xs: 1, md: 2, xl: 4 }} size="small">
              <Descriptions.Item label="OS">{asset.os ?? '-'}</Descriptions.Item>
              <Descriptions.Item label={t('thIP')}>{asset.ipAddrs?.join(', ') ?? '-'}</Descriptions.Item>
              <Descriptions.Item label={t('group')}>{group?.name ?? <Tag>{t('ungrouped')}</Tag>}</Descriptions.Item>
              <Descriptions.Item label={t('thSource')}>{asset.agentId ? 'agent' : t('sourceLog')}</Descriptions.Item>
              <Descriptions.Item label={t('firstSeen')}>{fmtTime(asset.firstSeen)}</Descriptions.Item>
              <Descriptions.Item label={t('thLastSeen')}>{fmtTime(asset.lastSeen)}</Descriptions.Item>
              <Descriptions.Item label={t('agentVersion')}>{asset.agentVersion ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="Agent ID">{asset.agentId ? <Typography.Text className="mono" copyable style={{ fontSize: 12 }}>{asset.agentId}</Typography.Text> : '-'}</Descriptions.Item>
              <Descriptions.Item label="ID"><Typography.Text className="mono" copyable style={{ fontSize: 12 }}>{asset.id}</Typography.Text></Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
        <Col span={24}>
          <Card>
            <Tabs
              items={[
                {
                  key: 'incidents',
                  label: t('tabIncidents', { n: incidents.data?.length ?? 0 }),
                  children: (
                    <Table size="small" rowKey="id" loading={incidents.isPending} dataSource={incidents.data ?? []} pagination={{ pageSize: 10, hideOnSinglePage: true }}
                      locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noIncidents')} /> }}
                      columns={[
                        { title: t('thSeverity'), dataIndex: 'severity', width: 90, render: v => <SeverityTag value={v} /> },
                        { title: t('thTitle'), dataIndex: 'title', render: (v, r) => <Link to={`/incidents/${r.id}`}>{v ?? r.id}</Link> },
                        { title: t('thStatus'), dataIndex: 'status', width: 100, render: v => <IncidentStatusTag value={v} /> },
                        { title: t('thCreatedAt'), dataIndex: 'createdAt', width: 170, render: fmtTime },
                      ]} />
                  ),
                },
                {
                  key: 'events',
                  label: t('tabEvents'),
                  children: (
                    <Table size="small" rowKey="id" loading={events.isPending} dataSource={events.data ?? []} pagination={{ pageSize: 20, hideOnSinglePage: true }}
                      expandable={{ expandedRowRender: r => <pre className="json-block">{JSON.stringify(r.raw, null, 2)}</pre> }}
                      columns={[
                        { title: t('thTime'), dataIndex: 'ts', render: fmtTime, width: 170 },
                        { title: t('thClass'), dataIndex: 'classUid', width: 110, render: v => (CLASS_KEY[v] ? t(CLASS_KEY[v]) : v) },
                        { title: t('thUser'), dataIndex: 'username', width: 160, render: v => v ?? '-' },
                        { title: t('thDetail'), dataIndex: 'raw', ellipsis: true, render: v => <span className="mono">{JSON.stringify(v)}</span> },
                      ]} />
                  ),
                },
                {
                  key: 'commands',
                  label: t('tabCommands'),
                  children: (
                    <Table size="small" rowKey="id" loading={commands.isPending} dataSource={commands.data ?? []} pagination={{ pageSize: 10, hideOnSinglePage: true }}
                      locale={{ emptyText: t('noCommands') }}
                      columns={[
                        { title: t('thTime'), dataIndex: 'createdAt', render: fmtTime, width: 170 },
                        { title: t('thAction'), dataIndex: 'kind', width: 120 },
                        { title: t('thMode'), dataIndex: 'dryRun', width: 90, render: d => <Tag color={d ? 'default' : 'red'}>{t(d ? 'dryRun' : 'liveRun')}</Tag> },
                        { title: t('thStatus'), dataIndex: 'status', width: 100 },
                        { title: t('thCreatedBy'), dataIndex: 'issuedBy', width: 120 },
                        { title: t('thResult'), dataIndex: 'detail', ellipsis: true },
                      ]} />
                  ),
                },
                { key: 'config', label: t('tabConfig'), children: <ConfigTab assetId={asset.id} canEdit={canAct} /> },
              ]}
            />
          </Card>
        </Col>
      </Row>
    </Page>
  )
}
