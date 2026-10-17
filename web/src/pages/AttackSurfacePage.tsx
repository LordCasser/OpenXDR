import { ApartmentOutlined, DeleteOutlined, PlusOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, App, Button, Card, Col, Drawer, Empty, Flex, Form, Input, Modal, Popconfirm, Row, Select, Skeleton, Space, Table, Tag, Tooltip, Typography, theme,
} from 'antd'
import { useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import {
  createZone, deleteZone, fetchAttackSurface, fetchZones, updateZone, type BlindSpot, type ExposedService, type ZoneKind, type ZoneRow,
} from '../api'
import { useSession } from '../app/session'
import { CritTag, ExposureTag, ZoneTag, useZoneColor } from '../components/AssetProfile'
import { LoadError } from '../components/LoadError'
import { Page } from '../components/Page'
import { errText, fmtTime } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'

const RISK: Record<string, { key: MsgKey; color: string }> = {
  high: { key: 'riskHigh', color: 'red' },
  medium: { key: 'riskMedium', color: 'orange' },
  low: { key: 'riskLow', color: 'default' },
}

function Stat({ label, value, tone }: { label: string; value: ReactNode; tone?: string }) {
  const { token } = theme.useToken()
  return (
    <Card size="small" styles={{ body: { padding: '14px 18px' } }}>
      <Typography.Text type="secondary" style={{ fontSize: 13 }}>{label}</Typography.Text>
      <div style={{ fontSize: 26, fontWeight: 600, marginTop: 2, color: tone ?? token.colorText, fontVariantNumeric: 'tabular-nums' }}>{value}</div>
    </Card>
  )
}

export function AttackSurfacePage() {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const { group, isAdmin } = useSession()
  const [zonesOpen, setZonesOpen] = useState(false)
  const query = useQuery({ queryKey: ['attackSurface', group?.id], queryFn: () => fetchAttackSurface(group!.id), enabled: !!group })
  const s = query.data
  const isGroupAdmin = isAdmin || group?.role === 'admin'

  return (
    <Page title={t('navAttackSurface')} subtitle={t('surfaceSubtitle')}
      extra={group && <Button icon={<ApartmentOutlined />} onClick={() => setZonesOpen(true)}>{t('manageZones')}</Button>}>
      {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : (
        <Flex vertical gap={16}>
          <Row gutter={[16, 16]}>
            <Col xs={12} lg={6} xl={4}><Stat label={t('surfInternet')} value={s?.summary.internet ?? '-'} tone={s?.summary.internet ? token.colorError : undefined} /></Col>
            <Col xs={12} lg={6} xl={4}><Stat label={t('surfDmz')} value={s?.summary.dmz ?? '-'} tone={s?.summary.dmz ? token.colorWarning : undefined} /></Col>
            <Col xs={12} lg={6} xl={4}><Stat label={t('surfInternal')} value={s?.summary.internal ?? '-'} /></Col>
            <Col xs={12} lg={6} xl={4}><Stat label={t('surfHigh')} value={s?.summary.high ?? '-'} tone={s?.summary.high ? token.colorError : undefined} /></Col>
            <Col xs={12} lg={6} xl={4}><Stat label={t('surfBlind')} value={s?.summary.blind ?? '-'} tone={s?.summary.blind ? token.colorWarning : undefined} /></Col>
          </Row>
          {!!s?.summary.noInventory.length && (
            <Alert type="info" showIcon title={t('surfNoInventory', { n: s.summary.noInventory.length, hosts: s.summary.noInventory.slice(0, 8).join('、') })} />
          )}
          <Card title={t('exposuresTitle')} extra={<Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('portGuessHint')}</Typography.Text>} styles={{ body: { padding: 0 } }}>
            <Table<ExposedService> rowKey={e => `${e.assetId}/${e.proto}/${e.addr}/${e.port}`} loading={query.isPending} dataSource={s?.exposures ?? []}
              scroll={{ x: 1100 }} pagination={{ pageSize: 20, hideOnSinglePage: true }}
              locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
              columns={[
                { title: t('thScore'), dataIndex: 'score', width: 96, sorter: (a, b) => a.score - b.score, render: v => <Typography.Text strong>{v}</Typography.Text> },
                { title: t('thHostname'), dataIndex: 'hostname', width: 150, render: (v, e) => <Link to={`/assets/${e.assetId}`}>{v}</Link> },
                { title: t('thService'), width: 260, render: (_, e) => (
                  <Space size={4} wrap>
                    <span className="mono">{e.proto}/{e.port}</span>
                    <Typography.Text type="secondary">{e.service.name || t('serviceUnknown')}</Typography.Text>
                    <Tag color={RISK[e.service.risk].color}>{t(RISK[e.service.risk].key)}</Tag>
                  </Space>
                ) },
                { title: t('thLevel'), dataIndex: 'level', width: 120, render: (v, e) => <Space size={4} wrap><ExposureTag level={v} />{e.fromPublic && <Tag color="volcano">{t('fromPublicTag')}</Tag>}</Space> },
                { title: t('zoneLabel'), width: 120, render: (_, e) => <ZoneTag zone={e.zone} /> },
                { title: t('criticality'), dataIndex: 'criticality', width: 110, render: v => <CritTag value={v} /> },
                { title: t('listenProcess'), dataIndex: 'process', width: 130, render: v => v ?? '-' },
                { title: t('thBind'), dataIndex: 'addr', width: 130, render: v => <span className="mono">{v}</span> },
                { title: t('thPeers'), render: (_, e) => e.peerCount === 0 ? '-' : (
                  <Tooltip title={(e.peers ?? []).join(', ')}>
                    <span>{(e.peers ?? []).slice(0, 3).join(', ')}{e.peerCount > 3 && ` +${e.peerCount - 3}`}</span>
                  </Tooltip>
                ) },
              ]} />
          </Card>
          <Card title={t('blindTitle')} styles={{ body: { padding: 0 } }}>
            <Table<BlindSpot> rowKey="ip" loading={query.isPending} dataSource={s?.blind ?? []} pagination={{ pageSize: 10, hideOnSinglePage: true }}
              scroll={{ x: 900 }} locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
              columns={[
                { title: t('thIP'), dataIndex: 'ip', width: 160, render: v => <span className="mono">{v}</span> },
                { title: t('zoneLabel'), width: 120, render: (_, b) => <ZoneTag zone={b.zone} /> },
                { title: t('thPorts'), dataIndex: 'ports', render: (v: string[]) => v.length ? v.map(p => <Tag key={p} className="mono">{p}</Tag>) : '-' },
                { title: t('thAccessed'), dataIndex: 'accessed', render: (v: string[]) => v.length ? v.map(p => <Tag key={p} className="mono">{p}</Tag>) : '-' },
                { title: t('thSeenBy'), dataIndex: 'seenBy', render: (v: string[]) => v.join(', ') },
                { title: t('thConnCount'), dataIndex: 'count', width: 110, align: 'right' },
                { title: t('thLastActive'), dataIndex: 'lastSeen', width: 170, render: fmtTime },
              ]} />
          </Card>
        </Flex>
      )}
      {group && <ZonesDrawer open={zonesOpen} groupId={group.id} canEdit={isGroupAdmin} onClose={() => setZonesOpen(false)} />}
    </Page>
  )
}

const KINDS: { value: ZoneKind; key: MsgKey }[] = [
  { value: 'internal', key: 'zoneInternal' }, { value: 'dmz', key: 'zoneDmz' }, { value: 'external', key: 'zoneExternal' }, { value: 'cloud', key: 'zoneCloud' },
]

// 区域定义：组 admin 可改，其余只读
function ZonesDrawer({ open, groupId, canEdit, onClose }: { open: boolean; groupId: string; canEdit: boolean; onClose: () => void }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const color = useZoneColor()
  const [editing, setEditing] = useState<ZoneRow | 'new' | null>(null)
  const [busy, setBusy] = useState(false)
  const [form] = Form.useForm()
  const zones = useQuery({ queryKey: ['zones', groupId], queryFn: () => fetchZones(groupId), enabled: open })

  const run = async (fn: () => Promise<void>) => {
    setBusy(true)
    try {
      await fn()
      await client.invalidateQueries({ queryKey: ['zones', groupId] })
      client.invalidateQueries({ queryKey: ['attackSurface'] })
      client.invalidateQueries({ queryKey: ['assetMap'] })
      client.invalidateQueries({ queryKey: ['assetProfile'] })
      return true
    } catch (e) {
      message.error(errText(e, t))
      return false
    } finally {
      setBusy(false)
    }
  }
  const submit = async (v: { name: string; kind: ZoneKind; cidrs?: string }) => {
    const body = { name: v.name.trim(), kind: v.kind, cidrs: (v.cidrs ?? '').split(/[\s,]+/).filter(Boolean) }
    const ok = await run(() => editing === 'new' ? createZone({ groupId, ...body }) : updateZone((editing as ZoneRow).id, body))
    if (ok) setEditing(null)
  }

  return (
    <Drawer open={open} size={520} title={t('manageZones')} onClose={onClose}
      extra={canEdit && <Button type="primary" icon={<PlusOutlined />} onClick={() => setEditing('new')}>{t('newZone')}</Button>}>
      <Typography.Paragraph type="secondary">{t('zonesHint')}</Typography.Paragraph>
      {zones.isError ? <LoadError error={zones.error} onRetry={() => zones.refetch()} /> : (
        zones.isPending ? <Skeleton active /> : !zones.data?.length ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noZones')} /> : (
          <Flex vertical gap={8}>
            {zones.data.map(z => (
              <Card key={z.id} size="small">
                <Flex justify="space-between" align="center" gap={8}>
                  <Space orientation="vertical" size={4} style={{ minWidth: 0 }}>
                    <Space><Tag color={color(z.kind)} variant="outlined">{t(KINDS.find(k => k.value === z.kind)!.key)}</Tag><Typography.Text strong>{z.name}</Typography.Text></Space>
                    <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>{(z.cidrs ?? []).join(', ') || '-'}</Typography.Text>
                  </Space>
                  {canEdit && (
                    <Space size={0}>
                      <Button type="link" size="small" onClick={() => setEditing(z)}>{t('editProfile')}</Button>
                      <Popconfirm title={t('zoneDeleteConfirm', { name: z.name })} onConfirm={() => run(() => deleteZone(z.id))}>
                        <Button type="link" size="small" danger icon={<DeleteOutlined />} aria-label={t('del')} />
                      </Popconfirm>
                    </Space>
                  )}
                </Flex>
              </Card>
            ))}
          </Flex>
        )
      )}
      <Modal open={!!editing} title={editing === 'new' ? t('newZone') : t('editProfile')} confirmLoading={busy} destroyOnHidden
        onCancel={() => { if (!busy) setEditing(null) }} onOk={() => form.submit()}
        afterOpenChange={o => o && form.setFieldsValue(editing && editing !== 'new'
          ? { name: editing.name, kind: editing.kind, cidrs: (editing.cidrs ?? []).join('\n') }
          : { name: '', kind: 'dmz', cidrs: '' })}>
        <Form form={form} layout="vertical" disabled={busy} onFinish={submit}>
          <Form.Item name="name" label={t('zoneName')} rules={[{ required: true, whitespace: true, max: 64 }]}><Input /></Form.Item>
          <Form.Item name="kind" label={t('zoneKind')}><Select options={KINDS.map(k => ({ value: k.value, label: t(k.key) }))} /></Form.Item>
          <Form.Item name="cidrs" label={t('zoneCidrs')} extra={t('zoneCidrsHint')}><Input.TextArea rows={4} className="mono" /></Form.Item>
        </Form>
      </Modal>
    </Drawer>
  )
}
