import { EditOutlined, LockOutlined, ReloadOutlined, UnlockOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App, Alert, Button, Descriptions, Empty, Form, Input, Modal, Rate, Select, Skeleton, Space, Table, Tag, Tooltip, Typography, theme,
} from 'antd'
import { useState } from 'react'
import {
  assignAssetZone, fetchAssetProfile, fetchZones, requestAnnotate, saveAssetProfile,
  type AssetProfile, type ExposureLevel, type ProfileEdit, type ZoneKind, type ZoneRef,
} from '../api'
import { useI18n, type MsgKey } from '../i18n'
import { LoadError } from './LoadError'
import { errText, fmtTime } from './format'

const ZONE_KEY: Record<ZoneKind, MsgKey> = { internal: 'zoneInternal', dmz: 'zoneDmz', external: 'zoneExternal', cloud: 'zoneCloud' }
const SOURCE_KEY: Record<ZoneRef['source'], MsgKey> = { manual: 'zoneSourceManual', cidr: 'zoneSourceCidr', cloud: 'zoneSourceCloud', auto: 'zoneSourceAuto' }
const CLOUD_KEY: Record<string, MsgKey> = { aws: 'cloudAws', azure: 'cloudAzure', gcp: 'cloudGcp', aliyun: 'cloudAliyun', tencent: 'cloudTencent' }
const EXPOSURE_KEY: Record<ExposureLevel, MsgKey> = { internet: 'exposureInternet', dmz: 'exposureDmz', internal: 'exposureInternal' }
export const CRIT_KEY: Record<number, MsgKey> = { 1: 'crit1', 2: 'crit2', 3: 'crit3', 4: 'crit4', 5: 'crit5' }

// 区域颜色：公网红、隔离区橙、云上蓝、内网绿，图谱与表格同一套
export function useZoneColor() {
  const { token } = theme.useToken()
  return (kind: ZoneKind) => ({ external: token.colorError, dmz: token.colorWarning, cloud: token.colorInfo, internal: token.colorSuccess })[kind]
}

export function zoneName(z: ZoneRef, t: (k: MsgKey) => string) {
  if (z.source === 'cloud') return CLOUD_KEY[z.name] ? t(CLOUD_KEY[z.name]) : z.name
  return z.name || t(ZONE_KEY[z.kind])
}

export function ZoneTag({ zone, detail }: { zone: ZoneRef; detail?: boolean }) {
  const { t } = useI18n()
  const color = useZoneColor()(zone.kind)
  return (
    <Tooltip title={`${t(ZONE_KEY[zone.kind])} · ${t(SOURCE_KEY[zone.source])}`}>
      <Tag color={color} variant="outlined">{zoneName(zone, t)}{detail && zone.name && ` · ${t(ZONE_KEY[zone.kind])}`}</Tag>
    </Tooltip>
  )
}

export function ExposureTag({ level }: { level: ExposureLevel }) {
  const { t } = useI18n()
  const color = { internet: 'error', dmz: 'warning', internal: 'default' }[level]
  return <Tag color={color}>{t(EXPOSURE_KEY[level])}</Tag>
}

export function CritTag({ value }: { value?: number | null }) {
  const { t } = useI18n()
  if (!value) return <Typography.Text type="secondary">-</Typography.Text>
  const color = value >= 5 ? 'red' : value === 4 ? 'orange' : value === 3 ? 'blue' : 'default'
  return <Tag color={color}>{value} · {t(CRIT_KEY[value])}</Tag>
}

function Locked({ locked }: { locked: boolean }) {
  const { t } = useI18n()
  return locked ? <Tooltip title={t('lockedByHuman')}><LockOutlined style={{ marginLeft: 6, fontSize: 12, opacity: 0.6 }} /></Tooltip> : null
}

// 资产画像：AI 标注 + 采集到的事实。组 analyst 能改标注，组 admin 能指派区域
export function AssetProfileView({ assetId, groupId, canEdit, isGroupAdmin, compact }: {
  assetId: string; groupId?: string | null; canEdit: boolean; isGroupAdmin: boolean; compact?: boolean
}) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [busy, setBusy] = useState(false)
  const profile = useQuery({ queryKey: ['assetProfile', assetId], queryFn: () => fetchAssetProfile(assetId) })
  const zones = useQuery({ queryKey: ['zones', groupId], queryFn: () => fetchZones(groupId!), enabled: !!groupId && isGroupAdmin })

  if (profile.isPending) return <Skeleton active />
  if (profile.isError) return <LoadError error={profile.error} onRetry={() => profile.refetch()} />
  const p = profile.data
  const locked = (f: string) => !!p.lockedFields?.includes(f)

  const run = async (fn: () => Promise<void>, ok?: string) => {
    setBusy(true)
    try {
      await fn()
      if (ok) message.success(ok)
      await client.invalidateQueries({ queryKey: ['assetProfile', assetId] })
      client.invalidateQueries({ queryKey: ['assetMap'] })
      client.invalidateQueries({ queryKey: ['attackSurface'] })
      return true
    } catch (e) {
      message.error(errText(e, t))
      return false
    } finally {
      setBusy(false)
    }
  }

  const annotation = !p.aiEnabled
    ? <Typography.Text type="secondary">{t('aiDisabledHint')}</Typography.Text>
    : p.annotateRequestedAt ? <Typography.Text type="secondary">{t('annotatePending')}</Typography.Text>
      : p.annotatedAt ? <Typography.Text type="secondary">{t('annotatedAt', { time: fmtTime(p.annotatedAt) })}</Typography.Text>
        : <Typography.Text type="secondary">{t('notAnnotated')}</Typography.Text>

  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <Space wrap style={{ justifyContent: 'space-between', width: '100%' }}>
        {annotation}
        {canEdit && (
          <Space size={4}>
            <Button size="small" icon={<EditOutlined />} onClick={() => setEditing(true)}>{t('editProfile')}</Button>
            {p.aiEnabled && <Button size="small" icon={<ReloadOutlined />} loading={busy} disabled={!!p.annotateRequestedAt}
              onClick={() => run(() => requestAnnotate(assetId), t('annotateQueued'))}>{t('reannotate')}</Button>}
          </Space>
        )}
      </Space>

      <Descriptions column={1} size="small" styles={{ label: { width: compact ? 88 : 110 } }}>
        <Descriptions.Item label={t('role')}>{p.role ? <Typography.Text strong>{p.role}</Typography.Text> : '-'}<Locked locked={locked('role')} /></Descriptions.Item>
        <Descriptions.Item label={t('criticality')}><CritTag value={p.criticality} /><Locked locked={locked('criticality')} /></Descriptions.Item>
        <Descriptions.Item label={t('summaryLabel')}>{p.summary || '-'}<Locked locked={locked('summary')} /></Descriptions.Item>
        {p.reason && <Descriptions.Item label={t('reasonLabel')}><Typography.Text type="secondary">{p.reason}</Typography.Text></Descriptions.Item>}
        <Descriptions.Item label={t('zoneLabel')}>
          <Space size={4} wrap>
            <ZoneTag zone={p.zone} detail />
            {isGroupAdmin && groupId && (
              <Select size="small" style={{ minWidth: 140 }} loading={zones.isPending} disabled={busy}
                value={p.zone.source === 'manual' ? p.zone.id : ''}
                onChange={v => run(() => assignAssetZone(assetId, v || null))}
                options={[{ value: '', label: t('zoneAuto') }, ...(zones.data ?? []).map(z => ({ value: z.id, label: z.name }))]} />
            )}
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label={t('exposureLabel')}><ExposureTag level={p.exposure} /></Descriptions.Item>
        {p.cloud && (
          <Descriptions.Item label={t('cloudLabel')}>
            {[CLOUD_KEY[p.cloud.provider] ? t(CLOUD_KEY[p.cloud.provider]) : p.cloud.provider, p.cloud.region, p.cloud.instanceId, p.cloud.publicIp].filter(Boolean).join(' · ')}
          </Descriptions.Item>
        )}
      </Descriptions>

      <div>
        <Typography.Text strong>{t('listeningPorts')}</Typography.Text>
        {!p.inventoryAt ? <Alert type="info" showIcon style={{ marginTop: 8 }} title={t('noInventory')} /> : (
          <Table size="small" rowKey={l => `${l.proto}/${l.addr}/${l.port}`} pagination={false} style={{ marginTop: 8 }}
            dataSource={p.listening ?? []} scroll={{ y: compact ? 220 : 320 }}
            locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
            columns={[
              { title: t('thPorts'), width: 92, render: (_, l) => <span className="mono">{l.proto}/{l.port}</span> },
              { title: t('thBind'), dataIndex: 'addr', ellipsis: true, render: (v: string) => <span className="mono">{v}</span> },
              { title: t('listenProcess'), dataIndex: 'process', ellipsis: true, render: (_, l) => <Tooltip title={l.path}>{l.process ?? '-'}</Tooltip> },
            ]} />
        )}
      </div>

      {(['outbound', 'inbound'] as const).map(dir => {
        const items = p[dir] ?? []
        return (
          <div key={dir}>
            <Typography.Text strong>{t(dir === 'outbound' ? 'dependsOn' : 'dependedBy')}</Typography.Text>
            <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {items.length === 0 ? <Typography.Text type="secondary">-</Typography.Text> : items.map(s => <Tag key={s} className="mono">{s}</Tag>)}
              {dir === 'outbound' && p.publicDestinations > 0 && <Typography.Text type="secondary">{t('publicDestinations', { n: p.publicDestinations })}</Typography.Text>}
            </div>
          </div>
        )
      })}

      <EditModal open={editing} profile={p} busy={busy} onClose={() => setEditing(false)}
        onSave={async edit => { if (await run(() => saveAssetProfile(assetId, edit))) setEditing(false) }} />
    </Space>
  )
}

// 编辑即锁定；已锁定的字段可以交还 AI
function EditModal({ open, profile, busy, onClose, onSave }: {
  open: boolean; profile: AssetProfile; busy: boolean; onClose: () => void; onSave: (e: ProfileEdit) => void
}) {
  const { t } = useI18n()
  const [form] = Form.useForm()
  const locked = profile.lockedFields ?? []
  const submit = (v: { role: string; summary: string; criticality: number }) => {
    const edit: ProfileEdit = {}
    if (v.role !== (profile.role ?? '')) edit.role = v.role
    if (v.summary !== (profile.summary ?? '')) edit.summary = v.summary
    if (v.criticality && v.criticality !== profile.criticality) edit.criticality = v.criticality
    onSave(edit)
  }
  const unlock = (f: string) => onSave({ unlock: [f] })
  const suffix = (f: string) => locked.includes(f) && (
    <Button type="link" size="small" icon={<UnlockOutlined />} disabled={busy} onClick={() => unlock(f)}>{t('unlockToAi')}</Button>
  )
  return (
    <Modal open={open} title={t('editProfile')} onCancel={() => { if (!busy) onClose() }} onOk={() => form.submit()} confirmLoading={busy} destroyOnHidden
      afterOpenChange={o => o && form.setFieldsValue({ role: profile.role ?? '', summary: profile.summary ?? '', criticality: profile.criticality ?? 0 })}>
      <Form form={form} layout="vertical" disabled={busy} onFinish={submit}>
        <Form.Item label={<Space>{t('role')}{suffix('role')}</Space>} name="role" rules={[{ required: true, whitespace: true, max: 32 }]}><Input /></Form.Item>
        <Form.Item label={<Space>{t('criticality')}{suffix('criticality')}</Space>} name="criticality">
          <Rate count={5} tooltips={[1, 2, 3, 4, 5].map(n => t(CRIT_KEY[n]))} />
        </Form.Item>
        <Form.Item label={<Space>{t('summaryLabel')}{suffix('summary')}</Space>} name="summary" rules={[{ max: 300 }]}><Input.TextArea rows={3} /></Form.Item>
      </Form>
    </Modal>
  )
}
