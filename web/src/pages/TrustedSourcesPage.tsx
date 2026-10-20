import { PlusOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Card, Form, Input, InputNumber, Modal, Popconfirm, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { useState } from 'react'
import { Link } from 'react-router'
import { createTrustedSource, fetchTrustedCandidates, fetchTrustedSources, revokeTrustedSource, type TrustedCandidate, type TrustedSource } from '../api'
import { useSession } from '../app/session'
import { EmptyHint } from '../components/Ago'
import { LoadError } from '../components/LoadError'
import { Page } from '../components/Page'
import { errText, fmtTime } from '../components/format'
import { useI18n } from '../i18n'

interface Draft {
  name: string
  reason?: string
  keyFingerprint?: string
  sourceCidr?: string
  loginUser?: string
  expiresInDays: number
}

const mono = (v: string | null) => (v ? <Typography.Text className="mono" copyable style={{ fontSize: 12 }}>{v}</Typography.Text> : '-')

// 可信自动化来源：按 SSH 登录身份认出运维自动化，命中的告警照常留痕、不进事件与研判。
// 登记是降低检测的操作，只有组管理员能做；AI 没有对应工具
export function TrustedSourcesPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { group, isAdmin } = useSession()
  const groupId = group?.id ?? ''
  const manage = isAdmin || group?.role === 'admin'
  const sources = useQuery({ queryKey: ['trustedSources', groupId], queryFn: () => fetchTrustedSources(groupId), enabled: !!groupId })
  const candidates = useQuery({ queryKey: ['trustedCandidates', groupId], queryFn: () => fetchTrustedCandidates(groupId), enabled: !!groupId && manage })
  const [draft, setDraft] = useState<Partial<Draft> | null>(null)
  const [busy, setBusy] = useState(false)
  const [form] = Form.useForm<Draft>()
  const now = Date.now()

  const refresh = () => Promise.all([
    client.invalidateQueries({ queryKey: ['trustedSources', groupId] }),
    client.invalidateQueries({ queryKey: ['trustedCandidates', groupId] }),
  ])
  const submit = async (v: Draft) => {
    setBusy(true)
    try {
      await createTrustedSource({ ...v, groupId })
      setDraft(null)
      await refresh()
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      setBusy(false)
    }
  }
  const revoke = async (id: string) => {
    try {
      await revokeTrustedSource(id)
      await refresh()
    } catch (e) {
      message.error(errText(e, t))
    }
  }
  const state = (s: TrustedSource) => (s.revokedAt
    ? <Tooltip title={`${s.revokedBy ?? ''} · ${fmtTime(s.revokedAt)}`}><Tag>{t('tsRevoked')}</Tag></Tooltip>
    : Date.parse(s.expiresAt) <= now ? <Tag>{t('tsExpired')}</Tag> : <Tag color="green">{t('supActive')}</Tag>)
  const fromCandidate = (c: TrustedCandidate) => setDraft({
    keyFingerprint: c.keyFingerprint ?? undefined,
    sourceCidr: c.srcIp,
    loginUser: c.user,
  })

  return (
    <Page
      title={t('navTrustedSources')}
      subtitle={t('tsSubtitle')}
      extra={manage && <Button type="primary" icon={<PlusOutlined />} onClick={() => setDraft({})}>{t('tsAdd')}</Button>}
    >
      <Alert type="info" showIcon style={{ marginBottom: 16 }} title={t('tsExplain')} description={t('tsExplainDetail')} />
      <Card styles={{ body: { padding: 0 } }}>
        {sources.isError ? <LoadError error={sources.error} onRetry={() => sources.refetch()} /> : <Table<TrustedSource>
          rowKey="id"
          loading={sources.isPending && !!groupId}
          dataSource={sources.data ?? []}
          pagination={{ pageSize: 20, hideOnSinglePage: true }}
          scroll={{ x: 1400 }}
          locale={{ emptyText: <EmptyHint title={t('tsEmpty')} hint={t('tsEmptyHint')} /> }}
          columns={[
            { title: t('tsName'), dataIndex: 'name', width: 160, render: (v: string, s) => <Tooltip title={s.reason}>{v}</Tooltip> },
            { title: t('thStatus'), key: 'state', width: 90, render: (_, s) => state(s) },
            { title: t('tsKeyFingerprint'), dataIndex: 'keyFingerprint', width: 260, render: mono },
            { title: t('tsSourceCidr'), dataIndex: 'sourceCidr', width: 140, render: mono },
            { title: t('tsLoginUser'), dataIndex: 'loginUser', width: 100, render: v => v ?? '-' },
            {
              title: t('thMatched'), dataIndex: 'matchedCount', width: 100, align: 'right',
              // 命中的事件按指纹或来源在日志检索里翻
              render: (v: number, s) => (v && (s.keyFingerprint || s.sourceCidr)
                ? <Link to={`/events?${new URLSearchParams({ q: s.keyFingerprint ?? s.sourceCidr!.replace(/\/\d+$/, ''), hours: '168' })}`}>{v}</Link>
                : v),
            },
            { title: t('thLastMatched'), dataIndex: 'lastMatchedAt', width: 160, render: fmtTime },
            { title: t('thExpires'), dataIndex: 'expiresAt', width: 160, render: fmtTime },
            { title: t('thCreatedBy'), dataIndex: 'createdBy', width: 110 },
            ...(manage
              ? [{
                  title: t('actions'), width: 90,
                  render: (_: unknown, s: TrustedSource) => !s.revokedAt && (
                    <Popconfirm title={t('confirmRevoke')} onConfirm={() => revoke(s.id)}>
                      <Button type="link" danger size="small">{t('revoke')}</Button>
                    </Popconfirm>
                  ),
                }]
              : []),
          ]}
        />}
      </Card>

      {manage && (
        <Card title={t('tsCandidates')} extra={<Typography.Text type="secondary">{t('tsCandidatesHint')}</Typography.Text>} style={{ marginTop: 16 }} styles={{ body: { padding: 0 } }}>
          {candidates.isError ? <LoadError error={candidates.error} onRetry={() => candidates.refetch()} /> : <Table<TrustedCandidate>
            rowKey={c => `${c.user}|${c.srcIp}|${c.keyFingerprint ?? ''}`}
            size="small"
            loading={candidates.isPending}
            dataSource={candidates.data ?? []}
            pagination={{ pageSize: 10, hideOnSinglePage: true }}
            scroll={{ x: 1000 }}
            locale={{ emptyText: <EmptyHint title={t('tsNoCandidates')} hint={t('tsNoCandidatesHint')} /> }}
            columns={[
              { title: t('tsLoginUser'), dataIndex: 'user', width: 100 },
              { title: t('tsSourceIp'), dataIndex: 'srcIp', width: 140, render: mono },
              {
                title: t('tsKeyFingerprint'), dataIndex: 'keyFingerprint', width: 320,
                render: (v: string | null, c) => (v ? <Space size={4}>{c.keyType && <Tag variant="filled">{c.keyType}</Tag>}{mono(v)}</Space> : <Typography.Text type="secondary">{t('tsNoKey')}</Typography.Text>),
              },
              { title: t('tsLogins'), dataIndex: 'logins', width: 90, align: 'right' },
              { title: t('tsHosts'), dataIndex: 'hosts', width: 80, align: 'right' },
              { title: t('tsLastSeen'), dataIndex: 'lastSeen', width: 160, render: fmtTime },
              {
                title: '', key: 'act', width: 110,
                render: (_, c) => (c.trustedSourceIds.length
                  ? <Tag color="green">{t('tsCovered')}</Tag>
                  : <Button size="small" onClick={() => fromCandidate(c)}>{t('tsAdd')}</Button>),
              },
            ]}
          />}
        </Card>
      )}

      <Modal
        open={draft !== null}
        title={t('tsAdd')}
        onCancel={() => { if (!busy) setDraft(null) }}
        onOk={() => form.submit()}
        confirmLoading={busy}
        width={620}
        destroyOnHidden
      >
        <Form<Draft> form={form} layout="vertical" disabled={busy} onFinish={submit} initialValues={{ expiresInDays: 90, ...draft }}>
          <Form.Item name="name" label={t('tsName')} rules={[{ required: true, whitespace: true, max: 100 }]}>
            <Input placeholder="Termix AI Ops" />
          </Form.Item>
          <Form.Item name="reason" label={t('reason')} rules={[{ max: 1000 }]}>
            <Input.TextArea rows={2} placeholder={t('tsReasonHint')} />
          </Form.Item>
          <Form.Item name="keyFingerprint" label={t('tsKeyFingerprint')} extra={t('tsKeyFingerprintHint')}>
            <Input className="mono" placeholder="SHA256:…" />
          </Form.Item>
          <Form.Item name="sourceCidr" label={t('tsSourceCidr')} extra={t('tsSourceCidrHint')}>
            <Input className="mono" placeholder="10.1.1.35/32" />
          </Form.Item>
          <Form.Item name="loginUser" label={t('tsLoginUser')}>
            <Input placeholder="root" />
          </Form.Item>
          <Form.Item name="expiresInDays" label={t('validityDays')} extra={t('tsValidityHint')} rules={[{ required: true }]}>
            <InputNumber min={1} max={365} />
          </Form.Item>
        </Form>
      </Modal>
    </Page>
  )
}
