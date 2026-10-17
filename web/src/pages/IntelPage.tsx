import { ImportOutlined, SyncOutlined } from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Card, Flex, Form, Input, InputNumber, List, Modal, Popconfirm, Space, Switch, Table, Tag, Typography } from 'antd'
import { useState } from 'react'
import { deleteIntel, fetchIntel, fetchIntelFeeds, importIntel, saveIntelFeeds, syncIntelFeeds, type IntelFeeds, type IntelRow } from '../api'
import { useSession } from '../app/session'
import { Page } from '../components/Page'
import { SeverityTag, fmtTime, errText } from '../components/format'
import { useI18n } from '../i18n'

// 情报订阅：开关即时生效（开的马上拉、关的马上清），命中过的订阅情报直接列出来
function FeedsCard() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { isAdmin } = useSession()
  const { data } = useQuery({ queryKey: ['intel-feeds'], queryFn: fetchIntelFeeds })
  const done = (d: IntelFeeds) => client.setQueryData(['intel-feeds'], d)
  const toggle = useMutation({
    mutationFn: ({ id, on }: { id: string; on: boolean }) =>
      saveIntelFeeds((data?.feeds ?? []).filter(f => (f.id === id ? on : f.enabled)).map(f => f.id)),
    onSuccess: done,
    onError: e => message.error(errText(e, t)),
  })
  const sync = useMutation({ mutationFn: syncIntelFeeds, onSuccess: done, onError: e => message.error(errText(e, t)) })

  return (
    <Card
      title={t('intelFeeds')}
      extra={isAdmin && <Button icon={<SyncOutlined />} loading={sync.isPending} onClick={() => sync.mutate()}>{t('intelFeedSync')}</Button>}
    >
      <Typography.Paragraph type="secondary">{t('intelFeedsHint', { n: data?.intervalHours ?? 6 })}</Typography.Paragraph>
      <List
        size="small"
        dataSource={data?.feeds ?? []}
        renderItem={f => (
          <List.Item
            actions={[<Switch key="on" checked={f.enabled} disabled={!isAdmin} loading={toggle.isPending && toggle.variables?.id === f.id}
              onChange={on => toggle.mutate({ id: f.id, on })} />]}
          >
            <List.Item.Meta
              title={<Space wrap><span>{f.name}</span><SeverityTag value={f.severity} /></Space>}
              description={
                <Space wrap size={12}>
                  <span>{t('intelFeedCount', { n: f.count })}</span>
                  <span>{t('intelFeedHits', { n: f.hits })}</span>
                  <span>{f.syncedAt ? t('intelFeedSynced', { time: fmtTime(f.syncedAt) }) : t('intelFeedNever')}</span>
                  {f.error && <Typography.Text type="danger">{t('intelFeedError', { err: f.error })}</Typography.Text>}
                </Space>
              }
            />
          </List.Item>
        )}
      />
      <Typography.Title level={5} style={{ marginTop: 16 }}>{t('intelFeedHitList')}</Typography.Title>
      <Table<IntelRow>
        size="small"
        rowKey="id"
        dataSource={data?.hits ?? []}
        pagination={{ pageSize: 10, hideOnSinglePage: true }}
        locale={{ emptyText: t('intelFeedNoHits') }}
        columns={[
          { title: t('thKind'), dataIndex: 'kind', width: 90, render: v => <Tag>{v}</Tag> },
          { title: t('thValue'), dataIndex: 'value', render: (v, r) => <span className="mono" title={r.note ?? ''}>{v}</span> },
          { title: t('thSource'), dataIndex: 'source', width: 160 },
          { title: t('thHits'), dataIndex: 'matchedCount', width: 90, align: 'right' },
          { title: t('thLastMatched'), dataIndex: 'lastMatchedAt', width: 170, render: fmtTime },
        ]}
      />
    </Card>
  )
}

// 威胁情报：命中数让每条 IOC 的价值可见，长期零命中的陈年情报该清理
export function IntelPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { canWrite } = useSession()
  const [importing, setImporting] = useState(false)
  const [busy, setBusy] = useState(false)
  const [form] = Form.useForm()
  const { data, isPending } = useQuery({ queryKey: ['intel'], queryFn: fetchIntel })

  const refresh = () => client.invalidateQueries({ queryKey: ['intel'] })
  const doImport = async (v: { text: string; source?: string; expiresInDays?: number }) => {
    setBusy(true)
    try {
      const r = await importIntel({ text: v.text, source: v.source || undefined, expiresInDays: v.expiresInDays ?? 0 })
      message.success(t('intelImported', { n: r.imported, skipped: r.skipped }))
      setImporting(false)
      form.resetFields()
      refresh()
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      setBusy(false)
    }
  }
  const revoke = (id: string) => deleteIntel(id).then(refresh).catch(e => message.error(errText(e, t)))

  return (
    <Page
      title={t('navIntel')}
      subtitle={t('intelSubtitle', { n: data?.length ?? 0 })}
      extra={canWrite && <Button type="primary" icon={<ImportOutlined />} onClick={() => setImporting(true)}>{t('intelImport')}</Button>}
    >
      <Flex vertical gap={16}>
      <FeedsCard />
      <Card title={t('intelManual')} styles={{ body: { padding: 0 } }}>
        <Table<IntelRow>
          rowKey="id"
          loading={isPending}
          dataSource={data ?? []}
          pagination={{ pageSize: 20, hideOnSinglePage: true }}
          locale={{ emptyText: t('noIntel') }}
          columns={[
            { title: t('thKind'), dataIndex: 'kind', width: 90, render: v => <Tag>{v}</Tag> },
            { title: t('thValue'), dataIndex: 'value', render: (v, r) => <span className="mono" title={r.note ?? ''}>{v}</span> },
            { title: t('thSource'), dataIndex: 'source', width: 140 },
            { title: t('thSeverity'), dataIndex: 'severity', width: 90, render: v => <SeverityTag value={v} /> },
            { title: t('thHits'), dataIndex: 'matchedCount', width: 90, align: 'right', sorter: (a, b) => a.matchedCount - b.matchedCount },
            { title: t('thLastMatched'), dataIndex: 'lastMatchedAt', width: 170, render: fmtTime },
            { title: t('thExpires'), dataIndex: 'expiresAt', width: 170, render: v => (v ? fmtTime(v) : t('longTerm')) },
            ...(canWrite
              ? [{
                  title: t('actions'), width: 90,
                  render: (_: unknown, r: IntelRow) => (
                    <Popconfirm title={t('confirmRevoke')} onConfirm={() => revoke(r.id)}>
                      <Button type="link" danger size="small">{t('revoke')}</Button>
                    </Popconfirm>
                  ),
                }]
              : []),
          ]}
        />
      </Card>
      </Flex>
      <Modal open={importing} title={t('intelImport')} onCancel={() => setImporting(false)} onOk={() => form.submit()} confirmLoading={busy} width={640} destroyOnHidden>
        <Form form={form} layout="vertical" onFinish={doImport} initialValues={{ expiresInDays: 0 }}>
          <Form.Item name="text" label={t('intelIocs')} extra={t('intelImportHint')} rules={[{ required: true }]}>
            <Input.TextArea rows={8} className="mono" />
          </Form.Item>
          <Form.Item name="source" label={t('intelSource')}>
            <Input />
          </Form.Item>
          <Form.Item name="expiresInDays" label={t('validityDays')} extra={t('validityZero')}>
            <InputNumber min={0} style={{ width: 160 }} />
          </Form.Item>
        </Form>
      </Modal>
    </Page>
  )
}
