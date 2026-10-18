import { ImportOutlined, SyncOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Card, Empty, Flex, Form, Input, InputNumber, List, Modal, Popconfirm, Space, Spin, Switch, Table, Tag, Typography } from 'antd'
import { useRef, useState } from 'react'
import { deleteIntel, fetchIntel, fetchIntelFeeds, importIntel, saveIntelFeeds, syncIntelFeeds, type IntelRow } from '../api'
import { useSession } from '../app/session'
import { LoadError } from '../components/LoadError'
import { Page } from '../components/Page'
import { SeverityTag, fmtTime, errText } from '../components/format'
import { useI18n } from '../i18n'

// 情报订阅：开关即时生效（开的马上拉、关的马上清），命中过的订阅情报直接列出来
function FeedsCard() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { isAdmin } = useSession()
  const { data, isPending, isError, error, refetch } = useQuery({ queryKey: ['intel-feeds'], queryFn: fetchIntelFeeds })
  const pending = useRef(false)
  const [busy, setBusy] = useState<string>()
  // 接口保存整份订阅配置，串行提交，避免后一次用旧快照覆盖前一次。
  const update = async (id?: string, on?: boolean) => {
    if (pending.current || !data) return
    pending.current = true
    setBusy(id ?? 'sync')
    try {
      const result = id === undefined
        ? await syncIntelFeeds()
        : await saveIntelFeeds(data.feeds.filter(f => f.id === id ? on : f.enabled).map(f => f.id))
      client.setQueryData(['intel-feeds'], result)
      await client.invalidateQueries({ queryKey: ['intel'] })
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      pending.current = false
      setBusy(undefined)
    }
  }

  return (
    <Card
      title={t('intelFeeds')}
      extra={isAdmin && <Button icon={<SyncOutlined />} loading={busy === 'sync'} disabled={!!busy || isPending || isError} onClick={() => update()}>{t('intelFeedSync')}</Button>}
    >
      {isError ? <LoadError error={error} onRetry={() => refetch()} /> : isPending ? <Spin /> : <>
      <Typography.Paragraph type="secondary">{t('intelFeedsHint', { n: data?.intervalHours ?? 6 })}</Typography.Paragraph>
      <List
        size="small"
        dataSource={data?.feeds ?? []}
        renderItem={f => (
          <List.Item
            actions={[<Switch key="on" checked={f.enabled} aria-label={f.name} disabled={!isAdmin || !!busy} loading={busy === f.id}
              onChange={on => update(f.id, on)} />]}
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
        scroll={{ x: 750 }}
        size="small"
        rowKey="id"
        dataSource={data?.hits ?? []}
        pagination={{ pageSize: 10, hideOnSinglePage: true }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('intelFeedNoHits')} /> }}
        columns={[
          { title: t('thKind'), dataIndex: 'kind', width: 90, render: v => <Tag>{v}</Tag> },
          { title: t('thValue'), dataIndex: 'value', render: (v, r) => <span className="mono" title={r.note ?? ''}>{v}</span> },
          { title: t('thSource'), dataIndex: 'source', width: 160 },
          { title: t('thHits'), dataIndex: 'matchedCount', width: 90, align: 'right' },
          { title: t('thLastMatched'), dataIndex: 'lastMatchedAt', width: 170, render: fmtTime },
        ]}
      />
      </>}
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
  const submitting = useRef(false)
  const [form] = Form.useForm()
  const { data, isPending, isError, error, refetch } = useQuery({ queryKey: ['intel'], queryFn: fetchIntel })

  const refresh = () => client.invalidateQueries({ queryKey: ['intel'] })
  const doImport = async (v: { text: string; source?: string; expiresInDays?: number }) => {
    if (submitting.current) return
    submitting.current = true
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
      submitting.current = false
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
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<IntelRow>
          scroll={{ x: 1100 }}
          rowKey="id"
          loading={isPending}
          dataSource={data ?? []}
          pagination={{ pageSize: 20, hideOnSinglePage: true }}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noIntel')} /> }}
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
        />}
      </Card>
      </Flex>
      <Modal open={importing} title={t('intelImport')} onCancel={() => { if (!busy) setImporting(false) }} closable={!busy} maskClosable={!busy} keyboard={!busy} cancelButtonProps={{ disabled: busy }} onOk={() => form.submit()} confirmLoading={busy} width={640} destroyOnHidden>
        <Form disabled={busy} form={form} layout="vertical" onFinish={doImport} initialValues={{ expiresInDays: 0 }}>
          <Form.Item name="text" label={t('intelIocs')} extra={t('intelImportHint')} rules={[{ required: true, whitespace: true }]}>
            <Input.TextArea rows={8} className="mono" />
          </Form.Item>
          <Form.Item name="source" label={t('intelSource')}>
            <Input />
          </Form.Item>
          <Form.Item name="expiresInDays" label={t('validityDays')} extra={t('validityZero')}>
            <InputNumber min={0} precision={0} style={{ width: 160 }} />
          </Form.Item>
        </Form>
      </Modal>
    </Page>
  )
}
