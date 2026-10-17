import { ArrowLeftOutlined, DownloadOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Card, Col, Descriptions, Result, Row, Skeleton, Space, Table, Typography } from 'antd'
import { useState } from 'react'
import { useNavigate, useParams } from 'react-router'
import { HttpError, downloadReport, fetchIncident, setIncidentStatus, type AlertRow } from '../api'
import { useCanActIn, useSession } from '../app/session'
import { HostLink } from '../components/HostLink'
import { IncidentGraph } from '../components/IncidentGraph'
import { LoadError } from '../components/LoadError'
import { Page } from '../components/Page'
import { ResponsePanel } from '../components/ResponsePanel'
import { ResolveModal } from '../components/ResolveModal'
import { SuppressModal } from '../components/SuppressModal'
import { VerdictCard } from '../components/VerdictCard'
import { IncidentStatusTag, SeverityTag, fmtTime, errText } from '../components/format'
import { useI18n } from '../i18n'

export function IncidentDetailPage() {
  const { t } = useI18n()
  const { id } = useParams()
  const navigate = useNavigate()
  const client = useQueryClient()
  const { message } = App.useApp()
  const { groups } = useSession()
  const [suppressing, setSuppressing] = useState(false)
  const [resolving, setResolving] = useState<'closed' | 'false_positive' | null>(null)
  const { data: inc, isPending, error, refetch } = useQuery({ queryKey: ['incident', id], queryFn: () => fetchIncident(id!), refetchInterval: 15_000 })
  const canAct = useCanActIn(inc?.groupId)

  if (isPending) return <Skeleton active paragraph={{ rows: 12 }} style={{ marginTop: 24 }} />
  if (error instanceof HttpError && error.status === 404) {
    return <Result status="404" title={t('incidentNotFound')} extra={<Button onClick={() => navigate('/incidents')}>{t('backToList')}</Button>} />
  }
  if (error || !inc) return <LoadError error={error} onRetry={() => refetch()} />

  // 返回是否成功：结案弹窗靠它决定关不关、备注留不留
  const changeStatus = async (status: string, note?: string) => {
    try {
      await setIncidentStatus(inc.id, status, note)
    } catch (e) {
      message.error(errText(e, t))
      return false
    }
    setResolving(null)
    await client.invalidateQueries({ queryKey: ['incident', id] })
    client.invalidateQueries({ queryKey: ['incidents'] })
    if (status === 'false_positive') setSuppressing(true)
    return true
  }
  const done = inc.status === 'closed' || inc.status === 'false_positive'

  return (
    <Page
      crumb={inc.title ?? inc.id}
      title={<Space><Button type="text" icon={<ArrowLeftOutlined />} onClick={() => navigate('/incidents')} />{inc.title ?? inc.id}</Space>}
      extra={
        <>
          {/* 只读角色也能导报告：写汇报不是处置动作 */}
          <Button icon={<DownloadOutlined />} onClick={() => downloadReport(inc.id, inc.title).catch(e => message.error(errText(e, t)))}>{t('exportReport')}</Button>
          {canAct && !done && <Button onClick={() => setResolving('closed')}>{t('close')}</Button>}
          {canAct && !done && <Button danger onClick={() => setResolving('false_positive')}>{t('markFp')}</Button>}
          {canAct && done && <Button onClick={() => changeStatus('open')}>{t('reopen')}</Button>}
        </>
      }
    >
      <Row gutter={[16, 16]}>
        <Col xs={24} xl={16}>
          <Space orientation="vertical" size={16} style={{ width: '100%' }}>
            <VerdictCard verdict={inc.aiVerdict} />
            <Card title={t('graphTitle')}><IncidentGraph graph={inc.graph} /></Card>
            <Card title={t('alertsTitle', { n: inc.alerts.length })} styles={{ body: { padding: 0 } }}>
              <Table<AlertRow>
                size="small"
                rowKey="id"
                dataSource={inc.alerts}
                pagination={{ pageSize: 20, hideOnSinglePage: true }}
                expandable={{ expandedRowRender: a => <pre className="json-block">{a.event ? JSON.stringify(a.event, null, 2) : t('noRawEvent')}</pre> }}
                columns={[
                  { title: t('thFirst'), dataIndex: 'ts', render: fmtTime, width: 170 },
                  { title: t('thLast'), dataIndex: 'lastTs', render: fmtTime, width: 170 },
                  { title: t('thRule'), dataIndex: 'ruleTitle', render: (v, a) => v ?? a.ruleId, ellipsis: true },
                  { title: t('thSeverity'), dataIndex: 'severity', render: v => <SeverityTag value={v} />, width: 90 },
                  { title: t('thCount'), dataIndex: 'count', align: 'right', width: 80 },
                ]}
              />
            </Card>
          </Space>
        </Col>
        <Col xs={24} xl={8}>
          <Space orientation="vertical" size={16} style={{ width: '100%' }}>
            <Card title={t('basicInfo')}>
              <Descriptions column={1} size="small">
                <Descriptions.Item label="ID"><Typography.Text className="mono" copyable style={{ fontSize: 12 }}>{inc.id}</Typography.Text></Descriptions.Item>
                <Descriptions.Item label={t('thStatus')}><IncidentStatusTag value={inc.status} /></Descriptions.Item>
                <Descriptions.Item label={t('thSeverity')}><SeverityTag value={inc.severity} /></Descriptions.Item>
                <Descriptions.Item label={t('thCreatedAt')}>{fmtTime(inc.createdAt)}</Descriptions.Item>
                <Descriptions.Item label={t('thAlerts')}>{inc.alerts.length}</Descriptions.Item>
                <Descriptions.Item label={t('thHostname')}><HostLink id={inc.assetId} /></Descriptions.Item>
                <Descriptions.Item label={t('group')}>{groups.find(g => g.id === inc.groupId)?.name ?? '-'}</Descriptions.Item>
                {inc.resolvedAt && <Descriptions.Item label={t('resolution')}>{inc.resolution}</Descriptions.Item>}
                {inc.resolvedAt && <Descriptions.Item label={t('resolvedBy')}>{inc.resolvedBy} · {fmtTime(inc.resolvedAt)}</Descriptions.Item>}
              </Descriptions>
            </Card>
            <ResponsePanel incidentId={inc.id} assetId={inc.assetId} canAct={canAct} />
          </Space>
        </Col>
      </Row>
      <ResolveModal
        open={!!resolving}
        title={t(resolving === 'closed' ? 'resolveClosedTitle' : 'resolveFpTitle')}
        hint={t('resolveHint')}
        onCancel={() => setResolving(null)}
        onSubmit={async note => { if (!await changeStatus(resolving!, note)) throw new Error() }}
      />
      <SuppressModal open={suppressing} alerts={inc.alerts} assetId={inc.assetId} onClose={() => setSuppressing(false)} />
    </Page>
  )
}
