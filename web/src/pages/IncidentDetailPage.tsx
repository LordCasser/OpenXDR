import { ArrowLeftOutlined, DownloadOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Card, Col, Descriptions, Result, Row, Space, Spin, Table, Typography } from 'antd'
import { useState } from 'react'
import { useNavigate, useParams } from 'react-router'
import { downloadReport, fetchAssets, fetchIncident, setIncidentStatus, type AlertRow } from '../api'
import { useCanActIn, useSession } from '../app/session'
import { IncidentGraph } from '../components/IncidentGraph'
import { Page } from '../components/Page'
import { ResponsePanel } from '../components/ResponsePanel'
import { SuppressModal } from '../components/SuppressModal'
import { VerdictCard } from '../components/VerdictCard'
import { IncidentStatusTag, SeverityTag, fmtTime } from '../components/format'
import { useI18n } from '../i18n'

export function IncidentDetailPage() {
  const { t } = useI18n()
  const { id } = useParams()
  const navigate = useNavigate()
  const client = useQueryClient()
  const { message } = App.useApp()
  const { groups } = useSession()
  const [suppressing, setSuppressing] = useState(false)
  const { data: inc, isPending, error } = useQuery({ queryKey: ['incident', id], queryFn: () => fetchIncident(id!), refetchInterval: 15_000 })
  const { data: assets = [] } = useQuery({ queryKey: ['assets'], queryFn: fetchAssets })
  const asset = assets.find(a => a.id === inc?.assetId)
  const canAct = useCanActIn(asset?.groupId)

  if (isPending) return <Spin style={{ display: 'block', marginTop: 120 }} />
  if (error || !inc) {
    return <Result status="404" title={t('incidentNotFound')} extra={<Button onClick={() => navigate('/incidents')}>{t('backToList')}</Button>} />
  }

  const changeStatus = async (status: string) => {
    try {
      await setIncidentStatus(inc.id, status)
      await client.invalidateQueries({ queryKey: ['incident', id] })
      client.invalidateQueries({ queryKey: ['incidents'] })
      if (status === 'false_positive') setSuppressing(true)
    } catch (e) {
      message.error(String(e))
    }
  }
  const done = inc.status === 'closed' || inc.status === 'false_positive'

  return (
    <Page
      title={<Space><Button type="text" icon={<ArrowLeftOutlined />} onClick={() => navigate('/incidents')} />{inc.title ?? inc.id}</Space>}
      extra={
        <>
          {/* 只读角色也能导报告：写汇报不是处置动作 */}
          <Button icon={<DownloadOutlined />} onClick={() => downloadReport(inc.id, inc.title).catch(e => message.error(String(e)))}>{t('exportReport')}</Button>
          {canAct && !done && <Button onClick={() => changeStatus('closed')}>{t('close')}</Button>}
          {canAct && !done && <Button danger onClick={() => changeStatus('false_positive')}>{t('markFp')}</Button>}
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
                <Descriptions.Item label={t('thHostname')}>{asset?.hostname ?? '-'}</Descriptions.Item>
                <Descriptions.Item label={t('group')}>{groups.find(g => g.id === asset?.groupId)?.name ?? '-'}</Descriptions.Item>
              </Descriptions>
            </Card>
            <ResponsePanel incidentId={inc.id} assetId={inc.assetId} canAct={canAct} />
          </Space>
        </Col>
      </Row>
      <SuppressModal open={suppressing} alerts={inc.alerts} assetId={inc.assetId} onClose={() => setSuppressing(false)} />
    </Page>
  )
}
