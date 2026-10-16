import { ArrowRightOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Card, Col, Empty, Row, Statistic, Table, Tooltip, Typography, theme } from 'antd'
import { Link } from 'react-router'
import { fetchIncidents, fetchStats } from '../api'
import { IncidentStatusTag, SeverityTag, fmtTime } from '../components/format'
import { Page } from '../components/Page'
import { useI18n } from '../i18n'

// 24h 告警趋势：24 根柱子，不为一张图引图表库
function Trend({ data }: { data: { hour: string; count: number }[] }) {
  const { token } = theme.useToken()
  const max = Math.max(1, ...data.map(b => b.count))
  return (
    <div className="trend">
      {data.map(b => (
        <Tooltip key={b.hour} title={`${new Date(b.hour).getHours()}:00 — ${b.count}`}>
          <div className="trend-bar">
            <div className="trend-fill" style={{ height: `${Math.max(2, Math.round((b.count / max) * 100))}%`, background: b.count ? token.colorPrimary : token.colorFillSecondary }} />
          </div>
        </Tooltip>
      ))}
    </div>
  )
}

// 态势总览：核心是降噪漏斗——原始事件 → 去重告警 → 待处理事件
export function OverviewPage() {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const stats = useQuery({ queryKey: ['stats'], queryFn: fetchStats, refetchInterval: 30_000 })
  const incidents = useQuery({ queryKey: ['incidents', 'open'], queryFn: () => fetchIncidents('open'), refetchInterval: 30_000 })
  const s = stats.data

  const arrow = <ArrowRightOutlined style={{ color: token.colorTextQuaternary, fontSize: 20 }} />
  return (
    <Page title={t('navOverview')} subtitle={t('overviewSubtitle')}>
      <Row gutter={[16, 16]}>
        <Col xs={24} xl={16}>
          <Card title={t('funnelTitle')} loading={stats.isPending}>
            <Row align="middle" justify="space-around">
              <Col><Statistic title={t('funnelEvents')} value={s?.events24h ?? 0} /></Col>
              <Col>{arrow}</Col>
              <Col><Statistic title={t('funnelAlerts')} value={s?.alerts24h ?? 0} /></Col>
              <Col>{arrow}</Col>
              <Col><Statistic title={t('funnelIncidents')} value={s?.openIncidents ?? 0} styles={{ content: { color: s?.openIncidents ? token.colorWarning : undefined } }} /></Col>
            </Row>
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card title={t('assetsOnline')} loading={stats.isPending}>
            <Statistic value={s?.assetsOnline ?? 0} suffix={`/ ${s?.assetsTotal ?? 0}`} />
            <Typography.Text type="secondary">{t('assetsOnlineHint')}</Typography.Text>
          </Card>
        </Col>
        <Col xs={24} xl={16}>
          <Card title={t('alertTrend24h')} loading={stats.isPending}>
            {s && <Trend data={s.alertTrend} />}
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card title={t('topRules')} loading={stats.isPending} styles={{ body: { padding: 0 } }}>
            <Table
              size="small"
              rowKey="ruleId"
              pagination={false}
              dataSource={s?.topRules ?? []}
              locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noAlerts24h')} /> }}
              columns={[
                { title: t('thRule'), dataIndex: 'ruleTitle', ellipsis: true, render: (v, r) => v ?? r.ruleId },
                { title: t('thHits'), dataIndex: 'count', width: 90, align: 'right' },
              ]}
            />
          </Card>
        </Col>
        <Col span={24}>
          <Card title={t('openIncidents')} extra={<Link to="/incidents">{t('viewAll')}</Link>} styles={{ body: { padding: 0 } }}>
            <Table
              size="small"
              rowKey="id"
              loading={incidents.isPending}
              dataSource={(incidents.data ?? []).slice(0, 8)}
              pagination={false}
              locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noIncidents')} /> }}
              columns={[
                { title: t('thSeverity'), dataIndex: 'severity', width: 90, render: v => <SeverityTag value={v} /> },
                { title: t('thTitle'), dataIndex: 'title', render: (v, r) => <Link to={`/incidents/${r.id}`}>{v ?? r.id}</Link> },
                { title: t('thStatus'), dataIndex: 'status', width: 100, render: v => <IncidentStatusTag value={v} /> },
                { title: t('thAlerts'), dataIndex: 'alertCount', width: 90, align: 'right' },
                { title: t('thCreatedAt'), dataIndex: 'createdAt', width: 180, render: fmtTime },
              ]}
            />
          </Card>
        </Col>
      </Row>
    </Page>
  )
}
