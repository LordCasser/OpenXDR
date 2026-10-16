import {
  AlertOutlined, ArrowRightOutlined, CheckCircleOutlined, CloudServerOutlined, FileTextOutlined, FilterOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Badge, Card, Col, Empty, Flex, Progress, Row, Segmented, Space, Statistic, Table, Tag, Typography, theme } from 'antd'
import { useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { fetchAgentReports, fetchApprovals, fetchAssets, fetchIncidents, fetchStats, fetchTaskRuns, fetchTasks } from '../api'
import { useSession } from '../app/session'
import { Page } from '../components/Page'
import { BarList, ColumnChart, SEVERITY_COLOR, useSeriesColor } from '../components/charts'
import { IncidentStatusTag, SessionStatusTag, SeverityTag, fmtTime } from '../components/format'
import { useI18n } from '../i18n'

const STALE_MS = 5 * 60_000

// KPI 卡：标签 · 数值 · 一句说明；数值用正文墨色，状态靠图标 + 文字
function Kpi({ icon, title, value, suffix, foot, to }: { icon: ReactNode; title: string; value: number; suffix?: ReactNode; foot?: ReactNode; to?: string }) {
  const { token } = theme.useToken()
  const body = (
    <Card size="small" hoverable={!!to} styles={{ body: { padding: 20 } }} style={{ height: '100%' }}>
      <Space size={8} style={{ color: token.colorTextSecondary }}>{icon}<span>{title}</span></Space>
      <Statistic value={value} suffix={suffix} styles={{ content: { fontSize: 30, fontWeight: 600, marginTop: 6 } }} />
      <div style={{ marginTop: 6, minHeight: 22 }}>{foot}</div>
    </Card>
  )
  return to ? <Link to={to}>{body}</Link> : body
}

// AI 运营：最近任务运行与报告、待审批，体现"纳管即安全"的持续巡检
function AiOps() {
  const { t } = useI18n()
  const { group } = useSession()
  const tasks = useQuery({ queryKey: ['tasks'], queryFn: fetchTasks })
  const runs = useQuery({
    queryKey: ['taskRuns', 'recent', tasks.data?.map(x => x.id)],
    queryFn: async () => (await Promise.all((tasks.data ?? []).map(x => fetchTaskRuns(x.id).then(rs => rs.map(r => ({ ...r, name: x.name }))))))
      .flat()
      .sort((a, b) => b.startedAt.localeCompare(a.startedAt))
      .slice(0, 4),
    enabled: !!tasks.data,
    refetchInterval: 30_000,
  })
  const reports = useQuery({ queryKey: ['reports', group?.id], queryFn: () => fetchAgentReports(group!.id), enabled: !!group })

  return (
    <Card title={t('aiOpsTitle')} style={{ height: '100%' }} extra={<Link to="/chat">{t('navChat')} <ArrowRightOutlined /></Link>}>
      <Typography.Text type="secondary" strong>{t('recentRuns')}</Typography.Text>
      <div className="mini-list">
        {(runs.data ?? []).length === 0 && <Typography.Text type="secondary">{t('noTaskRuns')}</Typography.Text>}
        {runs.data?.map(r => (
          <Flex key={r.id} justify="space-between" align="center" className="mini-row">
            <Typography.Text ellipsis style={{ maxWidth: '55%' }}>{r.name}</Typography.Text>
            <Space size={6}>
              <SessionStatusTag value={r.status} />
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>{fmtTime(r.startedAt).slice(5, 16)}</Typography.Text>
            </Space>
          </Flex>
        ))}
      </div>
      <Typography.Text type="secondary" strong>{t('recentReports')}</Typography.Text>
      <div className="mini-list">
        {(reports.data ?? []).length === 0 && <Typography.Text type="secondary">{t('noReports')}</Typography.Text>}
        {reports.data?.slice(0, 4).map(r => (
          <Flex key={r.id} justify="space-between" align="center" className="mini-row">
            <Link to="/reports" style={{ maxWidth: '65%' }}><Typography.Text ellipsis><FileTextOutlined /> {r.title}</Typography.Text></Link>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>{fmtTime(r.created_at).slice(5, 16)}</Typography.Text>
          </Flex>
        ))}
      </div>
    </Card>
  )
}

// 态势总览：顶部 KPI 回答"今天挡掉多少噪声、还剩几件事"，下面是趋势、分布与待办
export function OverviewPage() {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const { group } = useSession()
  const series = useSeriesColor()
  const [trendView, setTrendView] = useState<'chart' | 'table'>('chart')
  const stats = useQuery({ queryKey: ['stats'], queryFn: fetchStats, refetchInterval: 30_000, placeholderData: keepPreviousData })
  const incidents = useQuery({ queryKey: ['incidents', 'open'], queryFn: () => fetchIncidents('open'), refetchInterval: 30_000 })
  const assets = useQuery({ queryKey: ['assets'], queryFn: fetchAssets, refetchInterval: 30_000 })
  const isGroupAdmin = group?.role === 'admin'
  const approvals = useQuery({ queryKey: ['approvals', group?.id], queryFn: () => fetchApprovals(group!.id), enabled: !!group && isGroupAdmin, refetchInterval: 10_000 })
  const s = stats.data
  const pending = approvals.data?.filter(a => a.status === 'pending').length ?? 0
  const offline = (assets.data ?? []).filter(a => Date.now() - Date.parse(a.lastSeen) >= STALE_MS)
  const reduction = s && s.events24h ? 1 - s.openIncidents / s.events24h : null
  const sevItems = [5, 4, 3, 2, 1].map(n => ({
    key: String(n),
    label: <SeverityTag value={n} />,
    value: s?.alertsBySeverity?.[n] ?? 0,
    color: SEVERITY_COLOR[n],
  }))
  const hourOf = (iso: string) => new Date(iso).getHours()

  return (
    <Page title={t('navOverview')} subtitle={t('overviewSubtitle')}>
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} xl={isGroupAdmin ? 5 : 6}>
          <Kpi icon={<FilterOutlined />} title={t('funnelEvents')} value={s?.events24h ?? 0} to="/events"
            foot={reduction !== null && <Typography.Text type="secondary">{t('noiseReduction', { p: (reduction * 100).toFixed(reduction > 0.999 ? 2 : 1) })}</Typography.Text>} />
        </Col>
        <Col xs={24} sm={12} xl={isGroupAdmin ? 5 : 6}>
          <Kpi icon={<AlertOutlined />} title={t('funnelAlerts')} value={s?.alerts24h ?? 0}
            foot={<Typography.Text type="secondary">{t('topRuleCount', { n: s?.topRules.length ?? 0 })}</Typography.Text>} />
        </Col>
        <Col xs={24} sm={12} xl={isGroupAdmin ? 5 : 6}>
          <Kpi icon={<WarningOutlined />} title={t('funnelIncidents')} value={s?.openIncidents ?? 0} to="/incidents?status=open"
            foot={s?.openIncidents ? <Tag color="warning" icon={<WarningOutlined />}>{t('needsAction')}</Tag> : <Tag color="success" icon={<CheckCircleOutlined />}>{t('allClear')}</Tag>} />
        </Col>
        <Col xs={24} sm={12} xl={isGroupAdmin ? 5 : 6}>
          <Kpi icon={<CloudServerOutlined />} title={t('assetsOnline')} value={s?.assetsOnline ?? 0} suffix={<span style={{ fontSize: 16, color: token.colorTextTertiary }}>/ {s?.assetsTotal ?? 0}</span>} to="/assets"
            foot={<Progress percent={s?.assetsTotal ? Math.round((s.assetsOnline / s.assetsTotal) * 100) : 0} size="small" strokeColor={series} showInfo={false} />} />
        </Col>
        {isGroupAdmin && (
          <Col xs={24} sm={12} xl={4}>
            <Kpi icon={<CheckCircleOutlined />} title={t('navApprovals')} value={pending} to="/approvals"
              foot={<Typography.Text type="secondary">{t('approvalsOfGroup', { name: group.name })}</Typography.Text>} />
          </Col>
        )}

        <Col xs={24} xl={16}>
          <Card title={t('alertTrend24h')} style={{ height: '100%' }}
            extra={<Segmented size="small" value={trendView} onChange={v => setTrendView(v as 'chart' | 'table')} options={[{ value: 'chart', label: t('viewChart') }, { value: 'table', label: t('viewTable') }]} />}>
            {!s ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} /> : trendView === 'chart' ? (
              <ColumnChart
                dim={stats.isFetching && !stats.isPending}
                data={s.alertTrend.map(b => ({ key: b.hour, value: b.count }))}
                xLabel={i => (hourOf(s.alertTrend[i].hour) % 6 === 0 ? `${String(hourOf(s.alertTrend[i].hour)).padStart(2, '0')}:00` : null)}
                tip={i => t('trendTip', { h: String(hourOf(s.alertTrend[i].hour)).padStart(2, '0'), n: s.alertTrend[i].count })}
              />
            ) : (
              <Table size="small" rowKey="hour" pagination={false} scroll={{ y: 200 }} dataSource={s.alertTrend}
                columns={[
                  { title: t('thTime'), dataIndex: 'hour', render: v => fmtTime(v).slice(0, 16) },
                  { title: t('thAlerts'), dataIndex: 'count', align: 'right' },
                ]} />
            )}
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card title={t('alertsBySeverity')} style={{ height: '100%' }}>
            <BarList items={sevItems} labelWidth="64px" dim={stats.isFetching && !stats.isPending} />
          </Card>
        </Col>

        <Col xs={24} xl={16}>
          <Card title={t('openIncidents')} extra={<Link to="/incidents">{t('viewAll')}</Link>} styles={{ body: { padding: 0 } }} style={{ height: '100%' }}>
            <Table
              size="small"
              rowKey="id"
              loading={incidents.isPending}
              dataSource={(incidents.data ?? []).slice(0, 6)}
              pagination={false}
              locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noIncidents')} /> }}
              columns={[
                { title: t('thSeverity'), dataIndex: 'severity', width: 90, render: v => <SeverityTag value={v} /> },
                { title: t('thTitle'), dataIndex: 'title', ellipsis: true, render: (v, r) => <Link to={`/incidents/${r.id}`}>{v ?? r.id}</Link> },
                { title: t('thStatus'), dataIndex: 'status', width: 100, render: v => <IncidentStatusTag value={v} /> },
                { title: t('thAlerts'), dataIndex: 'alertCount', width: 80, align: 'right' },
                { title: t('thCreatedAt'), dataIndex: 'createdAt', width: 170, render: fmtTime },
              ]}
            />
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <AiOps />
        </Col>

        <Col xs={24} xl={12}>
          <Card title={t('topRules')} style={{ height: '100%' }}>
            {s?.topRules.length ? (
              <BarList items={s.topRules.map(r => ({ key: r.ruleId, label: <Typography.Text ellipsis title={r.ruleId}>{r.ruleTitle ?? r.ruleId}</Typography.Text>, value: r.count, color: series }))} />
            ) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noAlerts24h')} />}
          </Card>
        </Col>
        <Col xs={24} xl={12}>
          <Card title={t('offlineAssets', { n: offline.length })} style={{ height: '100%' }} extra={<Link to="/assets">{t('viewAll')}</Link>}>
            {offline.length === 0 ? (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('allOnline')} />
            ) : (
              <div className="mini-list">
                {offline.slice(0, 6).map(a => (
                  <Flex key={a.id} justify="space-between" className="mini-row">
                    <Link to={`/assets/${a.id}`}><Badge status="default" text={a.hostname} /></Link>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('lastSeenAt', { time: fmtTime(a.lastSeen) })}</Typography.Text>
                  </Flex>
                ))}
              </div>
            )}
          </Card>
        </Col>
      </Row>
    </Page>
  )
}

