import {
  AimOutlined, ApartmentOutlined, BranchesOutlined, CheckCircleFilled, ClockCircleOutlined, CloseCircleFilled, ExclamationCircleFilled,
  FieldTimeOutlined, NodeIndexOutlined, QuestionCircleFilled, ReloadOutlined, RobotOutlined, ShareAltOutlined, StarFilled, SwapOutlined,
} from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Drawer, Empty, Flex, Grid, Skeleton, Space, Switch, Tag, Typography, theme } from 'antd'
import { useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router'
import { explainEvent, fetchAssets, fetchRelatedEvents, type EventExplanation, type EventRow, type Relation } from '../api'
import { useSession } from '../app/session'
import { useI18n, type MsgKey } from '../i18n'
import { EventKind } from './EventKind'
import { useCanChat, useHandoff } from './Handoff'
import { HostLink } from './HostLink'
import { errText, fmtTime } from './format'
import { EventFacts } from './EventFacts'
import { eventAction, eventSummary } from './eventSummary'

const RELATION: Record<Relation, { key: MsgKey; icon: ReactNode }> = {
  ancestor: { key: 'relAncestor', icon: <ApartmentOutlined /> },
  process: { key: 'relProcess', icon: <NodeIndexOutlined /> },
  child: { key: 'relChild', icon: <BranchesOutlined /> },
  connection: { key: 'relConnection', icon: <SwapOutlined /> },
  peer: { key: 'relPeer', icon: <ShareAltOutlined /> },
  nearby: { key: 'relNearby', icon: <ClockCircleOutlined /> },
}

function Verdict({ v }: { v: EventExplanation['verdict'] }) {
  const { t } = useI18n()
  const map = {
    benign: { color: 'success', icon: <CheckCircleFilled />, key: 'verdictBenign' },
    suspicious: { color: 'warning', icon: <ExclamationCircleFilled />, key: 'verdictSuspicious' },
    malicious: { color: 'error', icon: <CloseCircleFilled />, key: 'verdictMalicious' },
    unknown: { color: 'default', icon: <QuestionCircleFilled />, key: 'verdictUnknown' },
  } as const
  const m = map[v]
  return <Tag color={m.color} icon={m.icon} style={{ marginInlineEnd: 0 }}>{t(m.key)}</Tag>
}

// 一条日志的紧凑行：类别图标、时刻、（别的主机时）主机、动作与摘要；点开看关键字段，可以以它为中心再问
function EventLine({ e, why, showHost, onAsk }: { e: EventRow; why?: string; showHost: boolean; onAsk: (e: EventRow) => void }) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const [open, setOpen] = useState(false)
  const act = eventAction(e.classUid, e.raw, t)
  return (
    <div className={`rel-line${why ? ' rel-picked' : ''}`}>
      <button type="button" className="rel-head" onClick={() => setOpen(!open)} aria-expanded={open}>
        <EventKind classUid={e.classUid} compact />
        <span className="mono rel-time">{fmtTime(e.ts).slice(11)}</span>
        {act && <span className={`ev-act ev-act-${act.tone}`}>{act.label}</span>}
        <Typography.Text className="mono" ellipsis style={{ flex: 1, minWidth: 0 }}>{eventSummary(e.classUid, e.raw, t, false) || e.connTuple || '-'}</Typography.Text>
      </button>
      {why && <div className="rel-why"><StarFilled style={{ color: token.colorWarning }} /> {why}</div>}
      {open && (
        <div className="rel-detail">
          {showHost && <div className="ev-field"><span>{t('thHostname')}</span><HostLink id={e.assetId} /></div>}
          <EventFacts classUid={e.classUid} raw={e.raw} username={e.username} />
          <Button size="small" type="link" icon={<AimOutlined />} style={{ padding: 0 }} onClick={() => onAsk(e)}>{t('askAround')}</Button>
        </div>
      )}
    </div>
  )
}

// 问 AI：先给结论（是什么、要不要紧、为什么），再列 AI 挑出的相关日志，最后是全部候选。
// 关联靠查库，打开就有；解读要调模型，analyst 以上才能发起，结果按日志缓存，关了再开不重复调用
export function EventAIDrawer({ event, onClose, onAsk }: { event: EventRow | null; onClose: () => void; onAsk: (e: EventRow) => void }) {
  const { t, locale } = useI18n()
  const { canWrite } = useSession()
  const navigate = useNavigate()
  const wide = !!Grid.useBreakpoint().md
  const [onlyPicked, setOnlyPicked] = useState(false)
  const related = useQuery({ queryKey: ['event-related', event?.id], queryFn: () => fetchRelatedEvents(event!.id), enabled: !!event })
  const explain = useQuery({
    queryKey: ['event-explain', event?.id, locale], queryFn: () => explainEvent(event!.id, locale),
    enabled: !!event && canWrite, staleTime: Infinity, retry: false,
  })
  const assets = useQuery({ queryKey: ['assets'], queryFn: fetchAssets, enabled: !!event })
  const canChat = useCanChat()
  const handoff = useHandoff()
  if (!event) return <Drawer open={false} />

  const groups = related.data ?? []
  const all = groups.flatMap(g => g.events)
  const why = new Map((explain.data?.related ?? []).map(p => [p.id, p.why]))
  const picked = (explain.data?.related ?? []).map(p => all.find(e => e.id === p.id)).filter((e): e is EventRow => !!e)
  const groupId = assets.data?.find(a => a.id === event.assetId)?.groupId
  const host = assets.data?.find(a => a.id === event.assetId)?.hostname ?? '-'
  const summary = eventSummary(event.classUid, event.raw, t) || event.connTuple || '-'
  const deep = () => groupId && handoff.start(groupId, [], t('eventDeepTitle', { host }),
    t('eventDeepPrompt', { host, id: event.id, ts: fmtTime(event.ts), summary, verdict: explain.data ? `${explain.data.title}：${explain.data.summary}` : '-' }))
  const line = (e: EventRow) => <EventLine key={e.id} e={e} why={why.get(e.id)} showHost={e.assetId !== event.assetId} onAsk={onAsk} />

  return (
    <Drawer open onClose={onClose} size={wide ? 640 : '100%'} title={<Space><RobotOutlined />{t('askAI')}</Space>}
      footer={(
        <Flex justify="space-between" gap={8} wrap>
          <Button icon={<FieldTimeOutlined />} onClick={() => {
            onClose()
            navigate(`/events?${new URLSearchParams({ ...(event.assetId && { assetId: event.assetId }), from: new Date(Date.parse(event.ts) - 300_000).toISOString(), to: new Date(Date.parse(event.ts) + 300_000).toISOString() })}`)
          }}>{t('pivotAround')}</Button>
          {groupId && canChat(groupId) && <Button type="primary" icon={<RobotOutlined />} loading={handoff.busy} onClick={deep}>{t('eventDeep')}</Button>}
        </Flex>
      )}>
      <Flex vertical gap={20}>
        {/* 问的是哪条 */}
        <div className="ask-target">
          <Space size={8} wrap>
            <EventKind classUid={event.classUid} />
            <Typography.Text type="secondary">{fmtTime(event.ts)}</Typography.Text>
            <HostLink id={event.assetId} />
            {event.username && <Typography.Text type="secondary">{event.username}</Typography.Text>}
          </Space>
          <Typography.Paragraph className="mono" style={{ margin: '8px 0 0', wordBreak: 'break-all' }}>{summary}</Typography.Paragraph>
        </div>

        {/* AI 解读 */}
        <section>
          <Flex justify="space-between" align="center" style={{ marginBottom: 8 }}>
            <Typography.Text strong><RobotOutlined /> {t('aiReading')}</Typography.Text>
            {explain.data && <Button size="small" type="text" icon={<ReloadOutlined />} loading={explain.isFetching} onClick={() => explain.refetch()}>{t('reexplain')}</Button>}
          </Flex>
          {!canWrite ? <Alert type="info" showIcon title={t('explainNeedsAnalyst')} />
            : explain.isPending ? (
              <div className="ai-reading">
                <Typography.Text type="secondary">{t('aiReadingNow', { n: all.length })}</Typography.Text>
                <Skeleton active paragraph={{ rows: 3 }} title={false} style={{ marginTop: 8 }} />
              </div>
            ) : explain.isError ? (
              <Alert type="warning" showIcon title={errText(explain.error, t)} action={<Button size="small" onClick={() => explain.refetch()}>{t('retry')}</Button>} />
            ) : (
              <div className={`ai-verdict ai-verdict-${explain.data.verdict}`}>
                <Space size={8} align="start">
                  <Verdict v={explain.data.verdict} />
                  <Typography.Text strong style={{ fontSize: 15 }}>{explain.data.title}</Typography.Text>
                </Space>
                <Typography.Paragraph style={{ margin: '10px 0 0' }}>{explain.data.summary}</Typography.Paragraph>
                {explain.data.points.length > 0 && <ul className="ai-points">{explain.data.points.map(p => <li key={p}>{p}</li>)}</ul>}
                {explain.data.next.length > 0 && (
                  <>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('nextSteps')}</Typography.Text>
                    <ol className="action-list" style={{ marginTop: 6 }}>{explain.data.next.map(n => <li key={n}>{n}</li>)}</ol>
                  </>
                )}
              </div>
            )}
        </section>

        {/* AI 挑出的相关日志 */}
        {picked.length > 0 && (
          <section>
            <Typography.Text strong><StarFilled /> {t('aiPicked', { n: picked.length })}</Typography.Text>
            <div className="rel-list">{picked.map(line)}</div>
          </section>
        )}

        {/* 全部候选：按关联方式分组 */}
        <section>
          <Flex justify="space-between" align="center">
            <Typography.Text strong>{t('relatedLogs', { n: all.length })}</Typography.Text>
            {picked.length > 0 && <Space size={6}><Switch size="small" checked={onlyPicked} onChange={setOnlyPicked} />{t('onlyPicked')}</Space>}
          </Flex>
          {related.isPending ? <Skeleton active paragraph={{ rows: 4 }} title={false} />
            : related.isError ? <Alert type="error" showIcon title={errText(related.error, t)} />
              : groups.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noRelated')} />
                : groups.map(g => {
                  const events = onlyPicked ? g.events.filter(e => why.has(e.id)) : g.events
                  if (!events.length) return null
                  return (
                    <div key={g.relation} className="rel-group">
                      <div className="rel-group-head">{RELATION[g.relation].icon}<span>{t(RELATION[g.relation].key)}</span><span className="rel-count">{events.length}</span></div>
                      <div className="rel-list">{events.map(line)}</div>
                    </div>
                  )
                })}
        </section>
      </Flex>
    </Drawer>
  )
}
