import { Descriptions, Tag, Typography } from 'antd'
import type { ReactNode } from 'react'
import { useI18n } from '../i18n'
import { RCODE, containerLabel, fmtDuration } from './eventSummary'

type Raw = Record<string, any>

const endpoint = (e: Raw | undefined) => (e?.ip ? (e.port ? `${e.ip}:${e.port}` : e.ip) : undefined)
const mono = (v: ReactNode) => <Typography.Text className="mono" copyable>{v}</Typography.Text>

// 展开日志时先给人看的几项：进程、容器、连接、DNS、退出。只列事件里真有的字段，其余看原始 JSON
export function EventFacts({ classUid, raw, username }: { classUid: number; raw: unknown; username?: string | null }) {
  const { t } = useI18n()
  const r = (raw ?? {}) as Raw
  const p: Raw = r.process ?? {}
  const items: { key: string; label: string; children: ReactNode }[] = []
  const add = (key: string, label: string, value: ReactNode) => {
    if (value !== undefined && value !== null && value !== '') items.push({ key, label, children: value })
  }

  if (p.name || p.pid) add('process', t('factProcess'), <>{p.name || '-'}{p.pid ? <Typography.Text type="secondary"> · pid {p.pid}</Typography.Text> : null}</>)
  add('path', t('factPath'), p.file?.path && mono(p.file.path))
  add('cmd', t('factCmd'), p.cmd_line && p.cmd_line !== p.name && mono(p.cmd_line))
  add('user', t('factUser'), username)
  const container = containerLabel(r.container)
  add('container', t('factContainer'), container && <><Tag variant="filled">{r.container.runtime}</Tag>{container}{r.container.name ? <Typography.Text type="secondary"> · {r.container.uid}</Typography.Text> : null}</>)
  // 周期行为汇总：折叠了多少次、首末时间
  if (classUid === 1007 && r.activity_id === 99 && r.periodic) {
    const time = (ms?: number) => (ms ? new Date(ms).toLocaleTimeString() : '-')
    add('periodic', t('factPeriodic'), t('factPeriodicValue', { n: r.periodic.count, from: time(r.periodic.first_time), to: time(r.periodic.last_time) }))
    add('parent', t('factParent'), p.parent_process?.cmd_line && mono(p.parent_process.cmd_line))
  }
  if (classUid === 1007 && r.activity_id === 2 && typeof r.duration_ms === 'number') {
    const duration = fmtDuration(r.duration_ms)
    add('exit', t('factExit'), p.exit_code != null ? t('factExitValue', { code: p.exit_code, duration }) : t('factExitUnknown', { duration }))
  }

  if (classUid === 4001 && r.src_endpoint) {
    const inbound = r.connection_info?.direction === 'inbound'
    const proto = (r.connection_info?.protocol_name ?? 'tcp').toUpperCase()
    add('conn', t('factConnection'), <>
      <Tag variant="filled" color={inbound ? 'orange' : 'blue'}>{inbound ? t('factInbound') : t('factOutbound')}</Tag>
      <Tag variant="filled">{proto}</Tag>
      <span className="mono">{endpoint(r.src_endpoint)} → {endpoint(r.dst_endpoint)}</span>
    </>)
    add('domain', t('factDomain'), r.dst_endpoint?.hostname || r.tls?.sni || r.http_request?.hostname)
  }

  if (classUid === 4003 && r.query) {
    const rcode = r.query.rcode_id
    add('query', t('factQuery'), <>
      <span className="mono">{r.query.hostname}</span> {r.query.type && <Tag variant="filled">{r.query.type}</Tag>}
      {rcode == null ? <Tag>{t('evNoAnswer')}</Tag> : rcode ? <Tag color="red">{RCODE[rcode] ?? `RCODE ${rcode}`}</Tag> : null}
      <Typography.Text type="secondary" className="mono"> {endpoint(r.src_endpoint)} → {endpoint(r.dst_endpoint)}</Typography.Text>
    </>)
    const answers = Array.isArray(r.answers) ? r.answers.map((a: Raw) => a.ip || a.rdata).filter(Boolean) : []
    add('answers', t('factAnswers'), answers.length > 0 && <span className="mono">{answers.join(', ')}</span>)
  }

  if (!items.length) return null
  return <Descriptions size="small" column={1} bordered items={items} style={{ marginBottom: 8 }} styles={{ label: { width: 110 } }} />
}
