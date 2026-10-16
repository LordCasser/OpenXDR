import { Tag } from 'antd'
import { useI18n, type MsgKey } from '../i18n'

const pad = (n: number) => String(n).padStart(2, '0')

// 统一 YYYY-MM-DD HH:mm:ss（本地时区），不随浏览器语言变成 10/16/2026, 12:39 PM
export const fmtTime = (iso: string | null | undefined) => {
  if (!iso) return '-'
  const d = new Date(iso)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

const SEV: Record<number, { key: MsgKey; color: string }> = {
  1: { key: 'sev1', color: 'default' },
  2: { key: 'sev2', color: 'blue' },
  3: { key: 'sev3', color: 'gold' },
  4: { key: 'sev4', color: 'orange' },
  5: { key: 'sev5', color: 'red' },
}

export function SeverityTag({ value }: { value: number }) {
  const { t } = useI18n()
  const s = SEV[value]
  return s ? <Tag color={s.color}>{t(s.key)}</Tag> : <Tag>{value}</Tag>
}

const INCIDENT_STATUS: Record<string, { key: MsgKey; color: string }> = {
  open: { key: 'statusOpen', color: 'orange' },
  triaged: { key: 'statusTriaged', color: 'blue' },
  closed: { key: 'statusClosed', color: 'default' },
  false_positive: { key: 'statusFalsePositive', color: 'green' },
}

export function IncidentStatusTag({ value }: { value: string }) {
  const { t } = useI18n()
  const s = INCIDENT_STATUS[value]
  return <Tag color={s?.color}>{s ? t(s.key) : value}</Tag>
}

export const INCIDENT_STATUSES = Object.keys(INCIDENT_STATUS)
export const incidentStatusKey = (s: string) => INCIDENT_STATUS[s]?.key

const SESSION_STATUS: Record<string, { key: MsgKey; color: string }> = {
  running: { key: 'sessionRunning', color: 'processing' },
  idle: { key: 'sessionIdle', color: 'default' },
  succeeded: { key: 'sessionSucceeded', color: 'success' },
  failed: { key: 'sessionFailed', color: 'error' },
}

export function SessionStatusTag({ value }: { value: string }) {
  const { t } = useI18n()
  const s = SESSION_STATUS[value]
  return <Tag color={s?.color}>{s ? t(s.key) : value}</Tag>
}

export const ROLE_KEY: Record<string, MsgKey> = { admin: 'roleAdmin', analyst: 'roleAnalyst', viewer: 'roleViewer' }

export const CLASS_KEY: Record<number, MsgKey> = {
  1001: 'classFile',
  1005: 'classModule',
  1007: 'classProcess',
  3002: 'classAuth',
  201002: 'classRegistry',
  4001: 'classNetwork',
  4003: 'classDNS',
  100001: 'classLog',
}
