import { ReloadOutlined } from '@ant-design/icons'
import { Button, Empty, Space, Tooltip, Typography } from 'antd'
import { useEffect, useState, type ReactNode } from 'react'
import { useI18n, type T } from '../i18n'
import { fmtTime } from './format'

// 全页共用一个 30 秒的节拍，相对时间不用每个单元格各开定时器
const listeners = new Set<() => void>()
setInterval(() => listeners.forEach(f => f()), 30_000)
function useTick() {
  const [, set] = useState(0)
  useEffect(() => {
    const f = () => set(n => n + 1)
    listeners.add(f)
    return () => { listeners.delete(f) }
  }, [])
}

export function ago(iso: string, t: T): string {
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000)
  if (s < 60) return t('agoJustNow')
  if (s < 3600) return t('agoMin', { n: Math.floor(s / 60) })
  if (s < 86400) return t('agoHour', { n: Math.floor(s / 3600) })
  if (s < 86400 * 30) return t('agoDay', { n: Math.floor(s / 86400) })
  return fmtTime(iso).slice(0, 10)
}

// 列表里的时间：先给"多久以前"，悬停看精确时刻；取证类页面仍用绝对时间
export function Ago({ iso }: { iso: string | null | undefined }) {
  const { t } = useI18n()
  useTick()
  if (!iso || Date.parse(iso) <= 0) return <>-</>
  return <Tooltip title={fmtTime(iso)}><span>{ago(iso, t)}</span></Tooltip>
}

// 列表右上角：数据多久前刷新过、点一下立刻刷新。自动轮询的页面让人知道数据是活的
export function Refreshed({ at, fetching, onRefresh }: { at: number; fetching: boolean; onRefresh: () => void }) {
  const { t } = useI18n()
  useTick()
  return (
    <Space size={4}>
      {at > 0 && <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('updatedAgo', { t: ago(new Date(at).toISOString(), t) })}</Typography.Text>}
      <Tooltip title={t('refresh')}>
        <Button type="text" size="small" aria-label={t('refresh')} icon={<ReloadOutlined spin={fetching} />} onClick={onRefresh} />
      </Tooltip>
    </Space>
  )
}

// 空状态：说清为什么是空的、下一步能做什么
export function EmptyHint({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} style={{ margin: '28px 0' }}
      description={<Space orientation="vertical" size={2}><Typography.Text>{title}</Typography.Text>{hint && <Typography.Text type="secondary">{hint}</Typography.Text>}</Space>}>
      {action}
    </Empty>
  )
}
