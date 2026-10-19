import { Button, Checkbox, Flex, Input, Segmented, Select, Space, Typography } from 'antd'
import { useState } from 'react'
import { useI18n, type MsgKey, type T } from '../i18n'

// 周期在后端是标准五段 cron（可带 CRON_TZ= 前缀与 @daily 等简写）。常见的三种形状用表单选，
// 认不出的形状落到「自定义」原样编辑，保证任何合法表达式都不会被表单改写
type Mode = 'daily' | 'weekly' | 'hourly' | 'custom'
interface Parsed { mode: Mode; tz: string; minute: number; hour: number; days: number[]; body: string }

const num = (x: string, max: number) => /^\d{1,2}$/.test(x) && +x <= max

export function parseCron(expr: string): Parsed {
  const m = /^(?:CRON_TZ=(\S+)\s+)?(.*)$/.exec(expr.trim())!
  const tz = m[1] ?? ''
  const body = m[2].trim()
  const base = { tz, minute: 0, hour: 0, days: [] as number[], body }
  if (body === '@daily' || body === '@midnight') return { ...base, mode: 'daily' }
  if (body === '@hourly') return { ...base, mode: 'hourly' }
  if (body === '@weekly') return { ...base, mode: 'weekly', days: [0] }
  const f = body.split(/\s+/)
  if (f.length !== 5 || f[2] !== '*' || f[3] !== '*') return { ...base, mode: 'custom' }
  if (num(f[0], 59) && f[1] === '*' && f[4] === '*') return { ...base, mode: 'hourly', minute: +f[0] }
  if (!num(f[0], 59) || !num(f[1], 23)) return { ...base, mode: 'custom' }
  const at = { ...base, minute: +f[0], hour: +f[1] }
  if (f[4] === '*') return { ...at, mode: 'daily' }
  if (/^[0-7](,[0-7])*$/.test(f[4])) return { ...at, mode: 'weekly', days: [...new Set(f[4].split(',').map(d => +d % 7))].sort() }
  return { ...base, mode: 'custom' }
}

function buildCron(p: Parsed): string {
  const tz = p.tz ? `CRON_TZ=${p.tz} ` : ''
  switch (p.mode) {
    case 'daily': return `${tz}${p.minute} ${p.hour} * * *`
    case 'weekly': return `${tz}${p.minute} ${p.hour} * * ${p.days.join(',')}`
    case 'hourly': return `${tz}${p.minute} * * * *`
    case 'custom': return `${tz}${p.body}`
  }
}

const pad = (n: number) => String(n).padStart(2, '0')

// 星期名交给浏览器按语言出：2026-01-04 是周日
function weekday(d: number, locale: string) {
  return new Intl.DateTimeFormat(locale === 'zh' ? 'zh-CN' : 'en', { weekday: 'short', timeZone: 'UTC' }).format(Date.UTC(2026, 0, 4 + d))
}
const WEEK = [1, 2, 3, 4, 5, 6, 0]

// 人话描述；自定义形状返回 null，调用方显示原表达式
export function describeCron(expr: string, t: T, locale: string): string | null {
  const p = parseCron(expr)
  const time = `${pad(p.hour)}:${pad(p.minute)}`
  const text = p.mode === 'daily' ? t('schedDescDaily', { time })
    : p.mode === 'weekly' ? t('schedDescWeekly', { days: p.days.map(d => weekday(d, locale)).join(t('listSep')), time })
      : p.mode === 'hourly' ? t('schedDescHourly', { m: p.minute })
        : monthly(expr, t)
  return text && p.tz ? `${text}（${p.tz}）` : text
}

// 每月某日某时（编辑器不提供这种形状，只在展示时翻成人话）
function monthly(expr: string, t: T): string | null {
  const m = /^(?:CRON_TZ=\S+\s+)?(\d{1,2}) (\d{1,2}) (\d{1,2}) \* \*$/.exec(expr.trim())
  return m ? t('schedDescMonthly', { day: m[3], time: `${pad(+m[2])}:${pad(+m[1])}` }) : null
}

const MODES: { value: Mode; key: MsgKey }[] = [
  { value: 'daily', key: 'schedDaily' }, { value: 'weekly', key: 'schedWeekly' }, { value: 'hourly', key: 'schedHourly' }, { value: 'custom', key: 'schedCustom' },
]

// 表单控件：value / onChange 是完整表达式，可直接放进 Form.Item
export function ScheduleEditor({ value = '', onChange, fallback }: { value?: string; onChange?: (v: string) => void; fallback: string }) {
  const { t, locale } = useI18n()
  const parsed = parseCron(value)
  const [mode, setMode] = useState<Mode>(parsed.mode)
  const emit = (patch: Partial<Parsed>) => onChange?.(buildCron({ ...parsed, mode, ...patch }))
  // 换形状时尽量沿用已有的时刻与时区；切到自定义就把当前表达式原样交给输入框
  const switchMode = (next: Mode) => {
    setMode(next)
    onChange?.(buildCron(next === 'custom'
      ? { ...parsed, mode: 'custom', body: buildCron({ ...parsed, mode, tz: '' }) }
      : { ...parsed, mode: next, days: parsed.days.length ? parsed.days : [1] }))
  }
  const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone
  const tzOptions = [...new Set(['', 'Asia/Shanghai', 'UTC', browserTz, parsed.tz])]
    .map(z => ({ value: z, label: z || t('schedServerTz') }))
  const minutes = Array.from({ length: 60 }, (_, i) => ({ value: i, label: pad(i) }))
  const hours = Array.from({ length: 24 }, (_, i) => ({ value: i, label: pad(i) }))
  const desc = mode === 'custom' ? null : describeCron(value, t, locale)

  return (
    <Flex vertical gap={12}>
      <Segmented block value={mode} onChange={v => switchMode(v as Mode)} options={MODES.map(m => ({ value: m.value, label: t(m.key) }))} />
      {mode === 'weekly' && (
        <Checkbox.Group value={parsed.days} onChange={v => v.length && emit({ days: (v as number[]).slice().sort() })}
          options={WEEK.map(d => ({ value: d, label: weekday(d, locale) }))} />
      )}
      {mode === 'custom' ? (
        <Input className="mono" value={parsed.body} onChange={e => emit({ body: e.target.value })} placeholder="0 2 * * *" />
      ) : (
        <Space wrap>
          {mode !== 'hourly' && <Select aria-label={t('schedHour')} style={{ width: 80 }} value={parsed.hour} options={hours} onChange={hour => emit({ hour })} />}
          {mode !== 'hourly' && ':'}
          {mode === 'hourly' && <Typography.Text>{t('schedMinuteOf')}</Typography.Text>}
          <Select aria-label={t('schedMinute')} style={{ width: 80 }} value={parsed.minute} options={minutes} onChange={minute => emit({ minute })} showSearch />
        </Space>
      )}
      <Space wrap>
        <Typography.Text type="secondary">{t('schedTz')}</Typography.Text>
        <Select style={{ minWidth: 180 }} value={parsed.tz} options={tzOptions} onChange={tz => emit({ tz })} />
      </Space>
      <div className="sched-preview">
        {desc && <Typography.Text strong>{desc}</Typography.Text>}
        <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>{value}</Typography.Text>
        {mode === 'custom' && <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('schedCustomHint')}</Typography.Text>}
      </div>
      {value.trim() !== fallback && (
        <Button type="link" size="small" style={{ alignSelf: 'flex-start', padding: 0 }}
          onClick={() => { const p = parseCron(fallback); setMode(p.mode); onChange?.(fallback) }}>{t('schedResetYaml', { yaml: fallback })}</Button>
      )}
    </Flex>
  )
}
