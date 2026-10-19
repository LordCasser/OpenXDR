import type { MsgKey, T } from '../i18n'
import type { SessionMessage } from '../api'

// AI 员工的一步：平台工具（exec、query……）或沙箱里的命令（xdr exec ……、整理数据的 bash），翻译成人话
export interface Activity {
  seq: number
  at: string
  kind: 'exec' | 'query' | 'record' | 'report' | 'read' | 'sandbox' | 'think'
  text: string
}

const clip = (s: string, n = 80) => {
  const line = s.split('\n')[0].trim()
  return line.length > n ? line.slice(0, n) + '…' : line
}

// xdr 子命令 → 动作与文案
const XDR: Record<string, [Activity['kind'], MsgKey]> = {
  sql: ['query', 'actSql'],
  context: ['read', 'actContext'],
  hosts: ['read', 'actContext'],
  memories: ['read', 'actMemories'],
  track: ['record', 'actTrack'],
  identify: ['record', 'actIdentify'],
  egress: ['record', 'actEgress'],
  remember: ['record', 'actRemember'],
  forget: ['record', 'actForget'],
  suppress: ['record', 'actSuppress'],
  'propose-close': ['record', 'actProposeClose'],
  report: ['report', 'actReport'],
}

// 平台工具名（非沙箱模式）与 xdr 子命令同义
const TOOL: Record<string, string> = { query: 'sql', propose_close: 'propose-close' }

function describeXdr(command: string, t: T): Pick<Activity, 'kind' | 'text'> | null {
  const m = /\bxdr\s+([a-z-]+)\s*([\s\S]*)/.exec(command)
  if (!m) return null
  const [, sub, rest] = m
  if (sub === 'exec') {
    const e = /^(\S+)\s+(['"])([\s\S]*?)\2/.exec(rest) ?? /^(\S+)\s+(\S+)/.exec(rest)
    const host = e?.[1] ?? '?'
    const cmd = e ? (e[3] ?? e[2]) : rest
    return { kind: 'exec', text: t('actExec', { host, cmd: clip(cmd, 70) }) }
  }
  const known = XDR[sub]
  return known ? { kind: known[0], text: t(known[1]) } : null
}

function describeCall(name: string, args: Record<string, unknown>, hosts: Record<string, string>, t: T): Pick<Activity, 'kind' | 'text'> {
  const str = (k: string) => (typeof args[k] === 'string' ? (args[k] as string) : '')
  switch (name) {
    case 'bash':
      return describeXdr(str('command'), t) ?? { kind: 'sandbox', text: t('actSandbox', { cmd: clip(str('command'), 70) }) }
    case 'read':
      return { kind: 'read', text: str('path').endsWith('SKILL.md') ? t('actSkill') : t('actRead', { path: clip(str('path'), 60) }) }
    case 'write':
    case 'edit':
      return { kind: 'sandbox', text: t('actNotes', { path: clip(str('path'), 60) }) }
    case 'exec':
      return { kind: 'exec', text: t('actExec', { host: hosts[str('host')] ?? str('host').slice(0, 8), cmd: clip(str('cmd'), 70) }) }
    default: {
      const known = XDR[TOOL[name] ?? name]
      return known ? { kind: known[0], text: t(known[1]) } : { kind: 'sandbox', text: name }
    }
  }
}

// 会话消息 → 活动流：每个工具调用一步；最后的文字回复算「写总结」
export function activitiesOf(messages: SessionMessage[], hosts: Record<string, string>, t: T): Activity[] {
  const out: Activity[] = []
  for (const m of messages) {
    if (m.content.role !== 'assistant') continue
    for (const part of m.content.content) {
      if (part.type === 'toolCall') {
        out.push({ seq: m.seq, at: m.created_at, ...describeCall(part.name, part.arguments, hosts, t) })
      } else if (part.type === 'text' && part.text.trim() && !m.content.content.some(p => p.type === 'toolCall')) {
        out.push({ seq: m.seq, at: m.created_at, kind: 'think', text: t('actSummary') })
      }
    }
  }
  return out
}
