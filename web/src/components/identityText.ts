import type { MsgKey } from '../i18n'

// 账号的可读名：名字缺失时退回 SID，Linux 带上 UID
export function accountLabel(a: { name: string | null; sid?: string | null; uid?: number | null; domain?: string | null }) {
  const name = a.name ?? a.sid ?? '—'
  const domain = a.domain ? `${a.domain}\\` : ''
  return a.uid != null ? `${name} (uid ${a.uid})` : domain + name
}

export function linkSource(source: string | null, t: (k: MsgKey) => string) {
  if (!source) return '—'
  return source === 'system' ? t('identitySystem') : source.replace(/^user:/, '')
}
