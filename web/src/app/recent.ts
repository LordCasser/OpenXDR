import { useEffect } from 'react'

// 最近打开的事件、主机与会话：存在本地，命令面板空查询时列在最前，值班来回切换不用再搜
export interface Recent { to: string; label: string; kind: 'incident' | 'asset' | 'session' }

const KEY = 'recentVisits'

export function loadRecent(): Recent[] {
  try {
    const v: unknown = JSON.parse(localStorage.getItem(KEY) ?? '[]')
    return Array.isArray(v) ? v.filter((x): x is Recent => typeof x?.to === 'string' && typeof x?.label === 'string') : []
  } catch { return [] }
}

export function useRemember(r: Recent | undefined | false) {
  const to = r ? r.to : undefined
  const label = r ? r.label : undefined
  const kind = r ? r.kind : undefined
  useEffect(() => {
    if (!to || !label || !kind) return
    localStorage.setItem(KEY, JSON.stringify([{ to, label, kind }, ...loadRecent().filter(x => x.to !== to)].slice(0, 8)))
  }, [to, label, kind])
}
