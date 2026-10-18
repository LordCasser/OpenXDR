import { useEffect, useRef, useState } from 'react'

// 自动刷新后新出现或有变化的行短暂高亮，值班不用自己比对哪条是新的。
// scope 是筛选与页码：换了 scope 是换了一批数据，不算变化
export function useFlash<T>(rows: T[] | undefined, id: (r: T) => string, sig: (r: T) => string, scope: string) {
  const prev = useRef<{ scope: string; sigs: Map<string, string> } | null>(null)
  const timer = useRef(0)
  const [flash, setFlash] = useState<Set<string>>(new Set())
  useEffect(() => {
    if (!rows) return
    const sigs = new Map(rows.map(r => [id(r), sig(r)]))
    const last = prev.current
    prev.current = { scope, sigs }
    if (!last || last.scope !== scope) return
    const changed = [...sigs].filter(([k, v]) => last.sigs.get(k) !== v).map(([k]) => k)
    if (!changed.length) return
    setFlash(new Set(changed))
    clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setFlash(new Set()), 4000)
  }, [rows, scope]) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => () => clearTimeout(timer.current), [])
  return flash
}
