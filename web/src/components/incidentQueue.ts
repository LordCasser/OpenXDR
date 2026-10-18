// 事件列表当前页记在会话存储里：详情页据此上一条 / 下一条、侧栏列出前后几条，结案后转到下一条
const KEY = 'incidentQueue'

export interface QueueItem { id: string; title: string | null; severity: number }

export const saveQueue = (rows: QueueItem[]) =>
  sessionStorage.setItem(KEY, JSON.stringify(rows.map(({ id, title, severity }) => ({ id, title, severity }))))

export function neighbors(id: string | undefined) {
  let items: QueueItem[] = []
  try {
    const v: unknown = JSON.parse(sessionStorage.getItem(KEY) ?? '[]')
    if (Array.isArray(v)) items = v.filter((x): x is QueueItem => typeof x?.id === 'string')
  } catch { /* 坏数据当作没有队列 */ }
  const i = id ? items.findIndex(x => x.id === id) : -1
  return { items, index: i, total: items.length, prev: i > 0 ? items[i - 1].id : undefined, next: i >= 0 ? items[i + 1]?.id : undefined }
}
