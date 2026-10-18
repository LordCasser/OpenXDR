// 事件列表当前页的顺序记在会话存储里：详情页据此上一条 / 下一条，结案后转到下一条
const KEY = 'incidentQueue'

export const saveQueue = (ids: string[]) => sessionStorage.setItem(KEY, JSON.stringify(ids))

export function neighbors(id: string | undefined) {
  let ids: string[] = []
  try {
    const v: unknown = JSON.parse(sessionStorage.getItem(KEY) ?? '[]')
    if (Array.isArray(v)) ids = v.filter(x => typeof x === 'string')
  } catch { /* 坏数据当作没有队列 */ }
  const i = id ? ids.indexOf(id) : -1
  return { index: i, total: ids.length, prev: i > 0 ? ids[i - 1] : undefined, next: i >= 0 ? ids[i + 1] : undefined }
}
