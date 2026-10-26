import type { ComponentProps } from 'react'

// 操作按整项换行，文字不拆字；保留原生事件和 ref，供 Tooltip 与键盘导航使用。
export function TableActions({ className, ...props }: ComponentProps<'div'>) {
  return <div {...props} className={['table-actions', className].filter(Boolean).join(' ')} />
}
