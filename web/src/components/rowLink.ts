import type { MouseEvent } from 'react'
import { useNavigate } from 'react-router'

// 行内自带交互的元素：点它们时让它们自己处理，不触发整行跳转
const INTERACTIVE = 'a, button, input, textarea, label, .ant-select, .ant-checkbox-wrapper, .ant-typography-copy'

// 整行点进详情（配合 rowClassName="row-link"）。弹层经 portal 冒泡上来的点击、选中文字时都不跳；Ctrl/⌘ 点开新标签
export function useRowLink<T>(to: (r: T) => string) {
  const navigate = useNavigate()
  return (r: T) => ({
    onClick: (e: MouseEvent<HTMLElement>) => {
      const target = e.target as HTMLElement
      if (!e.currentTarget.contains(target) || target.closest(INTERACTIVE) || window.getSelection()?.toString()) return
      if (e.ctrlKey || e.metaKey) window.open(to(r), '_blank', 'noopener')
      else navigate(to(r))
    },
  })
}
