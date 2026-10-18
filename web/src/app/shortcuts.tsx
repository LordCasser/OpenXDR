import { Modal, Typography } from 'antd'
import { Fragment, useEffect, useRef, type ReactNode } from 'react'
import { useNavigate } from 'react-router'
import { useI18n } from '../i18n'
import { NAV, type NavItem } from './nav'
import { useSession } from './session'

// 正在打字、按着修饰键、或有弹窗开着时不抢键
function ignored(e: KeyboardEvent) {
  const el = e.target as HTMLElement
  return e.ctrlKey || e.metaKey || e.altKey || el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName)
    || !!document.querySelector('.ant-modal-wrap:not([style*="display: none"])')
}

// 单键快捷键：键名取 KeyboardEvent.key，handler 每次渲染都可以换
export function useKeys(map: Record<string, () => void>) {
  const ref = useRef(map)
  useEffect(() => { ref.current = map })
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const fn = ref.current[e.key]
      if (!fn || ignored(e)) return
      e.preventDefault()
      fn()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])
}

// 带快捷键且当前用户看得见的页面（审批只给组 admin）
export function useHotkeyPages() {
  const { isAdmin, groups } = useSession()
  const groupAdmin = isAdmin || groups.some(g => g.role === 'admin')
  return NAV.flatMap(n => ('items' in n ? n.items : [n]))
    .filter((n): n is NavItem & { hotkey: string } => !!n.hotkey && (!n.groupAdmin || groupAdmin))
}

// 全局快捷键：G 再按页面键跳转，N 新对话，/ 打开命令面板，? 看帮助，[ 收起侧栏
export function useGlobalKeys({ palette, help, sider }: { palette: () => void; help: () => void; sider: () => void }) {
  const navigate = useNavigate()
  const pending = useRef(0)
  const go = Object.fromEntries(useHotkeyPages().map(p => [p.hotkey, () => navigate(p.path)]))
  const after = (fn: () => void) => () => { if (Date.now() - pending.current < 1500) fn(); pending.current = 0 }
  useKeys({
    g: () => { pending.current = Date.now() },
    '/': palette,
    '?': help,
    '[': sider,
    n: () => navigate('/chat'),
    ...Object.fromEntries(Object.entries(go).map(([k, fn]) => [k, after(fn)])),
  })
}

export function ShortcutHelp({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useI18n()
  const pages = useHotkeyPages()
  const mac = /Mac|iPhone|iPad/.test(navigator.platform)
  const rows = [
    { label: t('shortcutPalette'), keys: <><kbd>{mac ? '⌘' : 'Ctrl'}</kbd><kbd>K</kbd> / <kbd>/</kbd></> },
    { label: t('shortcutHelp'), keys: <kbd>?</kbd> },
    { label: t('shortcutSider'), keys: <kbd>[</kbd> },
    { label: t('newChat'), keys: <kbd>N</kbd> },
    { label: t('shortcutQueue'), keys: <><kbd>J</kbd> / <kbd>K</kbd></> },
  ]
  const goRows = pages.map(p => ({ label: t(p.key), keys: <><kbd>G</kbd> {t('shortcutsThen')} <kbd>{p.hotkey.toUpperCase()}</kbd></> }))
  const section = (title: string, list: { label: string; keys: ReactNode }[]) => (
    <>
      <Typography.Text type="secondary" className="shortcut-section">{title}</Typography.Text>
      <div className="shortcut-grid">
        {list.map(r => <Fragment key={r.label}><span>{r.label}</span><span>{r.keys}</span></Fragment>)}
      </div>
    </>
  )
  return (
    <Modal open={open} onCancel={onClose} footer={null} title={t('shortcutsTitle')} width={480}>
      {section(t('shortcutsSectionGeneral'), rows)}
      {section(t('shortcutsSectionGo'), goRows)}
    </Modal>
  )
}
