import { AlertOutlined, CloudServerOutlined, MessageOutlined, SearchOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Input, Modal, Typography, theme } from 'antd'
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router'
import { fetchAgentSessions, fetchAssets, fetchIncidents } from '../api'
import { SeverityTag } from '../components/format'
import { useI18n, type MsgKey } from '../i18n'
import { NAV, type NavItem } from './nav'
import { useSession } from './session'

interface Hit {
  key: string
  section: MsgKey
  icon: ReactNode
  label: string
  extra?: ReactNode
  to: string
}

// 命令面板：Ctrl/⌘+K 打开，一个输入框跳到页面、主机、未结案事件、本组会话
export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const navigate = useNavigate()
  const { isAdmin, groups, group } = useSession()
  const [q, setQ] = useState('')
  const [active, setActive] = useState(0)
  const list = useRef<HTMLDivElement>(null)
  const assets = useQuery({ queryKey: ['assets'], queryFn: fetchAssets, enabled: open })
  const incidents = useQuery({ queryKey: ['incidents', 'palette'], queryFn: () => fetchIncidents({ status: 'unresolved', limit: 200 }), enabled: open, staleTime: 30_000 })
  const sessions = useQuery({ queryKey: ['sessions', group?.id], queryFn: () => fetchAgentSessions(group!.id), enabled: open && !!group })

  const hits = useMemo(() => {
    const needle = q.trim().toLowerCase()
    const match = (...xs: (string | null | undefined)[]) => !needle || xs.some(x => x?.toLowerCase().includes(needle))
    const groupAdmin = isAdmin || groups.some(g => g.role === 'admin')
    const pages = NAV.flatMap(n => ('items' in n ? n.items.map(i => ({ ...i, admin: i.admin || n.admin })) : [n]))
      .filter((n: NavItem) => (!n.admin || isAdmin) && (!n.groupAdmin || groupAdmin))
    const out: Hit[] = [
      ...pages.filter(p => match(t(p.key), p.path)).map(p => ({ key: p.path, section: 'paletteSectionPages' as MsgKey, icon: p.icon, label: t(p.key), to: p.path })),
      ...(assets.data ?? []).filter(a => needle && match(a.hostname, ...(a.ipAddrs ?? []))).slice(0, 6)
        .map(a => ({ key: a.id, section: 'paletteSectionHosts' as MsgKey, icon: <CloudServerOutlined />, label: a.hostname, extra: a.ipAddrs?.join(', '), to: `/assets/${a.id}` })),
      ...(incidents.data?.items ?? []).filter(i => needle && match(i.title, i.id)).slice(0, 6)
        .map(i => ({ key: i.id, section: 'paletteSectionIncidents' as MsgKey, icon: <AlertOutlined />, label: i.title ?? i.id, extra: <SeverityTag value={i.severity} />, to: `/incidents/${i.id}` })),
      ...(sessions.data ?? []).filter(s => needle && match(s.title)).slice(0, 5)
        .map(s => ({ key: s.id, section: 'paletteSectionSessions' as MsgKey, icon: <MessageOutlined />, label: s.title || t('chatSession'), to: `/chat/${s.id}` })),
    ]
    return out
  }, [q, assets.data, incidents.data, sessions.data, isAdmin, groups, t])

  useEffect(() => setActive(0), [q])
  useEffect(() => {
    if (!open) setQ('')
  }, [open])
  useEffect(() => {
    list.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: 'nearest' })
  }, [active])

  const go = (h: Hit | undefined) => {
    if (!h) return
    onClose()
    navigate(h.to)
  }

  return (
    <Modal open={open} onCancel={onClose} footer={null} closable={false} width={600} styles={{ container: { padding: 0, overflow: 'hidden' }, body: { padding: 0 } }} destroyOnHidden
      style={{ top: 96 }}>
      <Input
        autoFocus
        size="large"
        variant="borderless"
        className="palette-input"
        prefix={<SearchOutlined style={{ color: token.colorTextTertiary }} />}
        placeholder={t('palettePlaceholder')}
        value={q}
        onChange={e => setQ(e.target.value)}
        onKeyDown={e => {
          if (e.key === 'ArrowDown') { e.preventDefault(); setActive(a => Math.min(a + 1, hits.length - 1)) }
          if (e.key === 'ArrowUp') { e.preventDefault(); setActive(a => Math.max(a - 1, 0)) }
          if (e.key === 'Enter') go(hits[active])
        }}
        style={{ padding: '14px 16px', borderBottom: `1px solid ${token.colorBorderSecondary}` }}
      />
      <div ref={list} className="palette-list">
        {hits.length === 0 && <Typography.Text type="secondary" style={{ display: 'block', padding: 20, textAlign: 'center' }}>{t('noMatch')}</Typography.Text>}
        {hits.map((h, i) => (
          <div key={h.section + h.key}>
            {(i === 0 || hits[i - 1].section !== h.section) && <div className="palette-section">{t(h.section)}</div>}
            <div
              role="option"
              aria-selected={i === active}
              data-active={i === active}
              className="palette-item"
              style={i === active ? { background: token.controlItemBgActive } : undefined}
              onMouseEnter={() => setActive(i)}
              onClick={() => go(h)}
            >
              <span style={{ color: token.colorTextSecondary }}>{h.icon}</span>
              <Typography.Text ellipsis style={{ flex: 1 }}>{h.label}</Typography.Text>
              {h.extra && <Typography.Text type="secondary" style={{ fontSize: 12 }}>{h.extra}</Typography.Text>}
            </div>
          </div>
        ))}
      </div>
      <div className="palette-foot" style={{ borderTop: `1px solid ${token.colorBorderSecondary}`, color: token.colorTextTertiary }}>
        <span><kbd>↑</kbd><kbd>↓</kbd> {t('paletteMove')}</span>
        <span><kbd>Enter</kbd> {t('paletteOpen')}</span>
        <span><kbd>Esc</kbd> {t('paletteClose')}</span>
      </div>
    </Modal>
  )
}
