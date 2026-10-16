import {
  AppstoreOutlined, LogoutOutlined, MenuFoldOutlined, MenuUnfoldOutlined, MoonOutlined, SunOutlined, TranslationOutlined, UserOutlined,
  CheckCircleOutlined,
} from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Avatar, Badge, Button, Drawer, Dropdown, Grid, Layout as AntLayout, Menu, Select, Space, Tag, Tooltip, Typography, theme } from 'antd'
import type { MenuProps } from 'antd'
import { useState } from 'react'
import { Link, Outlet, useLocation, useNavigate } from 'react-router'
import { fetchApprovals } from '../api'
import { ROLE_KEY } from '../components/format'
import { useI18n } from '../i18n'
import { Logo } from '../components/Logo'
import { NAV, type NavGroup, type NavItem } from './nav'
import { useSession } from './session'
import { useTheme } from './theme'

const MORE = 'more'

// 待审批数：只有组 admin 能看审批，Pi 正阻塞等着人，所以挂在顶栏
function ApprovalBell() {
  const { t } = useI18n()
  const { group } = useSession()
  const navigate = useNavigate()
  const isGroupAdmin = group?.role === 'admin'
  const { data } = useQuery({
    queryKey: ['approvals', group?.id],
    queryFn: () => fetchApprovals(group!.id),
    enabled: !!group && isGroupAdmin,
    refetchInterval: 10_000,
  })
  if (!isGroupAdmin) return null
  const pending = data?.filter(a => a.status === 'pending').length ?? 0
  return (
    <Tooltip title={t('pendingApprovals', { n: pending })}>
      <Badge count={pending} size="small">
        <Button type="text" aria-label={t('pendingApprovals', { n: pending })} icon={<CheckCircleOutlined />} onClick={() => navigate('/approvals')} />
      </Badge>
    </Tooltip>
  )
}

export function Layout() {
  const { t, locale, setLocale } = useI18n()
  const { dark, toggle } = useTheme()
  const { me, isAdmin, groups, group, setGroupId, signOut } = useSession()
  const { token } = theme.useToken()
  const wide = !!Grid.useBreakpoint().lg
  const [menuOpen, setMenuOpen] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('siderCollapsed') === '1')

  const visible = (x: { admin?: boolean }) => !x.admin || isAdmin
  const toItem = (n: NavItem) => ({ key: n.path, icon: n.icon, label: t(n.key) })
  type Item = NonNullable<MenuProps['items']>[number]
  const navGroups: NavGroup[] = NAV.filter((n): n is NavGroup => 'items' in n).filter(visible)
  // 平铺的是日常入口；分组都收进「更多」，默认折叠，当前页在里面时才展开
  const items: Item[] = [
    ...NAV.filter((n): n is NavItem => !('items' in n)).filter(visible).map(toItem),
    {
      key: MORE, icon: <AppstoreOutlined />, label: t('navMore'),
      children: navGroups.map(g => ({ type: 'group' as const, key: g.key, label: t(g.key), children: g.items.filter(visible).map(toItem) })),
    },
  ]
  const selected = '/' + location.pathname.split('/')[1]
  const inMore = navGroups.some(g => g.items.some(i => i.path === selected))

  const collapse = () => {
    localStorage.setItem('siderCollapsed', collapsed ? '0' : '1')
    setCollapsed(!collapsed)
  }

  return (
    <AntLayout style={{ minHeight: '100vh' }}>
      {wide ? (
        <AntLayout.Sider theme="light" width={220} collapsed={collapsed}
          style={{ borderRight: `1px solid ${token.colorBorderSecondary}`, position: 'sticky', top: 0, height: '100dvh', overflow: 'auto' }}>
          <Link className="brand" to="/chat" aria-label="OpenXDR">
            <Logo />{!collapsed && <span className="brand-name">OpenXDR</span>}
          </Link>
          <Menu mode="inline" selectedKeys={[selected]} defaultOpenKeys={inMore ? [MORE] : []} items={items} onClick={e => navigate(e.key)} style={{ borderInlineEnd: 'none' }} />
        </AntLayout.Sider>
      ) : (
        <Drawer title={<Space><Logo /><span>OpenXDR</span></Space>} placement="left" size={280}
          open={menuOpen} onClose={() => setMenuOpen(false)} styles={{ body: { padding: 0 } }}>
          <Menu mode="inline" selectedKeys={[selected]} defaultOpenKeys={inMore ? [MORE] : []} items={items}
            onClick={e => { navigate(e.key); setMenuOpen(false) }} />
        </Drawer>
      )}
      <AntLayout style={{ minWidth: 0 }}>
        <AntLayout.Header
          style={{
            background: token.colorBgContainer,
            borderBottom: `1px solid ${token.colorBorderSecondary}`,
            padding: wide ? '0 16px' : '0 8px',
            display: 'flex',
            alignItems: 'center',
            gap: wide ? 12 : 4,
            position: 'sticky',
            top: 0,
            zIndex: 10,
          }}
        >
          <Button type="text" aria-label={t('navigation')} aria-expanded={wide ? !collapsed : menuOpen} icon={collapsed || !wide ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />} onClick={wide ? collapse : () => setMenuOpen(true)} />
          <Space size={4} style={{ minWidth: 0, flex: wide ? undefined : 1 }}>
            {wide && <Typography.Text type="secondary">{t('currentGroup')}</Typography.Text>}
            <Select
              aria-label={t('currentGroup')}
              style={{ width: wide ? 180 : 112 }}
              value={group?.id}
              placeholder={t('noGroups')}
              onChange={setGroupId}
              options={groups.map(g => ({ value: g.id, label: g.name }))}
              notFoundContent={t('noGroups')}
            />
          </Space>
          <div style={{ flex: 1 }} />
          <ApprovalBell />
          <Tooltip title={dark ? t('lightMode') : t('darkMode')}>
            <Button type="text" aria-label={dark ? t('lightMode') : t('darkMode')} icon={dark ? <SunOutlined /> : <MoonOutlined />} onClick={toggle} />
          </Tooltip>
          <Tooltip title={locale === 'zh' ? 'English' : '中文'}>
            <Button type="text" aria-label={locale === 'zh' ? 'English' : '中文'} icon={<TranslationOutlined />} onClick={() => setLocale(locale === 'zh' ? 'en' : 'zh')} />
          </Tooltip>
          <Dropdown
            trigger={['click']}
            menu={{
              items: [{ key: 'logout', icon: <LogoutOutlined />, label: t('logout') }],
              onClick: () => signOut(),
            }}
          >
            <Button type="text" aria-label={me.username}>
              <Avatar size="small" icon={<UserOutlined />} style={{ background: token.colorPrimary }} />
              {wide && <span>{me.username}</span>}
              {wide && <Tag variant="filled">{t(ROLE_KEY[me.role])}</Tag>}
            </Button>
          </Dropdown>
        </AntLayout.Header>
        <AntLayout.Content className="app-content">
          <Outlet />
        </AntLayout.Content>
      </AntLayout>
    </AntLayout>
  )
}
