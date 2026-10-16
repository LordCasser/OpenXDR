import {
  LogoutOutlined, MenuFoldOutlined, MenuUnfoldOutlined, MoonOutlined, SunOutlined, TranslationOutlined, UserOutlined,
  CheckCircleOutlined,
} from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Avatar, Badge, Button, Dropdown, Grid, Layout as AntLayout, Menu, Select, Space, Tag, Tooltip, Typography, theme } from 'antd'
import type { MenuProps } from 'antd'
import { useState } from 'react'
import { Outlet, useLocation, useNavigate } from 'react-router'
import { fetchApprovals } from '../api'
import { ROLE_KEY } from '../components/format'
import { useI18n } from '../i18n'
import { Logo } from '../components/Logo'
import { NAV, type NavItem } from './nav'
import { useSession } from './session'
import { useTheme } from './theme'

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
        <Button type="text" icon={<CheckCircleOutlined />} onClick={() => navigate('/approvals')} />
      </Badge>
    </Tooltip>
  )
}

export function Layout() {
  const { t, locale, setLocale } = useI18n()
  const { dark, toggle } = useTheme()
  const { me, isAdmin, groups, group, setGroupId, signOut } = useSession()
  const { token } = theme.useToken()
  const wide = Grid.useBreakpoint().md
  const navigate = useNavigate()
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('siderCollapsed') === '1')

  const visible = (x: { admin?: boolean }) => !x.admin || isAdmin
  const toItem = (n: NavItem) => ({ key: n.path, icon: n.icon, label: t(n.key) })
  // 收起时分组标题挤不下，换成分隔线
  type Item = NonNullable<MenuProps['items']>[number]
  const items: Item[] = NAV.filter(visible).flatMap((n): Item[] =>
    !('items' in n)
      ? [toItem(n)]
      : collapsed
        ? [{ type: 'divider' as const, key: n.key }, ...n.items.filter(visible).map(toItem)]
        : [{ type: 'group' as const, key: n.key, label: t(n.key), children: n.items.filter(visible).map(toItem) }],
  )
  const selected = '/' + location.pathname.split('/')[1]

  const collapse = () => {
    localStorage.setItem('siderCollapsed', collapsed ? '0' : '1')
    setCollapsed(!collapsed)
  }

  return (
    <AntLayout style={{ minHeight: '100vh' }}>
      <AntLayout.Sider
        theme="light"
        width={220}
        collapsed={collapsed}
        breakpoint="lg"
        onBreakpoint={setCollapsed}
        style={{ borderRight: `1px solid ${token.colorBorderSecondary}`, position: 'sticky', top: 0, height: '100vh', overflow: 'auto' }}
      >
        <div className="brand" onClick={() => navigate('/chat')}>
          <Logo />
          {!collapsed && <span className="brand-name">OpenXDR</span>}
        </div>
        <Menu
          mode="inline"
          theme="light"
          selectedKeys={[selected]}
          items={items}
          onClick={e => navigate(e.key)}
          style={{ borderInlineEnd: 'none' }}
        />
      </AntLayout.Sider>
      <AntLayout>
        <AntLayout.Header
          style={{
            background: token.colorBgContainer,
            borderBottom: `1px solid ${token.colorBorderSecondary}`,
            padding: '0 16px',
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            position: 'sticky',
            top: 0,
            zIndex: 10,
          }}
        >
          <Button type="text" icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />} onClick={collapse} />
          <Space size={4}>
            {wide && <Typography.Text type="secondary">{t('currentGroup')}</Typography.Text>}
            <Select
              style={{ minWidth: wide ? 160 : 110 }}
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
            <Button type="text" icon={dark ? <SunOutlined /> : <MoonOutlined />} onClick={toggle} />
          </Tooltip>
          <Tooltip title={locale === 'zh' ? 'English' : '中文'}>
            <Button type="text" icon={<TranslationOutlined />} onClick={() => setLocale(locale === 'zh' ? 'en' : 'zh')} />
          </Tooltip>
          <Dropdown
            menu={{
              items: [{ key: 'logout', icon: <LogoutOutlined />, label: t('logout') }],
              onClick: () => signOut(),
            }}
          >
            <Space style={{ cursor: 'pointer' }}>
              <Avatar size="small" icon={<UserOutlined />} style={{ background: token.colorPrimary }} />
              {wide && <span>{me.username}</span>}
              {wide && <Tag variant="filled">{t(ROLE_KEY[me.role])}</Tag>}
            </Space>
          </Dropdown>
        </AntLayout.Header>
        <AntLayout.Content style={{ padding: 24 }}>
          <Outlet />
        </AntLayout.Content>
      </AntLayout>
    </AntLayout>
  )
}
