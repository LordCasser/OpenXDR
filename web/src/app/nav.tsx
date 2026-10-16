import {
  AimOutlined, AlertOutlined, AuditOutlined, BugOutlined, CheckCircleOutlined, ClockCircleOutlined, CloudServerOutlined,
  DashboardOutlined, FileSearchOutlined, FileTextOutlined, RobotOutlined, SafetyOutlined, SearchOutlined, StopOutlined,
  TeamOutlined, UserOutlined,
} from '@ant-design/icons'
import type { ReactNode } from 'react'
import type { MsgKey } from '../i18n'

export interface NavItem {
  path: string
  key: MsgKey
  icon: ReactNode
  admin?: boolean
}

export interface NavGroup {
  key: MsgKey
  items: NavItem[]
  admin?: boolean
}

// 菜单即信息架构：对话是主入口，原有能力按运营动线归组；面包屑也从这里推
export const NAV: (NavItem | NavGroup)[] = [
  { path: '/chat', key: 'navChat', icon: <RobotOutlined /> },
  { path: '/overview', key: 'navOverview', icon: <DashboardOutlined /> },
  {
    key: 'navGroupOps',
    items: [
      { path: '/incidents', key: 'navIncidents', icon: <AlertOutlined /> },
      { path: '/events', key: 'navEvents', icon: <SearchOutlined /> },
      { path: '/hunt', key: 'navHunt', icon: <AimOutlined />, admin: true },
    ],
  },
  { path: '/assets', key: 'navAssets', icon: <CloudServerOutlined /> },
  {
    key: 'navGroupAuto',
    items: [
      { path: '/reports', key: 'navReports', icon: <FileTextOutlined /> },
      { path: '/tasks', key: 'navTasks', icon: <ClockCircleOutlined /> },
      { path: '/approvals', key: 'navApprovals', icon: <CheckCircleOutlined /> },
    ],
  },
  {
    key: 'navGroupDetect',
    items: [
      { path: '/rules', key: 'navRules', icon: <FileSearchOutlined /> },
      { path: '/attack', key: 'navAttack', icon: <BugOutlined /> },
      { path: '/suppressions', key: 'navSuppressions', icon: <StopOutlined /> },
      { path: '/intel', key: 'navIntel', icon: <SafetyOutlined /> },
    ],
  },
  {
    key: 'navGroupSystem',
    admin: true,
    items: [
      { path: '/users', key: 'navUsers', icon: <UserOutlined /> },
      { path: '/groups', key: 'navGroups', icon: <TeamOutlined /> },
      { path: '/audit', key: 'navAudit', icon: <AuditOutlined /> },
    ],
  },
]

// 路径第一段 → [分组, 页面]，供面包屑用
export function crumbsOf(pathname: string): { group?: MsgKey; page?: NavItem } {
  const top = '/' + pathname.split('/')[1]
  for (const n of NAV) {
    if ('items' in n) {
      const page = n.items.find(i => i.path === top)
      if (page) return { group: n.key, page }
    } else if (n.path === top) return { page: n }
  }
  return {}
}
