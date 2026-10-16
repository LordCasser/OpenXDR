import { Button, Result, Spin } from 'antd'
import type { ComponentType, ReactNode } from 'react'
import { Navigate, RouterProvider, createBrowserRouter, useNavigate, useSearchParams } from 'react-router'
import { Layout } from './app/Layout'
import { SessionProvider, useMe, useSession } from './app/session'
import { useI18n } from './i18n'
import { LoginPage } from './pages/LoginPage'

// Webhook 里的老链接是 /?incident= 与 /?session=，进来后转到对应页面
function Home() {
  const [params] = useSearchParams()
  const incident = params.get('incident')
  const session = params.get('session')
  if (incident) return <Navigate to={`/incidents/${incident}`} replace />
  if (session) return <Navigate to={`/chat/${session}`} replace />
  return <Navigate to="/chat" replace />
}

function NotFound() {
  const { t } = useI18n()
  const navigate = useNavigate()
  return (
    <Result
      status="404"
      title="404"
      subTitle={t('notFound')}
      extra={<Button type="primary" onClick={() => navigate('/chat')}>{t('backHome')}</Button>}
    />
  )
}

// 管理页：后端同样拦着，这里只是别让人点进一个满屏 403 的页面
function AdminOnly({ children }: { children: ReactNode }) {
  const { t } = useI18n()
  const { isAdmin } = useSession()
  return isAdmin ? children : <Result status="403" title="403" subTitle={t('adminOnly')} />
}

// 页面按路由懒加载：首屏只带外壳与登录页，其余页面进入时再取
type Pages = Record<string, ComponentType>
const page = (load: () => Promise<Pages>, name: string, admin = false) => ({
  lazy: async () => {
    const C = (await load())[name]
    return { Component: admin ? () => <AdminOnly><C /></AdminOnly> : C }
  },
})

const router = createBrowserRouter([
  {
    path: '/',
    element: <Layout />,
    children: [
      { index: true, element: <Home /> },
      { path: 'chat', ...page(() => import('./pages/ChatPage'), 'ChatPage') },
      { path: 'chat/:sessionId', ...page(() => import('./pages/ChatPage'), 'ChatPage') },
      { path: 'overview', ...page(() => import('./pages/OverviewPage'), 'OverviewPage') },
      { path: 'incidents', ...page(() => import('./pages/IncidentsPage'), 'IncidentsPage') },
      { path: 'incidents/:id', ...page(() => import('./pages/IncidentDetailPage'), 'IncidentDetailPage') },
      { path: 'events', ...page(() => import('./pages/EventsPage'), 'EventsPage') },
      { path: 'hunt', ...page(() => import('./pages/HuntPage'), 'HuntPage', true) },
      { path: 'assets', ...page(() => import('./pages/AssetsPage'), 'AssetsPage') },
      { path: 'reports', ...page(() => import('./pages/ReportsPage'), 'ReportsPage') },
      { path: 'tasks', ...page(() => import('./pages/TasksPage'), 'TasksPage') },
      { path: 'approvals', ...page(() => import('./pages/ApprovalsPage'), 'ApprovalsPage') },
      { path: 'rules', ...page(() => import('./pages/RulesPage'), 'RulesPage') },
      { path: 'attack', ...page(() => import('./pages/AttackPage'), 'AttackPage') },
      { path: 'suppressions', ...page(() => import('./pages/SuppressionsPage'), 'SuppressionsPage') },
      { path: 'intel', ...page(() => import('./pages/IntelPage'), 'IntelPage') },
      { path: 'users', ...page(() => import('./pages/UsersPage'), 'UsersPage', true) },
      { path: 'groups', ...page(() => import('./pages/GroupsPage'), 'GroupsPage', true) },
      { path: 'audit', ...page(() => import('./pages/AuditPage'), 'AuditPage', true) },
      { path: '*', element: <NotFound /> },
    ],
  },
])

export default function App() {
  const { data: me, isPending } = useMe()
  if (isPending) return <Spin fullscreen />
  if (!me) return <LoginPage />
  return (
    <SessionProvider me={me}>
      <RouterProvider router={router} />
    </SessionProvider>
  )
}
