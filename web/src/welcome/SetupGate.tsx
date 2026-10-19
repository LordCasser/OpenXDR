import { useQuery } from '@tanstack/react-query'
import { Spin } from 'antd'
import { lazy, Suspense, type ReactNode } from 'react'
import { fetchSetup } from '../api'
import { useSession } from '../app/session'
import { LoadError } from '../components/LoadError'

// 欢迎页带着 three.js，只在首次安装时才取
const WelcomeFlow = lazy(() => import('./WelcomeFlow').then(m => ({ default: m.WelcomeFlow })))
const SetupWaiting = lazy(() => import('./WelcomeFlow').then(m => ({ default: m.SetupWaiting })))

// 安装初始化闸门：用户协议没同意前控制台不开放；管理员顺带走首次引导（升级上来的实例由 server 判定跳过）
export function SetupGate({ children }: { children: ReactNode }) {
  const { isAdmin } = useSession()
  const setup = useQuery({ queryKey: ['setup'], queryFn: fetchSetup })
  if (setup.isPending) return <Spin fullscreen />
  if (setup.isError) return <LoadError error={setup.error} onRetry={() => setup.refetch()} />
  const s = setup.data
  const welcome = isAdmin && (!s.accepted || !s.onboarded)
  if (!welcome && s.accepted) return children
  return (
    <Suspense fallback={<Spin fullscreen />}>
      {welcome ? <WelcomeFlow setup={s} /> : <SetupWaiting />}
    </Suspense>
  )
}
