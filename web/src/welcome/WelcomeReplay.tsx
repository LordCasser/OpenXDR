import { useQuery } from '@tanstack/react-query'
import { Spin } from 'antd'
import { useNavigate } from 'react-router'
import { fetchSetup } from '../api'
import { LoadError } from '../components/LoadError'
import { WelcomeFlow } from './WelcomeFlow'

// 重看欢迎页：片头、欢迎首屏与只读的用户协议，看完回到控制台。不改初始化状态
export function WelcomeReplay() {
  const navigate = useNavigate()
  const setup = useQuery({ queryKey: ['setup'], queryFn: fetchSetup })
  if (setup.isPending) return <Spin fullscreen />
  if (setup.isError) return <LoadError error={setup.error} onRetry={() => setup.refetch()} />
  return <WelcomeFlow setup={setup.data} onExit={() => (window.history.length > 1 ? navigate(-1) : navigate('/chat'))} />
}
