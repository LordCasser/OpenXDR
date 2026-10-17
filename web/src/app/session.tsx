import { Spin } from 'antd'
import { LoadError } from '../components/LoadError'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { fetchGroups, fetchMe, logout, Unauthorized, type GroupRow, type Me } from '../api'

// 登录用户与当前组。组是授权与纳管的单位：对话、审批、报告都在当前组里看
interface Session {
  me: Me
  isAdmin: boolean
  canWrite: boolean
  groups: GroupRow[]
  group: GroupRow | undefined
  setGroupId: (id: string) => void
  signOut: () => Promise<void>
}

const SessionContext = createContext<Session | null>(null)

export function SessionProvider({ me, children }: { me: Me; children: ReactNode }) {
  const client = useQueryClient()
  const groupsQuery = useQuery({ queryKey: ['groups'], queryFn: fetchGroups })
  const groups = groupsQuery.data ?? []
  const [groupId, setGroupIdState] = useState(() => localStorage.getItem('groupId'))
  const group = groups.find(g => g.id === groupId) ?? groups[0]

  // 记住的组可能已被删或已被移出，落回第一个可见组
  useEffect(() => {
    if (group && group.id !== groupId) setGroupIdState(group.id)
  }, [group, groupId])

  const setGroupId = (id: string) => {
    localStorage.setItem('groupId', id)
    setGroupIdState(id)
  }

  const signOut = async () => {
    await logout()
    client.removeQueries({ predicate: query => query.queryKey[0] !== 'me' })
    client.setQueryData(['me'], null)
  }

  if (groupsQuery.isPending) return <Spin fullscreen />
  if (groupsQuery.isError) return <LoadError error={groupsQuery.error} onRetry={() => groupsQuery.refetch()} />

  return (
    <SessionContext.Provider
      value={{
        me,
        isAdmin: me.role === 'admin',
        canWrite: me.role !== 'viewer',
        groups,
        group,
        setGroupId,
        signOut,
      }}
    >
      {children}
    </SessionContext.Provider>
  )
}

export function useSession(): Session {
  const s = useContext(SessionContext)
  if (!s) throw new Error('useSession 必须在 SessionProvider 内使用')
  return s
}

// 处置类操作：全局角色过了 analyst，且在组内也是 analyst 以上（后端两道检查）
export function useCanActIn(groupId: string | null | undefined) {
  return useCanAct()(groupId)
}

// 同上，列表里每行组不同时用
export function useCanAct() {
  const { isAdmin, canWrite, groups } = useSession()
  return (groupId: string | null | undefined) => {
    const role = groups.find(g => g.id === groupId)?.role
    return isAdmin || (canWrite && (role === 'admin' || role === 'analyst'))
  }
}

export const useMe = () =>
  useQuery({ queryKey: ['me'], queryFn: async () => {
    try { return await fetchMe() }
    catch (error) {
      if (error instanceof Unauthorized) return null
      throw error
    }
  }, staleTime: Infinity })
