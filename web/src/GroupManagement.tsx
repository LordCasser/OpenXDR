import { useCallback, useEffect, useState } from 'react'
import {
  assignAsset, createGroup, deleteGroup, fetchAssets, fetchGroups, fetchMembers, fetchUsers,
  removeMember, setMember, unassignAsset,
  type Asset, type GroupRow, type MemberRow, type UserRow,
} from './api'
import { useI18n, type MsgKey } from './i18n'

const ROLE_KEY: Record<string, MsgKey> = {
  admin: 'roleAdmin',
  analyst: 'roleAnalyst',
  viewer: 'roleViewer',
}

// 组管理：建删组、组内成员角色、资产归组。只有 admin 能打开
export function GroupManagement({ onClose }: { onClose: () => void }) {
  const { t } = useI18n()
  const [groups, setGroups] = useState<GroupRow[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [members, setMembers] = useState<MemberRow[]>([])
  const [users, setUsers] = useState<UserRow[]>([])
  const [assets, setAssets] = useState<Asset[]>([])
  const [name, setName] = useState('')
  const [newUser, setNewUser] = useState('')
  const [newRole, setNewRole] = useState('analyst')
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      const [g, u, a] = await Promise.all([fetchGroups(), fetchUsers(), fetchAssets()])
      setGroups(g)
      setUsers(u)
      setAssets(a)
      setMembers(selected ? await fetchMembers(selected) : [])
    } catch {
      /* 拉取失败保持原列表 */
    }
  }, [selected])

  useEffect(() => {
    refresh()
  }, [refresh])

  const run = async (fn: () => Promise<unknown>) => {
    setError(null)
    try {
      await fn()
      await refresh()
    } catch (e) {
      setError(String(e))
    }
  }

  const remove = (g: GroupRow) => {
    if (!confirm(t('groupDeleteConfirm', { name: g.name }))) return
    if (g.id === selected) setSelected(null)
    run(() => deleteGroup(g.id))
  }

  const group = groups.find(g => g.id === selected)
  const groupName = (id: string | null) => groups.find(g => g.id === id)?.name ?? t('ungrouped')
  const candidates = users.filter(u => !members.some(m => m.userId === u.id))

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={e => e.stopPropagation()}>
        <h3>{t('groupListTitle', { n: groups.length })}</h3>
        <table>
          <thead>
            <tr><th>{t('thGroup')}</th><th>{t('thAssetCount')}</th><th></th></tr>
          </thead>
          <tbody>
            {groups.map(g => (
              <tr key={g.id} className={g.id === selected ? 'selected-row' : ''}>
                <td>{g.name}</td>
                <td>{g.assetCount}</td>
                <td>
                  <div className="actions">
                    <button onClick={() => setSelected(g.id === selected ? null : g.id)}>
                      {g.id === selected ? t('collapse') : t('manage')}
                    </button>
                    <button onClick={() => remove(g)}>{t('del')}</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="field">
          <input placeholder={t('groupName')} value={name} onChange={e => setName(e.target.value)} />
          <button disabled={!name.trim()} onClick={() => run(async () => { await createGroup(name.trim()); setName('') })}>
            {t('create')}
          </button>
        </div>

        {group && (
          <>
            <h3>{t('groupMembersTitle', { name: group.name })}</h3>
            {members.length > 0 && (
              <table>
                <thead>
                  <tr><th>{t('username')}</th><th>{t('thRole')}</th><th></th></tr>
                </thead>
                <tbody>
                  {members.map(m => (
                    <tr key={m.userId}>
                      <td>{m.username}</td>
                      <td>
                        <select value={m.role} onChange={e => run(() => setMember(group.id, m.userId, e.target.value))}>
                          {Object.entries(ROLE_KEY).map(([r, k]) => <option key={r} value={r}>{t(k)}</option>)}
                        </select>
                      </td>
                      <td>
                        <div className="actions">
                          <button onClick={() => run(() => removeMember(group.id, m.userId))}>{t('del')}</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {members.length === 0 && <p className="muted">{t('noMembers')}</p>}
            <div className="field">
              <select value={newUser} onChange={e => setNewUser(e.target.value)}>
                <option value="">{t('pickUser')}</option>
                {candidates.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
              </select>
              <select value={newRole} onChange={e => setNewRole(e.target.value)}>
                {Object.entries(ROLE_KEY).map(([r, k]) => <option key={r} value={r}>{t(k)}</option>)}
              </select>
              <button disabled={!newUser} onClick={() => run(async () => { await setMember(group.id, newUser, newRole); setNewUser('') })}>
                {t('addMember')}
              </button>
            </div>

            <h3>{t('groupAssetsTitle', { name: group.name })}</h3>
            <table>
              <thead>
                <tr><th>{t('thHostname')}</th><th>{t('thGroup')}</th><th></th></tr>
              </thead>
              <tbody>
                {assets.map(a => (
                  <tr key={a.id}>
                    <td>{a.hostname}</td>
                    <td className="muted">{groupName(a.groupId)}</td>
                    <td>
                      <div className="actions">
                        {a.groupId === group.id ? (
                          <button onClick={() => run(() => unassignAsset(group.id, a.id))}>{t('removeFromGroup')}</button>
                        ) : (
                          <button onClick={() => run(() => assignAsset(group.id, a.id))}>{t('addToGroup')}</button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}

        {error && <div className="error">{error}</div>}
        <div className="actions modal-actions">
          <button onClick={onClose}>{t('close')}</button>
        </div>
      </div>
    </div>
  )
}
