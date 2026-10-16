import { useCallback, useEffect, useState } from 'react'
import { fetchTaskRuns, fetchTasks, updateTask, type GroupRow, type TaskRow, type TaskRunRow } from './api'
import { useI18n, type MsgKey } from './i18n'

const fmt = (iso: string) => new Date(iso).toLocaleString()

const RUN_KEY: Record<TaskRunRow['status'], MsgKey> = {
  running: 'sessionRunning',
  succeeded: 'sessionSucceeded',
  failed: 'sessionFailed',
}

// 预设任务：定义来自仓库 tasks/*.yml，这里只能启停与改周期（admin）；运行记录按组裁剪
export function TasksView({ isAdmin, groups, onOpenSession, onClose }: {
  isAdmin: boolean
  groups: GroupRow[]
  onOpenSession: (groupId: string, sessionId: string) => void
  onClose: () => void
}) {
  const { t } = useI18n()
  const [tasks, setTasks] = useState<TaskRow[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [runs, setRuns] = useState<TaskRunRow[]>([])
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      setTasks(await fetchTasks())
      setRuns(selected ? await fetchTaskRuns(selected) : [])
    } catch (e) {
      setError(String(e))
    }
  }, [selected])

  useEffect(() => {
    refresh()
  }, [refresh])

  const run = async (fn: () => Promise<unknown>) => {
    setError(null)
    try {
      await fn()
    } catch (e) {
      setError(String(e))
    }
    await refresh()
  }

  const editSchedule = (task: TaskRow) => {
    const v = prompt(t('taskSchedulePrompt', { yaml: task.schedule }), task.customSchedule ?? task.schedule)
    if (v === null) return
    // 与 YAML 一致就清掉自定义，免得 YAML 后续改了周期却被旧覆盖值挡住
    run(() => updateTask(task.id, { customSchedule: v.trim() === task.schedule ? '' : v.trim() }))
  }

  const groupName = (id: string) => groups.find(g => g.id === id)?.name ?? id

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={e => e.stopPropagation()}>
        <h3>{t('tasksTitle', { n: tasks.length })}</h3>
        <table>
          <thead>
            <tr><th>{t('taskName')}</th><th>{t('taskSchedule')}</th><th>{t('thGroup')}</th><th>{t('thStatus')}</th><th></th></tr>
          </thead>
          <tbody>
            {tasks.map(task => (
              <tr key={task.id} className={task.id === selected ? 'selected-row' : ''}>
                <td title={task.prompt}>{task.name}</td>
                <td>
                  <code>{task.customSchedule ?? task.schedule}</code>
                  {task.customSchedule && <span className="muted"> {t('taskCustom')}</span>}
                </td>
                <td>{task.targetGroup === '*' ? t('taskAllGroups') : task.targetGroup}</td>
                <td>{t(task.enabled ? 'taskEnabled' : 'taskDisabled')}</td>
                <td>
                  <div className="actions">
                    <button onClick={() => setSelected(task.id === selected ? null : task.id)}>
                      {task.id === selected ? t('collapse') : t('taskRuns')}
                    </button>
                    {isAdmin && (
                      <>
                        <button onClick={() => run(() => updateTask(task.id, { enabled: !task.enabled }))}>
                          {t(task.enabled ? 'taskDisable' : 'taskEnable')}
                        </button>
                        <button onClick={() => editSchedule(task)}>{t('taskEditSchedule')}</button>
                      </>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {tasks.length === 0 && !error && <p className="muted">{t('noTasks')}</p>}

        {selected && (
          <>
            <h3>{t('taskRunsTitle')}</h3>
            {runs.length === 0 ? (
              <p className="muted">{t('noTaskRuns')}</p>
            ) : (
              <table>
                <thead>
                  <tr><th>{t('thTime')}</th><th>{t('thGroup')}</th><th>{t('thStatus')}</th><th>{t('thDetail')}</th><th></th></tr>
                </thead>
                <tbody>
                  {runs.map(r => (
                    <tr key={r.id}>
                      <td className="muted">{fmt(r.startedAt)}</td>
                      <td>{groupName(r.groupId)}</td>
                      <td><span className={`status status-session-${r.status}`}>{t(RUN_KEY[r.status])}</span></td>
                      <td className="muted">{r.error ?? '-'}</td>
                      <td>
                        {r.sessionId && (
                          <button className="link" onClick={() => onOpenSession(r.groupId, r.sessionId!)}>{t('apOpenSession')}</button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
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
