import { CaretRightOutlined, EditOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Card, Empty, Form, Input, Modal, Space, Switch, Table, Tag, Tooltip, Typography } from 'antd'
import { useRef, useState } from 'react'
import { Link } from 'react-router'
import { fetchTaskRuns, fetchTasks, runTask, updateTask, type TaskRow, type TaskRunRow } from '../api'
import { useSession } from '../app/session'
import { LoadError } from '../components/LoadError'
import { Page } from '../components/Page'
import { SessionStatusTag, fmtTime, errText } from '../components/format'
import { useI18n } from '../i18n'

function Runs({ task }: { task: TaskRow }) {
  const { t } = useI18n()
  const { groups } = useSession()
  const { data, isPending, isError, error, refetch } = useQuery({ queryKey: ['taskRuns', task.id], queryFn: () => fetchTaskRuns(task.id), refetchInterval: 15_000 })
  if (isError) return <LoadError error={error} onRetry={() => refetch()} />
  return (
    <Table<TaskRunRow>
      scroll={{ x: 850 }}
      size="small"
      rowKey="id"
      loading={isPending}
      dataSource={data ?? []}
      pagination={{ pageSize: 10, hideOnSinglePage: true }}
      locale={{ emptyText: t('noTaskRuns') }}
      columns={[
        { title: t('thStartedAt'), dataIndex: 'startedAt', render: fmtTime, width: 180 },
        { title: t('thFinishedAt'), dataIndex: 'finishedAt', render: fmtTime, width: 180 },
        { title: t('group'), dataIndex: 'groupId', width: 140, render: v => groups.find(g => g.id === v)?.name ?? v.slice(0, 8) },
        { title: t('thStatus'), dataIndex: 'status', width: 100, render: v => <SessionStatusTag value={v} /> },
        { title: t('thDetail'), dataIndex: 'error', ellipsis: true, render: v => v ?? '-' },
        { title: '', dataIndex: 'sessionId', width: 100, render: v => v && <Link to={`/chat/${v}`}>{t('openSession')}</Link> },
      ]}
    />
  )
}

// 定时任务：定义来自仓库 tasks/*.yml，这里只能启停与改周期（admin）；运行记录按组可见
export function TasksPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { isAdmin } = useSession()
  const pending = useRef(new Set<string>())
  const [busy, setBusy] = useState<string[]>([])
  const [editing, setEditing] = useState<TaskRow | null>(null)
  const [form] = Form.useForm<{ schedule: string }>()
  const { data, isPending, isError, error, refetch } = useQuery({ queryKey: ['tasks'], queryFn: fetchTasks })

  const perform = async (id: string, action: () => Promise<void>) => {
    if (pending.current.has(id)) return false
    pending.current.add(id)
    setBusy([...pending.current])
    try { await action(); return true }
    catch (e) { message.error(errText(e, t)); return false }
    finally { pending.current.delete(id); setBusy([...pending.current]) }
  }
  const update = (id: string, body: { enabled?: boolean; customSchedule?: string }) => perform(id, async () => {
    await updateTask(id, body)
    await client.invalidateQueries({ queryKey: ['tasks'] })
  })
  const runNow = (id: string) => perform(id, async () => {
    await runTask(id)
    message.success(t('taskRunQueued'))
    await client.invalidateQueries({ queryKey: ['taskRuns', id] })
  })

  // 与 YAML 一致就清掉自定义，免得 YAML 后续改了周期却被旧覆盖值挡住
  const saveSchedule = async ({ schedule }: { schedule: string }) => {
    if (!editing) return
    const v = schedule.trim()
    if (await update(editing.id, { customSchedule: v === editing.schedule ? '' : v })) setEditing(null)
  }

  const saving = !!editing && busy.includes(editing.id)
  return (
    <Page title={t('navTasks')} subtitle={t('tasksSubtitle')}>
      <Card styles={{ body: { padding: 0 } }}>
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<TaskRow>
          scroll={{ x: 950 }}
          rowKey="id"
          loading={isPending}
          dataSource={data ?? []}
          pagination={false}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noTasks')} /> }}
          expandable={{ expandedRowRender: task => <Runs task={task} /> }}
          columns={[
            {
              title: t('taskName'), dataIndex: 'name',
              render: (v, task) => (
                <Tooltip title={<pre className="tooltip-pre">{task.prompt}</pre>}>
                  <Space orientation="vertical" size={0}>
                    <Typography.Text strong>{v}</Typography.Text>
                    <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>{task.id}</Typography.Text>
                  </Space>
                </Tooltip>
              ),
            },
            {
              title: t('taskSchedule'), width: 220,
              render: (_, task) => (
                <Space>
                  <code>{task.customSchedule ?? task.schedule}</code>
                  {task.customSchedule && <Tag color="blue">{t('taskCustom')}</Tag>}
                  {isAdmin && <Button type="link" size="small" aria-label={t('taskEditSchedule')} disabled={busy.includes(task.id)} icon={<EditOutlined />} onClick={() => { form.setFieldsValue({ schedule: task.customSchedule ?? task.schedule }); setEditing(task) }} />}
                </Space>
              ),
            },
            { title: t('taskTarget'), dataIndex: 'targetGroup', width: 140, render: v => (v === '*' ? t('taskAllGroups') : v) },
            { title: t('taskModel'), dataIndex: 'model', width: 160, render: v => v || <Typography.Text type="secondary">{t('defaultModel')}</Typography.Text> },
            {
              title: t('thStatus'), dataIndex: 'enabled', width: 110,
              render: (v, task) => <Switch checked={v} disabled={!isAdmin || busy.includes(task.id)} loading={busy.includes(task.id)} onChange={enabled => update(task.id, { enabled })} checkedChildren={t('taskEnabled')} unCheckedChildren={t('taskDisabled')} />,
            },
            ...(isAdmin ? [{
              title: '', width: 120,
              render: (_: unknown, task: TaskRow) => <Button size="small" icon={<CaretRightOutlined />} disabled={!task.enabled || busy.includes(task.id)} loading={busy.includes(task.id)} onClick={() => runNow(task.id)}>{t('taskRunNow')}</Button>,
            }] : []),
          ]}
        />}
      </Card>
      <Modal open={!!editing} title={t('taskEditSchedule')} onCancel={() => { if (!saving) setEditing(null) }} confirmLoading={saving} closable={!saving} maskClosable={!saving} keyboard={!saving} cancelButtonProps={{ disabled: saving }} onOk={() => form.submit()} destroyOnHidden>
        <Form disabled={saving} form={form} layout="vertical" onFinish={saveSchedule}>
          <Form.Item name="schedule" label={t('taskSchedule')} extra={t('taskScheduleHint', { yaml: editing?.schedule ?? '' })} rules={[{ required: true }]}>
            <Input className="mono" />
          </Form.Item>
        </Form>
      </Modal>
    </Page>
  )
}
