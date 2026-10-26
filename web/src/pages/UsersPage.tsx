import { TableActions } from '../components/TableActions'
import { PlusOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Form, Input, Modal, Popconfirm, Select, Table, Tag } from 'antd'
import { useRef, useState } from 'react'
import { createUser, deleteUser, fetchUsers, resetUserPassword, type UserRow } from '../api'
import { useSession } from '../app/session'
import { LoadError } from '../components/LoadError'
import { Page, TableCard } from '../components/Page'
import { ROLE_KEY, fmtTime, errText } from '../components/format'
import { useI18n } from '../i18n'

const ROLE_COLOR: Record<string, string> = { admin: 'red', analyst: 'blue', viewer: 'default' }

export function UsersPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { me } = useSession()
  const pending = useRef(false)
  const [busy, setBusy] = useState(false)
  const [creating, setCreating] = useState(false)
  const [resetting, setResetting] = useState<UserRow | null>(null)
  const [createForm] = Form.useForm()
  const [resetForm] = Form.useForm()
  const { data, isPending, isError, error, refetch } = useQuery({ queryKey: ['users'], queryFn: fetchUsers })

  const run = async (fn: () => Promise<unknown>, ok?: string) => {
    if (pending.current) return false
    pending.current = true
    setBusy(true)
    try {
      await fn()
      if (ok) message.success(ok)
      await client.invalidateQueries({ queryKey: ['users'] })
      // 删号会清掉组成员记录
      client.invalidateQueries({ queryKey: ['members'] })
      return true
    } catch (e) {
      message.error(errText(e, t))
      return false
    } finally { pending.current = false; setBusy(false) }
  }
  const roleOptions = Object.entries(ROLE_KEY).map(([value, key]) => ({ value, label: t(key) }))
  const pwRules = [{ required: true, min: 8, message: t('passwordMin') }]

  return (
    <Page
      title={t('navUsers')}
      subtitle={t('usersSubtitle')}
      extra={<Button type="primary" icon={<PlusOutlined />} disabled={busy} onClick={() => { createForm.resetFields(); setCreating(true) }}>{t('newUser')}</Button>}
    >
      <TableCard>
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<UserRow>
          scroll={{ x: 680 }}
          rowKey="id"
          loading={isPending}
          dataSource={data ?? []}
          pagination={false}
          columns={[
            { title: t('username'), dataIndex: 'username' },
            { title: t('globalRole'), dataIndex: 'role', width: 140, render: v => <Tag color={ROLE_COLOR[v]}>{t(ROLE_KEY[v] ?? 'roleViewer')}</Tag> },
            { title: t('thCreatedAt'), dataIndex: 'createdAt', width: 200, render: fmtTime },
            {
              title: t('actions'), width: 200,
              render: (_, u) => (
                <TableActions>
                  <Button type="link" size="small" disabled={busy} onClick={() => { resetForm.resetFields(); setResetting(u) }}>{t('resetPassword')}</Button>
                  {u.username !== me.username && (
                    <Popconfirm title={t('confirmDeleteUser', { name: u.username })} onConfirm={() => run(() => deleteUser(u.id))}>
                      <Button type="link" danger size="small" disabled={busy}>{t('del')}</Button>
                    </Popconfirm>
                  )}
                </TableActions>
              ),
            },
          ]}
        />}
      </TableCard>

      <Modal open={creating} title={t('newUser')} onCancel={() => { if (!busy) { createForm.resetFields(); setCreating(false) } }} confirmLoading={busy} closable={!busy} maskClosable={!busy} keyboard={!busy} cancelButtonProps={{ disabled: busy }} onOk={() => createForm.submit()} destroyOnHidden>
        <Form disabled={busy} form={createForm} layout="vertical" initialValues={{ role: 'analyst' }}
          onFinish={async v => { if (await run(() => createUser({ ...v, username: v.username.trim() }))) { setCreating(false); createForm.resetFields() } }}>
          <Form.Item name="username" label={t('username')} rules={[{ required: true, whitespace: true }]}><Input autoComplete="off" /></Form.Item>
          <Form.Item name="password" label={t('password')} rules={pwRules}><Input.Password autoComplete="new-password" /></Form.Item>
          <Form.Item name="role" label={t('globalRole')} extra={t('globalRoleHint')}><Select options={roleOptions} /></Form.Item>
        </Form>
      </Modal>

      <Modal open={!!resetting} title={t('resetPasswordFor', { name: resetting?.username ?? '' })} onCancel={() => { if (!busy) { resetForm.resetFields(); setResetting(null) } }} confirmLoading={busy} closable={!busy} maskClosable={!busy} keyboard={!busy} cancelButtonProps={{ disabled: busy }} onOk={() => resetForm.submit()} destroyOnHidden>
        <Form disabled={busy} form={resetForm} layout="vertical"
          onFinish={async v => { if (await run(() => resetUserPassword(resetting!.id, v.password), t('passwordReset'))) { resetForm.resetFields(); setResetting(null) } }}>
          <Form.Item name="password" label={t('newPassword')} rules={pwRules}><Input.Password autoComplete="new-password" /></Form.Item>
        </Form>
      </Modal>
    </Page>
  )
}
