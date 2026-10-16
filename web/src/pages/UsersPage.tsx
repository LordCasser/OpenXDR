import { PlusOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Card, Form, Input, Modal, Popconfirm, Select, Space, Table, Tag } from 'antd'
import { useState } from 'react'
import { createUser, deleteUser, fetchUsers, resetUserPassword, type UserRow } from '../api'
import { useSession } from '../app/session'
import { Page } from '../components/Page'
import { ROLE_KEY, fmtTime } from '../components/format'
import { useI18n } from '../i18n'

const ROLE_COLOR: Record<string, string> = { admin: 'red', analyst: 'blue', viewer: 'default' }

export function UsersPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { me } = useSession()
  const [creating, setCreating] = useState(false)
  const [resetting, setResetting] = useState<UserRow | null>(null)
  const [createForm] = Form.useForm()
  const [resetForm] = Form.useForm()
  const { data, isPending } = useQuery({ queryKey: ['users'], queryFn: fetchUsers })

  const run = async (fn: () => Promise<unknown>, ok?: string) => {
    try {
      await fn()
      if (ok) message.success(ok)
      await client.invalidateQueries({ queryKey: ['users'] })
      return true
    } catch (e) {
      message.error(String(e))
      return false
    }
  }
  const roleOptions = Object.entries(ROLE_KEY).map(([value, key]) => ({ value, label: t(key) }))
  const pwRules = [{ required: true, min: 8, message: t('passwordMin') }]

  return (
    <Page
      title={t('navUsers')}
      subtitle={t('usersSubtitle')}
      extra={<Button type="primary" icon={<PlusOutlined />} onClick={() => setCreating(true)}>{t('newUser')}</Button>}
    >
      <Card styles={{ body: { padding: 0 } }}>
        <Table<UserRow>
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
                <Space>
                  <Button type="link" size="small" onClick={() => setResetting(u)}>{t('resetPassword')}</Button>
                  {u.username !== me.username && (
                    <Popconfirm title={t('confirmDeleteUser', { name: u.username })} onConfirm={() => run(() => deleteUser(u.id))}>
                      <Button type="link" danger size="small">{t('del')}</Button>
                    </Popconfirm>
                  )}
                </Space>
              ),
            },
          ]}
        />
      </Card>

      <Modal open={creating} title={t('newUser')} onCancel={() => setCreating(false)} onOk={() => createForm.submit()} destroyOnHidden>
        <Form form={createForm} layout="vertical" initialValues={{ role: 'analyst' }}
          onFinish={async v => { if (await run(() => createUser(v))) { setCreating(false); createForm.resetFields() } }}>
          <Form.Item name="username" label={t('username')} rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="password" label={t('password')} rules={pwRules}><Input.Password /></Form.Item>
          <Form.Item name="role" label={t('globalRole')} extra={t('globalRoleHint')}><Select options={roleOptions} /></Form.Item>
        </Form>
      </Modal>

      <Modal open={!!resetting} title={t('resetPasswordFor', { name: resetting?.username ?? '' })} onCancel={() => setResetting(null)} onOk={() => resetForm.submit()} destroyOnHidden>
        <Form form={resetForm} layout="vertical"
          onFinish={async v => { if (await run(() => resetUserPassword(resetting!.id, v.password), t('passwordReset'))) setResetting(null) }}>
          <Form.Item name="password" label={t('newPassword')} rules={pwRules}><Input.Password /></Form.Item>
        </Form>
      </Modal>
    </Page>
  )
}
