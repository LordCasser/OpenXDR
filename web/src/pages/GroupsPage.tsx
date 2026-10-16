import { PlusOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Card, Drawer, Empty, Form, Input, Modal, Popconfirm, Select, Space, Table, Tabs, Transfer } from 'antd'
import { useState } from 'react'
import {
  assignAsset, createGroup, deleteGroup, fetchAssets, fetchGroups, fetchMembers, fetchUsers, removeMember, setMember, unassignAsset,
  type GroupRow, type MemberRow,
} from '../api'
import { Page } from '../components/Page'
import { ROLE_KEY, fmtTime } from '../components/format'
import { useI18n } from '../i18n'

function GroupDrawer({ group, onClose }: { group: GroupRow; onClose: () => void }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const [newUser, setNewUser] = useState<string>()
  const [newRole, setNewRole] = useState('analyst')
  const members = useQuery({ queryKey: ['members', group.id], queryFn: () => fetchMembers(group.id) })
  const { data: users = [] } = useQuery({ queryKey: ['users'], queryFn: fetchUsers })
  const { data: assets = [] } = useQuery({ queryKey: ['assets'], queryFn: fetchAssets })

  const run = async (fn: () => Promise<unknown>) => {
    try {
      await fn()
    } catch (e) {
      message.error(String(e))
    }
    client.invalidateQueries({ queryKey: ['members', group.id] })
    client.invalidateQueries({ queryKey: ['assets'] })
    client.invalidateQueries({ queryKey: ['groups'] })
  }
  const roleOptions = Object.entries(ROLE_KEY).map(([value, key]) => ({ value, label: t(key) }))
  const candidates = users.filter(u => !members.data?.some(m => m.userId === u.id))
  const inGroup = assets.filter(a => a.groupId === group.id).map(a => a.id)

  // 穿梭框：右侧即本组资产。移入归组（会离开原组），移出退回未分组
  const moveAssets = (_: React.Key[], direction: 'left' | 'right', keys: React.Key[]) => {
    void run(async () => {
      for (const id of keys.map(String)) {
        if (direction === 'right') await assignAsset(group.id, id)
        else await unassignAsset(group.id, id)
      }
    })
  }

  return (
    <Drawer open size={720} title={t('manageGroup', { name: group.name })} onClose={onClose}>
      <Tabs
        items={[
          {
            key: 'members',
            label: t('groupMembers'),
            children: (
              <Space orientation="vertical" style={{ width: '100%' }}>
                <Space.Compact style={{ width: '100%' }}>
                  <Select style={{ flex: 1 }} placeholder={t('pickUser')} value={newUser} onChange={setNewUser} options={candidates.map(u => ({ value: u.id, label: u.username }))} showSearch optionFilterProp="label" />
                  <Select style={{ width: 120 }} value={newRole} onChange={setNewRole} options={roleOptions} />
                  <Button type="primary" icon={<PlusOutlined />} disabled={!newUser} onClick={() => run(async () => { await setMember(group.id, newUser!, newRole); setNewUser(undefined) })}>{t('add')}</Button>
                </Space.Compact>
                <Table<MemberRow>
                  size="small"
                  rowKey="userId"
                  loading={members.isPending}
                  dataSource={members.data ?? []}
                  pagination={false}
                  locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noMembers')} /> }}
                  columns={[
                    { title: t('username'), dataIndex: 'username' },
                    { title: t('groupRole'), dataIndex: 'role', width: 160, render: (v, m) => <Select size="small" style={{ width: 130 }} value={v} options={roleOptions} onChange={r => run(() => setMember(group.id, m.userId, r))} /> },
                    {
                      title: t('actions'), width: 90,
                      render: (_, m) => (
                        <Popconfirm title={t('confirmRemoveMember', { name: m.username })} onConfirm={() => run(() => removeMember(group.id, m.userId))}>
                          <Button type="link" danger size="small">{t('remove')}</Button>
                        </Popconfirm>
                      ),
                    },
                  ]}
                />
              </Space>
            ),
          },
          {
            key: 'assets',
            label: t('groupAssets'),
            children: (
              <Transfer
                dataSource={assets.map(a => ({ key: a.id, title: a.hostname, description: a.ipAddrs?.join(', ') ?? '' }))}
                targetKeys={inGroup}
                onChange={moveAssets}
                render={item => item.title}
                titles={[t('otherAssets'), t('thisGroup')]}
                showSearch
                styles={{ section: { width: 300, height: 420 } }}
              />
            ),
          },
        ]}
      />
    </Drawer>
  )
}

// 资产组：纳管与授权的单位。组内角色决定能否在组里对话、处置、审批
export function GroupsPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const [creating, setCreating] = useState(false)
  const [managing, setManaging] = useState<GroupRow | null>(null)
  const [form] = Form.useForm()
  const { data, isPending } = useQuery({ queryKey: ['groups'], queryFn: fetchGroups })

  const run = async (fn: () => Promise<unknown>) => {
    try {
      await fn()
      await client.invalidateQueries({ queryKey: ['groups'] })
      return true
    } catch (e) {
      message.error(String(e))
      return false
    }
  }

  return (
    <Page
      title={t('navGroups')}
      subtitle={t('groupsSubtitle')}
      extra={<Button type="primary" icon={<PlusOutlined />} onClick={() => setCreating(true)}>{t('newGroup')}</Button>}
    >
      <Card styles={{ body: { padding: 0 } }}>
        <Table<GroupRow>
          rowKey="id"
          loading={isPending}
          dataSource={data ?? []}
          pagination={false}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noGroups')} /> }}
          columns={[
            { title: t('groupName'), dataIndex: 'name', render: (v, g) => <a onClick={() => setManaging(g)}>{v}</a> },
            { title: t('thAssetCount'), dataIndex: 'assetCount', width: 120, align: 'right' },
            { title: t('thCreatedAt'), dataIndex: 'createdAt', width: 200, render: fmtTime },
            {
              title: t('actions'), width: 160,
              render: (_, g) => (
                <Space>
                  <Button type="link" size="small" onClick={() => setManaging(g)}>{t('manage')}</Button>
                  <Popconfirm title={t('groupDeleteConfirm', { name: g.name })} onConfirm={() => run(() => deleteGroup(g.id))}>
                    <Button type="link" danger size="small">{t('del')}</Button>
                  </Popconfirm>
                </Space>
              ),
            },
          ]}
        />
      </Card>
      <Modal open={creating} title={t('newGroup')} onCancel={() => setCreating(false)} onOk={() => form.submit()} destroyOnHidden>
        <Form form={form} layout="vertical" onFinish={async v => { if (await run(() => createGroup(v.name.trim()))) { setCreating(false); form.resetFields() } }}>
          <Form.Item name="name" label={t('groupName')} rules={[{ required: true, whitespace: true }]}><Input /></Form.Item>
        </Form>
      </Modal>
      {managing && <GroupDrawer group={managing} onClose={() => setManaging(null)} />}
    </Page>
  )
}
