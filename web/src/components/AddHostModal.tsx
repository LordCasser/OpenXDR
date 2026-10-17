import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Collapse, Empty, Flex, List, Modal, Select, Space, Tabs, Tag, Typography, Popconfirm } from 'antd'
import { useState } from 'react'
import { createEnrollToken, fetchEnrollStatus, fetchEnrollTokens, revokeEnrollToken, type EnrollToken } from '../api'
import { useSession } from '../app/session'
import { useI18n } from '../i18n'
import { fmtTime, errText } from './format'

// 安装命令里的控制台地址就是用户现在访问的这个，主机必须能访问到它
function commands(token: string) {
  const base = window.location.origin
  return {
    linux: `curl -fsSL ${base}/api/enroll/install.sh | sudo sh -s -- ${base} ${token}`,
    windows: `& ([scriptblock]::Create((irm ${base}/api/enroll/install.ps1))) ${base} ${token}`,
  }
}

function Command({ text }: { text: string }) {
  return (
    <Typography.Paragraph className="mono" copyable={{ text }} style={{ margin: 0, padding: 12, borderRadius: 6, background: 'var(--ant-color-fill-tertiary)', wordBreak: 'break-all' }}>
      {text}
    </Typography.Paragraph>
  )
}

// 添加主机：选组 → 生成一条命令 → 到主机上执行。令牌管理收在折叠面板里，平时不用看
export function AddHostModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { groups, group } = useSession()
  const adminGroups = groups.filter(g => g.role === 'admin')
  // 组列表可能晚于弹窗挂载才到：没选过就跟着默认组走
  const [picked, setGroupId] = useState<string>()
  const groupId = picked ?? (group?.role === 'admin' ? group.id : adminGroups[0]?.id)
  const [days, setDays] = useState(7)
  const [issued, setIssued] = useState<EnrollToken>()

  const status = useQuery({ queryKey: ['enroll-status'], queryFn: fetchEnrollStatus, enabled: open })
  const tokens = useQuery({ queryKey: ['enroll-tokens', groupId], queryFn: () => fetchEnrollTokens(groupId!), enabled: open && !!groupId })
  const generate = useMutation({
    mutationFn: () => createEnrollToken(groupId!, days),
    onSuccess: tok => {
      setIssued(tok)
      client.invalidateQueries({ queryKey: ['enroll-tokens'] })
    },
    onError: e => message.error(errText(e, t)),
  })
  const revoke = useMutation({
    mutationFn: revokeEnrollToken,
    onSuccess: () => client.invalidateQueries({ queryKey: ['enroll-tokens'] }),
    onError: e => message.error(errText(e, t)),
  })

  const close = () => {
    setIssued(undefined)
    onClose()
  }
  const cmds = issued?.token ? commands(issued.token) : undefined
  const tokenState = (tok: EnrollToken) =>
    tok.revoked ? <Tag>{t('tokenRevoked')}</Tag>
      : Date.parse(tok.expiresAt) < Date.now() ? <Tag>{t('tokenExpired')}</Tag>
        : <Popconfirm title={t('revokeTokenConfirm')} okButtonProps={{ danger: true }} onConfirm={() => revoke.mutate(tok.id)}>
          <Button size="small" danger type="link">{t('revoke')}</Button>
        </Popconfirm>

  return (
    <Modal title={t('addHost')} open={open} onCancel={close} footer={null} width={720} destroyOnHidden>
      {window.location.protocol !== 'https:' ? (
        <Alert type="warning" showIcon message={t('hostHTTPSRequired')} />
      ) : status.data && !status.data.enabled ? (
        <Alert type="warning" showIcon message={t('addHostDisabled')} description={status.data.reason} />
      ) : adminGroups.length === 0 ? (
        <Alert type="info" showIcon message={t('addHostNoGroup')} />
      ) : (
        <Flex vertical gap={16}>
          <Space wrap>
            <span>{t('addHostGroup')}</span>
            <Select style={{ width: 200 }} value={groupId} onChange={g => { setGroupId(g); setIssued(undefined) }}
              options={adminGroups.map(g => ({ value: g.id, label: g.name }))} />
            <span>{t('addHostDays')}</span>
            <Select style={{ width: 100 }} value={days} onChange={setDays}
              options={[1, 7, 30].map(n => ({ value: n, label: t('addHostDaysUnit', { n }) }))} />
            <Button type="primary" loading={generate.isPending} onClick={() => generate.mutate()}>{t('addHostGenerate')}</Button>
          </Space>
          {cmds && (
            <>
              <Typography.Text type="secondary">{t('addHostHint')}</Typography.Text>
              <Tabs items={[
                { key: 'linux', label: t('addHostLinux'), children: <Command text={cmds.linux} /> },
                { key: 'windows', label: t('addHostWindows'), children: <Command text={cmds.windows} /> },
              ]} />
              <Alert type="success" showIcon message={t('addHostDone')} />
            </>
          )}
          <Collapse ghost size="small" items={[{
            key: 'tokens',
            label: t('addHostTokens'),
            children: tokens.data?.length ? (
              <List size="small" dataSource={tokens.data} renderItem={tok => (
                <List.Item actions={[tokenState(tok)]}>
                  <Space wrap>
                    <span>{fmtTime(tok.createdAt)}</span>
                    <Typography.Text type="secondary">{tok.createdBy}</Typography.Text>
                    <span>{t('tokenUses', { n: tok.uses })}</span>
                    <Typography.Text type="secondary">{t('tokenExpires', { time: fmtTime(tok.expiresAt) })}</Typography.Text>
                  </Space>
                </List.Item>
              )} />
            ) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('tokenNone')} />,
          }]} />
        </Flex>
      )}
    </Modal>
  )
}
