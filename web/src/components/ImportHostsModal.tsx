import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Flex, Input, Modal, Popconfirm, Select, Space, Table, Tabs, Tag, Typography, Upload } from 'antd'
import { useState } from 'react'
import { commitHostImport, deleteHostCredential, enrollHostCredential, fetchHostCredentials, fetchHostImportStatus, previewHostImport, type HostCredential, type HostImportPreview, type ImportedHost } from '../api'
import { useSession } from '../app/session'
import { useI18n } from '../i18n'

const template = 'hosts:\n  - hostname: app-01\n    address: 192.0.2.10\n    os: linux\n    port: 22\n    username: root\n    password: "replace-me"\n'

export function ImportHostsModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { groups } = useSession()
  const adminGroups = groups.filter(g => g.role === 'admin')
  const [groupId, setGroupId] = useState<string>()
  const selectedGroup = groupId ?? adminGroups[0]?.id
  const [document, setDocument] = useState('')
  const [preview, setPreview] = useState<HostImportPreview>()
  const [tab, setTab] = useState('import')
  const [target, setTarget] = useState<HostCredential>()
  const [fingerprint, setFingerprint] = useState('')
  const status = useQuery({ queryKey: ['host-import-status'], queryFn: fetchHostImportStatus, enabled: open })
  const credentials = useQuery({ queryKey: ['host-credentials', selectedGroup], queryFn: () => fetchHostCredentials(selectedGroup!), enabled: open && !!selectedGroup })
  const refresh = () => {
    client.invalidateQueries({ queryKey: ['assets'] })
    client.invalidateQueries({ queryKey: ['groups'] })
    client.invalidateQueries({ queryKey: ['host-credentials'] })
  }
  const parse = useMutation({ mutationFn: () => previewHostImport(selectedGroup!, document), onSuccess: setPreview, onError: e => message.error(e.message) })
  const save = useMutation({
    mutationFn: () => commitHostImport(selectedGroup!, document, preview!.digest),
    onSuccess: result => { setDocument(''); setPreview(undefined); setTab('credentials'); refresh(); message.success(t('hostImportSaved', { n: result.assetIds.length })) },
    onError: e => message.error(e.message),
  })
  const install = useMutation({
    mutationFn: () => enrollHostCredential(target!.id, fingerprint),
    onSuccess: () => { message.success(t('hostInstallDone')); setTarget(undefined); setFingerprint(''); refresh() },
    onError: e => { message.error(e.message); refresh() },
  })
  const remove = useMutation({ mutationFn: deleteHostCredential, onSuccess: refresh, onError: e => message.error(e.message) })
  const busy = parse.isPending || save.isPending || install.isPending
  const secure = window.location.protocol === 'https:'
  const close = () => {
    if (busy) return
    setDocument(''); setPreview(undefined); setTarget(undefined); setFingerprint('')
    parse.reset(); save.reset(); install.reset(); onClose()
  }
  const columns = [
    { title: t('thHostname'), dataIndex: 'hostname' },
    { title: t('hostAddress'), render: (_: unknown, h: ImportedHost) => `${h.address}:${h.port}` },
    { title: 'OS', dataIndex: 'os' },
    { title: t('hostUsername'), dataIndex: 'username' },
    { title: t('hostCredential'), render: (_: unknown, h: ImportedHost) => <Tag>{t(h.kind === 'none' ? 'hostNoCredential' : h.kind === 'password' ? 'hostPasswordStored' : 'hostKeyStored')}</Tag> },
  ]
  return <>
    <Modal title={t('hostImport')} open={open} onCancel={close} footer={null} width={960} closable={!busy} maskClosable={!busy} keyboard={!busy}>
      <Flex vertical gap={16}>
        {!secure && <Alert type="warning" title={t('hostHTTPSRequired')} />}
        <Select aria-label={t('addHostGroup')} value={selectedGroup} disabled={busy} options={adminGroups.map(g => ({ value: g.id, label: g.name }))}
          onChange={v => { setGroupId(v); setPreview(undefined) }} />
        {status.isError && <Alert type="error" title={t('hostImportStatusError')} />}
        {status.data && !status.data.credentialStorage && <Alert type="warning" title={t('hostVaultDisabled')} />}
        <Tabs activeKey={tab} onChange={setTab} items={[
          { key: 'import', label: t('hostImportDocument'), children: <Flex vertical gap={12}>
            <Typography.Text type="secondary">{t('hostImportHint')}</Typography.Text>
            <Upload accept=".md,.txt,.yaml,.yml,.json" showUploadList={false} disabled={busy} beforeUpload={async file => {
              if (file.size > 1024 * 1024) { message.error(t('hostImportTooLarge')); return false }
              setDocument(await file.text()); setPreview(undefined); return false
            }}><Button disabled={busy}>{t('hostChooseDocument')}</Button></Upload>
            <Input.TextArea aria-label={t('hostImportDocument')} autoComplete="off" spellCheck={false} rows={10} value={document} placeholder={template} disabled={busy}
              onChange={e => { setDocument(e.target.value); setPreview(undefined) }} />
            <Space>
              <Button loading={parse.isPending} disabled={!secure || !selectedGroup || !document || busy} onClick={() => parse.mutate()}>{t('hostImportPreview')}</Button>
              <Button type="primary" loading={save.isPending} disabled={!secure || !preview || busy} onClick={() => save.mutate()}>{t('hostImportConfirm')}</Button>
            </Space>
            {preview && <Table<ImportedHost> rowKey="hostname" size="small" scroll={{ x: 700 }} columns={columns} dataSource={preview.hosts} pagination={{ pageSize: 10 }} />}
          </Flex> },
          { key: 'credentials', label: t('hostCredentials'), children: <Flex vertical gap={12}>
            <Typography.Text type="secondary">{t('hostEnrollmentHint')}</Typography.Text>
            {credentials.isError && <Alert type="error" title={t('hostCredentialsError')} />}
            <Table<HostCredential> rowKey="id" loading={credentials.isPending} size="small" scroll={{ x: 850 }} dataSource={credentials.data ?? []} pagination={{ pageSize: 10 }} columns={[
              ...columns,
              { title: t('actions'), render: (_, c) => <Space>
                <Button size="small" disabled={!status.data?.sshEnrollment || busy} onClick={() => { setTarget(c); setFingerprint(c.hostKey) }}>{t('hostEnrollSSH')}</Button>
                <Popconfirm title={t('hostCredentialDeleteConfirm')} onConfirm={() => remove.mutateAsync(c.id)}><Button danger size="small" disabled={busy || remove.isPending}>{t('del')}</Button></Popconfirm>
              </Space> },
            ]} />
          </Flex> },
        ]} />
      </Flex>
    </Modal>
    <Modal title={t('hostEnrollSSH')} open={!!target} onCancel={() => !install.isPending && setTarget(undefined)} onOk={() => install.mutate()}
      confirmLoading={install.isPending} closable={!install.isPending} maskClosable={!install.isPending} keyboard={!install.isPending} okButtonProps={{ disabled: !fingerprint.startsWith('SHA256:') || install.isPending }}>
      <Flex vertical gap={12}>
        <Typography.Text>{target?.hostname} · {target?.username}@{target?.address}:{target?.port}</Typography.Text>
        <Alert type="info" title={t('hostFingerprintHint')} />
        <Input aria-label={t('hostFingerprint')} value={fingerprint} disabled={install.isPending || !!target?.hostKey} onChange={e => setFingerprint(e.target.value)} placeholder="SHA256:…" />
      </Flex>
    </Modal>
  </>
}
