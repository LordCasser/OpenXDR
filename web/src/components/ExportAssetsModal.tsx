import { App, Modal, Radio, Space, Typography } from 'antd'
import { useState } from 'react'
import { downloadAssets } from '../api'
import { useI18n } from '../i18n'
import { errText } from './format'

export function ExportAssetsModal({ open, onClose, ids, q, groupId, groupName }: {
  open: boolean; onClose: () => void; ids: string[]; q: string; groupId: string; groupName: string
}) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const [format, setFormat] = useState<'csv' | 'json'>('csv')
  const [mode, setMode] = useState<'filter' | 'ids'>('filter')
  const [busy, setBusy] = useState(false)
  const exportMode = mode === 'ids' && ids.length === 0 ? 'filter' : mode
  const submit = async () => {
    setBusy(true)
    try {
      await downloadAssets(format, exportMode === 'ids' ? { mode: 'ids', ids } : { mode: 'filter', q, groupId })
      onClose()
    } catch (e) { message.error(errText(e, t)) } finally { setBusy(false) }
  }
  return <Modal title={t('exportAssets')} open={open} onCancel={onClose} onOk={submit}
    okText={t('exportAssets')} confirmLoading={busy} cancelButtonProps={{ disabled: busy }} closable={!busy} maskClosable={!busy}>
    <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
      <Radio.Group value={format} onChange={e => setFormat(e.target.value)} options={['csv', 'json'].map(value => ({ value, label: value.toUpperCase() }))} />
      <Radio.Group value={exportMode} onChange={e => setMode(e.target.value)} options={[
        { value: 'filter', label: t('exportFilteredAssets') },
        { value: 'ids', label: t('exportSelectedAssets', { n: ids.length }), disabled: ids.length === 0 },
      ]} />
      {exportMode === 'filter' && <Typography.Text>{t('exportAssetFilter', { q: q || '—', group: groupName })}</Typography.Text>}
      <Typography.Paragraph type="secondary">{t('exportAssetsHint')}</Typography.Paragraph>
    </Space>
  </Modal>
}
