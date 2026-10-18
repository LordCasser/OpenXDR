import { CheckOutlined, CloseOutlined } from '@ant-design/icons'
import { App, Button, Space } from 'antd'
import { useRef, useState } from 'react'
import { decideApproval, type Approval } from '../api'
import { useI18n } from '../i18n'
import { errText } from './format'

// 两个审批入口共用：命令就在按钮旁边显示着，点了即生效，不再二次确认。成功后才刷新列表
export function ApprovalActions({ approval, onDecided, vertical = false }: {
  approval: Approval
  onDecided: () => void
  vertical?: boolean
}) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const [busy, setBusy] = useState<'approve' | 'reject' | null>(null)
  const submitting = useRef(false)
  const submit = async (approve: boolean) => {
    if (submitting.current || approval.status !== 'pending') return
    submitting.current = true
    setBusy(approve ? 'approve' : 'reject')
    try {
      await decideApproval(approval.id, approve)
      onDecided()
    } catch (e) {
      message.error(errText(e, t))
    } finally {
      submitting.current = false
      setBusy(null)
    }
  }
  const pending = approval.status === 'pending'
  return (
    <Space orientation={vertical ? 'vertical' : 'horizontal'}>
      <Button size="small" type="primary" icon={<CheckOutlined aria-hidden />} loading={busy === 'approve'} disabled={!!busy || !pending} onClick={() => submit(true)}>{t('apApprove')}</Button>
      <Button size="small" danger icon={<CloseOutlined aria-hidden />} loading={busy === 'reject'} disabled={!!busy || !pending} onClick={() => submit(false)}>{t('apReject')}</Button>
    </Space>
  )
}
