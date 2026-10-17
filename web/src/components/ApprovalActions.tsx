import { CheckOutlined, CloseOutlined } from '@ant-design/icons'
import { Alert, App, Button, Modal, Space } from 'antd'
import { useRef, useState } from 'react'
import { decideApproval, type Approval } from '../api'
import { useI18n } from '../i18n'
import { errText } from './format'

// 两个审批入口共用提交状态；失败保留确认框，成功后才刷新列表。
export function ApprovalActions({ approval, host, onDecided, vertical = false }: {
  approval: Approval
  host: string
  onDecided: () => void
  vertical?: boolean
}) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()
  const submitting = useRef(false)
  const submit = async (approve: boolean) => {
    if (submitting.current || approval.status !== 'pending') return
    submitting.current = true
    setBusy(true)
    setError(undefined)
    try {
      await decideApproval(approval.id, approve)
      setConfirming(false)
      onDecided()
    } catch (e) {
      const text = errText(e, t)
      if (approve) setError(text)
      else message.error(text)
    } finally {
      submitting.current = false
      setBusy(false)
    }
  }
  return <>
    <Space orientation={vertical ? 'vertical' : 'horizontal'}>
      <Button size="small" type="primary" icon={<CheckOutlined aria-hidden />} disabled={busy || approval.status !== 'pending'} onClick={() => { setError(undefined); setConfirming(true) }}>{t('apApprove')}</Button>
      <Button size="small" danger icon={<CloseOutlined aria-hidden />} disabled={busy || approval.status !== 'pending'} onClick={() => submit(false)}>{t('apReject')}</Button>
    </Space>
    <Modal open={confirming && approval.status === 'pending'} title={t('apConfirmLiveTitle', { host })}
      onOk={() => submit(true)} onCancel={() => { if (!busy) setConfirming(false) }}
      confirmLoading={busy} okButtonProps={{ danger: true }} cancelButtonProps={{ disabled: busy }}
      closable={!busy} maskClosable={!busy} keyboard={!busy}>
      <pre className="chat-code">{approval.cmd}</pre>
      {error && <Alert type="error" showIcon title={error} />}
    </Modal>
  </>
}
