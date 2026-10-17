import { Form, Input, Modal, Typography } from 'antd'
import { useRef, useState } from 'react'
import { useI18n } from '../i18n'

// 结案与处理待办共用：必须写明原因，备注会作为案例交给 AI。onSubmit 失败时应抛出，弹窗与备注保留
export function ResolveModal({ open, title, hint, onCancel, onSubmit }: {
  open: boolean
  title: string
  hint: string
  onCancel: () => void
  onSubmit: (note: string) => Promise<void>
}) {
  const { t } = useI18n()
  const [form] = Form.useForm<{ note: string }>()
  const [busy, setBusy] = useState(false)
  const submitting = useRef(false)
  const finish = async ({ note }: { note: string }) => {
    if (submitting.current) return
    submitting.current = true
    setBusy(true)
    try {
      await onSubmit(note.trim())
      form.resetFields()
    } catch {
      // 调用方已提示失败原因；保留备注，改完可以直接再提交
    } finally {
      submitting.current = false
      setBusy(false)
    }
  }
  return (
    <Modal open={open} title={title} onCancel={() => { if (!busy) onCancel() }} closable={!busy} maskClosable={!busy} keyboard={!busy} cancelButtonProps={{ disabled: busy }} onOk={() => form.submit()} confirmLoading={busy} destroyOnHidden>
      <Typography.Paragraph type="secondary">{hint}</Typography.Paragraph>
      <Form disabled={busy} form={form} layout="vertical" onFinish={finish}>
        <Form.Item name="note" label={t('resolveNote')} rules={[{ required: true, whitespace: true, message: t('resolveNoteRequired') }]}>
          <Input.TextArea rows={4} maxLength={2000} showCount autoFocus />
        </Form.Item>
      </Form>
    </Modal>
  )
}
