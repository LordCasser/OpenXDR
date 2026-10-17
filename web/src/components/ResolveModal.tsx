import { Form, Input, Modal, Typography } from 'antd'
import { useState } from 'react'
import { useI18n } from '../i18n'

// 结案与处理待办共用：必须写明原因，备注会作为案例交给 AI
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
  const finish = async ({ note }: { note: string }) => {
    setBusy(true)
    try {
      await onSubmit(note.trim())
      form.resetFields()
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal open={open} title={title} onCancel={onCancel} onOk={() => form.submit()} confirmLoading={busy} destroyOnHidden>
      <Typography.Paragraph type="secondary">{hint}</Typography.Paragraph>
      <Form form={form} layout="vertical" onFinish={finish}>
        <Form.Item name="note" label={t('resolveNote')} rules={[{ required: true, whitespace: true, message: t('resolveNoteRequired') }]}>
          <Input.TextArea rows={4} maxLength={2000} showCount autoFocus />
        </Form.Item>
      </Form>
    </Modal>
  )
}
