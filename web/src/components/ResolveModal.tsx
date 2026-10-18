import { Form, Input, Modal, Typography } from 'antd'
import { useRef, useState } from 'react'
import type { Verdict } from '../api'
import { useI18n } from '../i18n'

// 结论与 AI 研判一致（判良性按误报关、判恶意或可疑按属实关）时理由可以不写：说明取研判摘要，
// 不当人工案例回喂研判。相反或没有研判时必须写——那正是最值钱的人工判断
export function agreesWithAI(verdict: Verdict | null | undefined, status: 'closed' | 'false_positive' | null): boolean {
  const v = verdict?.verdict
  return status === 'false_positive' ? v === 'benign' : status === 'closed' && (v === 'malicious' || v === 'suspicious')
}

// 结案与处理待办共用：必须写明原因，备注会作为案例交给 AI。onSubmit 失败时应抛出，弹窗与备注保留
export function ResolveModal({ open, title, hint, initialNote, optional, onCancel, onSubmit }: {
  open: boolean
  title: string
  hint: string
  // 采纳 AI 结案建议时预填它的说明，人可以改
  initialNote?: string
  // 与 AI 研判一致，理由选填
  optional?: boolean
  onCancel: () => void
  onSubmit: (note: string) => Promise<void>
}) {
  const { t } = useI18n()
  const [form] = Form.useForm<{ note: string }>()
  const [busy, setBusy] = useState(false)
  const submitting = useRef(false)
  const finish = async ({ note }: { note?: string }) => {
    if (submitting.current) return
    submitting.current = true
    setBusy(true)
    try {
      await onSubmit((note ?? '').trim())
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
      <Form disabled={busy} form={form} layout="vertical" onFinish={finish} initialValues={{ note: initialNote }}>
        <Form.Item name="note" label={t('resolveNote')} extra={optional && t('resolveNoteOptional')}
          rules={optional ? [] : [{ required: true, whitespace: true, message: t('resolveNoteRequired') }]}>
          <Input.TextArea rows={4} maxLength={2000} showCount autoFocus placeholder={optional ? t('resolveNoteOptionalPlaceholder') : undefined} />
        </Form.Item>
      </Form>
    </Modal>
  )
}
