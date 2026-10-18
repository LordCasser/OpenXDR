import { Alert, App, Checkbox, Form, Input, Modal, Select, Typography } from 'antd'
import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { createSuppression, type AlertRow, type SuppressCondition } from '../api'
import { useI18n } from '../i18n'
import { errText } from './format'

// 告警事件里最能代表「这一类」的字段：域名、命令行、文件、对端地址。用它把抑制收窄到这一个值
function evidenceCondition(event: unknown): SuppressCondition | null {
  const r = (event ?? {}) as Record<string, any>
  const pick: [string, unknown][] = [
    ['query.hostname', r.query?.hostname], ['process.cmd_line', r.process?.cmd_line],
    ['file.path', r.file?.path], ['dst_endpoint.ip', r.dst_endpoint?.ip],
  ]
  const hit = pick.find(([, v]) => typeof v === 'string' && v !== '' && v.length <= 500)
  return hit ? { field: hit[0], op: 'equals', value: hit[1] as string } : null
}

// 标记误报后弹出：让分析师顺手把噪声源掐掉，而不是明天再看一遍同样的告警
export function SuppressModal({ open, alerts, assetId, onClose }: { open: boolean; alerts: AlertRow[]; assetId: string | null; onClose: () => void }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const [form] = Form.useForm()
  const scopeAsset = Form.useWatch('scopeAsset', form)
  const [busy, setBusy] = useState(false)
  // 同一事件可能由多条规则触发，逐条选择要抑制哪些
  const rules = Array.from(new Map(alerts.map(a => [a.ruleId, a.ruleTitle ?? a.ruleId])).entries())
  // 每条规则取它第一条告警的证据作为默认条件：默认只压这一个值，而不是整条规则
  const conditionOf = new Map(alerts.map(a => [a.ruleId, evidenceCondition(a.event)] as const).reverse())
  const narrow = Form.useWatch('narrow', form)

  const submit = async (v: { rules: string[]; scopeAsset: boolean; days: number; reason?: string; narrow: boolean }) => {
    setBusy(true)
    const results = await Promise.allSettled(v.rules.map(ruleId => {
      const c = v.narrow ? conditionOf.get(ruleId) : null
      return createSuppression({ ruleId, assetId: v.scopeAsset ? assetId : null, reason: v.reason, expiresInDays: v.days, conditions: c ? [c] : undefined })
    }))
    setBusy(false)
    client.invalidateQueries({ queryKey: ['suppressions'] })
    const failed = v.rules.filter((_, i) => results[i].status === 'rejected')
    if (failed.length < v.rules.length) message.success(t('suppressCreated', { n: v.rules.length - failed.length }))
    if (!failed.length) return onClose()
    // 失败的留在勾选里，改完可以直接重试，不会重复建已成功的
    form.setFieldValue('rules', failed)
    message.error(t('batchFailed', { n: failed.length, err: errText((results.find(r => r.status === 'rejected') as PromiseRejectedResult).reason, t) }))
  }

  return (
    <Modal open={open} title={t('suppressTitle')} onCancel={onClose} onOk={() => form.submit()} okText={t('createSuppressions')} cancelText={t('skip')} confirmLoading={busy} destroyOnHidden>
      <Typography.Paragraph type="secondary">{t('suppressExplain')}</Typography.Paragraph>
      <Form form={form} layout="vertical" onFinish={submit} initialValues={{ rules: rules.map(([id]) => id), scopeAsset: !!assetId, days: 30, narrow: true }}>
        <Form.Item name="rules" label={t('thRule')} rules={[{ required: true, message: t('pickRule') }]}>
          <Checkbox.Group options={rules.map(([id, title]) => ({ value: id, label: title }))} style={{ flexDirection: 'column' }} />
        </Form.Item>
        <Form.Item name="scopeAsset" valuePropName="checked">
          <Checkbox disabled={!assetId}>{t('scopeThisHost')}</Checkbox>
        </Form.Item>
        {scopeAsset === false && <Alert type="warning" showIcon title={t('scopeAllWarning')} style={{ marginBottom: 16 }} />}
        <Form.Item name="narrow" valuePropName="checked" extra={narrow !== false && rules.map(([id, title]) => {
          const c = conditionOf.get(id)
          return <div key={id} className="mono" style={{ fontSize: 12 }}>{title}：{c ? `${c.field} = ${c.value}` : t('supNoEvidence')}</div>
        })}>
          <Checkbox>{t('supNarrow')}</Checkbox>
        </Form.Item>
        {narrow === false && <Alert type="warning" showIcon title={t('supWholeRuleWarning')} style={{ marginBottom: 16 }} />}
        <Form.Item name="days" label={t('validity')}>
          <Select options={[7, 30, 90].map(n => ({ value: n, label: t('days', { n }) })).concat({ value: 0, label: t('longTerm') })} />
        </Form.Item>
        <Form.Item name="reason" label={t('reason')}>
          <Input placeholder={t('reasonPlaceholder')} />
        </Form.Item>
      </Form>
    </Modal>
  )
}
