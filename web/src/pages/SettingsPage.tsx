import { useMutation, useQuery } from '@tanstack/react-query'
import { App, Button, Card, Form, Input, Select, Skeleton, Space, Typography } from 'antd'
import { useEffect } from 'react'
import { fetchNotifySettings, saveNotifySettings, testNotifySettings, type NotifySettings } from '../api'
import { Page } from '../components/Page'
import { useI18n } from '../i18n'

// 系统设置：目前只有通知。出口只有一个——IM 群，填地址、点测试、保存
export function SettingsPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const [form] = Form.useForm<NotifySettings>()
  const { data, isPending } = useQuery({ queryKey: ['notify-settings'], queryFn: fetchNotifySettings })

  useEffect(() => {
    // 控制台地址没填过就用当前地址，绝大多数情况正是它
    if (data) form.setFieldsValue({ ...data, linkBase: data.linkBase || window.location.origin })
  }, [data, form])

  const save = useMutation({
    mutationFn: (v: NotifySettings) => saveNotifySettings(v),
    onSuccess: () => message.success(t('notifySaved')),
    onError: e => message.error(String(e)),
  })
  const test = useMutation({
    mutationFn: (v: NotifySettings) => testNotifySettings(v),
    onSuccess: () => message.success(t('notifyTestOk')),
    onError: e => message.error(String(e)),
  })

  const formats = [
    { value: 'dingtalk', label: t('formatDingtalk') },
    { value: 'feishu', label: t('formatFeishu') },
    { value: 'wecom', label: t('formatWecom') },
    { value: 'generic', label: t('formatGeneric') },
  ]
  const severities = [
    { value: 0, label: t('notifyAllSeverity') },
    ...[1, 2, 3, 4, 5].map(n => ({ value: n, label: t(`sev${n}` as 'sev1') })),
  ]

  return (
    <Page title={t('navSettings')}>
      <Card title={t('settingsNotify')}>
        <Typography.Paragraph type="secondary">{t('settingsNotifyHint')}</Typography.Paragraph>
        {isPending ? <Skeleton active /> : (
          <Form form={form} layout="vertical" style={{ maxWidth: 640 }} onFinish={v => save.mutate(v)}>
            <Form.Item name="url" label={t('notifyUrl')} extra={t('notifyUrlHint')}>
              <Input allowClear placeholder="https://oapi.dingtalk.com/robot/send?access_token=…" />
            </Form.Item>
            <Form.Item name="format" label={t('notifyFormat')}>
              <Select options={formats} style={{ width: 200 }} />
            </Form.Item>
            <Form.Item name="linkBase" label={t('notifyLinkBase')} extra={t('notifyLinkBaseHint')}>
              <Input />
            </Form.Item>
            <Form.Item name="minSeverity" label={t('notifyMinSeverity')}>
              <Select options={severities} style={{ width: 200 }} />
            </Form.Item>
            <Space>
              <Button type="primary" htmlType="submit" loading={save.isPending}>{t('save')}</Button>
              <Button loading={test.isPending} onClick={() => test.mutate(form.getFieldsValue())}>{t('notifyTest')}</Button>
            </Space>
          </Form>
        )}
      </Card>
    </Page>
  )
}
