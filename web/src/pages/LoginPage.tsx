import { LockOutlined, UserOutlined, ApartmentOutlined } from '@ant-design/icons'
import { useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Form, Input, Typography, theme } from 'antd'
import { useState } from 'react'
import { login } from '../api'
import { useI18n } from '../i18n'

export function LoginPage() {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const client = useQueryClient()
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (v: { username: string; password: string }) => {
    setBusy(true)
    setError(null)
    try {
      client.setQueryData(['me'], await login(v.username, v.password))
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap" style={{ background: token.colorBgLayout }}>
      <Card style={{ width: 380 }}>
        <div className="login-brand">
          <ApartmentOutlined style={{ fontSize: 32, color: token.colorPrimary }} />
          <Typography.Title level={3} style={{ margin: 0 }}>OpenXDR</Typography.Title>
          <Typography.Text type="secondary">{t('loginSubtitle')}</Typography.Text>
        </div>
        <Form layout="vertical" size="large" onFinish={submit} requiredMark={false}>
          <Form.Item name="username" rules={[{ required: true, message: t('usernameRequired') }]}>
            <Input prefix={<UserOutlined />} placeholder={t('username')} autoFocus />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: t('passwordRequired') }]}>
            <Input.Password prefix={<LockOutlined />} placeholder={t('password')} />
          </Form.Item>
          {error && <Alert type="error" title={error} showIcon style={{ marginBottom: 16 }} />}
          <Button type="primary" htmlType="submit" block loading={busy}>{t('signIn')}</Button>
        </Form>
      </Card>
    </div>
  )
}
