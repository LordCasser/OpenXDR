import { CheckCircleFilled, LockOutlined, UserOutlined } from '@ant-design/icons'
import { useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Form, Input, Space, Typography, theme } from 'antd'
import { useState } from 'react'
import { login } from '../api'
import { Logo } from '../components/Logo'
import { useI18n, type MsgKey } from '../i18n'
import { errText } from '../components/format'

const POINTS: MsgKey[] = ['loginPoint1', 'loginPoint2', 'loginPoint3']

// 左侧品牌介绍、右侧登录表单；窄屏只留表单
export function LoginPage() {
  const { t, locale, setLocale } = useI18n()
  const { token } = theme.useToken()
  const client = useQueryClient()
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (v: { username: string; password: string }) => {
    setBusy(true)
    setError(null)
    try {
      const me = await login(v.username, v.password)
      client.removeQueries({ predicate: query => query.queryKey[0] !== 'me' })
      client.setQueryData(['me'], me)
    } catch (e) {
      setError(errText(e, t))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <div className="login-hero">
        <Space size={12} align="center">
          <Logo size={44} />
          <span className="login-hero-name">OpenXDR</span>
        </Space>
        <div className="login-hero-title">{t('loginHeroTitle')}</div>
        <div className="login-hero-sub">{t('loginSubtitle')}</div>
        <Space orientation="vertical" size={14} style={{ marginTop: 36 }}>
          {POINTS.map(k => (
            <Space key={k} size={10} align="start">
              <CheckCircleFilled style={{ color: '#2997ff', marginTop: 4 }} />
              <span className="login-hero-point">{t(k)}</span>
            </Space>
          ))}
        </Space>
      </div>
      <div className="login-panel" style={{ background: token.colorBgContainer }}>
        <div className="login-form">
          <div className="login-mobile-brand"><Logo size={36} /><span className="brand-name">OpenXDR</span></div>
          <Typography.Title level={2} style={{ marginBottom: 6, fontWeight: 700, letterSpacing: '-.022em' }}>{t('signInTitle')}</Typography.Title>
          <Typography.Text type="secondary">{t('signInHint')}</Typography.Text>
          <Form disabled={busy} layout="vertical" size="large" onFinish={submit} requiredMark={false} style={{ marginTop: 32 }}>
            <Form.Item label={t('username')} name="username" rules={[{ required: true, message: t('usernameRequired') }]}>
              <Input prefix={<UserOutlined />} placeholder={t('username')} autoComplete="username" autoFocus />
            </Form.Item>
            <Form.Item label={t('password')} name="password" rules={[{ required: true, message: t('passwordRequired') }]}>
              <Input.Password prefix={<LockOutlined />} placeholder={t('password')} autoComplete="current-password" />
            </Form.Item>
            {error && <Alert type="error" title={error} showIcon style={{ marginBottom: 16 }} />}
            <Button type="primary" htmlType="submit" block loading={busy}>{t('signIn')}</Button>
          </Form>
          <Button type="link" style={{ marginTop: 24, padding: 0 }} onClick={() => setLocale(locale === 'zh' ? 'en' : 'zh')}>
            {locale === 'zh' ? 'English' : '中文'}
          </Button>
        </div>
      </div>
    </div>
  )
}
