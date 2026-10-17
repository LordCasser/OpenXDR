import { Button, Result } from 'antd'
import { errText } from './format'
import { useI18n } from '../i18n'

// 查询失败与"没有数据"必须分开：失败时给原因和重试，不显示空状态
export function LoadError({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const { t } = useI18n()
  return (
    <Result status="warning" title={t('loadFailed')} subTitle={errText(error, t)}
      extra={onRetry && <Button onClick={onRetry}>{t('retry')}</Button>} />
  )
}
