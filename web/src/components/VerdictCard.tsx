import { Alert, Card, Empty, Progress, Space, Tag, Typography } from 'antd'
import type { Verdict } from '../api'
import { useI18n, type MsgKey } from '../i18n'

const META: Record<string, { key: MsgKey; color: string }> = {
  malicious: { key: 'verdictMalicious', color: 'red' },
  suspicious: { key: 'verdictSuspicious', color: 'orange' },
  benign: { key: 'verdictBenign', color: 'green' },
}

export function VerdictCard({ verdict }: { verdict: Verdict | null }) {
  const { t } = useI18n()
  if (!verdict) return <Card title={t('aiVerdict')}><Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('waitingVerdict')} /></Card>
  if (verdict.error) return <Card title={t('aiVerdict')}><Alert type="warning" showIcon title={t('unparsableVerdict', { e: verdict.raw ?? verdict.error })} /></Card>
  const meta = META[verdict.verdict ?? '']
  return (
    <Card
      title={t('aiVerdict')}
      extra={
        <Space>
          <Tag color={meta?.color}>{meta ? t(meta.key) : verdict.verdict}</Tag>
          {verdict.confidence != null && (
            <Space size={4}>
              <Typography.Text type="secondary">{t('confidence')}</Typography.Text>
              <Progress percent={verdict.confidence} size="small" style={{ width: 100, margin: 0 }} />
            </Space>
          )}
        </Space>
      }
    >
      {verdict.summary && <Typography.Paragraph>{verdict.summary}</Typography.Paragraph>}
      {!!verdict.kill_chain?.length && (
        <>
          <Typography.Text strong>{t('killChain')}</Typography.Text>
          <ol className="verdict-list">{verdict.kill_chain.map((s, i) => <li key={i}>{s}</li>)}</ol>
        </>
      )}
      {!!verdict.actions?.length && (
        <>
          <Typography.Text strong>{t('suggestedActions')}</Typography.Text>
          <ul className="verdict-list">{verdict.actions.map((s, i) => <li key={i}>{s}</li>)}</ul>
        </>
      )}
    </Card>
  )
}
