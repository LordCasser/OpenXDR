import { CheckCircleFilled, ExclamationCircleFilled, RobotOutlined, WarningFilled } from '@ant-design/icons'
import { Alert, Card, Col, Empty, Flex, Row, Timeline, Typography, theme } from 'antd'
import type { ReactNode } from 'react'
import type { Verdict } from '../api'
import { useI18n, type MsgKey } from '../i18n'

// 研判结论放在详情页最上面：先看结论与置信度，再看攻击链与处置建议
export function VerdictCard({ verdict }: { verdict: Verdict | null }) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const META: Record<string, { key: MsgKey; color: string; bg: string; icon: ReactNode }> = {
    malicious: { key: 'verdictMalicious', color: token.colorError, bg: token.colorErrorBg, icon: <ExclamationCircleFilled /> },
    suspicious: { key: 'verdictSuspicious', color: token.colorWarning, bg: token.colorWarningBg, icon: <WarningFilled /> },
    benign: { key: 'verdictBenign', color: token.colorSuccess, bg: token.colorSuccessBg, icon: <CheckCircleFilled /> },
  }
  if (!verdict) return <Card title={t('aiVerdict')}><Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('waitingVerdict')} /></Card>
  if (verdict.error) return <Card title={t('aiVerdict')}><Alert type="warning" showIcon title={t('unparsableVerdict', { e: verdict.raw ?? verdict.error })} /></Card>
  const meta = META[verdict.verdict ?? '']
  const chain = verdict.kill_chain ?? []
  const actions = verdict.actions ?? []

  return (
    <Card styles={{ body: { padding: 0 } }}>
      <Flex align="center" gap={16} className="verdict-band" style={{ background: meta?.bg ?? token.colorFillQuaternary, borderLeftColor: meta?.color ?? token.colorBorder }}>
        <span style={{ fontSize: 30, color: meta?.color, lineHeight: 1 }}>{meta?.icon ?? <RobotOutlined />}</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}><RobotOutlined /> {t('aiVerdict')}</Typography.Text>
          <div style={{ fontSize: 20, fontWeight: 600, color: meta?.color }}>{meta ? t(meta.key) : verdict.verdict}</div>
        </div>
        {verdict.confidence != null && (
          <div style={{ textAlign: 'right' }}>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('confidence')}</Typography.Text>
            <div style={{ fontSize: 22, fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>{verdict.confidence}%</div>
          </div>
        )}
      </Flex>
      <div style={{ padding: '18px 24px 8px' }}>
        {verdict.summary && <Typography.Paragraph style={{ lineHeight: 1.8 }}>{verdict.summary}</Typography.Paragraph>}
        <Row gutter={[32, 8]}>
          {!!chain.length && (
            <Col xs={24} lg={actions.length ? 13 : 24}>
              <Typography.Title level={5} style={{ marginTop: 4 }}>{t('killChain')}</Typography.Title>
              <Timeline items={chain.map(s => ({ color: meta?.color ?? token.colorPrimary, content: s }))} />
            </Col>
          )}
          {!!actions.length && (
            <Col xs={24} lg={chain.length ? 11 : 24}>
              <Typography.Title level={5} style={{ marginTop: 4 }}>{t('suggestedActions')}</Typography.Title>
              <ol className="action-list">{actions.map((s, i) => <li key={i}>{s}</li>)}</ol>
            </Col>
          )}
        </Row>
      </div>
    </Card>
  )
}
