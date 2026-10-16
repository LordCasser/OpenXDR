import { useQuery } from '@tanstack/react-query'
import { Card, Space, Spin, Tag, Tooltip, Typography, theme } from 'antd'
import { fetchAttack } from '../api'
import { Page } from '../components/Page'
import { useI18n } from '../i18n'

// ATT&CK 战术显示名；顺序由后端按杀伤链排好
const TACTIC: Record<string, [string, string]> = {
  reconnaissance: ['侦察', 'Recon'],
  'resource-development': ['资源开发', 'Resource Dev'],
  'initial-access': ['初始访问', 'Initial Access'],
  execution: ['执行', 'Execution'],
  persistence: ['持久化', 'Persistence'],
  'privilege-escalation': ['提权', 'Priv Esc'],
  'defense-evasion': ['防御规避', 'Defense Evasion'],
  'credential-access': ['凭据访问', 'Cred Access'],
  discovery: ['发现', 'Discovery'],
  'lateral-movement': ['横向移动', 'Lateral Movement'],
  collection: ['收集', 'Collection'],
  'command-and-control': ['命令控制', 'C2'],
  exfiltration: ['数据外传', 'Exfiltration'],
  impact: ['影响', 'Impact'],
}

// 覆盖矩阵：空列不是排版问题，是检测缺口——让"没防住哪一环"无法被忽略
export function AttackPage() {
  const { t, locale } = useI18n()
  const { token } = theme.useToken()
  const { data: cov, isPending } = useQuery({ queryKey: ['attack'], queryFn: fetchAttack })
  const covered = cov?.tactics.filter(c => c.rules > 0).length ?? 0

  return (
    <Page
      title={t('navAttack')}
      subtitle={cov && [
        t('attackSummary', { covered, total: cov.tactics.length }),
        cov.untagged > 0 && t('attackUntagged', { n: cov.untagged }),
        cov.noDataSource > 0 && t('attackNoData', { n: cov.noDataSource }),
      ].filter(Boolean).join(' · ')}
    >
      <Card>
        {isPending && <Spin />}
        <div className="matrix">
          {cov?.tactics.map(col => (
            <div key={col.tactic} className="matrix-col">
              <div className="matrix-head" style={{ background: col.rules ? token.colorPrimaryBg : token.colorErrorBg }}>
                <Typography.Text strong>{TACTIC[col.tactic]?.[locale === 'zh' ? 0 : 1] ?? col.tactic}</Typography.Text>
                <Typography.Text type="secondary"> {col.rules}</Typography.Text>
              </div>
              <Space orientation="vertical" size={4} style={{ width: '100%' }}>
                {(col.techniques ?? []).map(cell => (
                  <Tooltip key={cell.id} title={cell.hasData ? t('attackCellRules', { n: cell.rules }) : t('noDataSource')}>
                    <Tag color={cell.hasData ? 'blue' : 'default'} style={{ width: '100%', margin: 0, textAlign: 'center', opacity: cell.hasData ? 1 : 0.6 }}>{cell.id}</Tag>
                  </Tooltip>
                ))}
                {col.rules === 0 && <Typography.Text type="danger" style={{ fontSize: 12 }}>{t('attackNoCoverage')}</Typography.Text>}
              </Space>
            </div>
          ))}
        </div>
      </Card>
    </Page>
  )
}
