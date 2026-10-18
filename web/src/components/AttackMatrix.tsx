import { useQuery } from '@tanstack/react-query'
import { Card, Flex, Space, Spin, Tooltip, Typography, theme } from 'antd'
import { useTheme } from '../app/theme'
import { LoadError } from './LoadError'
import { fetchAttack } from '../api'
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

// 覆盖深度：按规则数分三档，同一色相的有序色阶（亮暗各一组，均过 dataviz 校验：单色相、明度单调、最浅档对底色 ≥2:1），
// 格内文字按底色明暗取深或浅，对比度都在 5:1 以上
const DEPTH = {
  light: [{ bg: '#86b6ef', fg: '#0d366b' }, { bg: '#256abf', fg: '#ffffff' }, { bg: '#104281', fg: '#ffffff' }],
  dark: [{ bg: '#184f95', fg: '#ffffff' }, { bg: '#256abf', fg: '#ffffff' }, { bg: '#86b6ef', fg: '#0d366b' }],
}
const depthOf = (rules: number) => Math.min(rules, 3) - 1

// T1059.001 → https://attack.mitre.org/techniques/T1059/001/
const mitreUrl = (id: string) => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`

// 覆盖矩阵：一行排开全部战术（像 ATT&CK Navigator，放不下就横向滚动），空列不是排版问题，是检测缺口——让"没防住哪一环"无法被忽略
export function AttackMatrix() {
  const { t, locale } = useI18n()
  const { token } = theme.useToken()
  const { dark } = useTheme()
  const depth = DEPTH[dark ? 'dark' : 'light']
  const { data: cov, isPending, isError, error, refetch } = useQuery({ queryKey: ['attack'], queryFn: fetchAttack })
  const covered = cov?.tactics.filter(c => c.rules > 0).length ?? 0

  if (isError) return <LoadError error={error} onRetry={() => refetch()} />

  const swatch = (bg: string, label: string) => (
    <Space size={6} key={label}><span className="matrix-swatch" style={{ background: bg }} /><Typography.Text type="secondary" style={{ fontSize: 12 }}>{label}</Typography.Text></Space>
  )

  return (
    <Card>
      {isPending && <Spin />}
      {cov && (
        <Flex justify="space-between" align="center" wrap gap={12} style={{ marginBottom: 16 }}>
          <Typography.Text type="secondary">
            {[
              t('attackSummary', { covered, total: cov.tactics.length }),
              cov.untagged > 0 && t('attackUntagged', { n: cov.untagged }),
              cov.noDataSource > 0 && t('attackNoData', { n: cov.noDataSource }),
            ].filter(Boolean).join(' · ')}
          </Typography.Text>
          <Space size={14} wrap>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('attackLegend')}</Typography.Text>
            {swatch(depth[0].bg, '1')}
            {swatch(depth[1].bg, '2')}
            {swatch(depth[2].bg, '3+')}
            {swatch(token.colorFillSecondary, t('noDataSource'))}
          </Space>
        </Flex>
      )}
      <div className="matrix-scroll">
        <div className="matrix" style={{ gridTemplateColumns: `repeat(${cov?.tactics.length ?? 14}, minmax(96px, 1fr))` }}>
          {cov?.tactics.map(col => (
            <div key={col.tactic} className="matrix-col">
              <div className="matrix-head" style={{ borderBottomColor: col.rules ? token.colorPrimary : token.colorError }}>
                <Typography.Text strong style={{ fontSize: 13 }}>{TACTIC[col.tactic]?.[locale === 'zh' ? 0 : 1] ?? col.tactic}</Typography.Text>
                <Typography.Text type={col.rules ? 'secondary' : 'danger'} style={{ fontSize: 12 }}>
                  {col.rules ? t('attackCellRules', { n: col.rules }) : t('attackNoCoverage')}
                </Typography.Text>
              </div>
              <div className="matrix-cells">
                {(col.techniques ?? []).map(cell => {
                  const c = cell.hasData ? depth[depthOf(cell.rules)] : { bg: token.colorFillSecondary, fg: token.colorTextTertiary }
                  return (
                    <Tooltip key={cell.id} title={<>{cell.hasData ? t('attackCellRules', { n: cell.rules }) : t('noDataSource')}<br />{t('attackOpenMitre')}</>}>
                      <a className="matrix-cell" href={mitreUrl(cell.id)} target="_blank" rel="noopener noreferrer" style={{ background: c.bg, color: c.fg }}>{cell.id}</a>
                    </Tooltip>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </Card>
  )
}
