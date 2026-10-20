import { Space, Tag, Tooltip, Typography } from 'antd'
import type { AccountKind, IdentityAccount, LinkBasis, LoginStat } from '../api'
import { useI18n, type MsgKey } from '../i18n'
import { fmtTime } from './format'
import { accountLabel } from './identityText'

const ACCOUNT_KIND: Record<AccountKind, { key: MsgKey; color: string }> = {
  directory: { key: 'accountKindDirectory', color: 'purple' },
  windows: { key: 'accountKindWindows', color: 'blue' },
  linux: { key: 'accountKindLinux', color: 'cyan' },
}

const BASIS: Record<LinkBasis, { key: MsgKey; color?: string }> = {
  directory_anchor: { key: 'linkBasisDirectoryAnchor', color: 'purple' },
  ad_sid: { key: 'linkBasisADSID', color: 'green' },
  host_local: { key: 'linkBasisHostLocal' },
  manual: { key: 'linkBasisManual', color: 'gold' },
}

export function AccountKindTag({ kind }: { kind: AccountKind }) {
  const { t } = useI18n()
  return <Tag color={ACCOUNT_KIND[kind]?.color} variant="filled">{t(ACCOUNT_KIND[kind]?.key ?? 'identityUnknown')}</Tag>
}

export function IdentityKindTag({ kind }: { kind: 'directory' | 'host' }) {
  const { t } = useI18n()
  return <Tag color={kind === 'directory' ? 'purple' : undefined}>{t(kind === 'directory' ? 'identityKindDirectory' : 'identityKindHost')}</Tag>
}

export function BasisTag({ basis }: { basis: LinkBasis | null }) {
  const { t } = useI18n()
  if (!basis) return <>—</>
  return <Tag color={BASIS[basis]?.color}>{t(BASIS[basis]?.key ?? 'identityUnknown')}</Tag>
}

export function AccountName({ account }: { account: IdentityAccount }) {
  return <Space size={4} wrap>
    <AccountKindTag kind={account.kind} />
    <span style={{ overflowWrap: 'anywhere' }}>{accountLabel(account)}</span>
  </Space>
}

export function LoginSummary({ stat }: { stat: LoginStat | null }) {
  const { t } = useI18n()
  if (!stat) return <Typography.Text type="secondary">{t('identityLoginsNA')}</Typography.Text>
  if (!stat.success && !stat.failure) return <Typography.Text type="secondary">{t('identityNoLogins')}</Typography.Text>
  return <Space orientation="vertical" size={0}>
    <Space size={4}>
      <Tag color="blue">{t('identitySucceeded')} {stat.success}</Tag>
      <Tag color={stat.failure ? 'warning' : undefined}>{t('identityFailed')} {stat.failure}</Tag>
    </Space>
    <Typography.Text type="secondary">{fmtTime(stat.last)}</Typography.Text>
    {stat.sources.length > 0 && <Tooltip title={t('identityLoginSources')}>
      <Typography.Text type="secondary" style={{ overflowWrap: 'anywhere' }}>{stat.sources.join(', ')}</Typography.Text>
    </Tooltip>}
  </Space>
}

export function Evidence({ value }: { value: Record<string, unknown> | null }) {
  if (!value) return <>—</>
  return <Typography.Paragraph copyable className="mono" style={{ marginBottom: 0, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12 }}>
    {JSON.stringify(value, null, 2)}
  </Typography.Paragraph>
}
