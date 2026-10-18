import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Card, Popconfirm, Space, Table, Tag, Tooltip } from 'antd'
import { Link } from 'react-router'
import { deleteSuppression, fetchAssets, fetchSuppressions, reviewSuppression, type Suppression } from '../api'
import { useSession } from '../app/session'
import { HostLink } from '../components/HostLink'
import { Page } from '../components/Page'
import { fmtTime, errText } from '../components/format'
import { useI18n } from '../i18n'
import { LoadError } from '../components/LoadError'

// 抑制规则：最怕被遗忘——列出压掉的次数，让长期无人过问的抑制显形
export function SuppressionsPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { canWrite, isAdmin, groups } = useSession()
  const { data, isPending, isError, error, refetch } = useQuery({ queryKey: ['suppressions'], queryFn: fetchSuppressions })
  const assets = useQuery({ queryKey: ['assets'], queryFn: fetchAssets })
  // AI 提议由主机所在组的管理员批准，与命令审批同一档权限
  const canReview = (s: Suppression) => {
    const groupId = assets.data?.find(a => a.id === s.assetId)?.groupId
    return isAdmin || groups.find(g => g.id === groupId)?.role === 'admin'
  }
  // 待批准的排在最前
  const rows = [...(data ?? [])].sort((a, b) => Number(b.status === 'proposed') - Number(a.status === 'proposed'))
  const review = async (id: string, decision: 'approve' | 'reject') => {
    try {
      await reviewSuppression(id, decision)
      await client.invalidateQueries({ queryKey: ['suppressions'] })
    } catch (e) {
      message.error(errText(e, t))
    }
  }

  const revoke = async (id: string) => {
    try {
      await deleteSuppression(id)
      await client.invalidateQueries({ queryKey: ['suppressions'] })
    } catch (e) {
      message.error(errText(e, t))
    }
  }

  return (
    <Page title={t('navSuppressions')} subtitle={t('suppressionsSubtitle')}>
      <Card styles={{ body: { padding: 0 } }}>
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<Suppression>
          rowKey="id"
          loading={isPending}
          dataSource={rows}
          pagination={{ pageSize: 20, hideOnSinglePage: true }}
          locale={{ emptyText: t('noSuppressions') }}
          columns={[
            { title: t('thRule'), dataIndex: 'ruleTitle', render: (v, s) => <Tooltip title={s.ruleId}>{v ?? s.ruleId}</Tooltip> },
            {
              title: t('thStatus'), dataIndex: 'status', width: 110,
              render: (v: Suppression['status']) => <Tag color={v === 'proposed' ? 'gold' : v === 'rejected' ? 'default' : 'green'}>{t(v === 'proposed' ? 'supProposed' : v === 'rejected' ? 'supRejected' : 'supActive')}</Tag>,
            },
            { title: t('thScope'), dataIndex: 'assetId', width: 130, render: v => (v ? <HostLink id={v} /> : <Tag color="warning">{t('allHosts')}</Tag>) },
            { title: t('reason'), dataIndex: 'reason', ellipsis: true, render: v => v ?? '-' },
            { title: t('thMatched'), dataIndex: 'matchedCount', width: 100, align: 'right', sorter: (a, b) => a.matchedCount - b.matchedCount },
            { title: t('thLastMatched'), dataIndex: 'lastMatchedAt', width: 170, render: fmtTime },
            { title: t('thExpires'), dataIndex: 'expiresAt', width: 170, render: v => (v ? fmtTime(v) : t('longTerm')) },
            {
              title: t('thCreatedBy'), dataIndex: 'createdBy', width: 120,
              render: (v: string, s) => (s.sessionId ? <Space size={4}><Tag color="purple" variant="filled">AI</Tag><Link to={`/chat/${s.sessionId}`}>{t('openSession')}</Link></Space> : v),
            },
            ...(canWrite
              ? [{
                  title: t('actions'), width: 150,
                  render: (_: unknown, s: Suppression) => (
                    <Space size={0}>
                      {s.status === 'proposed' && canReview(s) && <>
                        <Popconfirm title={t('supApproveConfirm')} onConfirm={() => review(s.id, 'approve')}>
                          <Button type="link" size="small">{t('supApprove')}</Button>
                        </Popconfirm>
                        <Button type="link" size="small" onClick={() => review(s.id, 'reject')}>{t('supReject')}</Button>
                      </>}
                      {s.status !== 'proposed' && (
                        <Popconfirm title={t('confirmRevoke')} onConfirm={() => revoke(s.id)}>
                          <Button type="link" danger size="small">{t('revoke')}</Button>
                        </Popconfirm>
                      )}
                    </Space>
                  ),
                }]
              : []),
          ]}
        />}
      </Card>
    </Page>
  )
}
