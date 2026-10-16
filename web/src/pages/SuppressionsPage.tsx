import { useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Card, Popconfirm, Table, Tag, Tooltip } from 'antd'
import { deleteSuppression, fetchSuppressions, type Suppression } from '../api'
import { useSession } from '../app/session'
import { Page } from '../components/Page'
import { fmtTime } from '../components/format'
import { useI18n } from '../i18n'

// 抑制规则：最怕被遗忘——列出压掉的次数，让长期无人过问的抑制显形
export function SuppressionsPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { canWrite } = useSession()
  const { data, isPending } = useQuery({ queryKey: ['suppressions'], queryFn: fetchSuppressions })

  const revoke = async (id: string) => {
    try {
      await deleteSuppression(id)
      await client.invalidateQueries({ queryKey: ['suppressions'] })
    } catch (e) {
      message.error(String(e))
    }
  }

  return (
    <Page title={t('navSuppressions')} subtitle={t('suppressionsSubtitle')}>
      <Card styles={{ body: { padding: 0 } }}>
        <Table<Suppression>
          rowKey="id"
          loading={isPending}
          dataSource={data ?? []}
          pagination={{ pageSize: 20, hideOnSinglePage: true }}
          locale={{ emptyText: t('noSuppressions') }}
          columns={[
            { title: t('thRule'), dataIndex: 'ruleTitle', render: (v, s) => <Tooltip title={s.ruleId}>{v ?? s.ruleId}</Tooltip> },
            { title: t('thScope'), dataIndex: 'assetId', width: 110, render: v => (v ? <Tag>{t('singleHost')}</Tag> : <Tag color="warning">{t('allHosts')}</Tag>) },
            { title: t('reason'), dataIndex: 'reason', ellipsis: true, render: v => v ?? '-' },
            { title: t('thMatched'), dataIndex: 'matchedCount', width: 100, align: 'right', sorter: (a, b) => a.matchedCount - b.matchedCount },
            { title: t('thLastMatched'), dataIndex: 'lastMatchedAt', width: 170, render: fmtTime },
            { title: t('thExpires'), dataIndex: 'expiresAt', width: 170, render: v => (v ? fmtTime(v) : t('longTerm')) },
            { title: t('thCreatedBy'), dataIndex: 'createdBy', width: 110 },
            ...(canWrite
              ? [{
                  title: t('actions'), width: 90,
                  render: (_: unknown, s: Suppression) => (
                    <Popconfirm title={t('confirmRevoke')} onConfirm={() => revoke(s.id)}>
                      <Button type="link" danger size="small">{t('revoke')}</Button>
                    </Popconfirm>
                  ),
                }]
              : []),
          ]}
        />
      </Card>
    </Page>
  )
}
