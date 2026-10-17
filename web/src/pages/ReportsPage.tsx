import { ExportOutlined, FilePdfOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { App, Button, Card, Drawer, Empty, Space, Table } from 'antd'
import { useState } from 'react'
import { Link } from 'react-router'
import { downloadAgentPdf, fetchAgentReports, reportHtmlUrl, type AgentReport } from '../api'
import { useSession } from '../app/session'
import { Markdown } from '../components/Markdown'
import { Page } from '../components/Page'
import { fmtTime, errText } from '../components/format'
import { useI18n } from '../i18n'
import { LoadError } from '../components/LoadError'

// 报告中心：Pi 会话（含定时巡检）提交的报告，按当前组列出
export function ReportsPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const { group } = useSession()
  const [preview, setPreview] = useState<AgentReport | null>(null)
  const { data, isPending, isError, error, refetch } = useQuery({
    queryKey: ['reports', group?.id],
    queryFn: () => fetchAgentReports(group!.id),
    enabled: !!group,
    refetchInterval: 30_000,
  })
  const pdf = (r: AgentReport) => downloadAgentPdf(r).catch(e => message.error(errText(e, t)))

  if (!group) return <Empty style={{ marginTop: 120 }} description={t('noGroupsHint')} />
  return (
    <Page title={t('navReports')} subtitle={t('reportsSubtitle', { name: group.name })}>
      <Card styles={{ body: { padding: 0 } }}>
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<AgentReport>
          rowKey="id"
          loading={isPending}
          dataSource={data ?? []}
          pagination={{ pageSize: 20, hideOnSinglePage: true }}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('noReports')} /> }}
          columns={[
            { title: t('reportTitle'), dataIndex: 'title', render: (v, r) => <a onClick={() => setPreview(r)}>{v}</a> },
            { title: t('thCreatedAt'), dataIndex: 'created_at', width: 190, render: fmtTime },
            { title: t('sourceSession'), dataIndex: 'session_id', width: 140, render: v => <Link to={`/chat/${v}`}>{t('openSession')}</Link> },
            {
              title: t('actions'), width: 200,
              render: (_, r) => (
                <Space>
                  <Button size="small" icon={<ExportOutlined />} onClick={() => window.open(reportHtmlUrl(r.id), '_blank', 'noopener')}>HTML</Button>
                  <Button size="small" icon={<FilePdfOutlined />} onClick={() => pdf(r)}>PDF</Button>
                </Space>
              ),
            },
          ]}
        />}
      </Card>
      <Drawer
        size={760}
        open={!!preview}
        title={preview?.title}
        onClose={() => setPreview(null)}
        extra={preview && (
          <Space>
            <Button icon={<ExportOutlined />} onClick={() => window.open(reportHtmlUrl(preview.id), '_blank', 'noopener')}>HTML</Button>
            <Button icon={<FilePdfOutlined />} onClick={() => pdf(preview)}>PDF</Button>
          </Space>
        )}
      >
        {preview && <Markdown text={preview.markdown} />}
      </Drawer>
    </Page>
  )
}
