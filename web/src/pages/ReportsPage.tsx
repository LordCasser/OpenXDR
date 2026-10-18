import { ExportOutlined, FilePdfOutlined, FileSearchOutlined, SearchOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { App, Button, Drawer, Empty, Input, Space, Table } from 'antd'
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { downloadAgentPdf, fetchAgentReports, reportHtmlUrl, type AgentReport } from '../api'
import { useSession } from '../app/session'
import { Markdown } from '../components/Markdown'
import { EmptyHint, Refreshed } from '../components/Ago'
import { FilterCard, Page } from '../components/Page'
import { fmtTime, errText } from '../components/format'
import { useI18n } from '../i18n'
import { LoadError } from '../components/LoadError'

// 报告中心：Pi 会话（含定时巡检）提交的报告，按当前组列出
export function ReportsPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const { group } = useSession()
  const canChat = group?.role === 'admin' || group?.role === 'analyst'
  const [search, setSearch] = useState('')
  const [downloads, setDownloads] = useState<Set<string>>(new Set())
  const [preview, setPreview] = useState<AgentReport | null>(null)
  const { data, isPending, isError, error, refetch, isFetching, dataUpdatedAt } = useQuery({
    queryKey: ['reports', group?.id],
    queryFn: () => fetchAgentReports(group!.id),
    enabled: !!group,
    refetchInterval: 30_000,
  })
  useEffect(() => { setPreview(null); setSearch('') }, [group?.id])
  const pdf = async (r: AgentReport) => {
    if (downloads.has(r.id)) return
    setDownloads(previous => new Set(previous).add(r.id))
    try { await downloadAgentPdf(r) }
    catch (e) { message.error(errText(e, t)) }
    finally { setDownloads(previous => { const next = new Set(previous); next.delete(r.id); return next }) }
  }
  const rows = (data ?? []).filter(r => r.title.toLowerCase().includes(search.trim().toLowerCase()))

  if (!group) return <Empty style={{ marginTop: 120 }} description={t('noGroupsHint')} />
  return (
    <Page title={t('navReports')} subtitle={t('reportsSubtitle', { name: group.name })}>
      <FilterCard
        filters={<Input allowClear prefix={<SearchOutlined aria-hidden />} aria-label={t('searchReports')} placeholder={t('searchReports')} value={search} onChange={e => setSearch(e.target.value)} style={{ width: 280, maxWidth: '100%' }} />}
        onReset={search ? () => setSearch('') : undefined}
        extra={<Refreshed at={dataUpdatedAt} fetching={isFetching} onRefresh={() => refetch()} />}
      >
        {isError ? <LoadError error={error} onRetry={() => refetch()} /> : <Table<AgentReport>
          scroll={{ x: 800 }}
          rowKey="id"
          loading={isPending}
          dataSource={rows}
          pagination={{ pageSize: 20, hideOnSinglePage: true }}
          locale={{ emptyText: search ? <EmptyHint title={t('noMatch')} /> : <EmptyHint title={t('noReports')} hint={t('noReportsHint')}
            action={canChat && <Link to={`/chat?${new URLSearchParams({ prompt: t('reportPrompt') })}`}><Button type="primary">{t('reportAskAI')}</Button></Link>} /> }}
          columns={[
            { title: t('reportTitle'), dataIndex: 'title', render: (v, r) => <Button type="link" className="report-title-button" icon={<FileSearchOutlined aria-hidden />} onClick={() => setPreview(r)}>{v}</Button> },
            { title: t('thCreatedAt'), dataIndex: 'created_at', width: 190, render: fmtTime },
            { title: t('sourceSession'), dataIndex: 'session_id', width: 140, render: v => <Link to={`/chat/${v}`}>{t('openSession')}</Link> },
            {
              title: t('actions'), width: 200,
              render: (_, r) => (
                <Space>
                  <Button size="small" icon={<ExportOutlined aria-hidden />} onClick={() => window.open(reportHtmlUrl(r.id), '_blank', 'noopener')}>HTML</Button>
                  <Button size="small" icon={<FilePdfOutlined aria-hidden />} loading={downloads.has(r.id)} onClick={() => pdf(r)}>PDF</Button>
                </Space>
              ),
            },
          ]}
        />}
      </FilterCard>
      <Drawer
        size={760}
        open={!!preview}
        title={preview?.title}
        onClose={() => setPreview(null)}
        extra={preview && (
          <Space>
            <Button icon={<ExportOutlined aria-hidden />} onClick={() => window.open(reportHtmlUrl(preview.id), '_blank', 'noopener')}>HTML</Button>
            <Button icon={<FilePdfOutlined aria-hidden />} loading={downloads.has(preview.id)} onClick={() => pdf(preview)}>PDF</Button>
          </Space>
        )}
      >
        {preview && <Markdown text={preview.markdown} />}
      </Drawer>
    </Page>
  )
}
