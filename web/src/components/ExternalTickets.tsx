import { useQuery } from '@tanstack/react-query'
import { Card, Space, Tag, Typography } from 'antd'
import { fetchIncidentTickets } from '../api'
import { useI18n } from '../i18n'
import { LoadError } from './LoadError'
import { fmtTime } from './format'

export function ExternalTickets({ incidentId }: { incidentId: string }) {
  const { t } = useI18n()
  const query = useQuery({ queryKey: ['incidentTickets', incidentId], queryFn: () => fetchIncidentTickets(incidentId), refetchInterval: 30_000 })
  return <Card title={t('integrationExternalTickets')} loading={query.isPending}>
    {query.isError ? <LoadError error={query.error} onRetry={() => query.refetch()} /> : query.data?.length ? <Space orientation="vertical" style={{ width: '100%' }}>{query.data.map(ticket => <div key={ticket.id}>
      <Typography.Link href={/^https?:\/\//i.test(ticket.url) ? ticket.url : undefined} target="_blank" rel="noopener noreferrer">{ticket.externalId} · {ticket.title}</Typography.Link>
      <div><Tag>{ticket.status}</Tag><Typography.Text type="secondary">{fmtTime(ticket.updatedAt)}</Typography.Text></div>
    </div>)}</Space> : <Typography.Text type="secondary">{t('integrationNoTicket')}</Typography.Text>}
  </Card>
}
