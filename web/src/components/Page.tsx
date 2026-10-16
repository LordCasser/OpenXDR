import { HomeOutlined } from '@ant-design/icons'
import { Breadcrumb, Card, Flex, Typography } from 'antd'
import type { ReactNode } from 'react'
import { Link, useLocation } from 'react-router'
import { crumbsOf } from '../app/nav'
import { useI18n } from '../i18n'

// 页面骨架：面包屑 + 标题 + 说明 + 右侧操作，下面是内容。面包屑从菜单配置推，详情页给最后一级
export function Page({ title, subtitle, extra, crumb, children }: {
  title: ReactNode
  subtitle?: ReactNode
  extra?: ReactNode
  crumb?: ReactNode
  children: ReactNode
}) {
  const { t } = useI18n()
  const { pathname } = useLocation()
  const { group, page } = crumbsOf(pathname)
  const items = [
    { title: <Link to="/chat"><HomeOutlined /></Link> },
    ...(group ? [{ title: t(group) }] : []),
    ...(page ? [{ title: crumb ? <Link to={page.path}>{t(page.key)}</Link> : t(page.key) }] : []),
    ...(crumb ? [{ title: crumb }] : []),
  ]
  return (
    <div className="page">
      <Breadcrumb items={items} style={{ marginBottom: 8 }} />
      <Flex justify="space-between" align="flex-start" gap={16} wrap className="page-head">
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>{title}</Typography.Title>
          {subtitle && <Typography.Text type="secondary">{subtitle}</Typography.Text>}
        </div>
        {extra && <Flex gap={8} wrap>{extra}</Flex>}
      </Flex>
      {children}
    </div>
  )
}

// 列表卡片：筛选条单独一行在表格上方，右侧放计数或次要操作
export function FilterCard({ filters, extra, children }: { filters: ReactNode; extra?: ReactNode; children: ReactNode }) {
  return (
    <Card styles={{ body: { padding: 0 } }}>
      <Flex justify="space-between" align="center" gap={12} wrap className="filter-bar">
        <Flex gap={8} wrap align="center">{filters}</Flex>
        {extra}
      </Flex>
      {children}
    </Card>
  )
}
