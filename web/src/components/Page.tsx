import { Flex, Typography } from 'antd'
import type { ReactNode } from 'react'

// 页面骨架：标题 + 说明 + 右侧操作，下面是内容
export function Page({ title, subtitle, extra, children }: {
  title: ReactNode
  subtitle?: ReactNode
  extra?: ReactNode
  children: ReactNode
}) {
  return (
    <div className="page">
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
