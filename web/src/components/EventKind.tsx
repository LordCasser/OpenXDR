import {
  ApiOutlined, AppstoreOutlined, CodeOutlined, DatabaseOutlined, FileOutlined, FileTextOutlined, GlobalOutlined, LoginOutlined, QuestionOutlined,
} from '@ant-design/icons'
import { Tooltip, theme } from 'antd'
import type { ReactNode } from 'react'
import { useI18n } from '../i18n'
import { CLASS_KEY } from './format'

// 事件类别的图标与颜色：进程紫、文件青、网络绿、DNS 蓝，与事件实体图同一套；颜色只是辅助，旁边总有文字或提示
export function useClassStyle() {
  const { token } = theme.useToken()
  return (classUid: number): { icon: ReactNode; color: string } => {
    switch (classUid) {
      case 1007: return { icon: <CodeOutlined />, color: token.purple }
      case 1001: return { icon: <FileOutlined />, color: token.cyan }
      case 4001: return { icon: <ApiOutlined />, color: token.colorSuccess }
      case 4003: return { icon: <GlobalOutlined />, color: token.geekblue }
      case 3002: return { icon: <LoginOutlined />, color: token.orange }
      case 201002: return { icon: <DatabaseOutlined />, color: token.magenta }
      case 1005: return { icon: <AppstoreOutlined />, color: token.gold }
      case 100001: return { icon: <FileTextOutlined />, color: token.colorTextSecondary }
      default: return { icon: <QuestionOutlined />, color: token.colorTextTertiary }
    }
  }
}

// 类别徽标：图标放在浅色底的小方块里；compact 只出图标（悬停看类别名）
export function EventKind({ classUid, compact }: { classUid: number; compact?: boolean }) {
  const { t } = useI18n()
  const { icon, color } = useClassStyle()(classUid)
  const label = CLASS_KEY[classUid] ? t(CLASS_KEY[classUid]) : String(classUid)
  const badge = <span className="event-kind-icon" style={{ color, background: `color-mix(in srgb, ${color} 14%, transparent)` }}>{icon}</span>
  if (compact) return <Tooltip title={label}>{badge}</Tooltip>
  return <span className="event-kind">{badge}<span>{label}</span></span>
}
