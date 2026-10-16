import { CompressOutlined, ZoomInOutlined, ZoomOutOutlined } from '@ant-design/icons'
import { Button, Flex, Space, Tooltip, Typography, theme } from 'antd'
import { useEffect, useRef, useState } from 'react'
import type { Graph, GraphNode } from '../api'
import { useI18n } from '../i18n'

// 中间一列既放进程也放连接：端点证据和流量证据在同一层
const COLUMNS = ['asset', 'process', 'connection', 'alert'] as const
const COL_X: Record<string, number> = { asset: 20, process: 250, connection: 250, alert: 480 }
const NODE_W = 190
const NODE_H = 34
const GAP_Y = 52

export function IncidentGraph({ graph }: { graph: Graph }) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const colors: Record<string, string> = {
    asset: token.colorPrimary,
    process: token.purple,
    connection: token.colorSuccess,
    alert: token.colorError,
  }
  const columns: Record<string, GraphNode[]> = { asset: [], process: [], connection: [], alert: [] }
  for (const node of graph.nodes) (columns[node.type] ?? columns.process).push(node)

  const pos = new Map<string, { x: number; y: number }>()
  let middleRow = 0
  for (const col of COLUMNS) {
    // process 和 connection 共用中间列，纵向接着排，不能各自从 0 开始
    const shared = col === 'process' || col === 'connection'
    columns[col].forEach((n, i) => {
      const row = shared ? middleRow++ : i
      pos.set(n.id, { x: COL_X[col], y: 20 + row * GAP_Y })
    })
  }
  const rows = Math.max(columns.asset.length, middleRow, columns.alert.length, 1)
  const contentW = COL_X.alert + NODE_W + 20
  const contentH = 20 + rows * GAP_Y
  const height = Math.min(Math.max(contentH, 180), 460)

  // 视图变换：滚轮缩放（以指针为中心）、拖拽平移；节点多时比滚动条好用
  const box = useRef<HTMLDivElement>(null)
  const [view, setView] = useState({ k: 1, x: 0, y: 0 })
  const drag = useRef<{ x: number; y: number } | null>(null)
  const zoom = (f: number, cx = contentW / 2, cy = height / 2) =>
    setView(v => {
      const k = Math.min(3, Math.max(0.3, v.k * f))
      return { k, x: cx - ((cx - v.x) * k) / v.k, y: cy - ((cy - v.y) * k) / v.k }
    })
  const fit = () => {
    const w = box.current?.clientWidth ?? contentW
    const k = Math.min(1, w / contentW, height / contentH)
    setView({ k, x: (w - contentW * k) / 2, y: 0 })
  }
  useEffect(fit, [contentW, contentH, height])
  // React 的 onWheel 是被动监听，阻止不了页面滚动，只能手挂
  useEffect(() => {
    const el = box.current
    if (!el) return
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      const r = el.getBoundingClientRect()
      zoom(e.deltaY < 0 ? 1.1 : 1 / 1.1, e.clientX - r.left, e.clientY - r.top)
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  })

  return (
    <div>
      <Flex justify="flex-end" style={{ marginBottom: 8 }}>
      <Space.Compact size="small">
        <Tooltip title={t('zoomIn')}><Button icon={<ZoomInOutlined />} onClick={() => zoom(1.25)} /></Tooltip>
        <Tooltip title={t('zoomOut')}><Button icon={<ZoomOutOutlined />} onClick={() => zoom(0.8)} /></Tooltip>
        <Tooltip title={t('zoomFit')}><Button icon={<CompressOutlined />} onClick={fit} /></Tooltip>
      </Space.Compact>
      </Flex>
      <div
        ref={box}
        style={{ height, overflow: 'hidden', cursor: drag.current ? 'grabbing' : 'grab', touchAction: 'none' }}
        onPointerDown={e => { drag.current = { x: e.clientX - view.x, y: e.clientY - view.y }; e.currentTarget.setPointerCapture(e.pointerId) }}
        onPointerMove={e => { const d = drag.current; if (d) setView(v => ({ ...v, x: e.clientX - d.x, y: e.clientY - d.y })) }}
        onPointerUp={() => { drag.current = null }}
      >
      <svg width="100%" height={height}>
        <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
        {graph.edges.map((e, i) => {
          const from = pos.get(e.from)
          const to = pos.get(e.to)
          if (!from || !to) return null
          const x1 = from.x + NODE_W
          const y1 = from.y + NODE_H / 2
          const x2 = to.x
          const y2 = to.y + NODE_H / 2
          const mx = (x1 + x2) / 2
          const spawned = e.rel === 'spawned'
          // 父子进程在同一列，直连会压在节点上，绕到列右侧再回来
          const d = spawned
            ? `M ${x1} ${y1} C ${x1 + 40} ${y1}, ${x1 + 40} ${y2}, ${x2 + NODE_W} ${y2}`
            : `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`
          return <path key={i} d={d} fill="none" stroke={spawned ? colors.process : token.colorBorder} strokeWidth={1.5} strokeDasharray={spawned ? '4 3' : undefined} />
        })}
        {graph.nodes.map(node => {
          const p = pos.get(node.id)
          if (!p) return null
          const label = node.label.length > 24 ? node.label.slice(0, 23) + '…' : node.label
          return (
            <g key={node.id}>
              <rect x={p.x} y={p.y} width={NODE_W} height={NODE_H} rx={6} fill={token.colorBgContainer} stroke={colors[node.type] ?? token.colorBorder} strokeWidth={1.5} />
              <text x={p.x + 10} y={p.y + 21} fill={token.colorText} fontSize={12}>
                <title>{node.label}</title>
                {label}
              </text>
            </g>
          )
        })}
        </g>
      </svg>
      </div>
      {graph.overflow > 0 && <Typography.Text type="warning">{t('graphOverflow', { n: graph.overflow })}</Typography.Text>}
    </div>
  )
}
