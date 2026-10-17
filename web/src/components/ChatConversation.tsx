import {
  CheckCircleFilled, CloseCircleFilled, CodeOutlined, ExportOutlined, FilePdfOutlined, FileTextOutlined, LoadingOutlined,
  RobotOutlined, ToolOutlined, UserOutlined,
} from '@ant-design/icons'
import { Alert, App, Avatar, Button, Collapse, Drawer, Flex, Space, Timeline, Typography, theme } from 'antd'
import { useState } from 'react'
import { downloadAgentPdf, reportHtmlUrl, type AgentReport, type ContentPart, type PiMessage } from '../api'
import { useI18n } from '../i18n'
import { Markdown } from './Markdown'
import { fmtTime, errText } from './format'

export interface ChatRow {
  message: PiMessage
  at?: string
}

type ToolResult = Extract<PiMessage, { role: 'toolResult' }>
type ToolCallPart = Extract<ContentPart, { type: 'toolCall' }>

export const textOf = (content: string | ContentPart[]) =>
  typeof content === 'string' ? content : content.map(p => (p.type === 'text' ? p.text : '')).join('')

// report 工具返回 {"reportId", "title"}，拿到 id 才能给 HTML / PDF
function reportIdOf(r?: ToolResult) {
  try {
    return (JSON.parse(textOf(r?.content ?? '')) as { reportId?: string }).reportId
  } catch {
    return undefined
  }
}

function ReportDrawer({ call, result, onClose }: { call: ToolCallPart | null; result?: ToolResult; onClose: () => void }) {
  const { t } = useI18n()
  const { message } = App.useApp()
  const id = reportIdOf(result)
  const title = String(call?.arguments.title ?? '')
  return (
    <Drawer size={760} open={!!call} title={title} onClose={onClose}
      extra={id && (
        <Space>
          <Button icon={<ExportOutlined />} onClick={() => window.open(reportHtmlUrl(id), '_blank', 'noopener')}>HTML</Button>
          <Button icon={<FilePdfOutlined />} onClick={() => downloadAgentPdf({ id, title } as AgentReport).catch(e => message.error(errText(e, t)))}>PDF</Button>
        </Space>
      )}>
      {call && <Markdown text={String(call.arguments.markdown ?? '')} />}
    </Drawer>
  )
}

// 执行链：一轮里模型调用的工具按顺序排成时间线，每步的结果就地折叠在下面
function ExecChain({ calls, results, hosts, onPreview }: {
  calls: ToolCallPart[]
  results: Map<string, ToolResult>
  hosts: Record<string, string>
  onPreview: (c: ToolCallPart) => void
}) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const done = calls.filter(c => results.has(c.id)).length
  return (
    <div className="chat-chain" style={{ borderColor: token.colorBorderSecondary, background: token.colorFillQuaternary }}>
      <Space size={6} className="chat-chain-head" style={{ color: token.colorTextSecondary }}>
        <ToolOutlined />{t('execChain', { done, n: calls.length })}
      </Space>
      <Timeline
        items={calls.map(c => {
          const r = results.get(c.id)
          const icon = !r ? <LoadingOutlined style={{ color: token.colorPrimary }} />
            : r.isError ? <CloseCircleFilled style={{ color: token.colorError }} />
              : <CheckCircleFilled style={{ color: token.colorSuccess }} />
          const host = String(c.arguments.host ?? '')
          const title = c.name === 'exec' ? t('toolExec', { host: hosts[host] ?? host })
            : c.name === 'report' ? t('toolReport', { title: String(c.arguments.title ?? '') })
              : t('toolCall', { name: c.name })
          return {
            key: c.id,
            icon,
            content: (
              <div className="chat-step">
                <Space size={6}>
                  {c.name === 'report' ? <FileTextOutlined /> : <CodeOutlined />}
                  <Typography.Text strong>{title}</Typography.Text>
                  {!r && <Typography.Text type="secondary">{t(c.name === 'exec' ? 'stepWaitingExec' : 'stepRunning')}</Typography.Text>}
                </Space>
                {c.name === 'exec' && <pre className="chat-code">{String(c.arguments.cmd ?? '')}</pre>}
                {c.name !== 'exec' && c.name !== 'report' && <pre className="chat-code">{JSON.stringify(c.arguments, null, 2)}</pre>}
                {c.name === 'report' && <Button size="small" icon={<FileTextOutlined />} onClick={() => onPreview(c)} style={{ marginTop: 6 }}>{t('previewReport')}</Button>}
                {r && c.name !== 'report' && (
                  <Collapse ghost size="small" className="chat-step-out"
                    items={[{ key: 'o', label: t(r.isError ? 'stepFailedOutput' : 'stepOutput'), children: <pre className="chat-code">{textOf(r.content) || t('emptyOutput')}</pre> }]} />
                )}
              </div>
            ),
          }
        })}
      />
    </div>
  )
}

function Meta({ at }: { at?: string }) {
  return at ? <Typography.Text type="secondary" className="chat-meta">{fmtTime(at)}</Typography.Text> : null
}

// 会话渲染：user 右侧气泡；assistant 左侧，正文 Markdown + 本轮执行链；toolResult 不单独成行
export function ChatConversation({ rows, hosts }: { rows: ChatRow[]; hosts: Record<string, string> }) {
  const { t } = useI18n()
  const { token } = theme.useToken()
  const [preview, setPreview] = useState<ToolCallPart | null>(null)
  const results = new Map<string, ToolResult>()
  for (const { message } of rows) if (message.role === 'toolResult') results.set(message.toolCallId, message)

  return (
    <>
      {rows.map(({ message: m, at }, i) => {
        if (m.role === 'toolResult') return null
        if (m.role === 'user') {
          return (
            <Flex key={i} justify="flex-end" gap={8} className="chat-row">
              <Flex vertical align="flex-end" style={{ maxWidth: '80%' }}>
                <div className="chat-bubble chat-bubble-user" style={{ background: token.colorPrimaryBg }}>{textOf(m.content)}</div>
                <Meta at={at} />
              </Flex>
              <Avatar icon={<UserOutlined />} style={{ flex: 'none' }} />
            </Flex>
          )
        }
        const texts = m.content.filter((p): p is Extract<ContentPart, { type: 'text' }> => p.type === 'text' && !!p.text)
        const calls = m.content.filter((p): p is ToolCallPart => p.type === 'toolCall')
        return (
          <Flex key={i} gap={8} className="chat-row">
            <Avatar icon={<RobotOutlined />} style={{ background: token.colorPrimary, flex: 'none' }} />
            <Flex vertical gap={8} style={{ minWidth: 0, maxWidth: '85%', flex: 1 }}>
              {texts.map((p, j) => (
                <div key={j} className="chat-bubble" style={{ background: token.colorFillQuaternary }}><Markdown text={p.text} /></div>
              ))}
              {calls.length > 0 && <ExecChain calls={calls} results={results} hosts={hosts} onPreview={setPreview} />}
              {m.errorMessage && <Alert type="error" showIcon title={m.errorMessage} />}
              {(m.stopReason === 'length' || m.stopReason === 'max_turns') && <Alert type="warning" showIcon title={t('chatTruncated')} />}
              <Meta at={at} />
            </Flex>
          </Flex>
        )
      })}
      <ReportDrawer call={preview} result={preview ? results.get(preview.id) : undefined} onClose={() => setPreview(null)} />
    </>
  )
}
