import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

// 模型输出不可信：react-markdown 默认不渲染原始 HTML，并过滤 javascript: 等链接
export function Markdown({ text }: { text: string }) {
  return (
    <div className="markdown">
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{text}</ReactMarkdown>
    </div>
  )
}
