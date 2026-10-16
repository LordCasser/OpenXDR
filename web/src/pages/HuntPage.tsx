import { useMutation } from '@tanstack/react-query'
import { Alert, App, Button, Card, Collapse, Empty, Input, Space, Typography } from 'antd'
import { useState } from 'react'
import { draftRule, hunt, saveRule, type HuntStep } from '../api'
import { Page } from '../components/Page'
import { useI18n, type MsgKey } from '../i18n'

interface Turn {
  question: string
  answer: string
  steps: HuntStep[]
  // 规则草稿：undefined 未起草，字符串是可编辑 YAML；保存后只留标题
  draft?: string
  savedTitle?: string
}

const EXAMPLES: MsgKey[] = ['huntExample1', 'huntExample2', 'huntExample3']

// 威胁狩猎（旧 triage 引擎）：每次回答附上调用过的工具与参数，无从复核的结论没有价值
export function HuntPage() {
  const { t } = useI18n()
  const { message } = App.useApp()
  const [question, setQuestion] = useState('')
  const [turns, setTurns] = useState<Turn[]>([])
  const patch = (i: number, p: Partial<Turn>) => setTurns(prev => prev.map((x, j) => (j === i ? { ...x, ...p } : x)))

  const ask = useMutation({
    mutationFn: hunt,
    onSuccess: (r, q) => {
      setTurns(prev => [...prev, { question: q, answer: r.answer, steps: r.steps ?? [] }])
      setQuestion('')
    },
    onError: e => message.error(String(e)),
  })
  const draft = useMutation({
    mutationFn: ({ turn }: { i: number; turn: Turn }) => draftRule(turn.question, turn.answer),
    onSuccess: (r, { i }) => patch(i, { draft: r.yaml }),
    onError: e => message.error(String(e)),
  })
  const save = useMutation({
    mutationFn: ({ yaml }: { i: number; yaml: string }) => saveRule(yaml),
    onSuccess: (r, { i }) => patch(i, { draft: undefined, savedTitle: r.title || r.id }),
    onError: e => message.error(String(e)),
  })
  const submit = (q: string) => q.trim() && !ask.isPending && ask.mutate(q.trim())

  return (
    <Page title={t('navHunt')} subtitle={t('huntSubtitle')}>
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        <Card>
          <Input.Search
            size="large"
            enterButton={t('huntAsk')}
            loading={ask.isPending}
            placeholder={t('huntPlaceholder')}
            value={question}
            onChange={e => setQuestion(e.target.value)}
            onSearch={submit}
          />
          {turns.length === 0 && (
            <Space wrap style={{ marginTop: 12 }}>
              <Typography.Text type="secondary">{t('huntHint')}</Typography.Text>
              {EXAMPLES.map(k => <Button key={k} size="small" onClick={() => submit(t(k))}>{t(k)}</Button>)}
            </Space>
          )}
        </Card>
        {turns.length === 0 && !ask.isPending && <Empty description={t('huntEmpty')} />}
        {turns.map((turn, i) => (
          <Card key={i} title={turn.question} size="small">
            <Typography.Paragraph style={{ whiteSpace: 'pre-wrap' }}>{turn.answer}</Typography.Paragraph>
            {turn.steps.length > 0 && (
              <Collapse size="small" ghost items={[{
                key: 's',
                label: t('huntSteps', { n: turn.steps.length }),
                children: turn.steps.map((s, j) => <div key={j} className="mono">{s.tool}({s.args})</div>),
              }]} />
            )}
            {turn.savedTitle ? (
              <Alert type="success" showIcon title={t('huntRuleSaved', { title: turn.savedTitle })} />
            ) : turn.draft !== undefined ? (
              <Space orientation="vertical" style={{ width: '100%' }}>
                <Typography.Text type="secondary">{t('huntDraftHint')}</Typography.Text>
                <Input.TextArea className="mono" autoSize={{ minRows: 8 }} value={turn.draft} onChange={e => patch(i, { draft: e.target.value })} />
                <Space>
                  <Button type="primary" loading={save.isPending} onClick={() => save.mutate({ i, yaml: turn.draft! })}>{t('huntSave')}</Button>
                  <Button onClick={() => patch(i, { draft: undefined })}>{t('cancel')}</Button>
                </Space>
              </Space>
            ) : (
              <Button loading={draft.isPending && draft.variables?.i === i} onClick={() => draft.mutate({ i, turn })}>{t('huntSaveRule')}</Button>
            )}
          </Card>
        ))}
      </Space>
    </Page>
  )
}
