import type { ClosureProposal, Verdict } from '../api'

// AI 研判对应的结案状态：判良性 → 误报 / 良性，判恶意或可疑 → 属实已处置；没研判返回 null
export function verdictStatus(verdict: Verdict | null | undefined): 'closed' | 'false_positive' | null {
  const v = verdict?.verdict
  return v === 'benign' ? 'false_positive' : v === 'malicious' || v === 'suspicious' ? 'closed' : null
}

// 结论与 AI 研判一致（判良性按误报关、判恶意或可疑按属实关）时理由可以不写：说明取研判摘要，
// 不当人工案例回喂研判。相反或没有研判时必须写——那正是最值钱的人工判断
export function agreesWithAI(verdict: Verdict | null | undefined, status: 'closed' | 'false_positive' | null): boolean {
  const v = verdict?.verdict
  return status === 'false_positive' ? v === 'benign' : status === 'closed' && (v === 'malicious' || v === 'suspicious')
}

// 结案弹窗预填的说明：所选结论与 AI 结案建议相同时取最近一条建议的说明（人可以改），原样提交后端记为采纳 AI 建议。
// 事件列表与对话页结案共用
export function proposalNote(rows: { closureProposal: ClosureProposal | null }[], status: string | null | undefined): string | undefined {
  return rows
    .flatMap(({ closureProposal: p }) => (p && p.status === status ? [p] : []))
    .sort((a, b) => b.at.localeCompare(a.at))[0]?.note
}
