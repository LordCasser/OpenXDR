import type { MsgKey, T } from '../i18n'

// 事件体是 OCSF 风格的 JSON，字段随类别不同；这里只读、不信任，取不到就跳过
type Raw = Record<string, any>

const ACTIVITY: Record<number, Record<number, MsgKey>> = {
  1007: { 1: 'evLaunch', 2: 'evExit' },
  1001: { 1: 'evCreate', 3: 'evUpdate', 4: 'evDelete' },
  1005: { 1: 'evLoad', 4: 'evUnload' },
  201002: { 1: 'evCreate', 3: 'evUpdate', 4: 'evDelete' },
}

const join = (...parts: unknown[]) => parts.filter(p => p !== undefined && p !== null && p !== '').join(' ')
const endpoint = (e: Raw | undefined) => (e?.ip ? (e.port ? `${e.ip}:${e.port}` : e.ip) : undefined)

// 一行说清这条事件是什么：谁、做了什么、对象是谁。列表里不用再点开读 JSON
export function eventSummary(classUid: number, raw: unknown, t: T): string {
  const r = (raw ?? {}) as Raw
  const key = ACTIVITY[classUid]?.[r.activity_id]
  const act = key ? t(key) : undefined
  switch (classUid) {
    case 1007: {
      const p = r.process ?? {}
      const exit = r.activity_id === 2 && p.exit_code != null ? t('evExitCode', { n: p.exit_code }) : undefined
      return join(act, p.name || p.file?.path, p.cmd_line && p.cmd_line !== p.name ? `· ${p.cmd_line}` : undefined, exit)
    }
    case 1001:
      return join(act, r.file?.path, r.process?.name ? `· ${r.process.name}` : undefined)
    case 3002: {
      if (r.activity_id >= 10) return join(r.user?.name, r.group_name, r.target_server, r.policy_category)
      const ok = r.status_id === 1 ? t('evLoginOk') : t('evLoginFail')
      return join(ok, r.user?.name, r.src_endpoint?.ip ? `← ${r.src_endpoint.ip}` : undefined, r.service?.name ? `(${r.service.name})` : undefined)
    }
    case 4001: {
      const host = r.tls?.sni || r.http_request?.hostname
      return join(r.process?.name, endpoint(r.src_endpoint), '→', endpoint(r.dst_endpoint), host ? `(${host})` : undefined)
    }
    case 4003: {
      const answers = Array.isArray(r.answers) ? r.answers.map((a: Raw) => a.ip).filter(Boolean).join(', ') : ''
      return join(r.query?.hostname, answers ? `→ ${answers}` : undefined)
    }
    case 1005:
      return join(act, r.module?.file?.name || r.module?.file?.path)
    case 201002:
      return join(act, r.reg_key?.path, r.reg_value?.data != null ? `= ${r.reg_value.data}` : undefined)
    case 100001:
      return join(r.device?.hostname, r.message)
    default:
      return ''
  }
}
